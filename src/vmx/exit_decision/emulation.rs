//! Instructions Aleph0 executes for the guest: passthrough emulation.
//!
//! Some guest instructions always exit (CPUID, XSETBV). Others exit because the
//! exit bitmaps ask for it (RDMSR/WRMSR through the MSR bitmap, IN/OUT through
//! the I/O bitmaps, both in `vmx::exit_bitmaps`). A handler here decides
//! what to execute. `vmexit::handler` then runs the real
//! instruction in root operation, writes the result into the guest's
//! registers and moves RIP past the instruction, so the guest sees what the
//! hardware says, except where a policy here changes it
//! ([`cpuid_policy`]).
//!
//! The guest's MTRRs are the exception to passthrough. The CPU's still set
//! the memory types of Aleph0's own accesses in root operation, so the
//! guest's RDMSR and WRMSR of them reach a copy instead
//! (`vmexit::guest_mtrrs`), and a value WRMSR would refuse gets the #GP it
//! would get on bare metal. So does an MTRR address the CPU has no MSR at,
//! which the MSR bitmap intercepts too.
//!
//! Hyper-V's hypercalls and synthetic MSRs are passed through one level
//! further: Aleph0 makes the same access in root operation, and L0 Hyper-V
//! answers it (`vmx::hyperv`), or refuses it with the exception the guest
//! then gets.
//!
//! HLT is decided here too, but never executed: Aleph0 resumes past it (see
//! [`hlt`]).
//!
//! These handlers hold for any guest, so they read only the exit itself, never
//! the test guest's `ExitState`. What they did is counted afterwards, in
//! `vmexit::stats`.

use core::arch::x86_64::CpuidResult;

use super::{ExitEvent, ExitInfo};
use crate::vmx::cr::{CR4_OSXSAVE, CR4_PKE};
use crate::vmx::exit_bitmaps::{INTERCEPTED_MSRS, MsrAccess, msr_bit};
use crate::vmx::features::{CPUID_1_ECX_OSXSAVE, GuestFeatures};
use crate::vmx::hyperv;
use crate::vmx::mtrr::{self, MtrrCapabilities, MtrrMsr};

/// An instruction the exit handler executes for the guest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Emulation {
    /// CPUID with EAX = `leaf`, ECX = `subleaf`, from a guest whose CR4 is
    /// `guest_cr4` (GUEST_CR4), which the bits mirroring CR4 follow.
    Cpuid { leaf: u32, subleaf: u32, guest_cr4: u64 },
    /// XSETBV of `value` (EDX:EAX) to XCR0. `value` is one XSETBV takes
    /// ([`xcr0_valid`]), so the real XSETBV cannot fault.
    Xsetbv { value: u64 },
    /// RDMSR of `msr`, an intercepted MSR.
    Rdmsr { msr: u32 },
    /// WRMSR of `value` (EDX:EAX) to `msr`, an intercepted MSR. `value` is
    /// canonical, so the real WRMSR cannot fault.
    Wrmsr { msr: u32, value: u64 },
    /// RDMSR of `msr`, one of the guest's MTRRs: from its copy, never the
    /// CPU's.
    MtrrRead { msr: MtrrMsr },
    /// WRMSR of `value` to `msr`, one of the guest's MTRRs: into its copy,
    /// never the CPU's, and EPT takes the types it gives. `value` is one
    /// WRMSR would take.
    MtrrWrite { msr: MtrrMsr, value: u64 },
    /// IN of `size` from `port`.
    In { port: u16, size: IoSize },
    /// OUT of `value` (`size` wide) to `port`.
    Out { port: u16, size: IoSize, value: u32 },
    /// VMCALL with the hypercall input value `input` in RCX: made again in
    /// root operation with the guest's RCX, RDX and R8, for Hyper-V.
    Hypercall { input: u64 },
    /// RDMSR of `msr`, one of Hyper-V's synthetic MSRs: from Hyper-V.
    SyntheticRead { msr: u32 },
    /// WRMSR of `value` to `msr`, one of Hyper-V's synthetic MSRs: to
    /// Hyper-V, which checks the value.
    SyntheticWrite { msr: u32, value: u64 },
}

/// CPUID.1:ECX bit 5: VMX.
const CPUID_1_ECX_VMX: u32 = 1 << 5;
/// CPUID.(EAX=7,ECX=0):ECX bit 4: OSPKE, a copy of CR4.PKE.
const CPUID_7_ECX_OSPKE: u32 = 1 << 4;

/// `bit` if `cr4` has `cr4_bit` set, else 0.
fn mirrors(cr4: u64, cr4_bit: u64, bit: u32) -> u32 {
    if cr4 & cr4_bit != 0 { bit } else { 0 }
}

/// What the guest sees for CPUID `leaf`/`subleaf`, given what the processor
/// returned in root operation (`raw`), the guest's CR4 (`guest_cr4`) and what
/// bring-up offers it (`features`):
///
/// - CPUID.1:ECX.VMX is cleared. A guest that saw it would try VMXON, which
///   always exits (reason 27), and Aleph0 does not emulate VMX.
/// - CPUID.1:ECX.OSXSAVE and CPUID.(7,0):ECX.OSPKE copy the guest's
///   CR4.OSXSAVE and CR4.PKE. CPUID runs in root operation, where they copy
///   HOST_CR4, not the guest's.
/// - The bits of what bring-up does not offer are cleared
///   ([`GuestFeatures::hidden`]): their instructions would #UD in the guest.
///
/// Left as the processor says:
/// - ECX bit 31 (hypervisor present) and the leaves from 0x40000000, which
///   under Hyper-V describe Hyper-V: the guest keeps Hyper-V's interface,
///   and Aleph0 forwards it (docs/HYPERV_INTERFACE.md);
/// - leaf 0xD's sizes, which follow XCR0. VM entry and exit do not switch
///   XCR0, and only the guest's XSETBV changes it, so they are the guest's.
pub fn cpuid_policy(leaf: u32, subleaf: u32, raw: CpuidResult, guest_cr4: u64, features: GuestFeatures) -> CpuidResult {
    let hidden = features.hidden();
    match (leaf, subleaf) {
        (1, _) => CpuidResult {
            ecx: (raw.ecx & !(CPUID_1_ECX_VMX | CPUID_1_ECX_OSXSAVE | hidden.leaf_1_ecx))
                | mirrors(guest_cr4, CR4_OSXSAVE, CPUID_1_ECX_OSXSAVE),
            ..raw
        },
        (7, 0) => CpuidResult {
            ebx: raw.ebx & !hidden.leaf_7_ebx,
            ecx: (raw.ecx & !(CPUID_7_ECX_OSPKE | hidden.leaf_7_ecx)) | mirrors(guest_cr4, CR4_PKE, CPUID_7_ECX_OSPKE),
            ..raw
        },
        (0xD, 1) => CpuidResult {
            eax: raw.eax & !hidden.leaf_d_1_eax,
            ..raw
        },
        (0x8000_0001, _) => CpuidResult {
            edx: raw.edx & !hidden.extended_edx,
            ..raw
        },
        _ => raw,
    }
}

/// CPUID (exit reason 10), which always exits: execute it with the guest's
/// EAX (leaf) and ECX (subleaf), for its CR4.
pub(super) fn cpuid(exit: &ExitInfo) -> ExitEvent {
    ExitEvent::Emulated(Emulation::Cpuid {
        leaf: exit.guest_rax as u32,
        subleaf: exit.guest_rcx as u32,
        guest_cr4: exit.guest_cr4,
    })
}

// XCR0 components with rules of their own (Intel SDM Vol. 1, "Enabling the
// XSAVE Feature Set and XSAVE-Enabled Features").
/// Bit 0: x87 state, which is always on.
const XCR0_X87: u64 = 1 << 0;
/// Bit 1: SSE state.
const XCR0_SSE: u64 = 1 << 1;
/// Bit 2: AVX state, which needs SSE.
const XCR0_AVX: u64 = 1 << 2;
/// Bits 4:3: MPX's BNDREGS and BNDCSR, both or neither.
const XCR0_MPX: u64 = 0b11 << 3;
/// Bits 7:5: AVX-512's opmask, ZMM_Hi256 and Hi16_ZMM, all or none, and only
/// with SSE and AVX.
const XCR0_AVX512: u64 = 0b111 << 5;
/// Bits 18:17: AMX's XTILECFG and XTILEDATA, both or neither.
const XCR0_AMX: u64 = 0b11 << 17;

/// Whether XSETBV takes `value` for XCR0 on a CPU supporting the XCR0 bits
/// `supported`, as the SDM's XSETBV lists the #GP(0) cases: no bit outside
/// `supported`, x87 set, AVX only with SSE, AVX-512 all or none and only with
/// SSE and AVX, MPX and AMX both or neither.
pub fn xcr0_valid(value: u64, supported: u64) -> bool {
    let all_or_none = |bits: u64| value & bits == 0 || value & bits == bits;
    let sse_avx = XCR0_SSE | XCR0_AVX;
    value & !supported == 0
        && value & XCR0_X87 != 0
        && (value & XCR0_AVX == 0 || value & XCR0_SSE != 0)
        && all_or_none(XCR0_AVX512)
        && (value & XCR0_AVX512 == 0 || value & sse_avx == sse_avx)
        && all_or_none(XCR0_MPX)
        && all_or_none(XCR0_AMX)
}

/// XSETBV (exit reason 55), which always exits: of EDX:EAX to the XCR in
/// ECX, executed in root operation when it is XCR0 and a value XCR0 takes,
/// #GP(0) otherwise. The CPU raises #UD (guest CR4.OSXSAVE clear) and #GP
/// (CPL > 0) before the exit, so only the value is checked here (Intel SDM
/// Vol. 3C, "Relative Priority of Faults and VM Exits"). Without XSETBV in
/// root operation the supported bits are 0, so every value gets the #GP.
pub(super) fn xsetbv(exit: &ExitInfo) -> ExitEvent {
    // EDX:EAX, as for WRMSR.
    let value = wrmsr_value(exit);
    if exit.guest_rcx as u32 == 0 && xcr0_valid(value, exit.xcr0_supported) {
        ExitEvent::Emulated(Emulation::Xsetbv { value })
    } else {
        ExitEvent::GuestGeneralProtection
    }
}

/// HLT (exit reason 12): resume past it without halting. A halted vCPU
/// waits for an interrupt, and the guest's interrupts are delivered when it
/// next runs anyway, so going on at once is a correct, if busy, wait. The
/// HLT activity state would avoid one exit per idle loop round, but needs
/// IA32_VMX_MISC bit 6 and a rule for NMI exits taken in that state.
pub(super) fn hlt() -> ExitEvent {
    ExitEvent::Halted
}

/// Whether `value` is a canonical 48-bit address: bits 63:47 all equal.
/// With 5-level paging (CR4.LA57) it would be bits 63:56; Aleph0's guest
/// shares the host's CR4, which UEFI leaves without LA57.
pub fn is_canonical_48(value: u64) -> bool {
    ((value as i64) << 16 >> 16) as u64 == value
}

/// What an RDMSR or WRMSR of an MSR gets.
enum MsrRoute {
    /// In [`INTERCEPTED_MSRS`]: pass it through.
    Intercepted,
    /// One of the guest's MTRRs: read or write its copy.
    Mtrr(MtrrMsr),
    /// An address an MTRR has on some CPU, but not on this one (a variable
    /// range past IA32_MTRRCAP's count, the fixed ranges without
    /// IA32_MTRRCAP.FIX, any of them without MTRRs). The bitmap intercepts
    /// these too, and the guest gets the #GP a CPU without the MSR gives.
    AbsentMtrr,
    /// One of Hyper-V's synthetic MSRs ([`hyperv::SYNTHETIC_MSRS`]), with
    /// Hyper-V's interface present: forward it.
    Synthetic,
    /// Outside both MSR-bitmap ranges, so it exits whatever the bitmap
    /// says, and not forwarded. Aleph0 does not know it exists, and a real
    /// RDMSR/WRMSR of a missing MSR would #GP in the host, so the guest gets
    /// the #GP.
    OutOfRange,
    /// In range but its bit is clear, so it should never have exited: the
    /// bitmap is broken. Stop.
    NotIntercepted,
}

/// Which [`MsrRoute`] `msr` takes, for a guest whose MTRR MSRs are `mtrr`,
/// with Hyper-V's interface (`hyperv`) or without.
fn route(msr: u32, mtrr: MtrrCapabilities, hyperv: bool) -> MsrRoute {
    if msr_bit(msr, MsrAccess::Read).is_none() {
        if hyperv && hyperv::SYNTHETIC_MSRS.contains(&msr) {
            MsrRoute::Synthetic
        } else {
            MsrRoute::OutOfRange
        }
    } else if INTERCEPTED_MSRS.contains(&msr) {
        MsrRoute::Intercepted
    } else if let Some(msr) = mtrr.msr(msr) {
        MsrRoute::Mtrr(msr)
    } else if mtrr::is_msr_address(msr) {
        MsrRoute::AbsentMtrr
    } else {
        MsrRoute::NotIntercepted
    }
}

/// RDMSR (exit reason 31) of the MSR in ECX.
pub(super) fn rdmsr(exit: &ExitInfo) -> ExitEvent {
    let msr = exit.guest_rcx as u32;
    match route(msr, exit.mtrr, exit.hyperv) {
        MsrRoute::Intercepted => ExitEvent::Emulated(Emulation::Rdmsr { msr }),
        MsrRoute::Mtrr(msr) => ExitEvent::Emulated(Emulation::MtrrRead { msr }),
        MsrRoute::Synthetic => ExitEvent::Emulated(Emulation::SyntheticRead { msr }),
        MsrRoute::AbsentMtrr | MsrRoute::OutOfRange => ExitEvent::GuestGeneralProtection,
        MsrRoute::NotIntercepted => ExitEvent::Unexpected,
    }
}

/// The value a WRMSR exit writes: EDX:EAX. Like WRMSR itself, it ignores
/// the upper halves of RDX and RAX.
pub fn wrmsr_value(exit: &ExitInfo) -> u64 {
    (exit.guest_rdx << 32) | (exit.guest_rax & 0xFFFF_FFFF)
}

/// WRMSR (exit reason 32) of EDX:EAX to the MSR in ECX.
pub(super) fn wrmsr(exit: &ExitInfo) -> ExitEvent {
    let msr = exit.guest_rcx as u32;
    let value = wrmsr_value(exit);
    match route(msr, exit.mtrr, exit.hyperv) {
        // Every intercepted MSR holds an address (only IA32_KERNEL_GS_BASE
        // today). A real WRMSR of a non-canonical one would #GP in the host,
        // in exit context, so the guest gets that #GP instead.
        MsrRoute::Intercepted if !is_canonical_48(value) => ExitEvent::GuestGeneralProtection,
        MsrRoute::Intercepted => ExitEvent::Emulated(Emulation::Wrmsr { msr, value }),
        // Checked on its own, as the CPU does: a reserved type or bit gets
        // the #GP even in an MTRR not in use, and the copy stays as it was.
        MsrRoute::Mtrr(msr) => match exit.mtrr.check(msr, value) {
            Ok(()) => ExitEvent::Emulated(Emulation::MtrrWrite { msr, value }),
            Err(_) => ExitEvent::GuestGeneralProtection,
        },
        MsrRoute::Synthetic => ExitEvent::Emulated(Emulation::SyntheticWrite { msr, value }),
        MsrRoute::AbsentMtrr | MsrRoute::OutOfRange => ExitEvent::GuestGeneralProtection,
        MsrRoute::NotIntercepted => ExitEvent::Unexpected,
    }
}

/// How many bytes an IN or OUT moves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoSize {
    Byte,
    Word,
    Dword,
}

impl IoSize {
    /// Bytes moved: 1, 2 or 4.
    pub fn bytes(self) -> u8 {
        match self {
            Self::Byte => 1,
            Self::Word => 2,
            Self::Dword => 4,
        }
    }

    /// The bits of RAX the access uses: AL, AX or EAX.
    fn mask(self) -> u64 {
        match self {
            Self::Byte => 0xFF,
            Self::Word => 0xFFFF,
            Self::Dword => 0xFFFF_FFFF,
        }
    }
}

/// An I/O instruction's exit qualification (Intel SDM Vol. 3C, "Exit
/// Qualification for I/O Instructions"):
///
/// ```text
/// bits 2:0   size − 1: 0 = 1 byte, 1 = 2 bytes, 3 = 4 bytes
/// bit  3     direction: 1 = IN, 0 = OUT
/// bit  4     string instruction (INS/OUTS)
/// bit  5     REP prefix
/// bit  6     operand: 1 = immediate port, 0 = DX
/// bits 31:16 port
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IoQualification(pub u64);

impl IoQualification {
    /// The access size, or `None` for the encodings the SDM leaves unused.
    pub fn size(self) -> Option<IoSize> {
        match self.0 & 0b111 {
            0 => Some(IoSize::Byte),
            1 => Some(IoSize::Word),
            3 => Some(IoSize::Dword),
            _ => None,
        }
    }

    /// Whether it is IN (bit 3); OUT otherwise.
    pub fn is_in(self) -> bool {
        self.0 & (1 << 3) != 0
    }

    /// Whether it is INS or OUTS (bit 4).
    pub fn is_string(self) -> bool {
        self.0 & (1 << 4) != 0
    }

    /// Whether it has a REP prefix (bit 5).
    pub fn is_rep(self) -> bool {
        self.0 & (1 << 5) != 0
    }

    /// The port (bits 31:16).
    pub fn port(self) -> u16 {
        (self.0 >> 16) as u16
    }
}

/// RAX after an IN of `size` that read `value`. A 1- or 2-byte IN writes
/// only AL or AX and keeps the rest of RAX. A 4-byte IN writes EAX, which
/// zero-extends into RAX like every 32-bit register write in 64-bit mode.
pub fn merge_in(rax: u64, size: IoSize, value: u32) -> u64 {
    match size {
        IoSize::Dword => u64::from(value),
        _ => (rax & !size.mask()) | (u64::from(value) & size.mask()),
    }
}

/// The value an OUT of `size` sends: AL, AX or EAX.
pub fn out_value(rax: u64, size: IoSize) -> u32 {
    (rax & size.mask()) as u32
}

/// IN or OUT (exit reason 30), for a port the I/O bitmaps intercept: passed
/// through with the port and size from the exit qualification. Not checked
/// against INTERCEPTED_PORTS: an access to several ports exits if any of
/// them is intercepted (`in ax, dx` at 0x3FE covers 0x3FF), and passing
/// that access through is what the guest would have done anyway. String
/// and REP forms, which read or write guest memory, stop the guest.
pub(super) fn io(exit: &ExitInfo) -> ExitEvent {
    let io = IoQualification(exit.qualification);
    let Some(size) = io.size() else {
        return ExitEvent::Unexpected;
    };
    if io.is_string() || io.is_rep() {
        return ExitEvent::Unexpected;
    }
    let port = io.port();
    if io.is_in() {
        ExitEvent::Emulated(Emulation::In { port, size })
    } else {
        let value = out_value(exit.guest_rax, size);
        ExitEvent::Emulated(Emulation::Out { port, size, value })
    }
}

#[cfg(test)]
#[path = "../../../tests/unit/vmx/exit_decision/emulation.rs"]
mod tests;

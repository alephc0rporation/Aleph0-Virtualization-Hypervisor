//! Access to the x86 control registers (CRx) needed for VMX host state.
//!
//! CR0 controls basic execution modes, including protected mode and paging.
//! CR2 holds the linear address of the last page fault.
//! CR3 selects the current page-table root (and can carry PCID information).
//! CR4 enables additional CPU features, including VMX through CR4.VMXE.
//! On VM exit, the CPU loads host CR0, CR3, and CR4 from the VMCS, so those
//! fields must describe the environment the host handler will run in.
//!
//! VMX operation fixes some CR0 and CR4 bits (IA32_VMX_CR0/CR4_FIXED0/FIXED1).
//! To let the guest keep a view where they look as they did before VMX
//! operation (for instance CR4.VMXE = 0, since the guest's CPUID hides VMX),
//! Aleph0 gives the VMCS a guest/host mask over those bits and a read shadow
//! ([`CrControls`]); a MOV that changes an owned bit then exits (reason 28),
//! and `exit_decision::control_register` decides what to do. See
//! docs/CONTROL_REGISTERS.md.
use core::arch::asm;

use super::msr;

/// CR0 bit 0 (PE): protected mode. Clearing it (leaving protected mode)
/// needs an unrestricted guest, which Aleph0 does not enable.
pub const CR0_PE: u64 = 1 << 0;
/// CR0 bit 5 (NE): numeric-error reporting. VMX operation fixes it on, but a
/// guest may clear it in its own view (the real GUEST_CR0 keeps it set). The
/// production path forces it through FIXED0, not this constant, so it is only
/// named in tests.
#[cfg(test)]
pub const CR0_NE: u64 = 1 << 5;
/// CR0 bit 31 (PG): paging. Like PE, clearing it needs an unrestricted guest.
pub const CR0_PG: u64 = 1 << 31;

/// CR4 bit 12 (LA57): 5-level paging. [`super::paging::walk`] only handles
/// 4 levels.
pub const CR4_LA57: u64 = 1 << 12;

/// CR4 bit 13: VMX-enable. VMXON raises #UD while this is clear.
pub const CR4_VMXE: u64 = 1 << 13;

/// CR4 bit 18 (OSXSAVE): XGETBV and XSETBV may run, and CPUID.1:ECX bit 27
/// reports this bit.
pub const CR4_OSXSAVE: u64 = 1 << 18;

/// CR4 bit 22 (PKE): protection keys for user pages, which
/// CPUID.(EAX=7,ECX=0):ECX bit 4 (OSPKE) reports.
pub const CR4_PKE: u64 = 1 << 22;

/// CR4 bit 20 (SMEP): ring 0 may not execute from user pages.
pub const CR4_SMEP: u64 = 1 << 20;

/// CR4 bit 21 (SMAP): ring 0 may not read or write user pages while
/// RFLAGS.AC = 0.
pub const CR4_SMAP: u64 = 1 << 21;

/// Defines a safe reader, and optionally an unsafe writer, for one control
/// register. Reading a control register in ring 0 has no side effects;
/// writing one changes how the CPU runs, so writers stay `unsafe`.
macro_rules! control_register {
    ($read:ident, $write:ident, $register:literal) => {
        control_register!($read, $register);

        #[doc = concat!("Writes ", $register, ".")]
        ///
        /// # Safety
        ///
        /// The new value must keep the CPU in a state the running code can
        /// continue in (paging, protection and VMX fixed bits included).
        pub unsafe fn $write(value: u64) {
            // SAFETY: the caller guarantees the value is valid to load.
            unsafe { asm!(concat!("mov ", $register, ", {}"), in(reg) value, options(nostack, preserves_flags)) };
        }
    };
    ($read:ident, $register:literal) => {
        #[doc = concat!("Reads ", $register, ".")]
        pub fn $read() -> u64 {
            let value: u64;
            // SAFETY: a read of a control register in ring 0: no memory
            // access, no side effects.
            unsafe { asm!(concat!("mov {}, ", $register), out(reg) value, options(nomem, nostack, preserves_flags)) };
            value
        }
    };
}

control_register!(read_cr0, write_cr0, "cr0");
control_register!(read_cr2, "cr2");
control_register!(read_cr3, write_cr3, "cr3");
control_register!(read_cr4, write_cr4, "cr4");

/// Sets CR4.VMXE, leaving every other bit untouched.
///
/// # Safety
///
/// The CPU must support VMX (CPUID.1:ECX.VMX); otherwise the write faults.
pub unsafe fn enable_vmxe() {
    // SAFETY: only VMXE changes, which the caller has checked is supported.
    unsafe { write_cr4(read_cr4() | CR4_VMXE) };
}

/// Writes `value` to XCR0 with XSETBV (ECX = 0).
///
/// # Safety
///
/// CR4.OSXSAVE must be set, and `value` one XSETBV takes (the XSETBV
/// decision in `exit_decision`), or it faults. The new XCR0 decides which
/// state XSAVE saves, so it must be one the code running afterwards expects.
pub unsafe fn xsetbv(value: u64) {
    // SAFETY: the caller guarantees CR4.OSXSAVE and a value XCR0 takes.
    unsafe {
        asm!(
            "xsetbv",
            in("ecx") 0,
            in("eax") value as u32,
            in("edx") (value >> 32) as u32,
            options(nomem, nostack, preserves_flags),
        )
    };
}

/// The IA32_VMX_CR0/CR4_FIXED0/FIXED1 MSRs: the CR0 and CR4 bits VMX
/// operation fixes. A bit set in FIXED0 must be 1; a bit clear in FIXED1 must
/// be 0. The guest/host masks, read shadows ([`CrControls`]) and the
/// reason-28 decision (`exit_decision::control_register`) all follow from them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CrFixed {
    pub cr0_fixed0: u64,
    pub cr0_fixed1: u64,
    pub cr4_fixed0: u64,
    pub cr4_fixed1: u64,
}

impl CrFixed {
    /// All zero: no bit fixed. A placeholder for exits that are not
    /// control-register accesses, which `exit_decision::decide` never reads
    /// it for.
    pub const NONE: Self = Self {
        cr0_fixed0: 0,
        cr0_fixed1: 0,
        cr4_fixed0: 0,
        cr4_fixed1: 0,
    };

    /// Reads the four MSRs.
    ///
    /// # Safety
    ///
    /// The CPU must support VMX, so the FIXED MSRs exist (checked before
    /// VMXON, and still true in exit context).
    pub unsafe fn read() -> Self {
        // SAFETY: the caller guarantees VMX support, so the FIXED MSRs exist
        // and reading them has no side effects.
        unsafe {
            Self {
                cr0_fixed0: msr::rdmsr(msr::IA32_VMX_CR0_FIXED0),
                cr0_fixed1: msr::rdmsr(msr::IA32_VMX_CR0_FIXED1),
                cr4_fixed0: msr::rdmsr(msr::IA32_VMX_CR4_FIXED0),
                cr4_fixed1: msr::rdmsr(msr::IA32_VMX_CR4_FIXED1),
            }
        }
    }

    /// The CR0 bits VMX operation fixes, so the guest/host mask owns them
    /// (typically PE, NE and PG).
    pub fn cr0_owned(self) -> u64 {
        owned(self.cr0_fixed0, self.cr0_fixed1)
    }

    /// The CR4 bits VMX operation fixes, so the guest/host mask owns them
    /// (CR4.VMXE among them).
    pub fn cr4_owned(self) -> u64 {
        owned(self.cr4_fixed0, self.cr4_fixed1)
    }
}

/// The bits VMX operation fixes, from one register's FIXED0/FIXED1: the
/// must-be-1 bits (FIXED0) and the must-be-0 bits (`!FIXED1`). The guest must
/// not freely change them, so the guest/host mask owns exactly these.
pub fn owned(fixed0: u64, fixed1: u64) -> u64 {
    fixed0 | !fixed1
}

/// A control-register value forced into the range VMX operation requires,
/// as `vmxon::apply_fixed_bits` does for the host: must-be-1 bits set,
/// must-be-0 bits cleared. GUEST_CRn becomes this when a guest write is
/// emulated, so the real register stays legal whatever the guest asked for.
pub fn legal(requested: u64, fixed0: u64, fixed1: u64) -> u64 {
    (requested | fixed0) & fixed1
}

/// The read shadow a guest should start with: the value it had, except that
/// the `owned` bits show their value from before VMX operation (`original`),
/// not the one VMX operation forced. So the guest reads CR4.VMXE as 0 while
/// GUEST_CR4 keeps it set.
pub fn read_shadow(guest: u64, original: u64, owned: u64) -> u64 {
    (guest & !owned) | (original & owned)
}

/// Whether a MOV that loads `requested` into a control register with read
/// shadow `shadow` and guest/host mask `owned` causes a VM exit: exactly when
/// it changes an owned bit away from the shadow (Intel SDM Vol. 3C, "Changes
/// to Instruction Behavior in VMX Non-Root Operation"). A write matching the
/// shadow in every owned bit (Linux clearing CR4.VMXE, which the shadow shows
/// as 0) does not exit; the CPU keeps the owned bits and the real VMXE stays
/// set. The CPU enforces this at run time, so the helper exists to document
/// and test the condition.
#[cfg(test)]
pub fn mov_exits(requested: u64, shadow: u64, owned: u64) -> bool {
    (requested ^ shadow) & owned != 0
}

/// The CR0/CR4 guest/host masks and initial read shadows bring-up writes to
/// the VMCS. The masks own the bits VMX operation fixes; the shadows show the
/// guest the pre-VMX values of those bits (CR4.VMXE = 0), while GUEST_CR0/CR4
/// keep the real ones.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CrControls {
    pub cr0_mask: u64,
    pub cr4_mask: u64,
    pub cr0_shadow: u64,
    pub cr4_shadow: u64,
}

impl CrControls {
    /// From the FIXED MSRs, the guest's CR0/CR4 (the host's, which the guest
    /// state copies, so VMXE is set) and the CR0/CR4 from before VMXON
    /// (`original_*`, VMXE clear), which `VmxOperation` keeps.
    pub fn new(fixed: CrFixed, guest_cr0: u64, guest_cr4: u64, original_cr0: u64, original_cr4: u64) -> Self {
        let cr0_mask = fixed.cr0_owned();
        let cr4_mask = fixed.cr4_owned();
        Self {
            cr0_mask,
            cr4_mask,
            cr0_shadow: read_shadow(guest_cr0, original_cr0, cr0_mask),
            cr4_shadow: read_shadow(guest_cr4, original_cr4, cr4_mask),
        }
    }
}

#[cfg(test)]
#[path = "../../tests/unit/vmx/cr.rs"]
mod tests;

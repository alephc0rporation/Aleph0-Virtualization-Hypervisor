//! MOV to CR0/CR4 (exit reason 28): the pure decision.
//!
//! With the guest/host masks bring-up writes (`vmx::cr::CrControls`), the CPU
//! exits only on a MOV to CR0 or CR4 that changes a bit VMX operation owns,
//! away from the read shadow. Every such write takes one of three decisions:
//!
//! - **emulate** ([`ExitEvent::ControlRegisterWrite`]): the new read shadow is
//!   the requested value, and GUEST_CRn is that value forced into the VMX
//!   range (`cr::legal`). Clearing CR0.NE is the example: the guest reads
//!   NE = 0, the real NE stays 1;
//! - **#GP(0)** ([`ExitEvent::ControlRegisterGeneralProtection`]): a value the
//!   guest could not have loaded on a CPU without VMX, for instance CR4.VMXE
//!   set (its CPUID hides VMX) or a bit FIXED1 forbids;
//! - **stop** ([`ExitEvent::ControlRegisterUnhandled`]): a write clearing
//!   CR0.PE or CR0.PG (leaving protected mode or paging needs an unrestricted
//!   guest, which Aleph0 does not enable), or an access that Aleph0's masks
//!   should never have let exit (MOV from CR, CLTS, LMSW, CR3/CR8).
//!
//! Nothing here touches the CPU, so every case is a host unit test. See
//! docs/CONTROL_REGISTERS.md.

use crate::vmx::cr;

use super::{ExitEvent, ExitInfo};

/// Which control register a reason-28 exit touched (exit qualification bits
/// 3:0). Only CR0 and CR4 are owned, so only they can exit with Aleph0's
/// masks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrNumber {
    Cr0,
    Cr4,
}

impl CrNumber {
    /// `"CR0"` or `"CR4"`, for the report.
    pub fn name(self) -> &'static str {
        match self {
            Self::Cr0 => "CR0",
            Self::Cr4 => "CR4",
        }
    }
}

/// A MOV to CR0 or CR4 Aleph0 emulates: the guest reads `requested` back (its
/// new read shadow), while GUEST_CRn becomes `real` (forced into the VMX
/// range).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CrWrite {
    pub cr: CrNumber,
    /// The value the guest tried to load; also its new read shadow.
    pub requested: u64,
    /// The new GUEST_CRn ([`cr::legal`]).
    pub real: u64,
}

/// The access type of a control-register exit (exit qualification bits 5:4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrAccess {
    MovToCr,
    MovFromCr,
    Clts,
    Lmsw,
}

/// A control-register access's exit qualification (Intel SDM Vol. 3C, "Exit
/// Qualification for Control-Register Accesses").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CrQualification(pub u64);

impl CrQualification {
    /// Bits 3:0: the control-register number.
    pub fn cr(self) -> u8 {
        (self.0 & 0xF) as u8
    }

    /// Bits 5:4: the access type.
    pub fn access(self) -> CrAccess {
        match (self.0 >> 4) & 0b11 {
            0 => CrAccess::MovToCr,
            1 => CrAccess::MovFromCr,
            2 => CrAccess::Clts,
            // bits 5:4 are 2 bits, so the last arm is 3.
            _ => CrAccess::Lmsw,
        }
    }

    /// Bits 11:8: the general-purpose register of a MOV, in the instruction
    /// encoding's numbering (0 RAX, 1 RCX, 2 RDX, 3 RBX, 4 RSP, 5 RBP, 6 RSI,
    /// 7 RDI, 8-15 R8-R15), not `RegisterFrame`'s field order. RSP (4) is
    /// GUEST_RSP, not in the frame; the handler resolves the value.
    pub fn gpr(self) -> u8 {
        ((self.0 >> 8) & 0xF) as u8
    }
}

/// What a reason-28 exit is. Only a MOV to CR0 or CR4 can exit with the masks
/// Aleph0 sets; any other access should not have, so it stops.
pub(super) fn control_register(exit: &ExitInfo) -> ExitEvent {
    let qualification = CrQualification(exit.qualification);
    if qualification.access() != CrAccess::MovToCr {
        return ExitEvent::ControlRegisterUnhandled;
    }
    let fixed = exit.cr_fixed;
    match qualification.cr() {
        0 => decide_mov(CrNumber::Cr0, exit.cr_source, fixed.cr0_fixed0, fixed.cr0_fixed1),
        4 => decide_mov(CrNumber::Cr4, exit.cr_source, fixed.cr4_fixed0, fixed.cr4_fixed1),
        _ => ExitEvent::ControlRegisterUnhandled,
    }
}

/// The decision for a MOV that loads `requested` into `cr`, given that
/// register's FIXED0/FIXED1.
fn decide_mov(cr: CrNumber, requested: u64, fixed0: u64, fixed1: u64) -> ExitEvent {
    // CR4.VMXE: the guest's CPUID hides VMX (`emulation::cpuid_policy`), so on
    // a CPU without VMX this write would #GP. Checked before the FIXED1 test,
    // which allows VMXE in VMX operation.
    if cr == CrNumber::Cr4 && requested & cr::CR4_VMXE != 0 {
        return ExitEvent::ControlRegisterGeneralProtection;
    }
    // A bit FIXED1 forbids (must be 0 in VMX operation): not a value the guest
    // could load on any CPU.
    if requested & !fixed1 != 0 {
        return ExitEvent::ControlRegisterGeneralProtection;
    }
    // Leaving protected mode or paging needs an unrestricted guest (secondary
    // control bit 7), which Aleph0 does not enable: stop with a diagnostic.
    if cr == CrNumber::Cr0 && requested & (cr::CR0_PE | cr::CR0_PG) != cr::CR0_PE | cr::CR0_PG {
        return ExitEvent::ControlRegisterUnhandled;
    }
    // Emulate: the guest reads `requested` back, while GUEST_CRn keeps the
    // fixed bits (CR0.NE stays 1 even if the guest cleared it).
    ExitEvent::ControlRegisterWrite(CrWrite {
        cr,
        requested,
        real: cr::legal(requested, fixed0, fixed1),
    })
}

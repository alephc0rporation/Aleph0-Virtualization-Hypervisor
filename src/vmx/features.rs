//! What Aleph0 offers the guest beyond the minimal controls, chosen once at
//! bring-up ([`GuestFeatures`]):
//!
//! - the secondary controls an OS guest needs beyond EPT (RDTSCP, INVPCID,
//!   XSAVES/XRSTORS, user wait and pause), each requested when the CPU allows
//!   it. While one is 0 its instructions raise #UD in the guest (Intel SDM
//!   Vol. 3C, "Changes to Instruction Behavior in VMX Non-Root Operation");
//! - XSETBV, which always exits and which Aleph0 runs in root operation. That
//!   needs CR4.OSXSAVE in HOST_CR4 ([`GuestFeatures::host_cr4`]).
//!
//! What is not offered is hidden from the guest's CPUID
//! ([`GuestFeatures::hidden`], applied by `exit_decision::cpuid_policy`), so
//! the guest never runs an instruction that would #UD where hardware would
//! have run it. The exit handler reads the choice back with [`published`].

use core::arch::x86_64::{__cpuid, __cpuid_count};
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use super::cr::CR4_OSXSAVE;
use super::msr::{self, ControlCapability};
use super::vmcs::fields::{
    SECONDARY_ENABLE_EPT, SECONDARY_ENABLE_INVPCID, SECONDARY_ENABLE_RDTSCP, SECONDARY_ENABLE_USER_WAIT_PAUSE,
    SECONDARY_ENABLE_XSAVES,
};

/// CPUID.1:ECX bit 26 (XSAVE): XSAVE, XGETBV, XSETBV and XCR0 exist.
pub const CPUID_1_ECX_XSAVE: u32 = 1 << 26;
/// CPUID.1:ECX bit 27 (OSXSAVE): a copy of CR4.OSXSAVE.
pub const CPUID_1_ECX_OSXSAVE: u32 = 1 << 27;
/// CPUID leaf of the XSAVE components: subleaf 0 reports in EDX:EAX the XCR0
/// bits the CPU supports.
const XSAVE_LEAF: u32 = 0xD;

/// CPUID bits, by register, the guest must not see.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HiddenCpuid {
    /// CPUID.1:ECX.
    pub leaf_1_ecx: u32,
    /// CPUID.(EAX=7,ECX=0):EBX.
    pub leaf_7_ebx: u32,
    /// CPUID.(EAX=7,ECX=0):ECX.
    pub leaf_7_ecx: u32,
    /// CPUID.(EAX=0xD,ECX=1):EAX.
    pub leaf_d_1_eax: u32,
    /// CPUID.80000001H:EDX.
    pub extended_edx: u32,
}

impl HiddenCpuid {
    /// Nothing hidden.
    pub const NONE: Self = Self {
        leaf_1_ecx: 0,
        leaf_7_ebx: 0,
        leaf_7_ecx: 0,
        leaf_d_1_eax: 0,
        extended_edx: 0,
    };

    /// The bits of both.
    fn or(self, other: Self) -> Self {
        Self {
            leaf_1_ecx: self.leaf_1_ecx | other.leaf_1_ecx,
            leaf_7_ebx: self.leaf_7_ebx | other.leaf_7_ebx,
            leaf_7_ecx: self.leaf_7_ecx | other.leaf_7_ecx,
            leaf_d_1_eax: self.leaf_d_1_eax | other.leaf_d_1_eax,
            extended_edx: self.extended_edx | other.extended_edx,
        }
    }
}

/// The secondary controls requested when the CPU allows them, each with the
/// CPUID bits of the instructions it lets the guest run.
const OPTIONAL_CONTROLS: [(u32, HiddenCpuid); 4] = [
    // RDTSCP (CPUID.80000001H:EDX bit 27) and RDPID ((7,0):ECX bit 22).
    (
        SECONDARY_ENABLE_RDTSCP,
        HiddenCpuid {
            extended_edx: 1 << 27,
            leaf_7_ecx: 1 << 22,
            ..HiddenCpuid::NONE
        },
    ),
    // INVPCID ((7,0):EBX bit 10).
    (
        SECONDARY_ENABLE_INVPCID,
        HiddenCpuid {
            leaf_7_ebx: 1 << 10,
            ..HiddenCpuid::NONE
        },
    ),
    // XSAVES/XRSTORS ((0xD,1):EAX bit 3).
    (
        SECONDARY_ENABLE_XSAVES,
        HiddenCpuid {
            leaf_d_1_eax: 1 << 3,
            ..HiddenCpuid::NONE
        },
    ),
    // TPAUSE, UMONITOR, UMWAIT: WAITPKG ((7,0):ECX bit 5).
    (
        SECONDARY_ENABLE_USER_WAIT_PAUSE,
        HiddenCpuid {
            leaf_7_ecx: 1 << 5,
            ..HiddenCpuid::NONE
        },
    ),
];

/// The secondary controls to request from a CPU whose secondary capability
/// is `capability`: EPT, which `ept::check_support` has required, and each
/// of [`OPTIONAL_CONTROLS`] it allows.
pub fn secondary_request(capability: ControlCapability) -> u32 {
    OPTIONAL_CONTROLS
        .iter()
        .map(|&(control, _)| control)
        .filter(|&control| capability.allows(control))
        .fold(SECONDARY_ENABLE_EPT, |request, control| request | control)
}

/// What Aleph0 offers the guest, chosen at bring-up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuestFeatures {
    /// The secondary controls requested ([`secondary_request`]).
    pub secondary: u32,
    /// The XCR0 bits the guest's XSETBV may set: CPUID.(EAX=0xD,ECX=0):EDX:EAX,
    /// or 0 when XSETBV cannot run in root operation, so that every XSETBV
    /// gets #GP. Bit 0 (x87) is always reported, so 0 means only that.
    pub xcr0: u64,
}

impl GuestFeatures {
    /// EPT alone and no XSETBV: what the exit handler reads before bring-up
    /// has published.
    pub const NONE: Self = Self {
        secondary: SECONDARY_ENABLE_EPT,
        xcr0: 0,
    };

    /// The features for a CPU with secondary capability `secondary`,
    /// CPUID.1:ECX `cpuid_1_ecx`, IA32_VMX_CR4_FIXED1 `cr4_fixed1`, and XCR0
    /// bits `xcr0_supported` (CPUID.(0xD,0), meaningful only with XSAVE).
    /// XSETBV runs in root operation only with XSAVE and with CR4.OSXSAVE
    /// allowed in VMX operation.
    pub fn new(secondary: ControlCapability, cpuid_1_ecx: u32, cr4_fixed1: u64, xcr0_supported: u64) -> Self {
        let xsetbv = cpuid_1_ecx & CPUID_1_ECX_XSAVE != 0 && cr4_fixed1 & CR4_OSXSAVE != 0;
        Self {
            secondary: secondary_request(secondary),
            xcr0: if xsetbv { xcr0_supported } else { 0 },
        }
    }

    /// Reads what [`GuestFeatures::new`] needs from the CPU.
    ///
    /// # Safety
    ///
    /// The CPU must support VMX, so IA32_VMX_CR4_FIXED1 exists.
    pub unsafe fn read(secondary: ControlCapability) -> Self {
        let cpuid_1_ecx = __cpuid(1).ecx;
        // Leaf 0xD exists whenever XSAVE does.
        let xcr0_supported = if cpuid_1_ecx & CPUID_1_ECX_XSAVE != 0 {
            let leaf = __cpuid_count(XSAVE_LEAF, 0);
            (u64::from(leaf.edx) << 32) | u64::from(leaf.eax)
        } else {
            0
        };
        // SAFETY: the caller guarantees VMX support, so the MSR exists, and
        // reading it has no side effects.
        let cr4_fixed1 = unsafe { msr::rdmsr(msr::IA32_VMX_CR4_FIXED1) };
        Self::new(secondary, cpuid_1_ecx, cr4_fixed1, xcr0_supported)
    }

    /// Whether Aleph0 runs the guest's XSETBV.
    pub fn xsetbv(self) -> bool {
        self.xcr0 != 0
    }

    /// HOST_CR4 for the CR4 bring-up runs with (`cr4`): CR4.OSXSAVE added
    /// when Aleph0 runs XSETBV, which raises #UD in root operation without
    /// it. The guest's CR4 is captured on its own (`guest_state`) and keeps
    /// the firmware's OSXSAVE, and teardown loads the firmware's CR4 again.
    pub fn host_cr4(self, cr4: u64) -> u64 {
        if self.xsetbv() { cr4 | CR4_OSXSAVE } else { cr4 }
    }

    /// The CPUID bits the guest must not see: those of each optional control
    /// not requested, and XSAVE when Aleph0 cannot run XSETBV.
    pub fn hidden(self) -> HiddenCpuid {
        let xsave = if self.xsetbv() {
            HiddenCpuid::NONE
        } else {
            HiddenCpuid {
                leaf_1_ecx: CPUID_1_ECX_XSAVE,
                ..HiddenCpuid::NONE
            }
        };
        OPTIONAL_CONTROLS
            .iter()
            .filter(|&&(control, _)| self.secondary & control == 0)
            .fold(xsave, |hidden, &(_, bits)| hidden.or(bits))
    }
}

// What `publish` recorded, for the exit handler.
static SECONDARY: AtomicU32 = AtomicU32::new(GuestFeatures::NONE.secondary);
static XCR0: AtomicU64 = AtomicU64::new(GuestFeatures::NONE.xcr0);

/// Records, before VMLAUNCH, what the guest is offered.
pub fn publish(features: GuestFeatures) {
    SECONDARY.store(features.secondary, Ordering::Relaxed);
    XCR0.store(features.xcr0, Ordering::Relaxed);
}

/// What [`publish`] recorded.
pub fn published() -> GuestFeatures {
    GuestFeatures {
        secondary: SECONDARY.load(Ordering::Relaxed),
        xcr0: XCR0.load(Ordering::Relaxed),
    }
}

#[cfg(test)]
#[path = "../../tests/unit/vmx/features.rs"]
mod tests;

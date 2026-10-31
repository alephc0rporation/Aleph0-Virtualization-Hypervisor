//! Unit tests for `src/vmx/features.rs`.
//!
//! Compiled only by `cargo test-host`. That file includes this one with
//! `#[path]` as its child module `tests`, so `use super::*` reaches its
//! private items.

use super::*;

/// The secondary capability Hyper-V reports (docs/EPT.md):
/// `required=0x00000000 allowed=0x065018ae`.
const HYPER_V_SECONDARY: ControlCapability = ControlCapability(0x0650_18AE << 32);
/// CPUID.1:ECX under Hyper-V (ROADMAP.md): XSAVE (bit 26) set, OSXSAVE (bit
/// 27) clear.
const HYPER_V_LEAF_1_ECX: u32 = 0xF7FA_3223;
/// An IA32_VMX_CR4_FIXED1 allowing bits 22:0, OSXSAVE (bit 18) among them.
const CR4_FIXED1: u64 = 0x7F_FFFF;
/// x87, SSE, AVX and the three AVX-512 components.
const XCR0_SUPPORTED: u64 = 0xE7;

#[test]
fn hyper_v_gets_every_optional_control_and_no_cpuid_bit_hidden() {
    let features = GuestFeatures::new(HYPER_V_SECONDARY, HYPER_V_LEAF_1_ECX, CR4_FIXED1, XCR0_SUPPORTED);
    // Bits 1 (EPT), 3, 12, 20 and 26.
    assert_eq!(features.secondary, 0x0410_100A);
    assert_eq!(features.xcr0, XCR0_SUPPORTED);
    assert_eq!(features.hidden(), HiddenCpuid::NONE);
}

#[test]
fn a_control_the_cpu_does_not_allow_is_not_requested_and_its_cpuid_bits_are_hidden() {
    let ept_only = ControlCapability(u64::from(SECONDARY_ENABLE_EPT) << 32);
    let features = GuestFeatures::new(ept_only, HYPER_V_LEAF_1_ECX, CR4_FIXED1, XCR0_SUPPORTED);
    assert_eq!(features.secondary, SECONDARY_ENABLE_EPT);
    assert_eq!(
        features.hidden(),
        HiddenCpuid {
            leaf_7_ebx: 1 << 10,
            leaf_7_ecx: (1 << 22) | (1 << 5),
            leaf_d_1_eax: 1 << 3,
            extended_edx: 1 << 27,
            ..HiddenCpuid::NONE
        }
    );
    // Only RDTSCP missing: RDTSCP and RDPID hidden, nothing else.
    let no_rdtscp = ControlCapability((0x0650_18AE & !u64::from(SECONDARY_ENABLE_RDTSCP)) << 32);
    let features = GuestFeatures::new(no_rdtscp, HYPER_V_LEAF_1_ECX, CR4_FIXED1, XCR0_SUPPORTED);
    assert_eq!(features.secondary & SECONDARY_ENABLE_RDTSCP, 0);
    assert_eq!(
        features.hidden(),
        HiddenCpuid {
            leaf_7_ecx: 1 << 22,
            extended_edx: 1 << 27,
            ..HiddenCpuid::NONE
        }
    );
}

#[test]
fn xsetbv_needs_xsave_and_osxsave_allowed_in_vmx_operation() {
    let no_xsave = GuestFeatures::new(
        HYPER_V_SECONDARY,
        HYPER_V_LEAF_1_ECX & !CPUID_1_ECX_XSAVE,
        CR4_FIXED1,
        XCR0_SUPPORTED,
    );
    let osxsave_fixed = GuestFeatures::new(
        HYPER_V_SECONDARY,
        HYPER_V_LEAF_1_ECX,
        CR4_FIXED1 & !CR4_OSXSAVE,
        XCR0_SUPPORTED,
    );
    for features in [no_xsave, osxsave_fixed] {
        assert!(!features.xsetbv());
        assert_eq!(features.xcr0, 0);
        assert_eq!(features.host_cr4(0x2668), 0x2668);
        assert_eq!(
            features.hidden(),
            HiddenCpuid {
                leaf_1_ecx: CPUID_1_ECX_XSAVE,
                ..HiddenCpuid::NONE
            }
        );
    }
}

#[test]
fn host_cr4_gets_osxsave_when_xsetbv_runs_in_root_operation() {
    let features = GuestFeatures::new(HYPER_V_SECONDARY, HYPER_V_LEAF_1_ECX, CR4_FIXED1, XCR0_SUPPORTED);
    assert_eq!(features.host_cr4(0x2668), 0x2668 | CR4_OSXSAVE);
    assert_eq!(features.host_cr4(0x2668 | CR4_OSXSAVE), 0x2668 | CR4_OSXSAVE);
}

#[test]
fn nothing_published_offers_ept_alone() {
    assert_eq!(GuestFeatures::NONE.hidden().leaf_1_ecx, CPUID_1_ECX_XSAVE);
    assert_eq!(GuestFeatures::NONE.secondary, SECONDARY_ENABLE_EPT);
}

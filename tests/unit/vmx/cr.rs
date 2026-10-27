//! Unit tests for the control-register masking math in `src/vmx/cr.rs`.
//!
//! Compiled only by `cargo test-host`. That file includes this one with
//! `#[path]` as its child module `tests`, so `use super::*` reaches its items.

use super::*;

/// FIXED MSRs of the usual shape: CR0 fixes PE, NE and PG on (and the bits
/// above 31 reserved as 0); CR4 fixes VMXE on and allows the common bits.
const FIXED: CrFixed = CrFixed {
    cr0_fixed0: 0x8000_0021,
    cr0_fixed1: 0xFFFF_FFFF,
    cr4_fixed0: CR4_VMXE,
    cr4_fixed1: 0x2_7FFF,
};

#[test]
fn owned_is_the_must_be_one_and_must_be_zero_bits() {
    // FIXED0 (must be 1) and the complement of FIXED1 (must be 0).
    assert_eq!(owned(0x8000_0021, 0xFFFF_FFFF), 0x8000_0021 | !0xFFFF_FFFFu64);
    // CR0 owns PE, NE and PG; CR4 owns VMXE.
    assert_eq!(FIXED.cr0_owned() & (CR0_PE | CR0_NE | CR0_PG), CR0_PE | CR0_NE | CR0_PG);
    assert!(FIXED.cr4_owned() & CR4_VMXE != 0);
}

#[test]
fn legal_forces_the_fixed_bits() {
    // Clearing NE: the forced value keeps it set (FIXED0), reserved bits off.
    let requested = CR0_PE | CR0_PG;
    let forced = legal(requested, FIXED.cr0_fixed0, FIXED.cr0_fixed1);
    assert!(forced & CR0_NE != 0);
    assert_eq!(forced & !0xFFFF_FFFFu64, 0);
    // CR4 = 0 is forced to VMXE set.
    assert_eq!(legal(0, FIXED.cr4_fixed0, FIXED.cr4_fixed1), CR4_VMXE);
}

#[test]
fn the_shadow_shows_pre_vmx_values_of_the_owned_bits() {
    // The guest's CR4 (the host's) has VMXE set; the pre-VMX one does not.
    let owned = FIXED.cr4_owned();
    let shadow = read_shadow(CR4_VMXE | 0x20, 0x20, owned);
    assert_eq!(shadow & CR4_VMXE, 0); // VMXE hidden
    assert_eq!(shadow & 0x20, 0x20); // a non-owned bit shows through
}

#[test]
fn a_mov_exits_only_when_it_changes_an_owned_bit() {
    let owned = FIXED.cr4_owned();
    let shadow = 0; // VMXE clear
    // Writing VMXE = 0 (matching the shadow) does not exit; setting it does.
    assert!(!mov_exits(0, shadow, owned));
    assert!(mov_exits(CR4_VMXE, shadow, owned));
}

#[test]
fn cr_controls_hide_vmxe_but_keep_the_mask() {
    // Guest CR4 (host's) has VMXE set; original (pre-VMXON) does not.
    let controls = CrControls::new(FIXED, CR0_PE | CR0_NE | CR0_PG, CR4_VMXE, CR0_PE | CR0_NE | CR0_PG, 0);
    assert!(controls.cr4_mask & CR4_VMXE != 0);
    assert_eq!(controls.cr4_shadow & CR4_VMXE, 0);
}

//! The test guest's own exits: its write to the EPT-protected data page,
//! its main VMCALLs, NMI reinjection, and the reinjected NMI's delivery
//! faulting on the EPT-protected stack page. `decide` sends only the test
//! guest's VMCALLs and EPT violations here; NMI reinjection, with its NMI and
//! interrupt windows, serves every guest, the firmware too.
//!
//! The guest (`guest.rs`) writes its read-only data page, makes two main
//! VMCALLs, with `GUEST_MARKER` and then `GUEST_MARKER + 1` in RAX, and
//! waits between them for an NMI:
//!
//! ```text
//! (before these: the guest's emulated exits; see emulation.rs)
//! EPT violation  ──▶ a write to the protected data page: make it writable,
//!                    resume at the same RIP so the write is retried
//! main VMCALL #1 ──▶ resume past it (only after the EPT violation, and only
//!                    if ECX/EDX hold the data page's seed and new value)
//! NMI exit       ──▶ guest can take the NMI:  inject it at the next entry
//!                    guest cannot yet (MOV SS or NMI blocking):
//!                                             turn on NMI-window exiting,
//! NMI-window exit──▶                          inject when the window opens
//!                    only an STI shadow holds it back (any guest; the test
//!                    guest never runs STI):   turn on interrupt-window
//! interrupt-window──▶                         exiting instead, inject once
//!   exit                                      the shadow has ended
//! EPT violation  ──▶ the injected NMI's delivery pushed the interrupt frame
//!  (IDT-vectoring   onto the read-only stack page: make it writable and
//!   = the NMI)      re-deliver the NMI (the handler, from IDT-vectoring)
//! VMCALL with GUEST_NMI_MARKER (the guest's NMI handler) ──▶ resume past it
//! main VMCALL #2 ──▶ finished
//! ```
//!
//! Whether every emulated exit came is not decided here: bring-up checks the
//! exit statistics once the guest has finished (`guest::expected_stats`).

use super::{EptQualification, ExitEvent, ExitInfo, ExitState};
use crate::vmx::guest::{GUEST_DATA_SEED, GUEST_EPT_VALUE, GUEST_MARKER, GUEST_NMI_MARKER};

/// How many main VMCALLs the guest makes; the last one ends the run.
pub const PLANNED_MAIN_VMCALLS: u32 = 2;

/// Guest interruptibility bit 0: blocking by STI. The Intel SDM (Vol. 3C,
/// checks on guest non-register state) says: "A processor may require bit 0
/// (blocking by STI) to be 0 if the valid bit is 1 and the interruption type
/// is NMI." So an NMI is injected only when this bit is clear too.
pub(super) const BLOCKING_BY_STI: u32 = 1 << 0;
/// Guest interruptibility bit 1: blocking by MOV SS. VM entry refuses to
/// inject an NMI while it is set.
pub(super) const BLOCKING_BY_MOV_SS: u32 = 1 << 1;
/// Guest interruptibility bit 3: blocking by NMI. With virtual NMIs this is
/// an injected NMI the guest has not ended with IRET yet; VM entry refuses
/// to inject another while it is set.
pub(super) const BLOCKING_BY_NMI: u32 = 1 << 3;
/// Any of the blocking bits that may stop an NMI injection. The handler
/// injects only when none is set, and otherwise waits for the NMI window
/// instead of injecting blindly.
const NMI_INJECTION_BLOCKED: u32 = BLOCKING_BY_STI | BLOCKING_BY_MOV_SS | BLOCKING_BY_NMI;

/// Whether, at main VMCALL #1, ECX holds the seed the guest read from its
/// data page and EDX the value it wrote and read back. Compared as 32-bit
/// values: the guest loads both with 32-bit moves.
fn data_page_read_back(exit: &ExitInfo) -> bool {
    exit.guest_rcx as u32 == GUEST_DATA_SEED && exit.guest_rdx as u32 == GUEST_EPT_VALUE
}

/// The guest's RAX at its next main VMCALL: the marker, plus one for each
/// main VMCALL already handled (the guest runs `inc eax` before #2).
///
/// The test-only `unexpected-exit-test` Cargo feature expects one more than
/// the guest loads, so main VMCALL #1 is unexpected: a stop other than the
/// planned one, on purpose, to show its report on real VMX.
pub fn expected_main_rax(state: ExitState) -> u64 {
    u64::from(GUEST_MARKER) + u64::from(state.main_vmcalls) + u64::from(cfg!(feature = "unexpected-exit-test"))
}

/// The deferral of an NMI the guest cannot take yet (`interruptibility`
/// has a bit of [`NMI_INJECTION_BLOCKED`]), and `state` with it pending.
///
/// Blocking by STI alone waits for the interrupt window; any other blocking
/// for the NMI window. A CPU may report an NMI-window exit inside an STI
/// shadow, where no injection is allowed either, so waiting for the NMI window
/// there could exit at the same instruction forever (`ResumePlan::
/// WAIT_FOR_STI_SHADOW`).
fn deferred(state: ExitState, interruptibility: u32) -> (ExitEvent, ExitState) {
    let event = if interruptibility & NMI_INJECTION_BLOCKED == BLOCKING_BY_STI {
        ExitEvent::NmiDeferredPastSti
    } else {
        ExitEvent::NmiDeferred
    };
    (
        event,
        ExitState {
            nmi_pending: true,
            ..state
        },
    )
}

/// `state` after an NMI is injected: nothing pending. Several NMIs never
/// queue: a new NMI while one is pending replaces it, as on real hardware,
/// where at most one NMI waits.
fn injected(state: ExitState) -> ExitState {
    ExitState {
        nmi_pending: false,
        ..state
    }
}

/// Exception or NMI (exit reason 0). Only an NMI is handled: reinjected now,
/// or once the guest's NMI window opens. Any exception stops the guest.
pub(super) fn exception_or_nmi(state: ExitState, exit: &ExitInfo) -> (ExitEvent, ExitState) {
    if !exit.interruption_info.is_nmi() {
        return (ExitEvent::Unexpected, state);
    }
    if exit.interruptibility & NMI_INJECTION_BLOCKED == 0 {
        (ExitEvent::NmiInjected, injected(state))
    } else {
        deferred(state, exit.interruptibility)
    }
}

/// NMI window (exit reason 8): inject the pending NMI.
pub(super) fn nmi_window(state: ExitState, exit: &ExitInfo) -> (ExitEvent, ExitState) {
    if !state.nmi_pending {
        return (ExitEvent::Unexpected, state);
    }
    // Per the SDM, NMI-window exits never occur under MOV SS blocking, but
    // the processor may still report one under STI blocking. Injecting then
    // would fail the VM entry, so wait: for the interrupt window when STI is
    // the only blocker, which ends the loop such a CPU would otherwise run.
    // (MOV SS stays in the mask; it is harmless.)
    if exit.interruptibility & NMI_INJECTION_BLOCKED != 0 {
        deferred(state, exit.interruptibility)
    } else {
        (ExitEvent::NmiWindowInjected, injected(state))
    }
}

/// Interrupt window (exit reason 7): the STI shadow that held back the
/// pending NMI has ended, so inject it. Aleph0 turns interrupt-window exiting
/// on only for that (`ResumePlan::WAIT_FOR_STI_SHADOW`), so without a pending
/// NMI the exit is unexpected. The window opens with no STI or MOV SS
/// blocking; blocking by NMI is still checked, as at the NMI window, and
/// waits for the NMI window if set.
pub(super) fn interrupt_window(state: ExitState, exit: &ExitInfo) -> (ExitEvent, ExitState) {
    if !state.nmi_pending {
        return (ExitEvent::Unexpected, state);
    }
    if exit.interruptibility & NMI_INJECTION_BLOCKED != 0 {
        deferred(state, exit.interruptibility)
    } else {
        (ExitEvent::InterruptWindowInjected, injected(state))
    }
}

/// EPT violation (exit reason 48). Two are handled, each once: the guest's
/// write to its protected data page (before the first main VMCALL), and the
/// reinjected NMI's delivery faulting on the read-only stack page as the CPU
/// pushes the interrupt frame. The reinjected NMI's delivery carries the NMI
/// in the exit's IDT-vectoring field, which the handler re-delivers on top of
/// the grant (`ExitInfo::redelivery`).
///
/// The two faults are told apart by which read-only page the GPA fell in, not
/// by the IDT-vectoring field: the guest's main code never touches the stack
/// (only the NMI handler's push after the grant does), and a hypervisor
/// underneath may report the interrupted NMI's delivery with interruption
/// type 3 rather than 2 (Hyper-V does), so the vectoring field is not a
/// reliable discriminator. Any other EPT violation, a stray repeat of either
/// included, is [`ExitEvent::EptViolation`].
pub(super) fn ept_violation(state: ExitState, exit: &ExitInfo) -> (ExitEvent, ExitState) {
    let frame = exit.guest_physical & !0xFFF;
    let protected_write = exit.protected_page != 0
        && frame == exit.protected_page
        && EptQualification(exit.qualification).is_protected_write();
    if protected_write {
        if exit.stack_page != 0 && frame == exit.stack_page {
            // The push for the reinjected NMI faulted on the read-only stack page.
            if state.nmi_stack_grants == 0 {
                return (
                    ExitEvent::EptWriteGranted,
                    ExitState {
                        nmi_stack_grants: 1,
                        ..state
                    },
                );
            }
        } else if state.ept_writes_granted == 0 {
            return (
                ExitEvent::EptWriteGranted,
                ExitState {
                    ept_writes_granted: 1,
                    ..state
                },
            );
        }
    }
    (ExitEvent::EptViolation, state)
}

/// VMCALL (exit reason 18): the guest's NMI handler, or its next main
/// VMCALL. Main VMCALL #1 must come after the EPT violation and show the
/// data page read back as planned.
pub(super) fn vmcall(state: ExitState, exit: &ExitInfo) -> (ExitEvent, ExitState) {
    if exit.guest_rax == u64::from(GUEST_NMI_MARKER) {
        // Saturates: any guest code can make this VMCALL, any number of times.
        return (
            ExitEvent::GuestNmiHandler,
            ExitState {
                nmis_handled: state.nmis_handled.saturating_add(1),
                ..state
            },
        );
    }
    if exit.guest_rax != expected_main_rax(state) {
        return (ExitEvent::Unexpected, state);
    }
    if state.ept_writes_granted == 0 {
        return (ExitEvent::EptWriteMissing, state);
    }
    if state.main_vmcalls == 0 && !data_page_read_back(exit) {
        return (ExitEvent::DataPageMismatch, state);
    }
    let next = ExitState {
        main_vmcalls: state.main_vmcalls + 1,
        ..state
    };
    if next.main_vmcalls < PLANNED_MAIN_VMCALLS {
        (ExitEvent::MainVmcall, next)
    } else {
        (ExitEvent::LastMainVmcall, next)
    }
}

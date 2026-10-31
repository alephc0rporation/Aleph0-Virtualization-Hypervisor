//! What the VM-exit handler does with each exit: pure decisions, one
//! handler per exit reason.
//!
//! The handler reads the exit's VMCS fields into an [`ExitInfo`], calls
//! [`decide`] with the [`ExitState`] kept between exits, and applies the
//! [`ExitAction`] of the returned [`ExitEvent`]. Nothing here touches the
//! CPU, so every case is a host unit test.
//!
//! [`decide`] first checks what holds for every exit (a failed VM entry, an
//! interrupted event delivery), then dispatches on the exit reason to a
//! handler, the way KVM's `kvm_vmx_exit_handlers[]` does, but as a `match`
//! instead of a table of function pointers, so the handled reasons are listed
//! in one place:
//!
//! - `emulation.rs`: instructions Aleph0 executes for any guest (CPUID,
//!   XSETBV, RDMSR, WRMSR, IN, OUT), RDMSR and WRMSR of the guest's MTRRs, which
//!   reach a copy of them instead, and of Hyper-V's synthetic MSRs, which
//!   are forwarded to Hyper-V, and HLT, which it skips. Each handler reads
//!   the exit alone: `fn(&ExitInfo) -> ExitEvent`. MWAIT and MONITOR, which
//!   get #UD, need no handler of their own.
//! - `scenario.rs`: exits that depend on what came before:
//!   `fn(ExitState, &ExitInfo) -> (ExitEvent, ExitState)`. NMI reinjection,
//!   with its NMI and interrupt windows, for every guest, and the test
//!   guest's own exits: its EPT write and its VMCALLs. Any other EPT
//!   violation stops the guest as [`ExitEvent::EptViolation`].
//! - An EPT misconfiguration stops the guest as
//!   [`ExitEvent::EptMisconfig`]. Aleph0 makes no misconfigured entry on
//!   purpose (KVM does, for MMIO, and emulates the access in
//!   `handle_ept_misconfig`), so one means the map is broken.
//!
//! The guest's kind (`GuestKind`) decides the VMCALLs and the test guest's
//! own exits. The firmware has no scripted end: its VMCALLs are Aleph0's
//! own (`vmx::vmcall`) or else Hyper-V hypercalls, forwarded to Hyper-V
//! (`firmware_vmcall`), and every EPT violation stops it, so it never
//! finishes and runs until an exit Aleph0 does not handle.
//!
//! An exit reason without a handler stops the guest. Nothing here counts
//! exits: `vmexit::stats` does, for every guest, from what the handler
//! carried out.

mod control_register;
mod emulation;
mod scenario;

use crate::vmx::cr::CrFixed;
use crate::vmx::mtrr::MtrrCapabilities;
use crate::vmx::vmcall;
use crate::vmx::vmcs::GuestKind;

pub use control_register::{CrNumber, CrQualification, CrWrite};
pub use emulation::{Emulation, IoSize, cpuid_policy, is_canonical_48, merge_in, wrmsr_value};
pub use scenario::{PLANNED_MAIN_VMCALLS, expected_main_rax};

/// VM-exit reason, split into the fields of the VM_EXIT_REASON VMCS field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExitReason {
    /// Bits 15:0: which event caused the exit (Intel SDM Vol. 3D, Appendix C).
    pub basic: u16,
    /// Bit 31: VM entry itself failed. The guest never ran; `basic` says
    /// why (33 = invalid guest state, 34 = MSR loading, 41 = machine check).
    pub entry_failure: bool,
}

impl ExitReason {
    pub fn from_raw(raw: u32) -> Self {
        Self {
            basic: raw as u16,
            entry_failure: raw & (1 << 31) != 0,
        }
    }
}

/// Human-readable name for a basic exit reason. Only the reasons this
/// hypervisor is likely to meet early on are spelled out.
pub fn exit_reason_name(basic: u16) -> &'static str {
    match basic {
        0 => "exception or NMI",
        1 => "external interrupt",
        2 => "triple fault",
        3 => "INIT signal",
        7 => "interrupt window",
        8 => "NMI window",
        9 => "task switch",
        10 => "CPUID",
        12 => "HLT",
        18 => "VMCALL",
        28 => "control-register access",
        30 => "I/O instruction",
        31 => "RDMSR",
        32 => "WRMSR",
        33 => "VM-entry failure: invalid guest state",
        34 => "VM-entry failure: MSR loading",
        36 => "MWAIT",
        39 => "MONITOR",
        41 => "VM-entry failure: machine-check event",
        48 => "EPT violation",
        49 => "EPT misconfiguration",
        55 => "XSETBV",
        UNREADABLE_REASON => "VM_EXIT_REASON unreadable",
        _ => "unnamed exit reason",
    }
}

/// Reason the handler reports when VM_EXIT_REASON itself could not be read.
/// Basic exit reasons stop far below 0xFFFF, so it never names a real exit.
pub const UNREADABLE_REASON: u16 = 0xFFFF;

/// Basic exit reason of an exception or NMI exit.
pub const EXIT_REASON_EXCEPTION_OR_NMI: u16 = 0;
/// Basic exit reason of an interrupt-window exit: the guest can take an
/// external interrupt (RFLAGS.IF = 1, no STI or MOV SS blocking). Aleph0 turns
/// interrupt-window exiting on only to wait out an STI shadow that holds back
/// a pending NMI.
pub const EXIT_REASON_INTERRUPT_WINDOW: u16 = 7;
/// Basic exit reason of an NMI-window exit.
pub const EXIT_REASON_NMI_WINDOW: u16 = 8;
/// Basic exit reason of CPUID, which always exits.
pub const EXIT_REASON_CPUID: u16 = 10;
/// Basic exit reason of HLT, with HLT exiting on.
pub const EXIT_REASON_HLT: u16 = 12;
/// Basic exit reason of a VMCALL exit.
pub const EXIT_REASON_VMCALL: u16 = 18;
/// Basic exit reason of a control-register access: a MOV to a CR0/CR4 bit the
/// guest/host mask owns, CLTS, or LMSW.
pub const EXIT_REASON_CONTROL_REGISTER: u16 = 28;
/// Basic exit reason of IN/OUT (and INS/OUTS) to a port the I/O bitmaps
/// intercept.
pub const EXIT_REASON_IO_INSTRUCTION: u16 = 30;
/// Basic exit reason of RDMSR, which exits for MSRs the MSR bitmap
/// intercepts or does not cover.
pub const EXIT_REASON_RDMSR: u16 = 31;
/// Basic exit reason of WRMSR, which exits for the same MSRs as RDMSR.
pub const EXIT_REASON_WRMSR: u16 = 32;
/// Basic exit reason of MWAIT, with MWAIT exiting on (Hyper-V forces it).
pub const EXIT_REASON_MWAIT: u16 = 36;
/// Basic exit reason of MONITOR, with MONITOR exiting on (Hyper-V forces it).
pub const EXIT_REASON_MONITOR: u16 = 39;
/// Basic exit reason of an EPT violation: an access the EPT entries do not
/// allow.
pub const EXIT_REASON_EPT_VIOLATION: u16 = 48;
/// Basic exit reason of an EPT misconfiguration: an EPT entry the CPU
/// cannot use at all (for example W = 1 with R = 0). It stops the guest
/// ([`ExitEvent::EptMisconfig`]).
pub const EXIT_REASON_EPT_MISCONFIG: u16 = 49;
/// Basic exit reason of XSETBV, which always exits.
pub const EXIT_REASON_XSETBV: u16 = 55;

// Exit qualification bits of an EPT violation (Intel SDM Vol. 3C, "Exit
// Qualification for EPT Violations").
/// Bit 0: the access was a read.
pub const EPT_ACCESS_READ: u64 = 1 << 0;
/// Bit 1: the access was a write.
pub const EPT_ACCESS_WRITE: u64 = 1 << 1;
/// Bit 2: the access was an instruction fetch.
pub const EPT_ACCESS_FETCH: u64 = 1 << 2;
/// Bit 3: the EPT entries allowed reads of the page.
pub const EPT_PAGE_READABLE: u64 = 1 << 3;
/// Bit 4: the EPT entries allowed writes.
pub const EPT_PAGE_WRITABLE: u64 = 1 << 4;
/// Bit 5: the EPT entries allowed execution.
pub const EPT_PAGE_EXECUTABLE: u64 = 1 << 5;
/// Bit 7: GUEST_LINEAR_ADDRESS is valid.
pub const EPT_LINEAR_VALID: u64 = 1 << 7;
/// Bit 8 (with bit 7): the access was to the linear address the guest
/// used, not to one of the guest's own page tables during the walk.
pub const EPT_TRANSLATED_ACCESS: u64 = 1 << 8;
/// Bit 12: the violation happened during an IRET that ended NMI blocking
/// (undefined when IDT_VECTORING_INFO is valid). The IRET had already
/// unblocked NMIs when it faulted, so resuming at it needs blocking by NMI set
/// again by hand ([`ExitInfo::faulted_nmi_unblocking_iret`]).
pub const EPT_NMI_UNBLOCKING_IRET: u64 = 1 << 12;

/// An EPT violation's exit qualification (EXIT_QUALIFICATION), decoded with
/// the bits above.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EptQualification(pub u64);

impl EptQualification {
    /// Whether the access was a write.
    pub fn is_write(self) -> bool {
        self.0 & EPT_ACCESS_WRITE != 0
    }

    /// The kind of access, for the report. Only one is named; a write wins,
    /// since that is the access Aleph0 handles.
    pub fn access_name(self) -> &'static str {
        if self.is_write() {
            "write"
        } else if self.0 & EPT_ACCESS_FETCH != 0 {
            "instruction fetch"
        } else if self.0 & EPT_ACCESS_READ != 0 {
            "read"
        } else {
            "no access bit set"
        }
    }

    /// What the EPT entries allowed for the page, from bits 5:3, as
    /// `(R, W, X)` with 1 for allowed.
    pub fn permissions(self) -> (u8, u8, u8) {
        (
            u8::from(self.0 & EPT_PAGE_READABLE != 0),
            u8::from(self.0 & EPT_PAGE_WRITABLE != 0),
            u8::from(self.0 & EPT_PAGE_EXECUTABLE != 0),
        )
    }

    /// Whether GUEST_LINEAR_ADDRESS is valid (bit 7).
    pub fn linear_valid(self) -> bool {
        self.0 & EPT_LINEAR_VALID != 0
    }

    /// The EPT violation Aleph0 handles: a write to a page EPT maps readable
    /// but not writable, through the linear address the guest used. One
    /// during an IRET that ended NMI blocking (bit 12) counts too; the resume
    /// sets the blocking again ([`ResumePlan::restoring_nmi_blocking`]).
    pub fn is_protected_write(self) -> bool {
        let required = EPT_ACCESS_WRITE | EPT_PAGE_READABLE | EPT_LINEAR_VALID | EPT_TRANSLATED_ACCESS;
        self.0 & required == required && self.0 & EPT_PAGE_WRITABLE == 0
    }
}

/// IDT vector of NMI.
pub const NMI_VECTOR: u8 = 2;

/// An interruption-information value: VM_EXIT_INTERRUPTION_INFO,
/// IDT_VECTORING_INFO and VM_ENTRY_INTERRUPTION_INFO share the layout.
///
/// ```text
///  31    30  13  12           11          10   8  7      0
/// ┌─────┬──────┬────────────┬────────────┬───────┬────────┐
/// │valid│ res. │NMI unblock.│ error code │ type  │ vector │
/// │     │      │ (exit only)│   valid    │       │        │
/// └─────┴──────┴────────────┴────────────┴───────┴────────┘
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InterruptionInfo(pub u32);

impl InterruptionInfo {
    /// Bit 31: the field is valid.
    pub const VALID: u32 = 1 << 31;
    /// Interruption type 2 (bits 10:8): NMI.
    const TYPE_NMI: u32 = 2;
    /// Interruption type 3 (bits 10:8): hardware exception.
    const TYPE_HARDWARE_EXCEPTION: u32 = 3;
    /// Bit 11: deliver an error code (VM_ENTRY_EXCEPTION_ERROR_CODE).
    const DELIVER_ERROR_CODE: u32 = 1 << 11;
    /// Bit 12, in VM_EXIT_INTERRUPTION_INFO only: the exception was a fault
    /// in an IRET that ended NMI blocking.
    const NMI_UNBLOCKING_IRET: u32 = 1 << 12;
    /// IDT vector of #DF, for which bit 12 is undefined.
    const DF_VECTOR: u8 = 8;
    /// IDT vector of #UD.
    const UD_VECTOR: u32 = 6;
    /// IDT vector of #GP.
    const GP_VECTOR: u32 = 13;

    /// The VM_ENTRY_INTERRUPTION_INFO value that injects an NMI at the next
    /// VM entry: valid, type NMI, vector 2. The CPU clears the field after
    /// each successful entry, so it injects once.
    pub const NMI: Self = Self(Self::VALID | (Self::TYPE_NMI << 8) | NMI_VECTOR as u32);

    /// The VM_ENTRY_INTERRUPTION_INFO value that injects #GP with an error
    /// code at the next VM entry, delivered before the faulting instruction
    /// runs again.
    pub const GENERAL_PROTECTION: Self =
        Self(Self::VALID | (Self::TYPE_HARDWARE_EXCEPTION << 8) | Self::DELIVER_ERROR_CODE | Self::GP_VECTOR);

    /// The VM_ENTRY_INTERRUPTION_INFO value that injects #UD, which has no
    /// error code, at the next VM entry.
    pub const INVALID_OPCODE: Self = Self(Self::VALID | (Self::TYPE_HARDWARE_EXCEPTION << 8) | Self::UD_VECTOR);

    /// Whether the field describes an event at all (bit 31).
    pub fn is_valid(self) -> bool {
        self.0 & Self::VALID != 0
    }

    /// Whether this describes an NMI: valid, type 2, vector 2. Bit 12 (NMI
    /// unblocking due to IRET) is ignored.
    pub fn is_nmi(self) -> bool {
        self.is_valid() && (self.0 >> 8) & 0b111 == Self::TYPE_NMI && self.vector() == Some(NMI_VECTOR)
    }

    /// Whether this field, read as IDT_VECTORING_INFO, reports an NMI whose
    /// delivery the exit interrupted: valid, vector 2, interruption type 2
    /// (NMI) or 3 (hardware exception). Vector 2 is the NMI vector and has no
    /// hardware exception, but a hypervisor underneath (Hyper-V) reports the
    /// interrupted NMI with type 3, so both types count. Re-delivery re-arms
    /// it as a true NMI ([`InterruptionInfo::NMI`], type 2), not a vector-2
    /// hardware exception; [`ExitInfo::redelivery`] does that.
    pub fn is_nmi_vectoring(self) -> bool {
        self.is_valid()
            && self.vector() == Some(NMI_VECTOR)
            && matches!(self.event_type(), Self::TYPE_NMI | Self::TYPE_HARDWARE_EXCEPTION)
    }

    /// Whether this field, read as VM_EXIT_INTERRUPTION_INFO, reports a
    /// hardware exception raised by an IRET that had ended NMI blocking (bit
    /// 12). The SDM leaves bit 12 undefined for a double fault, so #DF never
    /// counts.
    pub fn is_nmi_unblocking_iret_fault(self) -> bool {
        self.is_valid()
            && self.event_type() == Self::TYPE_HARDWARE_EXCEPTION
            && self.vector() != Some(Self::DF_VECTOR)
            && self.0 & Self::NMI_UNBLOCKING_IRET != 0
    }

    /// Whether VM entry also delivers VM_ENTRY_EXCEPTION_ERROR_CODE (bit 11).
    pub fn delivers_error_code(self) -> bool {
        self.0 & Self::DELIVER_ERROR_CODE != 0
    }

    /// The vector (bits 7:0), if the field is valid.
    pub fn vector(self) -> Option<u8> {
        self.is_valid().then_some(self.0 as u8)
    }

    /// The interruption type (bits 10:8).
    const fn event_type(self) -> u32 {
        (self.0 >> 8) & 0b111
    }

    /// Whether VM entry charges an instruction length for this event:
    /// software interrupt (type 4), privileged software exception (5) and
    /// software exception (6). The CPU then needs VM_ENTRY_INSTRUCTION_LEN to
    /// land RIP past the INT/INT3/INTO it delivers.
    pub fn needs_instruction_len(self) -> bool {
        matches!(self.event_type(), 4..=6)
    }

    /// This field re-armed for VM entry from IDT_VECTORING_INFO: the valid
    /// bit and the event kept, bits 30:12 cleared. Bit 12 (NMI unblocking
    /// due to IRET) is an exit-only bit, undefined at entry, and bits 30:13
    /// are reserved there.
    pub fn for_reentry(self) -> Self {
        Self(self.0 & !0x7FFF_F000)
    }
}

/// An event the VM exit interrupted mid-delivery, to re-deliver at the next
/// VM entry (from IDT_VECTORING_INFO; Intel SDM Vol. 3C, "Information for VM
/// Exits During Event Delivery" and "Event Injection").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Redelivery {
    /// VM_ENTRY_INTERRUPTION_INFO: the interrupted event, re-armed for entry.
    pub info: InterruptionInfo,
    /// VM_ENTRY_EXCEPTION_ERROR_CODE, when the event carries one (bit 11).
    pub error_code: Option<u32>,
    /// VM_ENTRY_INSTRUCTION_LEN, for a software interrupt or exception.
    pub instruction_len: Option<u32>,
}

/// What the handler read about the current exit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExitInfo {
    pub reason: ExitReason,
    /// VM_EXIT_INTERRUPTION_INFO.
    pub interruption_info: InterruptionInfo,
    /// The guest's RAX, RCX and RDX. CPUID reads its leaf from EAX and its
    /// subleaf from ECX. RDMSR and WRMSR read the MSR from ECX, and WRMSR its
    /// value from EDX:EAX. OUT reads its value from AL, AX or EAX. At main
    /// VMCALL #1, ECX and EDX hold what the guest read from its data page
    /// before and after its write.
    pub guest_rax: u64,
    pub guest_rcx: u64,
    pub guest_rdx: u64,
    /// GUEST_INTERRUPTIBILITY_STATE.
    pub interruptibility: u32,
    /// IDT_VECTORING_INFO: when valid (bit 31), the exit interrupted the
    /// delivery of this event through the guest IDT, and it is re-delivered.
    pub idt_vectoring: InterruptionInfo,
    /// IDT_VECTORING_ERROR_CODE, meaningful when `idt_vectoring` is valid and
    /// delivers an error code.
    pub idt_vectoring_error_code: u32,
    /// EXIT_QUALIFICATION. Its layout depends on the reason; [`decide`]
    /// reads it for EPT violations ([`EptQualification`]) and I/O
    /// instructions (`emulation::IoQualification`) only. `read_exit` keeps
    /// the real value whenever the VMCS field is readable, and uses 0 only
    /// when it is unreadable on an exit `decide` does not judge by it. A
    /// handler that reads it for another reason (CR access, reason 28, for
    /// example) must add that reason to `judged_by_qualification` in
    /// `vmexit/handler.rs`.
    pub qualification: u64,
    /// GUEST_PHYSICAL_ADDRESS, read for EPT exits only; 0 otherwise.
    pub guest_physical: u64,
    /// GPA of the page EPT maps read-only (`ept::protected_page_for`), 0 if
    /// none. For an EPT violation it is the protected page the access fell
    /// in: the guest's data page, or the reinjected NMI's stack page.
    pub protected_page: u64,
    /// GPA of the page EPT maps read-only for the reinjected NMI's stack
    /// (`ept::nmi_stack_page`), 0 if none. The NMI-delivery fault lands in
    /// this page and the guest's own data write in [`Self::protected_page`]'s;
    /// the scenario tells the two EPT violations apart by which page the GPA
    /// is in, not by the vectoring field (a hypervisor may report the
    /// interrupted NMI as type 2 or 3).
    pub stack_page: u64,
    /// The guest's MTRR MSRs: which exist, and which values WRMSR refuses
    /// (`vmexit::guest_mtrrs`). [`MtrrCapabilities::NONE`] until bring-up
    /// publishes them, and on a CPU without MTRRs.
    pub mtrr: MtrrCapabilities,
    /// Whether bring-up found Hyper-V's interface (`hyperv::offered`): its
    /// hypercalls and synthetic MSRs are forwarded to it.
    pub hyperv: bool,
    /// The guest's CPL, SS.DPL (Intel SDM Vol. 3C, "Checks on Guest Segment
    /// Registers": SS.DPL is the CPL), read for VMCALL exits only; 0
    /// otherwise, which [`decide`] never looks at.
    pub guest_cpl: u8,
    /// The value a MOV to CR0/CR4 loads, from the register the exit
    /// qualification names (`CrQualification::gpr`, GUEST_RSP for RSP). Read
    /// for control-register exits only; 0 otherwise.
    pub cr_source: u64,
    /// The CR0/CR4 FIXED MSRs, for the control-register decision. Read for
    /// control-register exits only; [`CrFixed::NONE`] otherwise.
    pub cr_fixed: CrFixed,
    /// GUEST_CR4, which CPUID's OSXSAVE and OSPKE bits copy. Read for CPUID
    /// exits only; 0 otherwise.
    pub guest_cr4: u64,
    /// The XCR0 bits the guest's XSETBV may set (`features::GuestFeatures`),
    /// 0 when Aleph0 cannot run XSETBV.
    pub xcr0_supported: u64,
}

/// The CPL from the guest's SS access rights (GUEST_SS_ACCESS_RIGHTS): its
/// DPL, bits 6:5.
pub fn cpl_from_ss(access_rights: u64) -> u8 {
    (access_rights >> 5) as u8 & 0b11
}

impl ExitInfo {
    /// The event this exit interrupted mid-delivery, to re-deliver at the
    /// next VM entry, or `None` when the exit interrupted no delivery.
    /// `instruction_len` is VM_EXIT_INSTRUCTION_LEN, needed only for a
    /// software interrupt or exception; `None` when it was unreadable.
    pub fn redelivery(&self, instruction_len: Option<u32>) -> Option<Redelivery> {
        if !self.idt_vectoring.is_valid() {
            return None;
        }
        // Vector 2 is the NMI vector: re-deliver it as an NMI (type 2)
        // whatever type the vectoring field reports. Hyper-V reports the
        // interrupted NMI as a hardware exception (type 3), and re-arming that
        // verbatim would inject a #2 hardware exception, not an NMI.
        let info = if self.idt_vectoring.is_nmi_vectoring() {
            InterruptionInfo::NMI
        } else {
            self.idt_vectoring.for_reentry()
        };
        Some(Redelivery {
            info,
            error_code: info.delivers_error_code().then_some(self.idt_vectoring_error_code),
            instruction_len: info.needs_instruction_len().then_some(instruction_len).flatten(),
        })
    }

    /// Whether the exit came from a fault in an IRET that had already ended
    /// NMI blocking: bit 12 of an EPT violation's qualification, or of an
    /// exception exit's VM_EXIT_INTERRUPTION_INFO (Intel SDM Vol. 3C, "Exit
    /// Qualification for EPT Violations" and "Information for VM Exits Due to
    /// Vectored Events"). With virtual NMIs the CPU leaves the guest unblocked
    /// then, and resuming at the IRET would let an NMI in before the handler's
    /// IRET has run: the resume must set blocking by NMI again. Bit 12 is
    /// undefined when the exit interrupted an event's delivery, so such an
    /// exit never counts.
    pub fn faulted_nmi_unblocking_iret(&self) -> bool {
        if self.reason.entry_failure || self.idt_vectoring.is_valid() {
            return false;
        }
        match self.reason.basic {
            EXIT_REASON_EPT_VIOLATION => self.qualification & EPT_NMI_UNBLOCKING_IRET != 0,
            EXIT_REASON_EXCEPTION_OR_NMI => self.interruption_info.is_nmi_unblocking_iret_fault(),
            _ => false,
        }
    }
}

/// What the handler remembers between exits: the NMI waiting for the guest,
/// and how far the test guest's scenario has got.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ExitState {
    /// Main VMCALLs handled so far.
    pub main_vmcalls: u32,
    /// An NMI arrived while the guest blocked NMIs and is not injected yet.
    pub nmi_pending: bool,
    /// VMCALLs from the guest's NMI handler: reinjected NMIs that arrived.
    pub nmis_handled: u32,
    /// EPT violations on the data page after which write was granted.
    pub ept_writes_granted: u32,
    /// EPT violations while an NMI was being delivered (its push faulting on
    /// the read-only stack page) after which write was granted and the NMI
    /// re-delivered.
    pub nmi_stack_grants: u32,
}

impl ExitState {
    /// The state once an NMI that arrived while Aleph0 ran in root operation
    /// (`arrived`) is folded in: pending for the guest, like an NMI the guest
    /// could not take yet. The exit's own handler then decides with it, so
    /// an NMI-window exit injects it, and every other exit keeps it waiting
    /// for the window ([`ResumePlan::keeping_pending_nmi`]).
    ///
    /// At most one NMI waits, as on real hardware: an NMI arriving while one
    /// is pending is the same pending NMI.
    pub fn with_host_nmi(self, arrived: bool) -> Self {
        Self {
            nmi_pending: self.nmi_pending || arrived,
            ..self
        }
    }
}

/// What an exit turned out to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitEvent {
    /// A main VMCALL before the last one.
    MainVmcall,
    /// The last planned main VMCALL.
    LastMainVmcall,
    /// The guest's NMI handler reporting that a reinjected NMI arrived.
    GuestNmiHandler,
    /// An NMI the guest can take now: inject it.
    NmiInjected,
    /// An NMI while the guest cannot take an NMI yet (MOV SS or NMI
    /// blocking, with or without STI blocking): wait for the NMI window.
    NmiDeferred,
    /// An NMI held back by blocking by STI alone: wait for the interrupt
    /// window, which opens once the STI shadow ends. A CPU may report an
    /// NMI-window exit inside the shadow, so the NMI window could not wait it
    /// out ([`ResumePlan::WAIT_FOR_STI_SHADOW`]).
    NmiDeferredPastSti,
    /// The NMI window opened: inject the pending NMI.
    NmiWindowInjected,
    /// The interrupt window opened, so the STI shadow has ended: inject the
    /// pending NMI.
    InterruptWindowInjected,
    /// The guest wrote its protected data page: grant write and retry the
    /// write.
    EptWriteGranted,
    /// A main VMCALL arrived before any EPT violation: the write to the data
    /// page went through, so EPT did not protect it.
    EptWriteMissing,
    /// Main VMCALL #1 after the granted write, but ECX/EDX do not hold what
    /// the guest should have read from its data page: the seed before its
    /// write, its own value after it.
    DataPageMismatch,
    /// An EPT violation other than the guest's first write to its
    /// protected data page. The map allows every other access to every GPA
    /// up to MAXPHYADDR, so the map itself is wrong: stop, and show the walk
    /// of the GPA.
    EptViolation,
    /// An EPT misconfiguration: an entry on the GPA's path is one the CPU
    /// refuses. `Ept::build` makes none, so stop, and show the walk.
    EptMisconfig,
    /// An instruction Aleph0 executes for the guest, then resumes past it.
    Emulated(Emulation),
    /// RDMSR, WRMSR or XSETBV the guest gets a #GP for: an MSR outside the
    /// MSR bitmap that is not forwarded to Hyper-V, an MTRR address the CPU
    /// has no MSR at, a non-canonical value for an intercepted MSR, a value
    /// its MTRRs would refuse, or an XSETBV of another XCR than XCR0 or of a
    /// value XCR0 does not take.
    GuestGeneralProtection,
    /// A MOV to CR0/CR4 Aleph0 emulates: write the read shadow and GUEST_CRn,
    /// then resume past it (`control_register`).
    ControlRegisterWrite(CrWrite),
    /// A MOV to CR0/CR4 the guest could not have made on a CPU without VMX
    /// (CR4.VMXE set, or a bit FIXED1 forbids): inject #GP(0).
    ControlRegisterGeneralProtection,
    /// A control-register access Aleph0's masks should never have let exit, or
    /// a write leaving protected mode or paging: stop with the qualification.
    ControlRegisterUnhandled,
    /// HLT: resume past it at once. The guest's next instruction runs as if
    /// an interrupt had woken it.
    Halted,
    /// An instruction the guest gets #UD for, as on hardware without what
    /// it asks for: MWAIT or MONITOR (the guest's CPUID.1:ECX bit 3 is clear
    /// under Hyper-V, and `cpuid_policy` passes it through), or a VMCALL
    /// that is neither Aleph0's own nor one Hyper-V takes: without Hyper-V's
    /// interface, or from CPL > 0, which Hyper-V refuses with #UD too.
    GuestInvalidOpcode,
    /// Aleph0's `ExitBootServices` event ran in the guest
    /// ([`vmcall::BOOT_SERVICES_ENDED`]): resume past its VMCALL, from now
    /// on in the runtime output phase.
    BootServicesEnded,
    /// A VMCALL that only tests the exit ([`vmcall::TEST`]): resume past it.
    TestVmcall,
    /// Anything else.
    Unexpected,
}

/// How the handler prepares the VMCS (and EPT) before resuming the guest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResumePlan {
    /// Move GUEST_RIP past the exiting instruction, which also ends blocking
    /// by STI and by MOV SS ([`after_skipped_instruction`]).
    pub advance_rip: bool,
    /// Write [`InterruptionInfo::NMI`] to VM_ENTRY_INTERRUPTION_INFO.
    pub inject_nmi: bool,
    /// Turn NMI-window exiting on (`Some(true)`) or off (`Some(false)`), or
    /// leave it (`None`).
    pub nmi_window: Option<bool>,
    /// Turn interrupt-window exiting on (`Some(true)`) or off
    /// (`Some(false)`), or leave it (`None`). Only on while an STI shadow
    /// holds back a pending NMI.
    pub interrupt_window: Option<bool>,
    /// Make the protected page writable in EPT
    /// (`ept::ProtectedPage::grant_write`).
    pub grant_write: bool,
    /// Execute this instruction for the guest and put its result in the
    /// guest's registers, before RIP moves past it.
    pub emulate: Option<Emulation>,
    /// Write this exception to VM_ENTRY_INTERRUPTION_INFO, with error code 0
    /// when it delivers one. RIP stays on the faulting instruction.
    pub inject_exception: Option<InterruptionInfo>,
    /// Re-deliver an event the exit interrupted mid-delivery, by writing its
    /// VM-entry fields. Never set together with `advance_rip`, `inject_nmi`
    /// or `inject_exception`: only one event is injected per entry
    /// ([`ResumePlan::redelivering`]).
    pub redeliver: Option<Redelivery>,
    /// Clear blocking by NMI (bit 3) in GUEST_INTERRUPTIBILITY_STATE before
    /// resuming. Set only when re-delivering an NMI whose delivery faulted:
    /// that faulted delivery left bit 3 set, and VM entry refuses to inject
    /// an NMI while it is ([`ResumePlan::redelivering`]).
    pub clear_nmi_blocking: bool,
    /// Set blocking by NMI (bit 3) in GUEST_INTERRUPTIBILITY_STATE before
    /// resuming. Set only after a fault in an IRET that had ended NMI
    /// blocking ([`ResumePlan::restoring_nmi_blocking`]); never together with
    /// `clear_nmi_blocking`, which needs a valid IDT-vectoring field, where
    /// bit 12 is undefined.
    pub restore_nmi_blocking: bool,
    /// Write a guest CR0/CR4 value and its read shadow before resuming, for a
    /// MOV to CR0/CR4 Aleph0 emulates ([`ExitEvent::ControlRegisterWrite`]).
    pub write_cr: Option<CrWrite>,
}

impl ResumePlan {
    /// Go on where the guest was, with nothing changed: the base the plans
    /// below change.
    const AS_IS: Self = Self {
        advance_rip: false,
        inject_nmi: false,
        nmi_window: None,
        interrupt_window: None,
        grant_write: false,
        emulate: None,
        inject_exception: None,
        redeliver: None,
        clear_nmi_blocking: false,
        restore_nmi_blocking: false,
        write_cr: None,
    };
    /// Go on after the exiting instruction (a VMCALL).
    pub const PAST_INSTRUCTION: Self = Self {
        advance_rip: true,
        ..Self::AS_IS
    };
    /// Inject an NMI, delivered before the instruction the guest was about
    /// to run. Injecting always turns NMI-window and interrupt-window exiting
    /// off: either may have been on for the NMI now injected, and turning one
    /// off when it was already off is harmless.
    pub const INJECT_NMI: Self = Self {
        inject_nmi: true,
        nmi_window: Some(false),
        interrupt_window: Some(false),
        ..Self::AS_IS
    };
    /// Go on where the guest was, with NMI-window exiting on, so the next
    /// exit comes as soon as the guest can take an NMI. Interrupt-window
    /// exiting goes off: an interrupt-window exit with NMI blocking still set
    /// ends up here, and the NMI window alone waits for that blocking's IRET.
    pub const WAIT_FOR_NMI_WINDOW: Self = Self {
        nmi_window: Some(true),
        interrupt_window: Some(false),
        ..Self::AS_IS
    };
    /// Go on where the guest was, with interrupt-window exiting on and
    /// NMI-window exiting off, while blocking by STI alone holds a pending NMI
    /// back. A CPU may report an NMI-window exit inside an STI shadow (Intel
    /// SDM Vol. 3C, "NMI-Window Exiting"), and the NMI could not be injected
    /// there either, so with the NMI window on such a CPU would exit again at
    /// the same instruction forever. The interrupt window opens only once the
    /// shadow has ended, and blocking by STI implies RFLAGS.IF = 1, so it
    /// opens right after the guest's next instruction, unless that
    /// instruction is CLI: then the NMI waits for the guest's next exit,
    /// which turns the NMI window back on ([`ResumePlan::keeping_pending_nmi`]).
    /// KVM does the same (`vmx_enable_nmi_window`).
    pub const WAIT_FOR_STI_SHADOW: Self = Self {
        nmi_window: Some(false),
        interrupt_window: Some(true),
        ..Self::AS_IS
    };
    /// Make the protected page writable; RIP stays on the faulting write, so
    /// it runs again.
    pub const RETRY_AFTER_GRANT: Self = Self {
        grant_write: true,
        ..Self::AS_IS
    };
    /// Inject #GP(0); RIP stays on the faulting instruction, as for any
    /// fault.
    pub const INJECT_GP: Self = Self {
        inject_exception: Some(InterruptionInfo::GENERAL_PROTECTION),
        ..Self::AS_IS
    };
    /// Inject #UD; RIP stays on the faulting instruction.
    pub const INJECT_UD: Self = Self {
        inject_exception: Some(InterruptionInfo::INVALID_OPCODE),
        ..Self::INJECT_GP
    };
}

impl ResumePlan {
    /// This plan, with NMI-window exiting turned on if an NMI is still
    /// pending after the exit (`next`). Without that, an NMI folded in by
    /// [`ExitState::with_host_nmi`] at an exit that does not handle NMIs
    /// would wait until some unrelated exit came along. Plans that inject an
    /// NMI leave nothing pending, so they keep turning the window off. A plan
    /// that waits out an STI shadow ([`ResumePlan::WAIT_FOR_STI_SHADOW`])
    /// keeps the NMI window off: inside the shadow it could exit at the same
    /// instruction forever.
    pub fn keeping_pending_nmi(self, next: ExitState) -> Self {
        if next.nmi_pending && self.interrupt_window != Some(true) {
            Self {
                nmi_window: Some(true),
                ..self
            }
        } else {
            self
        }
    }

    /// This plan once Hyper-V refused its forwarded access with `exception`:
    /// RIP stays on the guest's instruction, which gets the exception, as it
    /// would without Aleph0. The rest of the plan (NMI window, the emulation
    /// it tried, for the counts) is kept.
    pub fn refused_with(self, exception: InterruptionInfo) -> Self {
        Self {
            advance_rip: false,
            inject_exception: Some(exception),
            ..self
        }
    }

    /// This plan, setting blocking by NMI again when `exit` was a fault in an
    /// IRET that had ended it ([`ExitInfo::faulted_nmi_unblocking_iret`]).
    /// The guest then resumes at the IRET (the faulting access runs again, or
    /// the fault is delivered there) with NMIs blocked, as they were before
    /// the IRET ran; its next IRET ends the blocking. KVM does the same
    /// (`vmx_recover_nmi_blocking`, `handle_ept_violation`).
    pub fn restoring_nmi_blocking(self, exit: &ExitInfo) -> Self {
        Self {
            restore_nmi_blocking: exit.faulted_nmi_unblocking_iret(),
            ..self
        }
    }

    /// GUEST_INTERRUPTIBILITY_STATE to resume with, from the one the exit
    /// found (`found`): blocking by STI and by MOV SS ended when RIP moves past
    /// the instruction ([`after_skipped_instruction`]), blocking by NMI
    /// cleared for an NMI re-delivery ([`after_nmi_redelivery`]) or set again
    /// after a fault in an NMI-unblocking IRET. The handler writes the field
    /// only when this differs from `found`.
    pub fn interruptibility(self, found: u32) -> u32 {
        let mut state = found;
        if self.advance_rip {
            state = after_skipped_instruction(state);
        }
        if self.clear_nmi_blocking {
            state = after_nmi_redelivery(state);
        }
        if self.restore_nmi_blocking {
            state |= scenario::BLOCKING_BY_NMI;
        }
        state
    }

    /// This plan with `redelivery` added, or `None` when it cannot be added
    /// and the guest must stop.
    ///
    /// Only one event is injected per VM entry, so a plan that advances RIP
    /// or injects an NMI or an exception of its own cannot also re-deliver
    /// one: stop (no double-fault synthesis yet). A software interrupt or
    /// exception also needs VM_ENTRY_INSTRUCTION_LEN, so an unreadable length
    /// stops too.
    pub fn redelivering(self, redelivery: Redelivery) -> Option<Self> {
        if self.advance_rip || self.inject_nmi || self.inject_exception.is_some() {
            return None;
        }
        if redelivery.info.needs_instruction_len() && redelivery.instruction_len.is_none() {
            return None;
        }
        Some(Self {
            redeliver: Some(redelivery),
            // The faulted NMI delivery left blocking by NMI set; clear it so
            // VM entry can inject the re-delivered NMI. `redelivery.info` is
            // already re-armed to a type-2 NMI for a vector-2 vectoring.
            clear_nmi_blocking: redelivery.info.is_nmi(),
            ..self
        })
    }
}

/// GUEST_INTERRUPTIBILITY_STATE after Aleph0 skips the instruction the guest
/// exited on: blocking by STI and by MOV SS cleared, the rest kept.
///
/// Both last until the end of the instruction after STI or MOV SS. When
/// that instruction is the one skipped, the CPU never ends them, so the
/// handler must, as KVM does whenever it skips an instruction. Example: an
/// idle loop's `sti; hlt` exits on the HLT with interruptibility 0x1.
/// Resumed past it with bit 0 still set, the guest would keep interrupts
/// blocked through one more instruction it never asked to protect.
pub fn after_skipped_instruction(interruptibility: u32) -> u32 {
    interruptibility & !(scenario::BLOCKING_BY_STI | scenario::BLOCKING_BY_MOV_SS)
}

/// GUEST_INTERRUPTIBILITY_STATE with blocking by NMI (bit 3) cleared, for
/// re-delivering an NMI whose delivery faulted. VM entry refuses to inject an
/// NMI while bit 3 is set, and the faulted delivery set it, so re-delivery
/// must clear it, as KVM's `__vmx_complete_interrupts` does when it re-queues
/// an NMI from IDT-vectoring.
pub fn after_nmi_redelivery(interruptibility: u32) -> u32 {
    interruptibility & !scenario::BLOCKING_BY_NMI
}

/// What the handler does after an exit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitAction {
    /// Return to the guest, after preparing it as the plan says.
    Resume(ResumePlan),
    /// The last planned exit arrived as expected; stop.
    Finished,
    /// Not an exit this hypervisor handles; stop without resuming.
    Unexpected,
}

impl ExitEvent {
    /// The action for this event.
    pub fn action(self) -> ExitAction {
        match self {
            Self::MainVmcall | Self::GuestNmiHandler => ExitAction::Resume(ResumePlan::PAST_INSTRUCTION),
            Self::NmiInjected | Self::NmiWindowInjected | Self::InterruptWindowInjected => {
                ExitAction::Resume(ResumePlan::INJECT_NMI)
            }
            Self::NmiDeferred => ExitAction::Resume(ResumePlan::WAIT_FOR_NMI_WINDOW),
            Self::NmiDeferredPastSti => ExitAction::Resume(ResumePlan::WAIT_FOR_STI_SHADOW),
            Self::EptWriteGranted => ExitAction::Resume(ResumePlan::RETRY_AFTER_GRANT),
            Self::Emulated(emulation) => ExitAction::Resume(ResumePlan {
                emulate: Some(emulation),
                ..ResumePlan::PAST_INSTRUCTION
            }),
            Self::GuestGeneralProtection | Self::ControlRegisterGeneralProtection => {
                ExitAction::Resume(ResumePlan::INJECT_GP)
            }
            Self::ControlRegisterWrite(write) => ExitAction::Resume(ResumePlan {
                write_cr: Some(write),
                ..ResumePlan::PAST_INSTRUCTION
            }),
            Self::Halted | Self::BootServicesEnded | Self::TestVmcall => {
                ExitAction::Resume(ResumePlan::PAST_INSTRUCTION)
            }
            Self::GuestInvalidOpcode => ExitAction::Resume(ResumePlan::INJECT_UD),
            Self::LastMainVmcall => ExitAction::Finished,
            Self::EptWriteMissing
            | Self::DataPageMismatch
            | Self::EptViolation
            | Self::EptMisconfig
            | Self::ControlRegisterUnhandled
            | Self::Unexpected => ExitAction::Unexpected,
        }
    }
}

/// Decides what `exit` of a `guest` is, given what happened before
/// (`state`), and returns the event with the state for the next exit.
///
/// A VM-entry failure is never handled, whatever the reason. Every other
/// exit goes to the handler for its reason. An exit that interrupted an
/// event's delivery (`exit.idt_vectoring` valid) is still judged by its
/// reason; the handler re-delivers the event with the plan's `redeliver`
/// (built by [`ExitInfo::redelivery`] and [`ResumePlan::redelivering`]).
pub fn decide(guest: GuestKind, state: ExitState, exit: ExitInfo) -> (ExitEvent, ExitState) {
    if exit.reason.entry_failure {
        return (ExitEvent::Unexpected, state);
    }
    let test_guest = guest == GuestKind::BuiltInTest;
    match exit.reason.basic {
        EXIT_REASON_CPUID => (emulation::cpuid(&exit), state),
        EXIT_REASON_XSETBV => (emulation::xsetbv(&exit), state),
        EXIT_REASON_RDMSR => (emulation::rdmsr(&exit), state),
        EXIT_REASON_WRMSR => (emulation::wrmsr(&exit), state),
        EXIT_REASON_IO_INSTRUCTION => (emulation::io(&exit), state),
        EXIT_REASON_HLT => (emulation::hlt(), state),
        EXIT_REASON_MWAIT | EXIT_REASON_MONITOR => (ExitEvent::GuestInvalidOpcode, state),
        EXIT_REASON_EXCEPTION_OR_NMI => scenario::exception_or_nmi(state, &exit),
        EXIT_REASON_NMI_WINDOW => scenario::nmi_window(state, &exit),
        EXIT_REASON_INTERRUPT_WINDOW => scenario::interrupt_window(state, &exit),
        EXIT_REASON_EPT_VIOLATION if test_guest => scenario::ept_violation(state, &exit),
        EXIT_REASON_EPT_VIOLATION => (ExitEvent::EptViolation, state),
        EXIT_REASON_EPT_MISCONFIG => (ExitEvent::EptMisconfig, state),
        EXIT_REASON_CONTROL_REGISTER => (control_register::control_register(&exit), state),
        EXIT_REASON_VMCALL if test_guest => scenario::vmcall(state, &exit),
        EXIT_REASON_VMCALL => (firmware_vmcall(&exit), state),
        _ => (ExitEvent::Unexpected, state),
    }
}

/// A VMCALL of the firmware, or of the OS after it:
///
/// | CPL | RCX | Event |
/// |---|---|---|
/// | > 0 | anything | #UD, as Hyper-V gives (and KVM's emulation of it) |
/// | 0 | one of Aleph0's own (`vmx::vmcall`) | handled here |
/// | 0 | anything else, with Hyper-V's interface | a hypercall, forwarded |
/// | 0 | anything else, without it | #UD, as on hardware without a hypervisor |
///
/// Aleph0's own values have reserved hypercall-input bits set, so no
/// hypercall Hyper-V would take is mistaken for one.
fn firmware_vmcall(exit: &ExitInfo) -> ExitEvent {
    if exit.guest_cpl != 0 {
        return ExitEvent::GuestInvalidOpcode;
    }
    match exit.guest_rcx {
        vmcall::BOOT_SERVICES_ENDED => ExitEvent::BootServicesEnded,
        vmcall::TEST => ExitEvent::TestVmcall,
        // shortcut: forwards the x64 register convention only; a guest
        // calling from 32-bit mode passes its input in EDX:EAX and would
        // need translating, once a 32-bit guest exists.
        input if exit.hyperv => ExitEvent::Emulated(Emulation::Hypercall { input }),
        _ => ExitEvent::GuestInvalidOpcode,
    }
}

#[cfg(test)]
#[path = "../../../tests/unit/vmx/exit_decision.rs"]
mod tests;

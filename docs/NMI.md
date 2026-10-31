# NMIs: catching them in the guest and giving them back

How Aleph0 handles a non-maskable interrupt (NMI) that arrives while its
guest runs:
- what an NMI is;
- why the firmware's IDT cannot take one for the guest;
- the guest's own IDT and NMI handler;
- the VMX controls involved (NMI exiting, virtual NMIs, the NMI and
  interrupt windows);
- the decision Aleph0 makes on each exit, and how it reinjects the NMI;
- what the Hyper-V run printed.

Code:
- `src/vmx/guest.rs`: guest code, guest IDT;
- `src/vmx/exit_decision/`: the pure decision `decide` (`mod.rs`), and the NMI, NMI-window, interrupt-window and VMCALL handlers it dispatches to (`scenario.rs`);
- `src/vmx/vmexit/`: the handler that applies it;
- `src/vmx/vmcs/mod.rs` and `fields.rs`: the controls;
- `scripts/run-hyperv.ps1 -InjectNmi`: the test.

## 1. IF and NMIs

**IF** (Interrupt Flag) is bit 9 of RFLAGS (`0x200`). With IF = 1 the CPU
takes ordinary interrupts (timer, devices); with IF = 0 they wait. `cli`
clears it, `sti` sets it.

| | Ordinary interrupt | NMI |
|---|---|---|
| blocked by IF = 0 (`cli`) | yes | **no** |
| vector | chosen by the system | always 2 |
| typical source | timer, devices | hardware errors, watchdogs, profiling, another CPU, a debugger |

An NMI ignores IF. The only thing that holds one back is *NMI blocking*:
from the moment the CPU delivers an NMI until the handler's `IRET`, a
second NMI waits. At most one waits; more collapse into it.

Aleph0's test guest runs with IF = 0 (guest RFLAGS `0x2`), so no ordinary
interrupt reaches it, but an NMI still can. The firmware guest keeps the
firmware's RFLAGS, normally IF = 1, and its ordinary interrupts go straight
to its own IDT (section 8).

## 2. Why the guest needs its own IDT

Before this step the guest used the firmware's IDT, and NMI exiting was
off. An NMI during the guest went straight through that IDT to the
firmware's default NMI handler, which dumps the CPU state and dead-loops
(`CpuDeadLoop` in EDK2), inside the guest. Aleph0 never saw an exit, and
the guest never came back.

Reinjecting an NMI into the guest therefore needs a handler that returns.
`GuestMemory` allocates a third page, the guest IDT, with one gate:

| Field | Value on the Hyper-V run |
|---|---|
| GUEST_IDTR | base `0x7eb0a000`, limit `0x2f` (three 16-byte gates, vectors 0-2) |
| gate at vector 2 | handler `0x7eb0c020` (the code page + 32), selector `0x28` (the guest CS) |

The gate is a 64-bit interrupt gate (`interrupt_gate` builds it; host
tests pin its bytes):

```text
offset  bytes        meaning
0-1     20 C0        handler bits 15:0  (0x7eb0c020 → 0xc020)
2-3     28 00        code segment selector 0x28
4       00           IST 0: use the current stack (the guest stack)
5       8E           present, DPL 0, type 0xE (64-bit interrupt gate)
6-7     B0 7E        handler bits 31:16 (0x7eb0)
8-11    00 00 00 00  handler bits 63:32
12-15   00 00 00 00  reserved
```

Vectors 0 and 1 are inside the limit but not present. No other vector is
ever delivered through this IDT:
- every exception exits to Aleph0 first (exception bitmap all ones);
- IF = 0 keeps ordinary interrupts out.

The page is checked like the others: `check_idt_permissions` refuses a
user page under CR4.SMAP, because the CPU reads the IDT as an implicit
supervisor access.

## 3. The guest code

49 bytes, copied into the code page (`0x7eb0c000` on the Hyper-V run).
This is the code as of the NMI step; the offsets and the run in section 7
refer to it. Since EPT, 24 bytes come first (the data-page read, write and
read back, `docs/EPT.md` section 5), so every offset below moves by 24:
the handler is at +56 and `dec ecx` at +45.

```text
+0   31 DB            xor ebx, ebx            ; no NMI handled yet
+2   B8 E0 A1 00 00   mov eax, 0xa1e0         ; GUEST_MARKER
+7   0F 01 C1         vmcall                  ; main VMCALL #1
+10  B9 00 00 00 04   mov ecx, 0x04000000     ; GUEST_WAIT_ITERATIONS
+15  85 DB            wait: test ebx, ebx
+17  75 06            jnz done
+19  F3 90            pause
+21  FF C9            dec ecx
+23  75 F6            jnz wait
+25  FF C0            done: inc eax           ; rax = 0xa1e1
+27  0F 01 C1         vmcall                  ; main VMCALL #2
+30  0F 0B            ud2                     ; never reached: Aleph0 stops at #2
+32  50               nmi handler: push rax   ; keep the main code's RAX
+33  B8 49 4D 4E 00   mov eax, 0x4e4d49       ; GUEST_NMI_MARKER, "NMI"
+38  0F 01 C1         vmcall                  ; "the reinjected NMI arrived"
+41  58               pop rax
+42  BB 01 00 00 00   mov ebx, 1              ; tell the wait loop
+47  48 CF            iretq                   ; back into the loop; ends NMI blocking
```

- The guest clears EBX itself. General-purpose registers are not VMCS
  fields, so at VMLAUNCH they hold whatever the host had.
- `IRETQ` restores only RIP, CS, RFLAGS, RSP and SS, so the `ebx = 1`
  written by the handler survives into the loop.
- Without an NMI, the loop runs out (ECX reaches 0) and the guest makes
  VMCALL #2 with `rbx = 0`. A run without `-InjectNmi` still ends normally.

## 4. The VMX controls

| Control | Bit | What it does |
|---|---|---|
| NMI exiting | pin-based bit 3 (`0x08`) | an NMI during the guest causes a VM exit (reason 0, interruption type 2) instead of guest delivery |
| virtual NMIs | pin-based bit 5 (`0x20`) | the CPU tracks the guest's NMI blocking: an injected NMI blocks further ones until the guest's `IRET` |
| NMI-window exiting | primary bit 22 (`0x400000`) | a VM exit (reason 8) as soon as the guest can take an NMI |
| interrupt-window exiting | primary bit 2 (`0x4`) | a VM exit (reason 7) as soon as the guest can take an external interrupt: RFLAGS.IF = 1, no STI or MOV SS blocking |

Each of the first three depends on the previous one: NMI-window exiting
needs virtual NMIs, which need NMI exiting. Interrupt-window exiting needs
nothing else. Hyper-V reported `pin allowed=0x3f` and
`primary allowed=0xf7f9fffe` (bits 2 and 22 set), so all four are
available:
- the first two are set at bring-up;
- bring-up checks that the CPU allows NMI-window and interrupt-window
  exiting, and otherwise stops with `NmiWindowExitingUnsupported` or
  `InterruptWindowExitingUnsupported`;
- the exit handler switches both windows on and off at run time
  (`set_nmi_window_exiting`, `set_interrupt_window_exiting`: read, change
  the bit, write back).

Aleph0 uses interrupt-window exiting only for an NMI an STI shadow holds
back (section 5), never to inject an external interrupt.

## 5. Reinjecting: `VM_ENTRY_INTERRUPTION_INFO`

To give the guest an NMI, Aleph0 writes the event into
`VM_ENTRY_INTERRUPTION_INFO` before VMRESUME. The CPU then delivers it
through the guest IDT as the first thing after entry, as if it had
arrived there:

```text
0x80000202
│     │ └┴─ bits 7:0   vector 2 (NMI)
│     └──── bits 10:8  type 2 (NMI)
└────────── bit 31     valid
```

The CPU clears the field after each successful entry, so the NMI is
injected once. The exit's own `VM_EXIT_INTERRUPTION_INFO` had the same
value, `0x80000202`: Aleph0 hands back exactly what it caught.

Guest RIP is **not** advanced on an NMI exit. The guest goes on at the
instruction it was about to run, and the NMI is delivered before it. The
`instruction length` printed for an NMI exit is undefined (no
instruction caused the exit); ignore it.

### When the NMI cannot be injected yet

VM entry refuses to inject an NMI when the guest's interruptibility state
(`GUEST_INTERRUPTIBILITY_STATE`) shows any of these:

| Bit | Blocking | Why it stops injection |
|---|---|---|
| 0 | by STI | the SDM lets a processor require it to be 0 for NMI injection |
| 1 | by MOV SS | always refuses injection of an NMI |
| 3 | by NMI | with virtual NMIs: an injected NMI the guest has not ended with `IRET` |

In that case Aleph0 keeps the NMI pending and turns on NMI-window
exiting. The CPU exits (reason 8) as soon as the guest can take an NMI,
and Aleph0 injects then and turns the window off again.

STI blocking is included even though the original plan left it out.
Some processors would fail the VM entry, and KVM treats it the same way.
Injection always turns both windows off, which is harmless when they were
not on.

### An STI shadow

STI blocks interrupts until the end of the instruction after it, and VM
entry may refuse an NMI in that shadow. The NMI window does not always wait
it out: the SDM lets a processor report an NMI-window exit while blocking by
STI still holds (Vol. 3C, "NMI-Window Exiting"). Aleph0 cannot inject there
either, and if it kept the NMI window on, such a CPU would exit again at the
same instruction, before the guest ever ran it, forever. An OS idles with
`sti; hlt`, so an NMI there is ordinary.

So when STI is the only blocker, Aleph0 waits for the interrupt window
instead, with the NMI window off (`ResumePlan::WAIT_FOR_STI_SHADOW`, as
KVM's `vmx_enable_nmi_window` does):
- blocking by STI implies RFLAGS.IF = 1 (STI sets it), so the interrupt
  window opens once the shadow ends, right after the guest's next
  instruction;
- at that exit (reason 7) nothing blocks the NMI any more, so Aleph0
  injects it and turns both windows off;
- if blocking by NMI or MOV SS holds as well, the NMI window waits as
  before: by the time that blocking ends, so has the shadow.

One case waits longer: `sti; cli`. The CLI runs inside the shadow and leaves
IF = 0, so the interrupt window never opens. The NMI stays pending until the
guest's next exit of any kind, which turns the NMI window back on
(`ResumePlan::keeping_pending_nmi`), and the NMI window then opens at once.
Monitor trap flag (primary bit 27), which would step exactly one
instruction, is not allowed under Hyper-V (bit 27 is clear in
`0xf7f9fffe`).

### After a fault in an IRET that ended NMI blocking

With virtual NMIs, an NMI handler's IRET ends blocking by NMI as it starts.
If that IRET then faults (an EPT violation on the stack it pops, or an
exception the exception bitmap catches), the exit reports bit 12: of the
EPT violation's exit qualification, or of `VM_EXIT_INTERRUPTION_INFO`
(Intel SDM Vol. 3C, "Exit Qualification for EPT Violations" and
"Information for VM Exits Due to Vectored Events"). The guest stopped at
the IRET, but NMIs are already unblocked: resumed as found, an NMI could
arrive before the handler has returned.

So any exit Aleph0 resumes from with bit 12 set gets blocking by NMI set
again (`GUEST_INTERRUPTIBILITY_STATE` bit 3,
`ResumePlan::restoring_nmi_blocking`, as KVM does): the IRET runs again, or
gets its fault, with NMIs blocked, as they were before it ran.
`ExitInfo::faulted_nmi_unblocking_iret` reads the bit only where the SDM
defines it: never for an exit during an event's delivery (IDT-vectoring
valid) or for a double fault. That also keeps it apart from the NMI
re-delivery of section 8, which clears bit 3 and needs a valid
IDT-vectoring field. The serial report prints `blocking by NMI set again`
when it happens.

## 6. The decision on each exit

`exit_decision::decide(state, exit)` is a pure function, and every row
below is a host unit test. `decide` itself makes the first `any` decision,
and the handler adds the other two to the plan (`ExitInfo::redelivery`,
`ResumePlan::restoring_nmi_blocking`); `decide` sends every other exit to
the handler for its reason, and the NMI, NMI-window, interrupt-window and
VMCALL rows are the handlers in `exit_decision/scenario.rs`.
The emulated instructions (CPUID, RDMSR, WRMSR, IN/OUT) have handlers of
their own in `emulation.rs` and are not in this table
([EMULATED_EXITS.md](EMULATED_EXITS.md)):

| Exit | Condition | Event | Action |
|---|---|---|---|
| any | VM-entry failure | `Unexpected` | stop |
| any | IDT-vectoring info valid (the exit interrupted an event's delivery) | the reason's own event | re-deliver the event on top of the plan (section 8) |
| any resumed | bit 12 of the EPT qualification or the interruption info (a fault in an NMI-unblocking IRET) | the reason's own event | set blocking by NMI again (section 5) |
| reason 0, NMI | no STI/MOV SS/NMI blocking | `NmiInjected` | inject, RIP unchanged, both windows off |
| reason 0, NMI | STI blocking only | `NmiDeferredPastSti` | NMI pending, interrupt window on, NMI window off |
| reason 0, NMI | MOV SS or NMI blocking | `NmiDeferred` | NMI pending, NMI window on, interrupt window off |
| reason 8 | NMI pending, STI blocking only | `NmiDeferredPastSti` | interrupt window on, NMI window off |
| reason 8 | NMI pending, NMI blocking | `NmiDeferred` | keep waiting |
| reason 8 | NMI pending, not blocked | `NmiWindowInjected` | inject, both windows off |
| reason 7 | NMI pending, not blocked | `InterruptWindowInjected` | inject, both windows off |
| reason 7 | NMI pending, NMI blocking | `NmiDeferred` | NMI window on, interrupt window off |
| reason 7 or 8 | no NMI pending | `Unexpected` | stop |
| VMCALL | `rax = 0x4e4d49` | `GuestNmiHandler` | advance RIP, resume |
| VMCALL | `rax = 0xa1e0`, first main VMCALL | `MainVmcall` | advance RIP, resume |
| VMCALL | `rax = 0xa1e1`, second main VMCALL | `LastMainVmcall` | stop: finished |
| anything else | — | `Unexpected` | stop |

Once the guest has finished, bring-up also checks that every emulated exit
happened (`guest::expected_stats`, against the vCPU's exit statistics);
otherwise the run fails with `UnexpectedExitStats`.

The state between exits holds:
- main VMCALLs;
- whether an NMI is pending;
- NMIs handled by the guest (its handler's VMCALLs);
- whether the protected page's write was granted.

NMIs injected are counted with the other exit statistics (`nmi_injections`
in `vmexit::stats`), not in the state, since no decision depends on them.

Main VMCALLs are counted on their own, because NMI exits now interleave
with them; exit #2 is no longer necessarily the second VMCALL.

## 7. The Hyper-V run

`.\scripts\run-hyperv.ps1 -InjectNmi`:
1. gives the VM one vCPU, so the NMI can only hit the CPU running the guest;
2. starts a background job that loads the Hyper-V module;
3. the job waits for `resuming the guest` on serial (main VMCALL #1 done,
   the guest is in its wait loop), then runs
   `Debug-VM -InjectNonMaskableInterrupt`.

What serial showed, with the code page at `0x7eb0c000`:

> This log predates EPT and the emulated exits. Since then the guest first
> causes nine emulated exits (CPUID, four MSR, four I/O; see
> [EMULATED_EXITS.md](EMULATED_EXITS.md)) and one EPT violation, so in a
> current run its VMCALLs and NMI exits are numbered ten higher (the first
> main VMCALL is exit #11, the NMI exit #12). The guest RIPs and addresses
> differ too.

```text
VM exit #1: expected VMCALL (rax=0xa1e0); resuming the guest at rip=0x000000007eb0c00a.
VM exit #2: reason=0 (exception or NMI)
VM exit #2: guest rip=0x000000007eb0c015 instruction length=3         ◀ +21, `dec ecx`; length meaningless
VM exit #2: guest rax=0x000000000000a1e0 rbx=0x0000000000000000 rcx=0x000000001f6f2a97
VM exit #2: NMI (interruption info=0x80000202); reinjecting it into the guest at rip=0x000000007eb0c015.
VM exit #3: guest rip=0x000000007eb0c026 instruction length=3         ◀ +38, the handler's vmcall
VM exit #3: guest rax=0x00000000004e4d49 ...                          ◀ "NMI": delivered through the guest IDT
VM exit #3: guest NMI handler ran (rax=0x4e4d49); the reinjected NMI was delivered; resuming the guest at rip=0x000000007eb0c029.
VM exit #4: guest rip=0x000000007eb0c01b instruction length=3         ◀ +27, main VMCALL #2
VM exit #4: guest rax=0x000000000000a1e1 rbx=0x0000000000000001 rcx=0x000000001f6f2a96
VM exit #4: expected VMCALL (rax=0xa1e1); all 2 planned VMCALLs handled; NMIs: 1 reinjected, 1 handled by the guest.
VM exit #4: stopping the guest; returning to bring-up.
Teardown: CR4.VMXE=0 firmware GDTR/IDTR restored=true IF=1.
Guest finished after 4 VM exits; VMX operation left.
Returning to firmware with SUCCESS.
```

What the numbers prove:
- **RCX at exit #2:** `0x1f6f2a97` means the loop had run `0x20000000 - 0x1f6f2a97 = 0x90d569` rounds (about 9.5 million) when the NMI arrived. The limit was `0x20000000` then. It is `0x04000000` since a plain run measured 65 s for the old one; PAUSE's speed varies between runs, and the new limit took at most about 2.5 s once, while the `-InjectNmi` NMI came after 18.8 million rounds.
- **RAX at exit #3:** `0x4e4d49` means the NMI was delivered through the guest's own IDT, to its handler.
- **RCX at exit #4:** `0x1f6f2a96`, exactly one lower than at exit #2. `iretq` returned to the `dec ecx` at +21, which ran once. The loop then saw `ebx = 1` and went on to VMCALL #2.
- **RBX at exit #4:** `1`; the handler's signal reached the main code.

So nested Hyper-V turns an external NMI into a VM exit for Aleph0, and
hardware injection through `VM_ENTRY_INTERRUPTION_INFO` works.

Without `-InjectNmi`, the same guest prints `no NMI arrived` at exit #2,
with `rcx = 0`: the loop ran out.

### The re-delivery run (#26, on master after #54)

Since #43 the guest's stack page is read-only in EPT, so the reinjected
NMI's delivery faults as the CPU pushes the interrupt frame. Serial of
`-InjectNmi` on 2026-10-31 (exits #1 to #23 are the emulated exits, the HLT,
the data-page EPT write and main VMCALL #1):

```text
VM exit #24: NMI (interruption info=0x80000202); reinjecting it into the guest at rip=0x000000007ff46178.
VM exit #25: reason=48 (EPT violation)
VM exit #25: qualification=0x000000000000058a
VM exit #25: EPT violation at GPA 0x000000007ff7fff8 (linear 0x000000007ff7fff8): write; ...
VM exit #25: guest rip=0x000000007ff46178 instruction length=0
VM exit #25: during event delivery: IDT-vectoring info=0x80000302 error code=0x0
VM exit #25: write to the NMI stack page at GPA 0x000000007ff7fff8: write granted ...
VM exit #25: re-delivering the interrupted event: entry interruption info=0x80000202, blocking by NMI cleared.
VM exit #26: guest NMI handler ran (rax=0x4e4d49); the reinjected NMI was delivered; ...
VM exit #27: expected VMCALL (rax=0xa1e1); all 2 planned VMCALLs handled; NMIs: 1 reinjected, 1 handled by the guest.
Guest finished after 27 VM exits; VMX operation left.
Returning to firmware with SUCCESS.
```

- **Exit #25** is the push of the NMI frame at the stack's top
  (`0x7ff7fff8`, the page below `rsp=0x7ff80000`), at the same RIP as the
  NMI exit, with instruction length 0: no instruction ran.
- **`0x80000302`:** Hyper-V reports the interrupted NMI with type 3
  (hardware exception), not 2; vector 2 is re-armed as a true NMI
  (`0x80000202`), and blocking by NMI, which the faulted delivery left set, is
  cleared so VM entry can inject it (section 8, `ExitInfo::redelivery`).
- **Exit #26** proves the re-delivered NMI reached the guest's handler.

Without `-InjectNmi` the guest ends as before: 24 exits, `SUCCESS`.

## 8. What is not covered yet

- **NMIs while Aleph0 itself runs** are now handled: a VM exit loads
  Aleph0's own IDT, whose NMI handler marks the NMI pending for the guest
  and turns NMI-window exiting on, so the guest gets it through the
  NMI-window path. See [HOST_ENVIRONMENT.md](HOST_ENVIRONMENT.md) section 6.
  NMIs that arrive after the guest stopped, before teardown loads the
  firmware's IDT, reach no guest.
- **Physical NMI blocking after an NMI exit.** An NMI-caused VM exit blocks
  NMIs until the next IRET or VM entry (Intel SDM Vol. 3C, "Architectural
  State Before a VM Exit"). Aleph0's exit path executes no IRET, so the next
  VMRESUME unblocks them, and an NMI that arrives in between is held and
  exits right after the entry. If the guest stops right after an NMI exit,
  the CPU returns to firmware with NMIs blocked until the firmware's first
  interrupt handler runs `IRET`.
- **The STI window loop** is gone: an NMI that only an STI shadow holds
  back waits for the interrupt window, not the NMI window (section 5).
  Host-tested only: the test guest never executes STI, and the firmware's
  `sti; hlt` has not met an NMI on a recorded run yet. `sti; cli` leaves the
  NMI pending until the guest's next exit.
- **NMI blocking after a fault in IRET** is set again before resuming
  (section 5). Host-tested only: neither guest's IRET faults today.
- **Interrupted delivery** is now re-delivered. An exit whose IDT-vectoring
  info is valid interrupted an event the CPU was delivering through the
  guest IDT. `decide` judges the exit by its reason as usual; the handler
  then re-delivers the interrupted event by writing it to the VM-entry
  fields (`VM_ENTRY_INTERRUPTION_INFO` with bits 30:12 cleared, the error
  code when bit 11 is set, and the instruction length for a software
  interrupt or exception), with RIP left where it is. Only one event is
  injected per VM entry, so a plan that advances RIP or injects its own
  event cannot also re-deliver one: the guest stops (no double-fault
  synthesis yet). The test guest's case is the reinjected NMI whose delivery
  faults on the read-only stack page, as the CPU pushes the interrupt frame:
  an EPT violation whose IDT-vectoring field holds the NMI, so Aleph0 grants
  write to the stack page and re-delivers the NMI. The report shows such an
  exit with `during event delivery: IDT-vectoring info=…` and the
  re-delivery with `re-delivering the interrupted event: entry interruption
  info=…`.
- **Ordinary interrupts pass straight through**, for the first OS boot
  too. External-interrupt exiting stays off (the pin-based controls request
  NMI exiting and virtual NMIs only), so an interrupt that arrives while
  the guest runs goes through the guest's own IDT, with no VM exit. One
  that arrives while Aleph0 runs stays pending: a VM exit leaves RFLAGS.IF
  = 0 in root operation (`vmx/vmexit/mod.rs`), and Aleph0 executes no STI,
  so the interrupt reaches the guest's IDT right after VMRESUME, if the
  guest has IF = 1. Aleph0 therefore never injects an external interrupt,
  and needs no APIC virtualization. One whose delivery itself exits (an
  EPT violation on the guest's IDT or stack) is re-delivered like any
  other event, above. This is the firmware guest's behaviour since #21:
  its timer and Hyper-V's synthetic interrupts reach it this way
  ([HYPERV_INTERFACE.md](HYPERV_INTERFACE.md)). On Hyper-V with one vCPU
  (`-ProcessorCount 1`, 2026-10-31), the firmware guest ran with IF = 1:
  its timer fired, and in 12.4 million exits over 67 s there were only
  CPUID, HLT, VMCALL and RDMSR exits (reasons 10, 12, 18, 31): no
  external-interrupt exit and no stop on IDT-vectoring info.
- **No double-fault synthesis.** An exit whose own plan advances RIP or
  injects an event while another is being re-delivered stops the guest.

## Cheat sheet

| Name | Where | What |
|---|---|---|
| `GUEST_NMI_MARKER` (`0x4e4d49`) | `guest.rs` | RAX of the guest NMI handler's VMCALL |
| `GUEST_WAIT_ITERATIONS` (`0x04000000`) | `guest.rs` | rounds of the wait loop, a few seconds on Hyper-V |
| `GuestMemory::idt` | `guest.rs` | guest IDTR: one gate, vector 2 |
| `interrupt_gate` | `guest.rs` | encodes a 64-bit interrupt gate |
| `PIN_BASED_NMI_EXITING`, `PIN_BASED_VIRTUAL_NMIS` | `vmcs/fields.rs` | pin bits 3 and 5 |
| `CPU_BASED_NMI_WINDOW_EXITING` | `vmcs/fields.rs` | primary bit 22 |
| `CPU_BASED_INTERRUPT_WINDOW_EXITING` | `vmcs/fields.rs` | primary bit 2 |
| `set_nmi_window_exiting` | `vmcs/mod.rs` | turns the NMI window on or off |
| `set_interrupt_window_exiting` | `vmcs/mod.rs` | turns the interrupt window on or off |
| `ResumePlan::WAIT_FOR_STI_SHADOW` | `exit_decision/mod.rs` | an NMI behind an STI shadow: interrupt window on, NMI window off |
| `ExitInfo::faulted_nmi_unblocking_iret` | `exit_decision/mod.rs` | bit 12: the exit came from a fault in an NMI-unblocking IRET |
| `ResumePlan::interruptibility` | `exit_decision/mod.rs` | `GUEST_INTERRUPTIBILITY_STATE` to resume with |
| `InterruptionInfo::NMI` (`0x80000202`) | `exit_decision/mod.rs` | `VM_ENTRY_INTERRUPTION_INFO` value |
| `decide` | `exit_decision/mod.rs` | the dispatch; the NMI, NMI-window and VMCALL rows of section 6 are the handlers in `scenario.rs` |
| `-InjectNmi` | `scripts/run-hyperv.ps1` | one vCPU, `Debug-VM` NMI after VMCALL #1 |

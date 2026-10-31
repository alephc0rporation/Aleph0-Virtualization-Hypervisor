# Control registers: CR0/CR4 guest/host masks and read shadows

A guest reaches VMX non-root operation with the host's CR0, CR3 and CR4
(`src/vmx/guest_state.rs`). By then VMXON has set CR4.VMXE and the VMX fixed
bits, so the guest starts with **CR4.VMXE = 1** — a bit its own CPUID says it
does not have (`cpuid_policy` hides CPUID.1:ECX.VMX). Two things then go wrong
for a real OS:

- an OS clears VMXE when it writes CR4 (Linux's `head_64.S` keeps only a few
  bits). In VMX non-root operation a MOV to CR0/CR4 that gives a bit the guest
  owns a value the IA32_VMX_CR0/CR4_FIXED0/FIXED1 MSRs forbid raises #GP;
- the guest can read VMXE = 1 while its CPUID hides VMX.

The fix is the VMX mechanism for exactly this: a **guest/host mask** over the
bits VMX operation fixes, and a **read shadow** that shows the guest the value
those bits had before VMX operation. The guest then owns only the bits VMX
does not fix; a MOV that changes an owned bit away from the shadow exits
(reason 28), and Aleph0 emulates it. This page covers:

- the ownership and the shadows, and how bring-up writes them;
- which MOV exits, and the three decisions (emulate, #GP, stop);
- the exit qualification and the register decode;
- what cannot exit, and what is out of scope.

Code:
- `src/vmx/cr.rs`: `CrFixed`, `owned`, `legal`, `read_shadow`, `mov_exits`,
  and `CrControls` (the masks and shadows bring-up writes);
- `src/vmx/exit_decision/control_register.rs`: the reason-28 decision and the
  exit-qualification decode;
- `src/vmx/vmcs/mod.rs`: `configure_cr_shadowing`, the four VMCS writes;
- `src/vmx/vmexit/handler.rs`: `cr_source_value` (the register the MOV reads)
  and the write of GUEST_CRn and CRn_READ_SHADOW in `prepare_resume`;
- `src/bring_up/mod.rs`: `write_cr_shadowing`, run before the launch.

## 1. Ownership and the read shadow

`IA32_VMX_CR0_FIXED0`/`FIXED1` and the CR4 pair say which bits VMX operation
fixes: a bit set in FIXED0 must be 1, a bit clear in FIXED1 must be 0. The
guest/host mask owns exactly those:

```rust
pub fn owned(fixed0: u64, fixed1: u64) -> u64 {
    fixed0 | !fixed1
}
```

For CR0 that is typically PE, NE and PG (bits 0, 5, 31); for CR4 it includes
VMXE (bit 13). A bit the mask owns is read from the shadow and may not be
freely changed; every other bit the guest owns outright, read from the real
GUEST_CRn.

The initial read shadow is the guest's CR0/CR4 (the host's, VMXE set) with the
owned bits taken from the values **before VMXON**, which `VmxOperation` keeps
(`original_cr0`, `original_cr4`, VMXE clear):

```rust
pub fn read_shadow(guest: u64, original: u64, owned: u64) -> u64 {
    (guest & !owned) | (original & owned)
}
```

So the guest reads CR4.VMXE = 0, while GUEST_CR4 keeps it set. Bring-up builds
all four values once (`CrControls::new`) and writes them to the VMCS before
the launch (`configure_cr_shadowing` → `CR0_GUEST_HOST_MASK` `0x6000`,
`CR4_GUEST_HOST_MASK` `0x6002`, `CR0_READ_SHADOW` `0x6004`, `CR4_READ_SHADOW`
`0x6006`), beside the explicit control zeros.

## 2. Which MOV exits

A MOV to CR0/CR4 exits only when it would change an owned bit away from the
shadow (Intel SDM Vol. 3C, "Changes to Instruction Behavior in VMX Non-Root
Operation"):

```rust
pub fn mov_exits(requested: u64, shadow: u64, owned: u64) -> bool {
    (requested ^ shadow) & owned != 0
}
```

This is why **Linux's CR4 write with VMXE clear does not exit**: the shadow
already shows VMXE = 0, so clearing it changes no owned bit. The CPU completes
the MOV itself, loading the non-owned bits and keeping the owned ones, so the
real CR4.VMXE stays set. The reason-28 exits are the writes that *do* change an
owned bit, for instance a guest clearing CR0.NE.

## 3. The three decisions

`control_register::control_register` decides a reason-28 exit
(`decide_mov`):

| Case | Decision | Resume |
|---|---|---|
| a legal owned-bit change (e.g. clear CR0.NE) | `ControlRegisterWrite` | write the shadow and GUEST_CRn, advance RIP |
| CR4.VMXE set, or a bit FIXED1 forbids | `ControlRegisterGeneralProtection` | inject #GP(0), RIP unchanged |
| clear CR0.PE or CR0.PG | `ControlRegisterUnhandled` | stop |

For an emulated write the new read shadow is the requested value, and
GUEST_CRn is that value forced into the VMX range:

```rust
pub fn legal(requested: u64, fixed0: u64, fixed1: u64) -> u64 {
    (requested | fixed0) & fixed1
}
```

Clearing CR0.NE is the worked example: the guest reads NE = 0 back (the
shadow), the real GUEST_CR0 keeps NE = 1 (FIXED0 forces it). Setting CR4.VMXE
is #GP because the guest's CPUID hides VMX, so on a CPU without VMX the write
could not be made. Clearing CR0.PE or CR0.PG means leaving protected mode or
paging, which needs an unrestricted guest (secondary control bit 7) Aleph0
does not enable, so it stops with the qualification.

## 4. The exit qualification and the register

`CrQualification` decodes the control-register exit qualification (Intel SDM
Vol. 3C, "Exit Qualification for Control-Register Accesses"):

```text
bits 3:0   control register (0 = CR0, 4 = CR4)
bits 5:4   access: 0 MOV to CR, 1 MOV from CR, 2 CLTS, 3 LMSW
bit  6     LMSW operand type
bits 11:8  general-purpose register of a MOV
bits 31:16 LMSW source data
```

The register number (bits 11:8) follows the instruction encoding (0 RAX, 1
RCX, 2 RDX, 3 RBX, 4 RSP, 5 RBP, 6 RSI, 7 RDI, 8-15 R8-R15), not
`RegisterFrame`'s field order, and RSP is **not** in the frame: it is
GUEST_RSP. `handler::cr_source_value` reads the value from the frame, or from
GUEST_RSP for register 4.

## 5. What cannot exit

With these masks:

- **MOV from CR0/CR4** reads the shadow without an exit; CLTS cannot exit (TS
  is not owned); LMSW cannot change an owned bit of a 64-bit guest (it can only
  set PE, already 1). If one of these exits anyway, the masks are wrong:
  `control_register` stops (`ControlRegisterUnhandled`).
- **CR3 and CR8** do not exit with the current controls: the primary controls
  request neither CR3-load nor CR3-store exiting, and Hyper-V requires neither
  (`required=0x240065f2`). The guest's MOV to and from CR3 runs without an
  exit, and its CR3 is a guest-physical address EPT translates.

## 6. Out of scope

- CR4.OSXSAVE, XSETBV and the CPUID bits that follow CR4: #25
  ([EMULATED_EXITS.md](EMULATED_EXITS.md) sections 3 and 3a). OSXSAVE is not
  an owned bit, so setting it does not exit; the #25 test guest's MOV to CR4
  confirmed that on Hyper-V.
- Unrestricted guest and a guest that leaves protected mode or paging, needed
  for INIT/SIPI with multiple vCPUs: after the first boot. Clearing CR0.PE or
  CR0.PG stops until then.
- Exiting on CR writes or CR3 loads to watch the guest (ROADMAP section 6).

## 7. Tested

The decisions are pure, so they are host unit tests
(`tests/unit/vmx/cr.rs`, `tests/unit/vmx/exit_decision.rs`): the owned bits for
FIXED values of the usual shape, the shadow that hides VMXE, the write that
matches the shadow in every owned bit (no exit), clearing CR0.NE (emulated,
real NE kept), setting CR4.VMXE (#GP), a bit FIXED1 forbids (#GP), clearing
CR0.PE/PG (stop), MOV from CR / CLTS / LMSW (stop), and the register decode for
all 16 numbers with RSP from GUEST_RSP (`tests/unit/vmx/vmexit/handler.rs`). A
Hyper-V run exercising a guest CR4 write and a CR0.NE clear is still to be
recorded (ROADMAP section 5).

## Cheat sheet

| Item | Value |
|---|---|
| `CR0_GUEST_HOST_MASK` / `CR4_GUEST_HOST_MASK` | `0x6000` / `0x6002` |
| `CR0_READ_SHADOW` / `CR4_READ_SHADOW` | `0x6004` / `0x6006` |
| Owned bits | `FIXED0 \| !FIXED1` (CR0: PE, NE, PG; CR4: VMXE) |
| Read shadow | guest value, owned bits from before VMXON (VMXE = 0) |
| MOV exits when | `(requested ^ shadow) & owned != 0` |
| New GUEST_CRn on emulate | `(requested \| FIXED0) & FIXED1` |
| Exit reason 28 | control-register access |
| Injected #GP | `0x80000B0D`, error code 0, RIP unchanged |

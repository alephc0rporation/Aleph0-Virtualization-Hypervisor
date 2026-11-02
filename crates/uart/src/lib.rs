//! Port I/O and the polled 16550 UART driver Aleph0 prints with, and the
//! tools that boot it too (`tools/ebs-harness`, `tools/os-loader`), so all
//! three agree on the serial port. Needs no firmware and no allocation.

// Host unit tests build with std and the test harness; the UEFI build is
// no_std.
#![cfg_attr(not(test), no_std)]
#![warn(clippy::undocumented_unsafe_blocks)]

pub mod port;
pub mod serial;

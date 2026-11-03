//! The OS loader: the `BOOTX64.EFI` that boots an OS as Aleph0's guest
//! (`run-hyperv.ps1 -Kernel`, docs/LINUX_GUEST.md section 8).
//!
//! 1. Loads `\EFI\BOOT\aleph0.efi` from its own volume and starts it. When
//!    `StartImage` returns, the loader runs as Aleph0's guest, which it
//!    checks: Aleph0 hides VMX from CPUID.
//! 2. Loads `\EFI\aleph0\linux.efi` the same way and starts it. The kernel's
//!    EFI stub calls `ExitBootServices` itself, which Aleph0 learns of from
//!    its own event, so `StartImage` returns only if the kernel fails.
//!
//! Aleph0 never learns what boots next: the boot path is the loader's. Both
//! paths are fixed, as the runner stages them.
//!
//! The loader prints on COM1, the kernel's console, before the kernel does;
//! Aleph0 prints on COM2.

// A test build (rust-analyzer checks every target) links std and its panic
// handler; the UEFI build is no_std with a firmware entry point.
#![cfg_attr(not(test), no_main)]
#![cfg_attr(not(test), no_std)]

extern crate alloc;

use core::arch::x86_64::__cpuid;

use uefi::boot::{self, LoadImageSource};
use uefi::prelude::*;
use uefi::{CStr16, cstr16};

// Aleph0's own UART driver (`crates/uart`), as the harness uses it.
use uart::serial::{self, SerialPort};
use uart::serial_println;

/// Prefix of every line the loader prints.
const TAG: &str = "[os-loader]";

/// Prints a tagged line on COM1.
macro_rules! say {
    ($($arg:tt)*) => {
        crate::serial_println!("{} {}", crate::TAG, format_args!($($arg)*))
    };
}

/// Aleph0's image, next to the loader.
const ALEPH0_PATH: &CStr16 = cstr16!("\\EFI\\BOOT\\aleph0.efi");
/// The kernel, where `scripts/linux/build.sh`'s image is staged (#17).
const KERNEL_PATH: &CStr16 = cstr16!("\\EFI\\aleph0\\linux.efi");

/// CPUID.1:ECX bit 5: VMX, which Aleph0 hides from its guest.
const CPUID_1_ECX_VMX: u32 = 1 << 5;

#[cfg_attr(not(test), entry)]
fn main() -> Status {
    if serial::init(SerialPort::COM1).is_err() {
        // Nowhere to report anything.
        return Status::DEVICE_ERROR;
    }
    say!("starting Aleph0 from {ALEPH0_PATH}.");
    if let Err(error) = start(ALEPH0_PATH) {
        say!("Aleph0 did not start: {:?}.", error.status());
        return error.status();
    }
    if __cpuid(1).ecx & CPUID_1_ECX_VMX != 0 {
        say!("Aleph0 returned, but CPUID shows VMX: the loader is not its guest. Was it built with -TestGuest?");
        return Status::ABORTED;
    }
    say!("Aleph0 returned SUCCESS; the loader runs as its guest (CPUID hides VMX).");
    say!("starting the kernel from {KERNEL_PATH}.");
    let status = match start(KERNEL_PATH) {
        Ok(()) => Status::SUCCESS,
        Err(error) => error.status(),
    };
    say!("the kernel returned {status:?}.");
    status
}

/// Reads the image at `path` from the loader's own volume, loads it and
/// starts it. Returns once the image has returned.
fn start(path: &CStr16) -> uefi::Result {
    let image = {
        let mut volume = uefi::fs::FileSystem::new(boot::get_image_file_system(boot::image_handle())?);
        let bytes = volume.read(path).map_err(|_| uefi::Error::from(Status::NOT_FOUND))?;
        boot::load_image(
            boot::image_handle(),
            LoadImageSource::FromBuffer {
                buffer: &bytes,
                file_path: None,
            },
        )?
    };
    boot::start_image(image)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    say!("PANIC: {info}");
    loop {
        // SAFETY: HLT only waits for the next interrupt.
        unsafe { core::arch::asm!("hlt", options(nomem, nostack)) };
    }
}

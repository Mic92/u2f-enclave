//! Bare-metal authenticator kernel.
//!
//! At this stage the goal is only to prove the full `ctap` stack (sha2, hmac,
//! p256, ecdsa) links and runs without `std` on `x86_64-unknown-none`. Boot
//! glue (PVH/IGVM entry, page tables, GHCB, virtio-vsock) is layered on top
//! of this in subsequent commits — see `DESIGN.md` for the lift map.
//!
//! Build: `cargo build -p enclave --target x86_64-unknown-none --release`

#![no_std]
#![no_main]

extern crate alloc;

use core::arch::asm;
use core::panic::PanicInfo;
use core::ptr::addr_of_mut;
use linked_list_allocator::LockedHeap;

mod boot;
mod platform;
mod serial;

const HEAP_SIZE: usize = 256 * 1024;
static mut HEAP: [u8; HEAP_SIZE] = [0; HEAP_SIZE];

#[global_allocator]
static ALLOC: LockedHeap = LockedHeap::empty();

/// 64-bit entry, far-jumped to from `ram32.s` with a valid stack and
/// [0, 2 MiB) identity-mapped.
#[no_mangle]
pub extern "C" fn rust64_start() -> ! {
    // SAFETY: single-threaded, runs once before any allocation.
    unsafe {
        ALLOC.lock().init(addr_of_mut!(HEAP) as *mut u8, HEAP_SIZE);
    }
    serial::init();
    serial::print("u2f-enclave: boot\n");

    kmain();

    serial::print("u2f-enclave: halt\n");
    qemu_exit(0);
}

fn kmain() {
    let mut auth = ctap::Authenticator::new(platform::BareMetal::new(), ctap::AAGUID);

    // Smoke: feed one all-zero report (invalid CID) and confirm we get an
    // error packet back. Exercises CTAPHID, alloc, and the panic-free path
    // before any transport exists.
    let out = auth.process_report(&[0u8; ctap::HID_REPORT_SIZE]);
    serial::print("u2f-enclave: ctap link ok, resp pkts=");
    serial::print_u32(out.len() as u32);
    serial::print("\n");

    // TODO(M2): bring up virtio-vsock, accept(), then loop:
    //   read 64B -> auth.process_report -> write all 64B replies
}

/// Exit QEMU via `isa-debug-exit`; falls back to `hlt` on real hardware.
/// QEMU's exit status is `(code << 1) | 1`, so 0 → 1, anything else → odd>1.
fn qemu_exit(code: u32) -> ! {
    unsafe { asm!("out dx, eax", in("dx") 0xf4u16, in("eax") code) };
    loop {
        unsafe { asm!("hlt", options(nomem, nostack)) };
    }
}

#[panic_handler]
fn panic(info: &PanicInfo<'_>) -> ! {
    serial::print("PANIC: ");
    if let Some(loc) = info.location() {
        serial::print(loc.file());
        serial::print(":");
        serial::print_u32(loc.line());
    }
    serial::print("\n");
    qemu_exit(0x31);
}

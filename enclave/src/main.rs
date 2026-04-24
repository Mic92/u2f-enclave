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

mod platform;
mod serial;

const HEAP_SIZE: usize = 256 * 1024;
static mut HEAP: [u8; HEAP_SIZE] = [0; HEAP_SIZE];

#[global_allocator]
static ALLOC: LockedHeap = LockedHeap::empty();

/// ELF entry. Under plain QEMU `-kernel` this is reached via the PVH stub
/// (TODO); under SEV-SNP via the IGVM-described initial VMSA. Either way we
/// arrive in 64-bit mode with a usable stack.
#[no_mangle]
pub extern "C" fn _start() -> ! {
    // SAFETY: single-threaded, runs once before any allocation.
    unsafe {
        ALLOC.lock().init(addr_of_mut!(HEAP) as *mut u8, HEAP_SIZE);
    }
    serial::init();
    serial::print("u2f-enclave: boot\n");

    kmain();

    serial::print("u2f-enclave: halt\n");
    halt();
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

fn halt() -> ! {
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
    halt();
}

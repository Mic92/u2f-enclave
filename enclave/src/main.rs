//! Bare-metal authenticator kernel.
//!
//! PVH-boots, brings up a polling virtio-vsock, and serves CTAP HID reports
//! over it. SEV-SNP (#VC, GHCB, attestation) is layered on top — see
//! `DESIGN.md`.
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
mod virtio;
mod vsock;

const VSOCK_PORT: u32 = 5555;

const HEAP_SIZE: usize = 256 * 1024;
static mut HEAP: [u8; HEAP_SIZE] = [0; HEAP_SIZE];

#[global_allocator]
static ALLOC: LockedHeap = LockedHeap::empty();

/// 64-bit entry, far-jumped to from `ram32.s` with a valid stack and
/// [0, 4 GiB) identity-mapped.
#[no_mangle]
pub extern "C" fn rust64_start() -> ! {
    // SAFETY: single-threaded, runs once before any allocation.
    unsafe {
        ALLOC.lock().init(addr_of_mut!(HEAP) as *mut u8, HEAP_SIZE);
    }
    serial::init();
    serial::print("u2f-enclave: boot\n");

    let mut auth = ctap::Authenticator::new(platform::BareMetal::new(), ctap::AAGUID);

    let Some(vs) = vsock::init(VSOCK_PORT) else {
        // No virtio-vsock (e.g. plain `pc` machine in CI) — keep the link
        // smoke so `boot-enclave.sh` still has something to assert on.
        let out = auth.process_report(&[0u8; ctap::HID_REPORT_SIZE]);
        serial::print("u2f-enclave: ctap link ok, resp pkts=");
        serial::print_u32(out.len() as u32);
        serial::print("\nu2f-enclave: no vsock, halt\n");
        qemu_exit(0);
    };
    serial::print("u2f-enclave: vsock cid=");
    serial::print_u32(vsock::guest_cid(vs) as u32);
    serial::print(" port=");
    serial::print_u32(VSOCK_PORT);
    serial::print("\n");

    let mut report = [0u8; ctap::HID_REPORT_SIZE];
    loop {
        vs.read_report(&mut report);
        for r in auth.process_report(&report) {
            vs.write_report(&r);
        }
    }
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

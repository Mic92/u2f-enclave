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

use core::panic::PanicInfo;
use core::ptr::addr_of_mut;
use linked_list_allocator::LockedHeap;

mod boot;
mod platform;
mod serial;
mod sev;
mod virtio;
mod vsock;

const VSOCK_PORT: u32 = 5555;

const HEAP_SIZE: usize = 256 * 1024;
static mut HEAP: [u8; HEAP_SIZE] = [0; HEAP_SIZE];

#[global_allocator]
static ALLOC: LockedHeap = LockedHeap::empty();

/// 64-bit entry, far-jumped to from `ram32.s` with a valid stack,
/// [0, 4 GiB) identity-mapped, and `c_bit` = SEV C-bit position the vmm
/// passed in `%esi` (0 ⇒ plain VM).
#[no_mangle]
pub extern "C" fn rust64_start(c_bit: u32) -> ! {
    if c_bit != 0 {
        // Brings up the GHCB so port I/O works; everything below is then
        // identical for plain and encrypted boots.
        sev::init(c_bit);
    }

    // SAFETY: single-threaded, runs once before any allocation.
    unsafe {
        ALLOC.lock().init(addr_of_mut!(HEAP) as *mut u8, HEAP_SIZE);
    }
    serial::init();
    serial::print("u2f-enclave: boot\n");
    if sev::active() {
        serial::print("u2f-enclave: SEV-SNP active, GHCB up\n");
        // vsock under SNP is not wired yet (rings need shared pages and
        // virtio-mmio needs the GHCB-MMIO path).
        sev::terminate(sev::TERM_BOOT_OK);
    }

    let Some(vs) = vsock::init(VSOCK_PORT) else {
        serial::print("u2f-enclave: no vsock, halt\n");
        debug_exit(0);
    };
    serial::print("u2f-enclave: vsock cid=");
    serial::print_u32(vs.cid() as u32);
    serial::print(" port=");
    serial::print_u32(VSOCK_PORT);
    serial::print("\n");

    let mut auth = ctap::Authenticator::new(platform::BareMetal::new(), ctap::AAGUID);
    let mut report = [0u8; ctap::HID_REPORT_SIZE];
    loop {
        vs.read_report(&mut report);
        for r in auth.process_report(&report) {
            vs.write_report(&r);
        }
    }
}

/// Signal exit via the isa-debug-exit port; the vmm turns this into a
/// process exit code of `(code << 1) | 1`. Falls back to `hlt` if nobody is
/// listening.
fn debug_exit(code: u32) -> ! {
    sev::outl(0xf4, code);
    loop {
        unsafe { core::arch::asm!("hlt", options(nomem, nostack)) };
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
    debug_exit(0x31);
}

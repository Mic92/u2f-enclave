//! Bare-metal authenticator kernel.
//!
//! PVH-boots, brings up a polling virtio-vsock, and serves CTAP HID reports
//! over it. SEV-SNP (paravirt GHCB, attestation) is layered on top — see
//! `DESIGN.md`.
//!
//! Build: `cargo build -p guest --target x86_64-unknown-none --release`

#![no_std]
#![no_main]

extern crate alloc;

use core::panic::PanicInfo;
use core::ptr::addr_of_mut;
use linked_list_allocator::LockedHeap;

mod boot;
mod greq;
mod platform;
mod pv;
mod seal;
mod serial;
mod sev;
#[path = "../../host/src/snp_report.rs"]
mod snp_report;
mod virtio;
mod vsock;

const VSOCK_PORT: u32 = 5555;

const HEAP_SIZE: usize = 256 * 1024;
static mut HEAP: [u8; HEAP_SIZE] = [0; HEAP_SIZE];

#[global_allocator]
static ALLOC: LockedHeap = LockedHeap::empty();

/// 64-bit entry, far-jumped to from `ram32.s` with a valid stack,
/// [0, 4 GiB) identity-mapped, and `c_bit` ≥32 = SEV C-bit position
/// (0 = plain VM).
#[no_mangle]
pub extern "C" fn rust64_start(c_bit: u32) -> ! {
    if c_bit != 0 {
        sev::init(c_bit);
        greq::init();
    }

    // SAFETY: single-threaded, runs once before any allocation.
    unsafe {
        ALLOC.lock().init(addr_of_mut!(HEAP) as *mut u8, HEAP_SIZE);
    }
    serial::init();
    serial::print("u2f-enclave: boot\n");
    if sev::active() {
        serial::print("u2f-enclave: SEV-SNP active, GHCB up\n");
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

    // Under SNP the master is random and persists via the host's state
    // file; under plain KVM it is per-process ephemeral.
    let master = if sev::active() {
        seal::prelude(vs)
    } else {
        let mut m = [0u8; 32];
        platform::fill_rdrand(&mut m);
        m
    };

    let mut auth = ctap::Authenticator::new(platform::BareMetal::new(master), ctap::AAGUID);
    let mut report = [0u8; ctap::HID_REPORT_SIZE];
    loop {
        vs.read_report(&mut report);
        for r in auth.process_report(&report) {
            vs.write_report(&r);
        }
    }
}

/// Signal exit via the isa-debug-exit port; the host turns this into a
/// process exit code of `(code << 1) | 1`. Falls back to `hlt` if nobody is
/// listening.
pub fn debug_exit(code: u32) -> ! {
    pv::outl(0xf4, code);
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

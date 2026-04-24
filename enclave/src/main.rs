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
        // Reaching here under SEV-ES with the C-bit applied means the
        // encrypted launch + page-table setup worked. There is no `#VC`
        // handler yet, so any IOIO/MMIO would triple-fault; bow out via the
        // GHCB MSR protocol with a marker the vmm/e2e can check.
        let _ = sev::status(); // sanity: non-interceptable; #GP if vmm lied
        sev::terminate(sev::TERM_BOOT_OK);
    }

    // SAFETY: single-threaded, runs once before any allocation.
    unsafe {
        ALLOC.lock().init(addr_of_mut!(HEAP) as *mut u8, HEAP_SIZE);
    }
    serial::init();
    serial::print("u2f-enclave: boot\n");

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
    debug_exit(0x31);
}

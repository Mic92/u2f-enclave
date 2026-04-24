//! Ring-3 SGX enclave — sibling of `guest/`, different isolation primitive
//! (EPC pages instead of a confidential VM).  The host EENTERs with a
//! pointer into untrusted memory in `rdi`.
//!
//! Build: `cargo build -p sgx --target x86_64-unknown-none --release`
#![no_std]
#![no_main]

use core::arch::global_asm;

global_asm!(include_str!("entry.s"), options(att_syntax));

/// Liveness probe: write a marker the host checks for, so a successful
/// round-trip proves ECREATE→EADD→EINIT→EENTER→EEXIT all worked.
#[unsafe(no_mangle)]
extern "C" fn encl_main(arg: *mut u64, _rsi: u64) {
    unsafe { arg.write_volatile(0x53475821) }; // "SGX!"
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    // No I/O channel here; an AEX surfaces to the host as an exception via
    // the vDSO run struct, which is at least observable.
    unsafe { core::arch::asm!("ud2", options(noreturn)) }
}

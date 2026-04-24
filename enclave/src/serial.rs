//! 16550 UART on the legacy COM1 port for bring-up logging.
//!
//! Port I/O goes through `sev::{inb,outb}` which transparently routes via
//! the GHCB when running encrypted; the vmm sees plain `KVM_EXIT_IO` either
//! way.

use crate::sev::{inb, outb};

const COM1: u16 = 0x3F8;

pub fn init() {
    outb(COM1 + 1, 0x00); // IER: off
    outb(COM1 + 3, 0x80); // LCR: DLAB
    outb(COM1, 0x01); //     DLL: 115200
    outb(COM1 + 1, 0x00); // DLM
    outb(COM1 + 3, 0x03); // LCR: 8N1
    outb(COM1 + 2, 0xC7); // FCR: enable+clear FIFOs
}

pub fn print(s: &str) {
    for b in s.bytes() {
        while inb(COM1 + 5) & 0x20 == 0 {}
        outb(COM1, b);
    }
}

pub fn print_u32(mut n: u32) {
    let mut buf = [0u8; 10];
    let mut i = buf.len();
    loop {
        i -= 1;
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    print(core::str::from_utf8(&buf[i..]).unwrap());
}

//! 16550 UART on the legacy COM1 port for bring-up logging.
//!
//! Under SEV-ES/SNP every `in`/`out` raises `#VC`; until the GHCB IOIO path
//! is wired this only produces output on plain (non-confidential) QEMU. That
//! is exactly what early bring-up needs.

use core::arch::asm;

const COM1: u16 = 0x3F8;

unsafe fn outb(port: u16, val: u8) {
    asm!("out dx, al", in("dx") port, in("al") val, options(nomem, nostack));
}
unsafe fn inb(port: u16) -> u8 {
    let val: u8;
    asm!("in al, dx", out("al") val, in("dx") port, options(nomem, nostack));
    val
}

pub fn init() {
    unsafe {
        outb(COM1 + 1, 0x00); // IER: off
        outb(COM1 + 3, 0x80); // LCR: DLAB
        outb(COM1, 0x01); //     DLL: 115200
        outb(COM1 + 1, 0x00); // DLM
        outb(COM1 + 3, 0x03); // LCR: 8N1
        outb(COM1 + 2, 0xC7); // FCR: enable+clear FIFOs
    }
}

pub fn print(s: &str) {
    for b in s.bytes() {
        unsafe {
            while inb(COM1 + 5) & 0x20 == 0 {}
            outb(COM1, b);
        }
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

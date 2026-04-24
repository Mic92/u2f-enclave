//! Paravirt I/O dispatch.
//!
//! Three call paths for the same operations: plain VM (raw instructions),
//! SEV-SNP (GHCB) and TDX (TDVMCALL). Callers use these wrappers; whichever
//! backend `init`ed at boot wins. KVM normalises all three to ordinary
//! `KVM_EXIT_IO`/`_MMIO` so the vmm doesn't care which one is in use.

use core::arch::asm;

use crate::{sev, tdx};

#[inline]
pub fn outb(port: u16, v: u8) {
    if tdx::active() {
        tdx::io(port, 1, true, v as u64);
    } else if sev::active() {
        sev::outb(port, v);
    } else {
        unsafe { asm!("out dx, al", in("dx") port, in("al") v, options(nomem, nostack)) };
    }
}
#[inline]
pub fn inb(port: u16) -> u8 {
    if tdx::active() {
        tdx::io(port, 1, false, 0) as u8
    } else if sev::active() {
        sev::inb(port)
    } else {
        let v: u8;
        unsafe { asm!("in al, dx", out("al") v, in("dx") port, options(nomem, nostack)) };
        v
    }
}
#[inline]
pub fn outl(port: u16, v: u32) {
    if tdx::active() {
        tdx::io(port, 4, true, v as u64);
    } else if sev::active() {
        sev::outl(port, v);
    } else {
        unsafe { asm!("out dx, eax", in("dx") port, in("eax") v, options(nomem, nostack)) };
    }
}

#[inline]
pub fn mmio_read32(gpa: u64) -> u32 {
    if tdx::active() {
        tdx::mmio_read32(gpa)
    } else if sev::active() {
        sev::mmio_read32(gpa)
    } else {
        unsafe { (gpa as *const u32).read_volatile() }
    }
}
#[inline]
pub fn mmio_write32(gpa: u64, v: u32) {
    if tdx::active() {
        tdx::mmio_write32(gpa, v);
    } else if sev::active() {
        sev::mmio_write32(gpa, v);
    } else {
        unsafe { (gpa as *mut u32).write_volatile(v) };
    }
}

/// Mark a page-aligned range readable/writable by the host (virtqueue
/// rings, DMA buffers). No-op on a plain VM where all memory already is.
pub fn share(va: u64, bytes: usize) {
    if tdx::active() {
        tdx::share(va, bytes);
    } else if sev::active() {
        sev::share(va, bytes);
    }
}

#[inline]
pub fn hlt() {
    if tdx::active() {
        tdx::hlt();
    } else {
        unsafe { asm!("hlt", options(nomem, nostack)) };
    }
}

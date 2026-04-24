//! Paravirt SEV-ES/SNP guest support.
//!
//! We own every privileged-instruction call site (serial `in/out`,
//! `debug_exit`, virtio MMIO), so instead of taking the `#VC` trap, decoding
//! the faulting instruction, and replaying it via the GHCB, we just *call*
//! the GHCB directly from those sites. No IDT, no exception frame asm, no
//! instruction decoder. `objdump` confirms the binary contains zero
//! `cpuid`/`rdtsc`/`wbinvd`, so nothing else can `#VC`.
//!
//! Refs: AMD GHCB spec rev 2.03, APM Vol 2 §15.34/§15.36, Linux
//! `arch/x86/include/asm/{sev-common,svm}.h`, `arch/x86/kvm/svm/sev.c`.

use core::arch::asm;
use core::ptr::{addr_of, addr_of_mut, write_bytes, write_volatile};
use core::sync::atomic::{compiler_fence, Ordering};

use crate::boot::{PageTable, PDPT};

// --- MSRs / GHCB MSR-protocol opcodes -------------------------------------

const MSR_SEV_STATUS: u32 = 0xc001_0131;
const MSR_GHCB: u32 = 0xc001_0130;

const GHCB_MSR_REG_GPA_REQ: u64 = 0x012;
const GHCB_MSR_REG_GPA_RESP: u64 = 0x013;
const GHCB_MSR_PSC_REQ: u64 = 0x014;
const GHCB_MSR_PSC_RESP: u64 = 0x015;
const GHCB_MSR_TERM_REQ: u64 = 0x100;

const PSC_SHARED: u64 = 2;

// --- GHCB save-area offsets (`struct ghcb_save_area`) ---------------------

const GHCB_RAX: usize = 0x1f8;
const GHCB_EXIT_CODE: usize = 0x390;
const GHCB_EXIT_INFO1: usize = 0x398;
const GHCB_EXIT_INFO2: usize = 0x3a0;
const GHCB_BITMAP: usize = 0x3f0;
const GHCB_PROTO_VER: usize = 0xffa;
const GHCB_USAGE: usize = 0xffc;

const SVM_EXIT_IOIO: u64 = 0x7b;
const IOIO_IN: u64 = 1;
const IOIO_D8: u64 = 1 << 4;
const IOIO_D32: u64 = 1 << 6;

/// Anything ≤0x07 in reason-set 0 is a spec-defined failure, so pick a
/// value that can't be mistaken for one.
pub const TERM_BOOT_OK: u8 = 0x77;
const TERM_FATAL: u8 = 0x7f;

// --- shared state ---------------------------------------------------------

#[repr(C, align(4096))]
struct Page([u8; 4096]);

/// 0 ⇒ SEV inactive. Otherwise the C-bit mask for leaf PTEs.
static mut C_MASK: u64 = 0;
static mut GHCB: Page = Page([0; 4096]);
/// 4 KiB-granular tables for [0, 2 MiB) so the GHCB (and later virtqueue
/// rings) can have C=0 while everything else stays private.
static mut PD0: PageTable = PageTable([0; 512]);
static mut PT0: PageTable = PageTable([0; 512]);

#[inline(always)]
pub fn active() -> bool {
    unsafe { C_MASK != 0 }
}

// --- low-level primitives -------------------------------------------------

#[inline]
fn rdmsr(msr: u32) -> u64 {
    let (lo, hi): (u32, u32);
    unsafe {
        asm!("rdmsr", in("ecx") msr, out("eax") lo, out("edx") hi,
             options(nomem, nostack, preserves_flags))
    };
    ((hi as u64) << 32) | lo as u64
}
#[inline]
fn wrmsr(msr: u32, v: u64) {
    unsafe {
        asm!("wrmsr", in("ecx") msr, in("eax") v as u32, in("edx") (v >> 32) as u32,
             options(nomem, nostack, preserves_flags))
    };
}
#[inline]
fn vmgexit() {
    // VMGEXIT = `rep; vmmcall` (F3 0F 01 D9). The hypervisor reads/writes
    // the GHCB page, hence the fences and no `nomem`.
    compiler_fence(Ordering::Release);
    unsafe { asm!("rep vmmcall", options(nostack)) };
    compiler_fence(Ordering::Acquire);
}
#[inline]
fn flush_tlb() {
    unsafe { asm!("mov {0}, cr3", "mov cr3, {0}", out(reg) _, options(nostack)) };
}
/// PVALIDATE: change the RMP `validated` bit. Runs at VMPL0, no hypervisor
/// involvement.
#[inline]
fn pvalidate(va: u64, validate: bool) -> u32 {
    let rc: u64;
    unsafe {
        asm!(".byte 0xf2, 0x0f, 0x01, 0xff",
             inout("rax") va => rc, in("ecx") 0u32, in("edx") validate as u32,
             options(nostack))
    };
    rc as u32
}

fn msr_proto(req: u64) -> u64 {
    wrmsr(MSR_GHCB, req);
    vmgexit();
    rdmsr(MSR_GHCB)
}

/// Never returns: KVM converts to `KVM_EXIT_SYSTEM_EVENT(SEV_TERM)` with
/// `data[0]` = the raw GHCB MSR value.
pub fn terminate(reason: u8) -> ! {
    wrmsr(MSR_GHCB, GHCB_MSR_TERM_REQ | ((reason as u64) << 16));
    loop {
        vmgexit();
    }
}

#[cold]
fn die(_why: &str) -> ! {
    // No serial yet (that's what we're bringing up). The vmm prints the
    // GHCB value, which is enough to bisect.
    terminate(TERM_FATAL);
}

// --- bring-up -------------------------------------------------------------

/// Refine page tables to 4 KiB for [0, 2 MiB), flip the GHCB page to shared,
/// and register it. After this `outb`/`inb`/`outl` route via the GHCB.
pub fn init(c_bit: u32) {
    let _ = rdmsr(MSR_SEV_STATUS); // #GP-triple-faults if vmm lied about SEV.
    let c = 1u64 << c_bit;

    // Build PT0/PD0, then atomically swing PDPT[0] from its 1 GiB leaf to
    // PD0. We are executing out of this range; the new leaf entries map the
    // same PA with the same C-bit, so the CR3 reload is seamless.
    let pt0 = unsafe { &mut *addr_of_mut!(PT0) };
    let pd0 = unsafe { &mut *addr_of_mut!(PD0) };
    for i in 0..512u64 {
        pt0.0[i as usize] = (i << 12) | 0x03 | c;
        pd0.0[i as usize] = (i << 21) | 0x83 | c;
    }
    pd0.0[0] = (addr_of!(PT0) as u64) | 0x03 | c;
    unsafe {
        write_volatile(addr_of_mut!(PDPT.0[0]), (addr_of!(PD0) as u64) | 0x03 | c);
    }
    flush_tlb();

    let gpa = addr_of!(GHCB) as u64;
    if gpa >= 0x20_0000 {
        die("GHCB above PT0's 2 MiB window");
    }
    make_shared(gpa, c);
    unsafe { write_bytes(addr_of_mut!(GHCB) as *mut u8, 0, 4096) };

    // SNP requires the GHCB GPA to be registered before the first
    // page-based VMGEXIT (KVM rejects otherwise).
    let r = msr_proto(GHCB_MSR_REG_GPA_REQ | gpa);
    if r != (GHCB_MSR_REG_GPA_RESP | gpa) {
        die("REG_GPA refused");
    }

    unsafe { C_MASK = c };
}

/// Convert one identity-mapped 4 KiB page from private to shared:
/// rescind validation, ask the hypervisor to RMPUPDATE it shared, then drop
/// the C-bit. Order matters: touching the page between PVALIDATE and the
/// PTE flip would `#VC` on validated=0.
fn make_shared(gpa: u64, c: u64) {
    if pvalidate(gpa, false) != 0 {
        die("PVALIDATE rescind");
    }
    let r = msr_proto(GHCB_MSR_PSC_REQ | gpa | (PSC_SHARED << 52));
    if r != GHCB_MSR_PSC_RESP {
        die("PSC shared");
    }
    unsafe {
        let e = addr_of_mut!(PT0.0[(gpa >> 12) as usize]);
        write_volatile(e, *e & !c);
    }
    flush_tlb();
}

// --- GHCB-page protocol ---------------------------------------------------

fn ghcb_set(off: usize, v: u64) {
    unsafe {
        let p = (addr_of_mut!(GHCB) as *mut u8).add(off) as *mut u64;
        write_volatile(p, v);
        // Mark field valid in the bitmap (index = byte-offset / 8).
        let bit = off / 8;
        *(addr_of_mut!(GHCB) as *mut u8).add(GHCB_BITMAP + bit / 8) |= 1 << (bit & 7);
    }
}
fn ghcb_get(off: usize) -> u64 {
    unsafe {
        let p = (addr_of!(GHCB) as *const u8).add(off) as *const u64;
        core::ptr::read_volatile(p)
    }
}

fn ghcb_call(exit_code: u64, info1: u64, info2: u64, rax: u64) -> u64 {
    // Clear bitmap + version/usage; the rest is don't-care.
    unsafe {
        write_bytes((addr_of_mut!(GHCB) as *mut u8).add(GHCB_BITMAP), 0, 16);
        write_volatile(
            (addr_of_mut!(GHCB) as *mut u8).add(GHCB_PROTO_VER) as *mut u16,
            2,
        );
        write_volatile(
            (addr_of_mut!(GHCB) as *mut u8).add(GHCB_USAGE) as *mut u32,
            0,
        );
    }
    ghcb_set(GHCB_RAX, rax);
    ghcb_set(GHCB_EXIT_CODE, exit_code);
    ghcb_set(GHCB_EXIT_INFO1, info1);
    ghcb_set(GHCB_EXIT_INFO2, info2);
    wrmsr(MSR_GHCB, addr_of!(GHCB) as u64);
    vmgexit();
    if ghcb_get(GHCB_EXIT_INFO1) & 0xffff_ffff != 0 {
        die("GHCB call rejected");
    }
    ghcb_get(GHCB_RAX)
}

// --- paravirt port I/O ----------------------------------------------------
//
// Under SEV-ES KVM forwards `SVM_EXIT_IOIO` to its regular `io_interception`
// handler, which surfaces as plain `KVM_EXIT_IO` — the vmm's existing serial
// / debug-exit emulation works unchanged.

#[inline]
fn ioio(port: u16, dbits: u64, is_in: bool, val: u64) -> u64 {
    let info1 = ((port as u64) << 16) | dbits | if is_in { IOIO_IN } else { 0 };
    ghcb_call(SVM_EXIT_IOIO, info1, 0, val)
}

#[inline]
pub fn outb(port: u16, v: u8) {
    if active() {
        ioio(port, IOIO_D8, false, v as u64);
    } else {
        unsafe { asm!("out dx, al", in("dx") port, in("al") v, options(nomem, nostack)) };
    }
}
#[inline]
pub fn inb(port: u16) -> u8 {
    if active() {
        ioio(port, IOIO_D8, true, 0) as u8
    } else {
        let v: u8;
        unsafe { asm!("in al, dx", out("al") v, in("dx") port, options(nomem, nostack)) };
        v
    }
}
#[inline]
pub fn outl(port: u16, v: u32) {
    if active() {
        ioio(port, IOIO_D32, false, v as u64);
    } else {
        unsafe { asm!("out dx, eax", in("dx") port, in("eax") v, options(nomem, nostack)) };
    }
}

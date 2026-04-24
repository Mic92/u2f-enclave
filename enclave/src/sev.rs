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

use crate::boot;

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
const GHCB_SW_SCRATCH: usize = 0x3a8;
const GHCB_BITMAP: usize = 0x3f0;
const GHCB_SHARED_BUF: usize = 0x800;
const GHCB_PROTO_VER: usize = 0xffa;
const GHCB_USAGE: usize = 0xffc;

const SVM_EXIT_IOIO: u64 = 0x7b;
const IOIO_IN: u64 = 1;
const IOIO_D8: u64 = 1 << 4;
const IOIO_D32: u64 = 1 << 6;

const SVM_VMGEXIT_MMIO_READ: u64 = 0x8000_0001;
const SVM_VMGEXIT_MMIO_WRITE: u64 = 0x8000_0002;
const SVM_VMGEXIT_GUEST_REQUEST: u64 = 0x8000_0011;

const TERM_FATAL: u8 = 0x7f;

// --- shared state ---------------------------------------------------------

#[repr(C, align(4096))]
pub struct Page(pub [u8; 4096]);
impl Page {
    pub const ZERO: Self = Self([0; 4096]);
}

/// 0 ⇒ SEV inactive. Otherwise the C-bit mask for leaf PTEs.
static mut C_MASK: u64 = 0;
static mut GHCB: Page = Page::ZERO;

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

#[cold]
fn die(_why: &str) -> ! {
    // Can be reached before the GHCB is up (init/PSC failures), so serial
    // is not safe; the MSR-protocol terminate is the one path that always
    // works. KVM surfaces it as `KVM_EXIT_SYSTEM_EVENT(SEV_TERM)` with the
    // raw GHCB MSR value, which is enough to bisect.
    wrmsr(MSR_GHCB, GHCB_MSR_TERM_REQ | ((TERM_FATAL as u64) << 16));
    loop {
        vmgexit();
    }
}

// --- bring-up -------------------------------------------------------------

/// Refine page tables to 4 KiB for [0, 2 MiB), flip the GHCB page to shared,
/// and register it.
pub fn init(c_bit: u32) {
    let _ = rdmsr(MSR_SEV_STATUS); // #GP-triple-faults if vmm lied about SEV.
    let c = 1u64 << c_bit;
    boot::refine_low_2m(c);

    let gpa = addr_of!(GHCB) as u64;
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

/// Flip an identity-mapped, page-aligned range to shared. Anything the host
/// must read or write goes through here; everything else stays private.
pub fn share(va: u64, bytes: usize) {
    let c = unsafe { C_MASK };
    debug_assert!(c != 0 && va & 0xfff == 0);
    let mut p = va;
    while p < va + bytes as u64 {
        make_shared(p, c);
        p += 4096;
    }
}

/// Convert one identity-mapped 4 KiB page from private to shared:
/// rescind validation, ask the hypervisor to RMPUPDATE it shared, then drop
/// the C-bit. Order matters: touching the page between PVALIDATE and the
/// PTE flip would `#VC` on validated=0.
fn make_shared(gpa: u64, c: u64) {
    if gpa >= 0x20_0000 {
        die("shared page above PT0's 2 MiB window");
    }
    if pvalidate(gpa, false) != 0 {
        die("PVALIDATE rescind");
    }
    let r = msr_proto(GHCB_MSR_PSC_REQ | gpa | (PSC_SHARED << 52));
    if r != GHCB_MSR_PSC_RESP {
        die("PSC shared");
    }
    unsafe {
        let e = boot::pt0_entry(gpa);
        write_volatile(e, *e & !c);
    }
    boot::flush_tlb();
}

// --- GHCB-page protocol ---------------------------------------------------

fn ghcb_ptr(off: usize) -> *mut u8 {
    unsafe { (addr_of_mut!(GHCB) as *mut u8).add(off) }
}
fn ghcb_set(off: usize, v: u64) {
    unsafe {
        write_volatile(ghcb_ptr(off) as *mut u64, v);
        // Mark field valid in the bitmap (index = byte-offset / 8).
        let bit = off / 8;
        *ghcb_ptr(GHCB_BITMAP + bit / 8) |= 1 << (bit & 7);
    }
}
fn ghcb_get(off: usize) -> u64 {
    unsafe { core::ptr::read_volatile(ghcb_ptr(off) as *const u64) }
}

fn ghcb_begin(exit_code: u64, info1: u64, info2: u64) {
    // Clear bitmap + version/usage; the rest is don't-care.
    unsafe {
        write_bytes(ghcb_ptr(GHCB_BITMAP), 0, 16);
        write_volatile(ghcb_ptr(GHCB_PROTO_VER) as *mut u16, 2);
        write_volatile(ghcb_ptr(GHCB_USAGE) as *mut u32, 0);
    }
    ghcb_set(GHCB_EXIT_CODE, exit_code);
    ghcb_set(GHCB_EXIT_INFO1, info1);
    ghcb_set(GHCB_EXIT_INFO2, info2);
}
fn ghcb_exit() {
    wrmsr(MSR_GHCB, addr_of!(GHCB) as u64);
    vmgexit();
    if ghcb_get(GHCB_EXIT_INFO1) & 0xffff_ffff != 0 {
        die("GHCB call rejected");
    }
}

// --- paravirt port I/O ----------------------------------------------------
//
// Under SEV-ES KVM forwards `SVM_EXIT_IOIO` to its regular `io_interception`
// handler, which surfaces as plain `KVM_EXIT_IO` — the vmm's existing serial
// / debug-exit emulation works unchanged.

fn ioio(port: u16, dbits: u64, is_in: bool, val: u64) -> u64 {
    let info1 = ((port as u64) << 16) | dbits | if is_in { IOIO_IN } else { 0 };
    ghcb_begin(SVM_EXIT_IOIO, info1, 0);
    ghcb_set(GHCB_RAX, val);
    ghcb_exit();
    ghcb_get(GHCB_RAX)
}

#[inline]
pub fn outb(port: u16, v: u8) {
    ioio(port, IOIO_D8, false, v as u64);
}
#[inline]
pub fn inb(port: u16) -> u8 {
    ioio(port, IOIO_D8, true, 0) as u8
}
#[inline]
pub fn outl(port: u16, v: u32) {
    ioio(port, IOIO_D32, false, v as u64);
}

// --- paravirt MMIO --------------------------------------------------------
//
// `SVM_VMGEXIT_MMIO_*` shuttle data via `sw_scratch` → GHCB `shared_buffer`;
// KVM forwards to `kvm_sev_es_mmio_*` which surfaces as plain `KVM_EXIT_MMIO`,
// so the vmm's virtio-mmio emulation is again unchanged.

fn ghcb_scratch() -> u64 {
    addr_of!(GHCB) as u64 + GHCB_SHARED_BUF as u64
}

pub fn mmio_read32(gpa: u64) -> u32 {
    ghcb_begin(SVM_VMGEXIT_MMIO_READ, gpa, 4);
    ghcb_set(GHCB_SW_SCRATCH, ghcb_scratch());
    ghcb_exit();
    unsafe { core::ptr::read_volatile(ghcb_ptr(GHCB_SHARED_BUF) as *const u32) }
}

pub fn mmio_write32(gpa: u64, v: u32) {
    ghcb_begin(SVM_VMGEXIT_MMIO_WRITE, gpa, 4);
    unsafe { write_volatile(ghcb_ptr(GHCB_SHARED_BUF) as *mut u32, v) };
    ghcb_set(GHCB_SW_SCRATCH, ghcb_scratch());
    ghcb_exit();
}

// --- guest→PSP request ----------------------------------------------------

/// `SNP_GUEST_REQUEST`: KVM copies `req_gpa` to the PSP and the PSP's reply
/// to `resp_gpa`, both via the memslot's shared half. Returns `exit_info_2`
/// (`fw_err` low 32, vmm err high 32; 0 = success).
pub fn guest_request(req_gpa: u64, resp_gpa: u64) -> u64 {
    ghcb_begin(SVM_VMGEXIT_GUEST_REQUEST, req_gpa, resp_gpa);
    ghcb_exit();
    ghcb_get(GHCB_EXIT_INFO2)
}

//! Paravirt Intel TDX guest support.
//!
//! Same idea as `sev.rs`: every privileged-instruction call site is ours,
//! so port I/O / MMIO go via explicit `TDG.VP.VMCALL` hypercalls instead of
//! taking the `#VE` trap and decoding instructions. KVM converts the
//! standard GHCI sub-functions back into ordinary `KVM_EXIT_IO`/`_MMIO`, so
//! the vmm side is shared with SEV.
//!
//! Refs: Intel GHCI spec, `arch/x86/coco/tdx/tdx.c`,
//! `intel/tdx-module/src/common/data_structures/td_vmcs_init.c`.

use core::arch::asm;
use core::ptr::write_volatile;
use core::sync::atomic::{compiler_fence, Ordering};

use crate::boot;

/// Set by `init`; both "is TDX" and the bit to OR into PTEs/GPAs to mark
/// memory shared with the host (the inverse of SEV's C-bit).
static mut SHARED_MASK: u64 = 0;

#[inline(always)]
pub fn active() -> bool {
    unsafe { SHARED_MASK != 0 }
}

// --- TDCALL leaves / GHCI sub-functions ----------------------------------

const TDG_VP_VMCALL: u64 = 0;

const EXIT_REASON_HLT: u64 = 12;
const EXIT_REASON_IO_INSTRUCTION: u64 = 30;
const EXIT_REASON_EPT_VIOLATION: u64 = 48;
const TDVMCALL_MAP_GPA: u64 = 0x10001;
const TDVMCALL_REPORT_FATAL_ERROR: u64 = 0x10003;

const TDVMCALL_STATUS_RETRY: u64 = 1;

/// Registers exposed to the VMM on TDVMCALL: r10..r15.
const VMCALL_EXPOSE: u64 = 0xfc00;

const PORT_WRITE: u64 = 1;

// --- raw TDCALL ----------------------------------------------------------

/// `TDG.VP.VMCALL`: TDCALL leaf 0. Returns (r10 status, r11 output value).
/// All listed GPRs are visible to the untrusted VMM, hence the fence.
#[inline]
fn tdvmcall(r11: u64, r12: u64, r13: u64, r14: u64, r15: u64) -> (u64, u64) {
    let (r10, r11o);
    compiler_fence(Ordering::Release);
    unsafe {
        asm!(
            ".byte 0x66, 0x0f, 0x01, 0xcc",  // TDCALL
            inout("rax") TDG_VP_VMCALL => _,
            inout("rcx") VMCALL_EXPOSE => _,
            inout("r10") 0u64 => r10,
            inout("r11") r11 => r11o,
            inout("r12") r12 => _,
            inout("r13") r13 => _,
            inout("r14") r14 => _,
            inout("r15") r15 => _,
            options(nostack)
        );
    }
    compiler_fence(Ordering::Acquire);
    (r10, r11o)
}

// --- bring-up ------------------------------------------------------------

/// We force GPAW=48 in `KVM_TDX_INIT_VM` so this is fixed; keeps PTEs and
/// the offline measurement host-independent.
pub const SHARED_BIT: u32 = 47;

pub fn init() {
    boot::refine_low_2m(0);
    unsafe { SHARED_MASK = 1u64 << SHARED_BIT };
}

/// Flip an identity-mapped, page-aligned range to shared. Private contents
/// are lost.
pub fn share(va: u64, bytes: usize) {
    let s = unsafe { SHARED_MASK };
    debug_assert!(s != 0 && va & 0xfff == 0);
    let end = va + bytes as u64;
    let mut p = va | s;
    loop {
        let (st, next) = tdvmcall(TDVMCALL_MAP_GPA, p, (end | s) - p, 0, 0);
        match st {
            0 => break,
            // r11 is the host's resume point; untrusted, so range-check.
            TDVMCALL_STATUS_RETRY if (p..end | s).contains(&next) => p = next,
            _ => die("MapGPA"),
        }
    }
    let mut p = va;
    while p < end {
        unsafe { write_volatile(boot::pt0_entry(p), p | 0x03 | s) };
        p += 4096;
    }
    boot::flush_tlb();
}

#[cold]
pub fn die(_why: &str) -> ! {
    // GHCI `ReportFatalError`: r12 = error code; KVM surfaces it as
    // `KVM_EXIT_SYSTEM_EVENT(TDX_FATAL)` with the GPR array.
    loop {
        tdvmcall(TDVMCALL_REPORT_FATAL_ERROR, 0x7f, 0, 0, 0);
    }
}

// --- paravirt port I/O ---------------------------------------------------

#[inline]
pub fn io(port: u16, size: u64, write: bool, val: u64) -> u64 {
    let (st, out) = tdvmcall(
        EXIT_REASON_IO_INSTRUCTION,
        size,
        if write { PORT_WRITE } else { 0 },
        port as u64,
        val,
    );
    if st != 0 {
        die("Instruction.IO");
    }
    out
}

/// `hlt` would `#VE`; KVM honours `Instruction.HLT` instead.
#[inline]
pub fn hlt() {
    tdvmcall(EXIT_REASON_HLT, 0, 0, 0, 0);
}

// --- paravirt MMIO -------------------------------------------------------

/// KVM's `tdx_emulate_mmio` rejects GPAs without the shared bit (private
/// MMIO is meaningless), then strips it before `KVM_EXIT_MMIO`.
#[inline]
fn mmio(write: u64, gpa: u64, v: u64) -> u64 {
    let (st, out) = tdvmcall(
        EXIT_REASON_EPT_VIOLATION,
        4,
        write,
        gpa | unsafe { SHARED_MASK },
        v,
    );
    if st != 0 {
        die("RequestMMIO");
    }
    out
}
#[inline]
pub fn mmio_read32(gpa: u64) -> u32 {
    mmio(0, gpa, 0) as u32
}
#[inline]
pub fn mmio_write32(gpa: u64, v: u32) {
    mmio(1, gpa, v as u64);
}

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
use core::sync::atomic::{compiler_fence, Ordering};

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
const _TDVMCALL_MAP_GPA: u64 = 0x10001;
const TDVMCALL_REPORT_FATAL_ERROR: u64 = 0x10003;

/// Registers exposed to the VMM on TDVMCALL: r10..r15.
const VMCALL_EXPOSE: u64 = 0xfc00;

const _PORT_READ: u64 = 0;
const PORT_WRITE: u64 = 1;
const _EPT_READ: u64 = 0;
const _EPT_WRITE: u64 = 1;

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
            in("rcx") VMCALL_EXPOSE,
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

/// We force GPAW=48 in `KVM_TDX_INIT_VM`, so the shared bit is always 47;
/// hard-coding it (and asserting `%ebx` from `TDH.VP.INIT` agrees later)
/// keeps every PTE constant for offline measurement.
pub const SHARED_BIT: u32 = 47;

pub fn init() {
    unsafe { SHARED_MASK = 1u64 << SHARED_BIT };
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

#[inline]
pub fn mmio_read32(gpa: u64) -> u32 {
    let (st, v) = tdvmcall(EXIT_REASON_EPT_VIOLATION, 4, 0, gpa, 0);
    if st != 0 {
        die("RequestMMIO read");
    }
    v as u32
}
#[inline]
pub fn mmio_write32(gpa: u64, v: u32) {
    let (st, _) = tdvmcall(EXIT_REASON_EPT_VIOLATION, 4, 1, gpa, v as u64);
    if st != 0 {
        die("RequestMMIO write");
    }
}

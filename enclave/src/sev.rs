//! AMD SEV/SEV-ES/SEV-SNP guest support — for now just the GHCB MSR
//! protocol, which is enough to prove an encrypted boot without a `#VC`
//! handler. The full GHCB page (IOIO/MMIO) comes in a later step.
//!
//! Refs: AMD GHCB spec rev 2.03, AMD APM Vol 2 §15.34/§15.36, Linux
//! `arch/x86/include/asm/sev-common.h`.

use core::arch::asm;

const MSR_SEV_STATUS: u32 = 0xc001_0131;
const MSR_GHCB: u32 = 0xc001_0130;
const GHCB_MSR_TERM_REQ: u64 = 0x100;

/// Reason code we report on a clean step-1 boot; chosen to be unambiguous in
/// `KVM_EXIT_SYSTEM_EVENT.data[0]` (anything in reason set 0 ≤ 0x07 is a
/// spec-defined failure).
pub const TERM_BOOT_OK: u8 = 0x77;

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
    let (lo, hi) = (v as u32, (v >> 32) as u32);
    unsafe {
        asm!("wrmsr", in("ecx") msr, in("eax") lo, in("edx") hi,
             options(nomem, nostack, preserves_flags))
    };
}

/// `SEV_STATUS` is a non-interceptable read-only MSR (GHCB spec §2.2), so
/// this is safe to call before any `#VC` handling exists — but only on a
/// CPU that *has* the MSR. The vmm tells us via the C-bit hint whether to
/// look; on a non-SEV host this would `#GP`.
pub fn status() -> u64 {
    rdmsr(MSR_SEV_STATUS)
}

/// GHCB MSR-protocol terminate. KVM converts this to
/// `KVM_EXIT_SYSTEM_EVENT { type: SEV_TERM, data[0]: ghcb_msr }`.
pub fn terminate(reason: u8) -> ! {
    wrmsr(MSR_GHCB, GHCB_MSR_TERM_REQ | ((reason as u64) << 16));
    // VMGEXIT = `rep; vmmcall` (F3 0F 01 D9).
    loop {
        unsafe { asm!("rep vmmcall", options(nomem, nostack)) };
    }
}

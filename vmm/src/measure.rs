//! Offline launch-measurement predictors.
//!
//! Reproduce what the SNP firmware / TDX module hash over the launched
//! pages so a relying party can derive the expected measurement from the
//! ELF alone, on any machine. SNP per firmware ABI §8.17.2;
//! VMSA template per `arch/x86/kvm/svm/sev.c::sev_es_sync_vmsa` and verified
//! byte-for-byte against `print_hex_dump_debug` output on a 6.18 kernel.
//! Every input is fixed by this binary, so the digests are too.

use sha2::{Digest, Sha384};

use crate::snp::C_BIT;

pub const VMSA_GPA: u64 = 0xFFFF_FFFF_F000;

const PAGE_TYPE_NORMAL: u8 = 1;
const PAGE_TYPE_VMSA: u8 = 2;
const PAGE_TYPE_SECRETS: u8 = 5;

/// What KVM writes for our PVH vCPU after its own transforms (forced
/// EFER/CR4 bits, vCPU-reset defaults, FPU init). Keep in lock-step with
/// `setup_pvh_cpu`.
pub fn vmsa_page(entry: u32) -> [u8; 4096] {
    let mut p = [0u8; 4096];
    // vmcb_seg = u16 selector, u16 attrib, u32 limit, u64 base.
    let seg = |p: &mut [u8; 4096], off: usize, sel: u16, attr: u16, lim: u32| {
        p[off..off + 2].copy_from_slice(&sel.to_le_bytes());
        p[off + 2..off + 4].copy_from_slice(&attr.to_le_bytes());
        p[off + 4..off + 8].copy_from_slice(&lim.to_le_bytes());
    };
    let q = |p: &mut [u8; 4096], off: usize, v: u64| {
        p[off..off + 8].copy_from_slice(&v.to_le_bytes());
    };

    // PVH flat 4 GiB code/data → svm_set_segment packs the attribute bits.
    // 0xc9b = type=0xb|S|P|DB|G; 0xc93 = type=3|S|P|DB|G.
    seg(&mut p, 0x010, 0x10, 0x0c9b, 0xffff_ffff); // cs
    for off in [0x000, 0x020, 0x030, 0x040, 0x050] {
        seg(&mut p, off, 0x18, 0x0c93, 0xffff_ffff); // es ss ds fs gs
    }
    // We GET_SREGS-round-trip these without touching them, so they keep
    // KVM's vCPU-reset defaults. svm_set_{gdt,idt} only set base+limit,
    // hence attrib=0 there.
    seg(&mut p, 0x060, 0, 0x00, 0xffff); // gdtr
    seg(&mut p, 0x070, 0, 0x82, 0xffff); // ldtr
    seg(&mut p, 0x080, 0, 0x00, 0xffff); // idtr
    seg(&mut p, 0x090, 0, 0x83, 0xffff); // tr

    q(&mut p, 0x0d0, 0x1000); // efer: we set 0; svm_set_efer ORs SVME
    q(&mut p, 0x148, 0x40); // cr4: we set 0; svm_set_cr4 ORs host MCE
    q(&mut p, 0x158, 0x01); // cr0: PE
    q(&mut p, 0x160, 0x400); // dr7: DR7_FIXED_1
    q(&mut p, 0x168, 0xffff_0ff0); // dr6: DR6_ACTIVE_LOW
    q(&mut p, 0x170, 0x2); // rflags
    q(&mut p, 0x178, entry as u64); // rip
    q(&mut p, 0x268, 0x0007_0406_0007_0406); // g_pat: MSR_IA32_CR_PAT_DEFAULT
    q(&mut p, 0x330, C_BIT as u64); // rsi: see ram32.s
    q(&mut p, 0x3b0, 0x1); // sev_features: SVM_SEV_FEAT_SNP_ACTIVE
    q(&mut p, 0x3e8, 0x1); // xcr0
    p[0x408..0x40c].copy_from_slice(&0x1f80u32.to_le_bytes()); // mxcsr
    p[0x410..0x412].copy_from_slice(&0x037fu16.to_le_bytes()); // x87_fcw
    p
}

/// SNP firmware ABI §8.17.2: each `LAUNCH_UPDATE` folds a 0x70-byte
/// `PAGE_INFO` (prev digest ‖ page contents-hash ‖ metadata) into the
/// running SHA-384.
struct Gctx([u8; 48]);

impl Gctx {
    fn new() -> Self {
        Self([0u8; 48])
    }
    fn fold(&mut self, page_type: u8, gpa: u64, contents: [u8; 48]) {
        let mut pi = [0u8; 0x70];
        pi[..48].copy_from_slice(&self.0);
        pi[48..96].copy_from_slice(&contents);
        pi[96..98].copy_from_slice(&0x70u16.to_le_bytes());
        pi[98] = page_type;
        // is_imi=0, vmpl{3,2,1}_perms=0, pad=0
        pi[104..112].copy_from_slice(&gpa.to_le_bytes());
        self.0 = Sha384::digest(pi).into();
    }
}

/// Compute the launch digest exactly as `Snp::launch()` sequences it:
/// NORMAL pages over `mem[lo..hi]`, then the SECRETS page (metadata-only),
/// then the single vCPU's VMSA.
pub fn launch_digest(
    mem: &[u8],
    lo: u64,
    hi: u64,
    secrets_gpa: u64,
    vmsa: &[u8; 4096],
) -> [u8; 48] {
    assert!(lo.is_multiple_of(4096) && hi.is_multiple_of(4096));
    let mut g = Gctx::new();
    let mut gpa = lo;
    while gpa < hi {
        let p = &mem[gpa as usize..gpa as usize + 4096];
        g.fold(PAGE_TYPE_NORMAL, gpa, Sha384::digest(p).into());
        gpa += 4096;
    }
    g.fold(PAGE_TYPE_SECRETS, secrets_gpa, [0u8; 48]);
    g.fold(PAGE_TYPE_VMSA, VMSA_GPA, Sha384::digest(vmsa).into());
    g.0
}

/// Compute MRTD as `Tdx::launch()` sequences it (low PT_LOAD pages then
/// the reset page). `TDH.MNG.INIT` only `sha384_init()`s, so attributes/
/// xfam/cpuid are not part of MRTD — they sit elsewhere in TDREPORT.
pub fn mrtd(mem: &[u8], lo: u64, hi: u64, reset: &[u8; 4096]) -> [u8; 48] {
    assert!(lo.is_multiple_of(4096) && hi.is_multiple_of(4096));
    let mut h = Sha384::new();
    let mut page = |gpa: u64, content: &[u8]| {
        let mut blk = [0u8; 128];
        blk[..12].copy_from_slice(b"MEM.PAGE.ADD");
        blk[16..24].copy_from_slice(&gpa.to_le_bytes());
        h.update(blk);
        for off in (0..4096u64).step_by(256) {
            let mut blk = [0u8; 128];
            blk[..9].copy_from_slice(b"MR.EXTEND");
            blk[16..24].copy_from_slice(&(gpa + off).to_le_bytes());
            h.update(blk);
            h.update(&content[off as usize..off as usize + 256]);
        }
    };
    let mut gpa = lo;
    while gpa < hi {
        page(gpa, &mem[gpa as usize..gpa as usize + 4096]);
        gpa += 4096;
    }
    page(crate::elf::RESET_GPA, reset);
    h.finalize().into()
}

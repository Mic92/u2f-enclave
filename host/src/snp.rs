//! SEV-SNP launch sequence on top of the bare KVM uapi.
//!
//! KVM does the heavy lifting: it builds the VMSA from whatever
//! `KVM_SET_{REGS,SREGS,CPUID2}` left in the vCPU and encrypts it during
//! `LAUNCH_FINISH` (`sev_es_sync_vmsa`/`snp_launch_update_vmsa`). So the
//! existing PVH register setup is reused unchanged; this module only adds
//! the wrapping ioctls.
//!
//! Refs: `arch/x86/include/uapi/asm/kvm.h`, `arch/x86/kvm/svm/sev.c`.

use std::io;
use std::os::fd::{AsRawFd, OwnedFd};

use crate::kvm::{self, ioctl_ref};

// `enum sev_cmd_id`
const KVM_SEV_INIT2: u32 = 22;
const KVM_SEV_SNP_LAUNCH_START: u32 = 100;
const KVM_SEV_SNP_LAUNCH_UPDATE: u32 = 101;
const KVM_SEV_SNP_LAUNCH_FINISH: u32 = 102;

const SNP_PAGE_TYPE_NORMAL: u8 = 1;
const SNP_PAGE_TYPE_SECRETS: u8 = 5;

pub use crate::measure::{C_BIT, SECRETS_GPA, SNP_POLICY};

/// Embedded build-time-signed ID block: PSP checks `ID_BLOCK.ld == launch
/// digest` and the P-384 chain in `ID_AUTH`, then stamps `author_key_digest`
/// (the SNP analogue of MRSIGNER) into every attestation report.
pub static ID_BLOCK: &[u8; 96] = include_bytes!(concat!(env!("OUT_DIR"), "/snp.idblock"));
pub static ID_AUTH: &[u8; 4096] = include_bytes!(concat!(env!("OUT_DIR"), "/snp.idauth"));
pub static AUTHOR_KEY_DIGEST: &[u8; 48] = include_bytes!(concat!(env!("OUT_DIR"), "/snp.akd"));

#[repr(C)]
#[derive(Default)]
struct SevCmd {
    id: u32,
    pad0: u32,
    data: u64,
    error: u32,
    sev_fd: u32,
}

#[repr(C)]
#[derive(Default)]
struct SevInit {
    vmsa_features: u64,
    flags: u32,
    ghcb_version: u16,
    pad1: u16,
    pad2: [u32; 8],
}

#[repr(C)]
#[derive(Default)]
struct SnpLaunchStart {
    policy: u64,
    gosvw: [u8; 16],
    flags: u16,
    pad0: [u8; 6],
    pad1: [u64; 4],
}

#[repr(C)]
#[derive(Default)]
struct SnpLaunchUpdate {
    gfn_start: u64,
    uaddr: u64,
    len: u64,
    type_: u8,
    pad0: u8,
    flags: u16,
    pad1: u32,
    pad2: [u64; 4],
}

#[repr(C)]
#[derive(Default)]
struct SnpLaunchFinish {
    id_block_uaddr: u64,
    id_auth_uaddr: u64,
    id_block_en: u8,
    auth_key_en: u8,
    vcek_disabled: u8,
    host_data: [u8; 32],
    pad0: [u8; 3],
    flags: u16,
    pad1: [u64; 4],
}

pub struct Snp {
    /// KVM stores this fd *number* at LAUNCH_START and reuses it for every
    /// later PSP command (incl. runtime GUEST_REQUEST), so it must outlive
    /// the launch.
    sev: OwnedFd,
    /// Kernel takes its own ref at SET_USER_MEMORY_REGION2, but keeping it
    /// open is the conservative choice and matches QEMU.
    _gmem: OwnedFd,
}

impl Snp {
    /// `KVM_SEV_INIT2` + `guest_memfd` + memslot. Must run before any vCPU
    /// is created.
    pub fn init(vm: &OwnedFd, mem: *mut u8, mem_size: u64) -> io::Result<Self> {
        let sev = crate::open_dev("/dev/sev")?.into();

        let host_c_bit = std::arch::x86_64::__cpuid(0x8000_001f).ebx & 0x3f;
        if host_c_bit != C_BIT {
            return Err(io::Error::other(format!(
                "host SEV C-bit position is {host_c_bit}, but this build assumes {C_BIT}"
            )));
        }

        sev_op(vm, &sev, KVM_SEV_INIT2, &mut SevInit::default())?;

        let gmem = kvm::guest_memfd(vm, mem_size)?;
        kvm::private_slot(vm, 0, 0, mem as u64, mem_size, &gmem, 0)?;

        Ok(Self { sev, _gmem: gmem })
    }

    /// `LAUNCH_START` → encrypt+measure `[gpa, gpa+len)` from `uaddr` →
    /// `LAUNCH_FINISH`. Call after `KVM_SET_{REGS,SREGS,CPUID2}` so the
    /// VMSA picks them up.
    pub fn launch(&self, vm: &OwnedFd, uaddr: *const u8, gpa: u64, len: u64) -> io::Result<()> {
        debug_assert!(gpa & 0xfff == 0 && len & 0xfff == 0 && (uaddr as u64) & 0xfff == 0);

        sev_op(
            vm,
            &self.sev,
            KVM_SEV_SNP_LAUNCH_START,
            &mut SnpLaunchStart {
                policy: SNP_POLICY,
                ..Default::default()
            },
        )?;

        self.update(vm, uaddr, gpa, len, SNP_PAGE_TYPE_NORMAL)?;
        // PSP overwrites this page with VMPCKs; the source bytes are
        // irrelevant but a uaddr is still required.
        self.update(vm, uaddr, SECRETS_GPA, 0x1000, SNP_PAGE_TYPE_SECRETS)?;

        sev_op(
            vm,
            &self.sev,
            KVM_SEV_SNP_LAUNCH_FINISH,
            &mut SnpLaunchFinish {
                id_block_uaddr: ID_BLOCK.as_ptr() as u64,
                id_auth_uaddr: ID_AUTH.as_ptr() as u64,
                id_block_en: 1,
                auth_key_en: 1,
                ..Default::default()
            },
        )?;
        Ok(())
    }

    fn update(&self, vm: &OwnedFd, uaddr: *const u8, gpa: u64, len: u64, ty: u8) -> io::Result<()> {
        // KVM may process fewer pages than requested and hand back updated
        // gfn_start/len/uaddr; loop until done.
        let mut up = SnpLaunchUpdate {
            gfn_start: gpa >> 12,
            uaddr: uaddr as u64,
            len,
            type_: ty,
            ..Default::default()
        };
        while up.len > 0 {
            sev_op(vm, &self.sev, KVM_SEV_SNP_LAUNCH_UPDATE, &mut up)?;
        }
        Ok(())
    }
}

fn sev_op<T>(vm: &OwnedFd, sev: &OwnedFd, id: u32, data: &mut T) -> io::Result<()> {
    let mut cmd = SevCmd {
        id,
        data: data as *mut T as u64,
        sev_fd: sev.as_raw_fd() as u32,
        ..Default::default()
    };
    ioctl_ref(vm, kvm::KVM_MEMORY_ENCRYPT_OP, &mut cmd).map_err(|e| {
        io::Error::other(format!(
            "KVM_MEMORY_ENCRYPT_OP id={id}: {e} (psp_error={:#x})",
            cmd.error
        ))
    })
}

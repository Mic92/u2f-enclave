//! Intel TDX launch sequence on top of the bare KVM uapi.
//!
//! Unlike SEV-SNP, the TDX module fixes the initial vCPU state (flat 32-bit
//! protected mode at `0xFFFFFFF0`, EFER.LME=1), so we cannot reuse the PVH
//! `KVM_SET_{REGS,SREGS}` and instead place a one-instruction reset stub at
//! GPA `0xFFFFF000` that jumps into the same low-memory `ram32` code. The
//! stub gets its own memslot/guest_memfd page; SEV/plain boots ignore it.
//!
//! KVM normalises GHCI TDVMCALLs back to ordinary `KVM_EXIT_IO`/`_MMIO`/
//! `_HYPERCALL(MAP_GPA_RANGE)`, so the run loop is shared with SEV.
//!
//! Refs: `arch/x86/include/uapi/asm/kvm.h`, `arch/x86/kvm/vmx/tdx.c`.

use std::io;
use std::os::fd::{AsRawFd, OwnedFd};

use crate::elf::RESET_GPA;
use crate::kvm::{self, ioctl_fd, ioctl_ref, Cpuid2, NCPUID};

const KVM_TDX_CAPABILITIES: u32 = 0;
const KVM_TDX_INIT_VM: u32 = 1;
const KVM_TDX_INIT_VCPU: u32 = 2;
const KVM_TDX_INIT_MEM_REGION: u32 = 3;
const KVM_TDX_FINALIZE_VM: u32 = 4;

const KVM_TDX_MEASURE_MEMORY_REGION: u32 = 1;

const TDX_ATTR_SEPT_VE_DISABLE: u64 = 1 << 28;

#[repr(C)]
#[derive(Default)]
struct TdxCmd {
    id: u32,
    flags: u32,
    data: u64,
    hw_error: u64,
}

#[repr(C)]
struct TdxCaps {
    supported_attrs: u64,
    supported_xfam: u64,
    _tdvmcallinfo: [u64; 4],
    _reserved: [u64; 250],
    cpuid: Cpuid2<NCPUID>,
}
const _: () = assert!(std::mem::offset_of!(TdxCaps, cpuid) == 2048);

#[repr(C)]
struct TdxInitVm {
    attributes: u64,
    xfam: u64,
    mrconfigid: [u64; 6],
    mrowner: [u64; 6],
    mrownerconfig: [u64; 6],
    reserved: [u64; 12],
    cpuid: Cpuid2<NCPUID>,
}
const _: () = assert!(std::mem::offset_of!(TdxInitVm, cpuid) == 256);

#[repr(C)]
struct TdxInitMem {
    source_addr: u64,
    gpa: u64,
    nr_pages: u64,
}

pub struct Tdx {
    _gmem: OwnedFd,
    /// Page-aligned scratch for `INIT_MEM_REGION`'s `source_addr`; doubles
    /// as the reset slot's userspace alias (never read once private).
    reset_va: *mut u8,
}

impl Tdx {
    /// Everything that must precede vCPU creation: split irqchip,
    /// `KVM_TDX_INIT_VM`, guest_memfd memslots (low + reset page), private
    /// attribute, MapGPA hypercall exit.
    pub fn init(vm: &OwnedFd, mem: *mut u8, mem_size: u64) -> io::Result<Self> {
        // `tdx_vcpu_create` insists on this; we never deliver interrupts
        // but the in-kernel LAPIC must exist.
        ioctl_ref(
            vm,
            kvm::KVM_ENABLE_CAP,
            &mut kvm::EnableCap {
                cap: kvm::KVM_CAP_SPLIT_IRQCHIP,
                ..Default::default()
            },
        )?;
        // Same MapGPA → KVM_EXIT_HYPERCALL path as SEV-SNP's PSC.
        ioctl_ref(
            vm,
            kvm::KVM_ENABLE_CAP,
            &mut kvm::EnableCap {
                cap: kvm::KVM_CAP_EXIT_HYPERCALL,
                args: [1 << kvm::KVM_HC_MAP_GPA_RANGE, 0, 0, 0],
                ..Default::default()
            },
        )?;

        // KVM rejects INIT_VM if any cpuid entry isn't one the TDX module
        // can configure (`setup_tdparams_cpuids` insists copy_cnt==nent),
        // and the module rejects feature bits inconsistent with `xfam` etc.
        // The guest never executes `cpuid` (would #VE), so request nothing:
        // pass exactly the module's configurable leaf set with all-zero
        // values (module applies its fixed1 bits). The one exception is
        // KVM's out-of-band GPAW selector in 0x80000008 EAX[23:16], which
        // KVM consumes for the EPT level and then clears before the module
        // sees it. GPAW=48 → shared bit 47 → matches the guest's 4-level
        // page table and `enclave/src/tdx.rs::SHARED_BIT`.
        let mut caps: Box<TdxCaps> = Box::new(unsafe { std::mem::zeroed() });
        caps.cpuid.nent = NCPUID as u32;
        tdx_op(vm, KVM_TDX_CAPABILITIES, 0, &mut *caps as *mut _ as u64)?;

        for e in caps.cpuid.entries.iter_mut().take(caps.cpuid.nent as usize) {
            e.eax = if e.function == 0x8000_0008 {
                48 << 16
            } else {
                0
            };
            e.ebx = 0;
            e.ecx = 0;
            e.edx = 0;
        }

        let init = Box::new(TdxInitVm {
            // SEPT #VE on unaccepted private memory would triple-fault our
            // IDT-less guest; disabling it means a VMM bug surfaces as an
            // EPT violation in KVM instead. Masked: not all module versions
            // expose it (newer ones make it always-on).
            attributes: TDX_ATTR_SEPT_VE_DISABLE & caps.supported_attrs,
            xfam: 0, // kernel ORs in xfam_fixed1 (x87|SSE)
            mrconfigid: [0; 6],
            mrowner: [0; 6],
            mrownerconfig: [0; 6],
            reserved: [0; 12],
            cpuid: Cpuid2 {
                nent: caps.cpuid.nent,
                padding: 0,
                entries: caps.cpuid.entries,
            },
        });
        tdx_op(vm, KVM_TDX_INIT_VM, 0, &*init as *const _ as u64)?;

        // One guest_memfd backs both regions: low RAM at offset 0, the
        // reset page tacked on at the end.
        let gmem_size = mem_size + 0x1000;
        let mut gm = kvm::CreateGuestMemfd {
            size: gmem_size,
            ..Default::default()
        };
        let gmem = ioctl_fd(vm, kvm::KVM_CREATE_GUEST_MEMFD, &mut gm as *mut _ as _)?;

        let reset_mem = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                0x1000,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if reset_mem == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }

        for (slot, gpa, ua, sz, off) in [
            (0, 0, mem as u64, mem_size, 0),
            (1, RESET_GPA, reset_mem as u64, 0x1000, mem_size),
        ] {
            ioctl_ref(
                vm,
                kvm::KVM_SET_USER_MEMORY_REGION2,
                &mut kvm::UserMemRegion2 {
                    slot,
                    flags: kvm::KVM_MEM_GUEST_MEMFD,
                    guest_phys_addr: gpa,
                    memory_size: sz,
                    userspace_addr: ua,
                    guest_memfd_offset: off,
                    guest_memfd: gmem.as_raw_fd() as u32,
                    ..Default::default()
                },
            )?;
            ioctl_ref(
                vm,
                kvm::KVM_SET_MEMORY_ATTRIBUTES,
                &mut kvm::MemAttrs {
                    address: gpa,
                    size: sz,
                    attributes: kvm::KVM_MEMORY_ATTRIBUTE_PRIVATE,
                    flags: 0,
                },
            )?;
        }

        Ok(Self {
            _gmem: gmem,
            reset_va: reset_mem as *mut u8,
        })
    }

    /// `INIT_VCPU` (initial RCX → guest), encrypt+measure both regions,
    /// `FINALIZE_VM`. Call after `KVM_CREATE_VCPU`.
    pub fn launch(
        &self,
        vm: &OwnedFd,
        vcpu: &OwnedFd,
        low_uaddr: *const u8,
        low_gpa: u64,
        low_len: u64,
        reset_page: &[u8; 4096],
    ) -> io::Result<()> {
        // `data` becomes the guest's initial RCX; we don't need a TD-HOB.
        tdx_op(vcpu, KVM_TDX_INIT_VCPU, 0, 0)?;

        // INIT_MEM_REGION's `source_addr` must be page-aligned; reuse the
        // reset slot's mmap as scratch.
        unsafe {
            self.reset_va
                .copy_from_nonoverlapping(reset_page.as_ptr(), 4096)
        };
        for (src, gpa, len) in [
            (low_uaddr as u64, low_gpa, low_len),
            (self.reset_va as u64, RESET_GPA, 0x1000),
        ] {
            tdx_op(
                vcpu,
                KVM_TDX_INIT_MEM_REGION,
                KVM_TDX_MEASURE_MEMORY_REGION,
                &TdxInitMem {
                    source_addr: src,
                    gpa,
                    nr_pages: len >> 12,
                } as *const _ as u64,
            )?;
        }

        tdx_op(vm, KVM_TDX_FINALIZE_VM, 0, 0)?;
        Ok(())
    }
}

fn tdx_op(fd: &impl AsRawFd, id: u32, flags: u32, data: u64) -> io::Result<()> {
    let mut cmd = TdxCmd {
        id,
        flags,
        data,
        hw_error: 0,
    };
    ioctl_ref(fd, kvm::KVM_MEMORY_ENCRYPT_OP, &mut cmd).map_err(|e| {
        io::Error::other(format!(
            "KVM_TDX cmd={id}: {e} (hw_error={:#x})",
            cmd.hw_error
        ))
    })
}

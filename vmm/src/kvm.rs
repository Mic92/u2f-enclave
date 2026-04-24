//! Just enough of the KVM uapi to launch one vCPU in 32-bit protected mode.
//! Layouts mirror `include/uapi/linux/kvm.h` and `arch/x86/include/uapi/asm/kvm.h`.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

const KVMIO: u32 = 0xAE;
pub const fn ioc_raw(dir: u32, ty: u32, nr: u32, size: u32) -> libc::c_ulong {
    ((dir << 30) | (size << 16) | (ty << 8) | nr) as libc::c_ulong
}
const fn ioc(dir: u32, nr: u32, size: u32) -> libc::c_ulong {
    ioc_raw(dir, KVMIO, nr, size)
}
const fn io(nr: u32) -> libc::c_ulong {
    ioc(0, nr, 0)
}
const fn iow<T>(nr: u32) -> libc::c_ulong {
    ioc(1, nr, std::mem::size_of::<T>() as u32)
}
const fn ior<T>(nr: u32) -> libc::c_ulong {
    ioc(2, nr, std::mem::size_of::<T>() as u32)
}
const fn iowr<T>(nr: u32) -> libc::c_ulong {
    ioc(3, nr, std::mem::size_of::<T>() as u32)
}

pub const KVM_GET_API_VERSION: libc::c_ulong = io(0x00);
pub const KVM_CREATE_VM: libc::c_ulong = io(0x01);
pub const KVM_GET_VCPU_MMAP_SIZE: libc::c_ulong = io(0x04);
pub const KVM_GET_SUPPORTED_CPUID: libc::c_ulong = iowr::<Cpuid2Hdr>(0x05);
pub const KVM_CREATE_VCPU: libc::c_ulong = io(0x41);
pub const KVM_SET_USER_MEMORY_REGION: libc::c_ulong = iow::<UserMemRegion>(0x46);
pub const KVM_SET_USER_MEMORY_REGION2: libc::c_ulong = iow::<UserMemRegion2>(0x49);
pub const KVM_RUN: libc::c_ulong = io(0x80);
pub const KVM_SET_REGS: libc::c_ulong = iow::<Regs>(0x82);
pub const KVM_GET_SREGS: libc::c_ulong = ior::<Sregs>(0x83);
pub const KVM_SET_SREGS: libc::c_ulong = iow::<Sregs>(0x84);
pub const KVM_SET_CPUID2: libc::c_ulong = iow::<Cpuid2Hdr>(0x90);
pub const KVM_MEMORY_ENCRYPT_OP: libc::c_ulong = iowr::<u64>(0xba);
pub const KVM_SET_MEMORY_ATTRIBUTES: libc::c_ulong = iow::<MemAttrs>(0xd2);
pub const KVM_CREATE_GUEST_MEMFD: libc::c_ulong = iowr::<CreateGuestMemfd>(0xd4);

pub const KVM_X86_SNP_VM: libc::c_ulong = 4;
pub const KVM_MEM_GUEST_MEMFD: u32 = 1 << 2;
pub const KVM_MEMORY_ATTRIBUTE_PRIVATE: u64 = 1 << 3;

pub const EXIT_IO: u32 = 2;
pub const EXIT_HLT: u32 = 5;
pub const EXIT_MMIO: u32 = 6;
pub const EXIT_SHUTDOWN: u32 = 8;
pub const EXIT_SYSTEM_EVENT: u32 = 24;

pub const SYSTEM_EVENT_SEV_TERM: u32 = 6;

pub const IO_IN: u8 = 0;
pub const IO_OUT: u8 = 1;

#[repr(C)]
pub struct UserMemRegion {
    pub slot: u32,
    pub flags: u32,
    pub guest_phys_addr: u64,
    pub memory_size: u64,
    pub userspace_addr: u64,
}

#[repr(C)]
#[derive(Default)]
pub struct UserMemRegion2 {
    pub slot: u32,
    pub flags: u32,
    pub guest_phys_addr: u64,
    pub memory_size: u64,
    pub userspace_addr: u64,
    pub guest_memfd_offset: u64,
    pub guest_memfd: u32,
    pub pad1: u32,
    pub pad2: [u64; 14],
}

#[repr(C)]
#[derive(Default)]
pub struct MemAttrs {
    pub address: u64,
    pub size: u64,
    pub attributes: u64,
    pub flags: u64,
}

#[repr(C)]
#[derive(Default)]
pub struct CreateGuestMemfd {
    pub size: u64,
    pub flags: u64,
    pub reserved: [u64; 6],
}

#[repr(C)]
#[derive(Default)]
pub struct Regs {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rsp: u64,
    pub rbp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub rflags: u64,
}
const _: () = assert!(std::mem::size_of::<Regs>() == 144);

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Segment {
    pub base: u64,
    pub limit: u32,
    pub selector: u16,
    pub type_: u8,
    pub present: u8,
    pub dpl: u8,
    pub db: u8,
    pub s: u8,
    pub l: u8,
    pub g: u8,
    pub avl: u8,
    pub unusable: u8,
    pub padding: u8,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Dtable {
    pub base: u64,
    pub limit: u16,
    pub padding: [u16; 3],
}

#[repr(C)]
pub struct Sregs {
    pub cs: Segment,
    pub ds: Segment,
    pub es: Segment,
    pub fs: Segment,
    pub gs: Segment,
    pub ss: Segment,
    pub tr: Segment,
    pub ldt: Segment,
    pub gdt: Dtable,
    pub idt: Dtable,
    pub cr0: u64,
    pub cr2: u64,
    pub cr3: u64,
    pub cr4: u64,
    pub cr8: u64,
    pub efer: u64,
    pub apic_base: u64,
    pub interrupt_bitmap: [u64; 4],
}
const _: () = assert!(std::mem::size_of::<Sregs>() == 312);

/// Prefix of `struct kvm_run`; enough to read `exit_reason` and the io/mmio
/// union arms.
#[repr(C)]
pub struct RunHdr {
    pub request_interrupt_window: u8,
    pub immediate_exit: u8,
    pub _pad1: [u8; 6],
    pub exit_reason: u32,
    pub ready_for_interrupt_injection: u8,
    pub if_flag: u8,
    pub flags: u16,
    pub cr8: u64,
    pub apic_base: u64,
    pub u: RunUnion,
}
#[repr(C)]
pub union RunUnion {
    pub io: RunIo,
    pub mmio: RunMmio,
    pub system_event: RunSysEvent,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RunSysEvent {
    pub type_: u32,
    pub ndata: u32,
    pub data: [u64; 16],
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RunIo {
    pub direction: u8,
    pub size: u8,
    pub port: u16,
    pub count: u32,
    pub data_offset: u64,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RunMmio {
    pub phys_addr: u64,
    pub data: [u8; 8],
    pub len: u32,
    pub is_write: u8,
}

#[repr(C)]
pub struct Cpuid2Hdr {
    pub nent: u32,
    pub padding: u32,
}

/// Pass everything KVM can virtualise straight through; the guest needs at
/// least LM, PAE, Page1GB and RDRAND or `ram32.s`/`platform.rs` will fault.
pub fn passthrough_cpuid(kvm: &impl AsRawFd, vcpu: &impl AsRawFd) -> io::Result<()> {
    const N: usize = 256;
    let mut buf = vec![0u8; 8 + N * 40];
    unsafe {
        (buf.as_mut_ptr() as *mut Cpuid2Hdr).write(Cpuid2Hdr {
            nent: N as u32,
            padding: 0,
        })
    };
    ioctl(
        kvm,
        KVM_GET_SUPPORTED_CPUID,
        buf.as_mut_ptr() as libc::c_ulong,
    )?;
    ioctl(vcpu, KVM_SET_CPUID2, buf.as_ptr() as libc::c_ulong)?;
    Ok(())
}

pub fn ioctl(fd: &impl AsRawFd, req: libc::c_ulong, arg: libc::c_ulong) -> io::Result<i32> {
    let r = unsafe { libc::ioctl(fd.as_raw_fd(), req, arg) };
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(r)
    }
}

pub fn ioctl_fd(fd: &impl AsRawFd, req: libc::c_ulong, arg: libc::c_ulong) -> io::Result<OwnedFd> {
    let r = ioctl(fd, req, arg)?;
    Ok(unsafe { OwnedFd::from_raw_fd(r as RawFd) })
}

pub fn ioctl_ref<T>(fd: &impl AsRawFd, req: libc::c_ulong, arg: &mut T) -> io::Result<()> {
    ioctl(fd, req, arg as *mut T as libc::c_ulong).map(|_| ())
}

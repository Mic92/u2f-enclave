//! Hand-rolled SGX loader: lay the embedded `sgx` ELF into EPC via
//! `/dev/sgx_enclave`, EINIT with the build-time SIGSTRUCT, and call into it
//! through the kernel vDSO.  No Intel SDK, no SGXS files — the ELF's three
//! PT_LOADs map 1:1 to TCS / RX-REG / RW-REG segments so the loader stays a
//! straight walk over program headers.
//!
//! Refs: SDM Vol 3D ch 38–40; `arch/x86/include/{uapi/,}asm/sgx.h`; the
//! kernel selftest in `tools/testing/selftests/sgx/`.

use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;

use crate::kvm::ioc_raw;
use crate::open_dev;
use crate::sgx_layout::*;

const SGX_MAGIC: u32 = 0xA4;
const SGX_PAGE_MEASURE: u64 = 1;

const ENCLU_EENTER: u32 = 2;
const ENCLU_EEXIT: u32 = 4;

/// Signed at build time from `$U2FE_SGX_KEY`; the private key never reaches
/// this binary, so the (untrusted) host cannot mint another SIGSTRUCT under
/// the same MRSIGNER.
pub static SIGSTRUCT: &[u8; 1808] = include_bytes!(concat!(env!("OUT_DIR"), "/sgx.sigstruct"));

pub fn mrenclave() -> &'static [u8] {
    &SIGSTRUCT[960..992]
}
pub fn mrsigner() -> [u8; 32] {
    use sha2::Digest;
    sha2::Sha256::digest(&SIGSTRUCT[128..512]).into()
}

#[repr(C)]
struct AddPages {
    src: u64,
    offset: u64,
    length: u64,
    secinfo: u64,
    flags: u64,
    count: u64,
}

#[repr(C, align(64))]
struct Secinfo {
    flags: u64,
    _rsvd: [u8; 56],
}

#[repr(C)]
#[derive(Default)]
struct EnclaveRun {
    tcs: u64,
    function: u32,
    exc_vector: u16,
    exc_errcode: u16,
    exc_addr: u64,
    user_handler: u64,
    user_data: u64,
    _rsvd: [u64; 27],
}
const _: () = assert!(std::mem::size_of::<EnclaveRun>() == 256);

const SGX_IOC_CREATE: libc::c_ulong = ioc_raw(1, SGX_MAGIC, 0x00, 8);
const SGX_IOC_ADD_PAGES: libc::c_ulong =
    ioc_raw(3, SGX_MAGIC, 0x01, std::mem::size_of::<AddPages>() as u32);
const SGX_IOC_INIT: libc::c_ulong = ioc_raw(1, SGX_MAGIC, 0x02, 8);

pub struct Enclave {
    _fd: std::fs::File,
    base: u64,
    size: u64,
    vdso: usize,
}

pub fn load(elf: &[u8]) -> io::Result<Enclave> {
    let fd = open_dev("/dev/sgx_enclave")?;
    let (segs, img) = layout(elf);
    let bytes = img.as_ptr() as *const u8;
    let size = secs_size(&segs);

    // SECS.base must be naturally aligned to SECS.size, which the C heap
    // won't give us.  Reserve double, pick the aligned window inside, and
    // hand back the trimmings.
    let area = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            (size * 2) as _,
            libc::PROT_NONE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if area == libc::MAP_FAILED {
        return Err(io::Error::last_os_error());
    }
    let area = area as u64;
    let base = (area + size - 1) & !(size - 1);
    if base > area {
        unsafe {
            libc::munmap(area as _, (base - area) as _);
            libc::munmap((base + size) as _, (area + size - base) as _);
        }
    } else {
        unsafe { libc::munmap((base + size) as _, size as _) };
    }

    // ECREATE
    let mut secs = Box::new(AlignedPage([0; 4096]));
    secs.0[0..8].copy_from_slice(&size.to_le_bytes());
    secs.0[8..16].copy_from_slice(&base.to_le_bytes());
    secs.0[16..20].copy_from_slice(&1u32.to_le_bytes()); // ssa_frame_size (in pages)
    secs.0[48..56].copy_from_slice(&ATTR_MODE64BIT.to_le_bytes());
    secs.0[56..64].copy_from_slice(&XFRM_LEGACY.to_le_bytes());
    let mut p = secs.0.as_ptr() as u64;
    ioctl(&fd, SGX_IOC_CREATE, &mut p, "SGX_IOC_ENCLAVE_CREATE")?;

    // EADD + EEXTEND
    for s in &segs {
        let secinfo = Secinfo {
            flags: s.flags,
            _rsvd: [0; 56],
        };
        let mut ap = AddPages {
            src: unsafe { bytes.add(s.off as usize) } as u64,
            offset: s.off,
            length: s.len,
            secinfo: &secinfo as *const _ as u64,
            flags: SGX_PAGE_MEASURE,
            count: 0,
        };
        // Kernel may stop short on a pending signal; resume from where it left off.
        while ap.length > 0 {
            ioctl(&fd, SGX_IOC_ADD_PAGES, &mut ap, "SGX_IOC_ENCLAVE_ADD_PAGES")?;
            ap.src += ap.count;
            ap.offset += ap.count;
            ap.length -= ap.count;
            ap.count = 0;
        }
    }

    // EINIT — the kernel programs IA32_SGXLEPUBKEYHASH from our modulus
    // (FLC), so any signing key works without a launch token.
    let mut p = SIGSTRUCT.as_ptr() as u64;
    ioctl(&fd, SGX_IOC_INIT, &mut p, "SGX_IOC_ENCLAVE_INIT")?;

    // Map each segment over the reservation so EENTER can actually reach it.
    // EPC permissions cap the VMA's; the driver rejects a wider mmap.
    for s in &segs {
        let prot = if s.flags == SECINFO_TCS {
            libc::PROT_READ | libc::PROT_WRITE
        } else {
            (s.flags & 7) as libc::c_int
        };
        let r = unsafe {
            libc::mmap(
                (base + s.off) as _,
                s.len as _,
                prot,
                libc::MAP_SHARED | libc::MAP_FIXED,
                fd.as_raw_fd(),
                0,
            )
        };
        if r == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
    }

    Ok(Enclave {
        _fd: fd,
        base,
        size,
        vdso: vdso_lookup()?,
    })
}

impl Enclave {
    /// One EENTER→EEXIT round-trip via the vDSO trampoline.  `rdi` carries
    /// the host argument (a pointer into untrusted memory).
    pub fn enter(&self, rdi: u64) -> io::Result<()> {
        let mut run = EnclaveRun {
            tcs: self.base, // TCS is segment 0, offset 0
            ..Default::default()
        };
        let ret: i64;
        // The vDSO is not SysV-compliant: it forwards GPRs verbatim and the
        // enclave may clobber anything, so call it from asm rather than
        // through a Rust fn pointer.  vsgx.S itself saves/restores rbp+rbx;
        // r12–r15 it does not, so declare them clobbered even though our own
        // entry stub happens to preserve them.  No alignment fix-up needed:
        // the no-handler path touches no XMM and re-aligns before any
        // user_handler call.
        unsafe {
            std::arch::asm!(
                "push rbp",
                "push {run}",        // becomes [rbp+16] inside the vDSO frame
                "call {entry}",
                "add rsp, 8",
                "pop rbp",
                run   = in(reg) &mut run as *mut EnclaveRun,
                entry = in(reg) self.vdso,
                inout("rdi") rdi => _,
                in("rsi") 0u64,
                in("rdx") 0u64,
                in("ecx") ENCLU_EENTER,
                in("r8")  0u64,
                in("r9")  0u64,
                lateout("rax") ret,
                lateout("r12") _, lateout("r13") _,
                lateout("r14") _, lateout("r15") _,
                clobber_abi("sysv64"),
            );
        }
        if ret != 0 || run.function != ENCLU_EEXIT {
            return Err(io::Error::other(format!(
                "EENTER ret={} fn={} vec={} err={:#x} addr={:#x}",
                ret, run.function, run.exc_vector, run.exc_errcode, run.exc_addr,
            )));
        }
        Ok(())
    }
}

impl Drop for Enclave {
    fn drop(&mut self) {
        unsafe { libc::munmap(self.base as _, self.size as _) };
    }
}

fn ioctl<T>(fd: &impl AsRawFd, req: libc::c_ulong, arg: &mut T, what: &str) -> io::Result<()> {
    let r = unsafe { libc::ioctl(fd.as_raw_fd(), req, arg as *mut T) };
    if r != 0 {
        let e = io::Error::last_os_error();
        return Err(io::Error::new(e.kind(), format!("{what}: {e}")));
    }
    Ok(())
}

// --- vDSO lookup ---------------------------------------------------------

const DT_HASH: u64 = 4;
const DT_STRTAB: u64 = 5;
const DT_SYMTAB: u64 = 6;

/// Resolve `__vdso_sgx_enter_enclave`.  The vDSO has no .gnu.hash, so use
/// the SysV hash table the kernel still emits.
fn vdso_lookup() -> io::Result<usize> {
    let base = unsafe { libc::getauxval(libc::AT_SYSINFO_EHDR) } as usize;
    if base == 0 {
        return Err(io::Error::other("no vDSO (AT_SYSINFO_EHDR)"));
    }
    let rd = |off: usize, len: usize| unsafe {
        std::slice::from_raw_parts((base + off) as *const u8, len)
    };
    let u16 = |o| u16::from_le_bytes(rd(o, 2).try_into().unwrap()) as usize;
    let u32 = |o| u32::from_le_bytes(rd(o, 4).try_into().unwrap()) as usize;
    let u64 = |o| u64::from_le_bytes(rd(o, 8).try_into().unwrap()) as usize;

    let phoff = u64(32);
    let (phentsz, phnum) = (u16(54), u16(56));
    let mut dyntab = 0;
    for i in 0..phnum {
        let ph = phoff + i * phentsz;
        if u32(ph) == 2 {
            // PT_DYNAMIC
            dyntab = u64(ph + 8);
        }
    }
    let (mut sym, mut strt, mut hash) = (0, 0, 0);
    let mut i = dyntab;
    loop {
        let tag = u64(i);
        let val = u64(i + 8);
        match tag as u64 {
            0 => break,
            DT_SYMTAB => sym = val,
            DT_STRTAB => strt = val,
            DT_HASH => hash = val,
            _ => {}
        }
        i += 16;
    }
    let nchain = u32(hash + 4); // = number of symbols
    for k in 0..nchain {
        let s = sym + k * 24;
        let name = u32(s);
        let cstr = unsafe { std::ffi::CStr::from_ptr((base + strt + name) as *const _) };
        if cstr.to_bytes() == b"__vdso_sgx_enter_enclave" {
            return Ok(base + u64(s + 8));
        }
    }
    Err(io::Error::other(
        "__vdso_sgx_enter_enclave not in vDSO (kernel built without CONFIG_X86_SGX?)",
    ))
}

// --- transport -----------------------------------------------------------

/// Mailbox in untrusted memory; mirrors `Slot` in `sgx/src/main.rs`.
#[repr(C)]
struct Slot {
    op: u32,
    _pad: u32,
    buf: [u8; 64],
}
const OP_INPUT: u32 = 1;
const OP_DRAIN: u32 = 2;

pub fn run(elf: &[u8]) -> io::Result<()> {
    let e = load(elf)?;
    eprintln!("u2f-enclave: SGX EINIT ok ({} KiB EPC)", e.size >> 10);

    // Reuse the existing uhid pump unchanged: hand it one half of a
    // socketpair, drive the enclave on the other.  Same wire format as the
    // KVM/vsock and sim paths (raw 64-byte CTAPHID reports).
    let (mut near, far) = UnixStream::pair()?;
    let far_r = far.try_clone()?;
    std::thread::spawn(move || {
        if let Err(e) = bridge::serve(far_r, far) {
            eprintln!("bridge: {e}");
            std::process::exit(1);
        }
    });

    let mut slot = Box::new(Slot {
        op: 0,
        _pad: 0,
        buf: [0; 64],
    });
    let p = &mut *slot as *mut Slot as u64;
    loop {
        near.read_exact(&mut slot.buf)?;
        slot.op = OP_INPUT;
        e.enter(p)?;
        while slot.op == 1 {
            near.write_all(&slot.buf)?;
            slot.op = OP_DRAIN;
            e.enter(p)?;
        }
    }
}

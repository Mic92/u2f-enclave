//! Hand-rolled SGX loader: lay the embedded `sgx` ELF into EPC via
//! `/dev/sgx_enclave`, sign a SIGSTRUCT for it on the fly, and call into it
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

const PAGE: u64 = 4096;
const SGX_MAGIC: u32 = 0xA4;
const SGX_PAGE_MEASURE: u64 = 1;

const SECINFO_R: u64 = 1;
const SECINFO_W: u64 = 2;
const SECINFO_X: u64 = 4;
const SECINFO_TCS: u64 = 1 << 8;
const SECINFO_REG: u64 = 2 << 8;

const ATTR_MODE64BIT: u64 = 1 << 2;
const XFRM_LEGACY: u64 = 0x3; // x87 + SSE; mandatory floor

const ENCLU_EENTER: u32 = 2;
const ENCLU_EEXIT: u32 = 4;

const SIGSTRUCT_LEN: usize = 1808;
const MOD: usize = 384; // 3072-bit

#[repr(C)]
struct AddPages {
    src: u64,
    offset: u64,
    length: u64,
    secinfo: u64,
    flags: u64,
    count: u64,
}

#[repr(C, align(4096))]
struct Page([u8; 4096]);

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

struct Seg {
    off: u64,
    len: u64,
    flags: u64,
    prot: i32,
}

/// Layout the ELF (linked at 0, p_vaddr == enclave offset) into a fresh
/// page-aligned image and derive per-segment SECINFO from p_flags.
fn layout(elf: &[u8]) -> (Vec<Seg>, Box<[Page]>) {
    let phoff = u64::from_le_bytes(elf[32..40].try_into().unwrap()) as usize;
    let phentsz = u16::from_le_bytes(elf[54..56].try_into().unwrap()) as usize;
    let phnum = u16::from_le_bytes(elf[56..58].try_into().unwrap()) as usize;

    // Compute total span first so the image buffer can be sized once.
    let mut hi = 0u64;
    for i in 0..phnum {
        let ph = &elf[phoff + i * phentsz..];
        if u32::from_le_bytes(ph[0..4].try_into().unwrap()) != 1 {
            continue; // PT_LOAD only
        }
        let va = u64::from_le_bytes(ph[16..24].try_into().unwrap());
        let memsz = u64::from_le_bytes(ph[40..48].try_into().unwrap());
        hi = hi.max((va + memsz).next_multiple_of(PAGE));
    }
    let mut img = (0..hi / PAGE)
        .map(|_| Page([0; 4096]))
        .collect::<Box<[_]>>();
    let bytes = unsafe { std::slice::from_raw_parts_mut(img.as_mut_ptr() as *mut u8, hi as usize) };

    let mut segs = Vec::new();
    for i in 0..phnum {
        let ph = &elf[phoff + i * phentsz..];
        if u32::from_le_bytes(ph[0..4].try_into().unwrap()) != 1 {
            continue;
        }
        let pf = u32::from_le_bytes(ph[4..8].try_into().unwrap());
        let foff = u64::from_le_bytes(ph[8..16].try_into().unwrap()) as usize;
        let va = u64::from_le_bytes(ph[16..24].try_into().unwrap());
        let filesz = u64::from_le_bytes(ph[32..40].try_into().unwrap()) as usize;
        let memsz = u64::from_le_bytes(ph[40..48].try_into().unwrap());

        bytes[va as usize..va as usize + filesz].copy_from_slice(&elf[foff..foff + filesz]);

        // First segment is the TCS by linker-script convention.
        // SECINFO {R,W,X} and PROT_{READ,WRITE,EXEC} share bit positions
        // (1/2/4), so the SECINFO low bits double as the mmap prot.
        let (flags, prot) = if segs.is_empty() {
            (SECINFO_TCS, libc::PROT_READ | libc::PROT_WRITE)
        } else {
            let rwx = (if pf & 4 != 0 { SECINFO_R } else { 0 })
                | (if pf & 2 != 0 { SECINFO_W } else { 0 })
                | (if pf & 1 != 0 { SECINFO_X } else { 0 });
            (SECINFO_REG | rwx, rwx as libc::c_int)
        };
        let off = va & !(PAGE - 1);
        segs.push(Seg {
            off,
            len: (va + memsz).next_multiple_of(PAGE) - off,
            flags,
            prot,
        });
    }
    (segs, img)
}

pub fn load(elf: &[u8]) -> io::Result<Enclave> {
    let fd = open_dev("/dev/sgx_enclave")?;
    let (segs, img) = layout(elf);
    let bytes = img.as_ptr() as *const u8;
    let blob = segs.last().map(|s| s.off + s.len).unwrap();
    let size = blob.next_power_of_two();

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
    let mut secs = Box::new(Page([0; 4096]));
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
    // (FLC), so the in-tree debug key works without a launch token.
    let ss = sigstruct(&segs, bytes, size);
    let mut p = ss.as_ptr() as u64;
    ioctl(&fd, SGX_IOC_INIT, &mut p, "SGX_IOC_ENCLAVE_INIT")?;

    // Map each segment over the reservation so EENTER can actually reach it.
    // EPC permissions cap the VMA's; the driver rejects a wider mmap.
    for s in &segs {
        let r = unsafe {
            libc::mmap(
                (base + s.off) as _,
                s.len as _,
                s.prot,
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

// --- MRENCLAVE + SIGSTRUCT -----------------------------------------------

use num_bigint::BigUint;
use sha2::{Digest, Sha256};

/// Reproduce the SHA-256 stream EINIT checks against MRENCLAVE: one 64-byte
/// record per ECREATE / EADD, plus per 256-byte chunk one EEXTEND record
/// followed by the chunk itself.  Mirrors `mrenclave_*` in the kernel
/// selftest's `sigstruct.c`.
fn mrenclave(segs: &[Seg], img: *const u8, size: u64) -> [u8; 32] {
    let mut h = Sha256::new();
    let mut rec = |tag: u64, b: u64, c: u64, dlen, data: &[u8]| {
        let mut r = [0u8; 64];
        r[0..8].copy_from_slice(&tag.to_le_bytes());
        r[8..8 + dlen].copy_from_slice(&b.to_le_bytes()[..dlen]);
        r[8 + dlen..16 + dlen].copy_from_slice(&c.to_le_bytes());
        h.update(r);
        h.update(data);
    };
    // "ECREATE\0", ssaframesize=1 (u32), size (u64)
    rec(0x0045544145524345, 1, size, 4, &[]);
    for s in segs {
        for p in (s.off..s.off + s.len).step_by(PAGE as usize) {
            rec(0x0000000044444145, p, s.flags, 8, &[]); // "EADD"
            for c in (p..p + PAGE).step_by(256) {
                let chunk = unsafe { std::slice::from_raw_parts(img.add(c as usize), 256) };
                rec(0x00444E4554584545, c, 0, 8, chunk); // "EEXTEND"
            }
        }
    }
    h.finalize().into()
}

fn le384(n: &BigUint) -> [u8; MOD] {
    let mut b = [0u8; MOD];
    let v = n.to_bytes_le();
    b[..v.len()].copy_from_slice(&v);
    b
}

/// Debug RSA-3072 (e=3) key, generated once with `openssl genrsa -3 3072`.
/// MRSIGNER (= SHA-256 of the LE modulus) is therefore a fixed constant
/// independent of the enclave contents.
const DEBUG_N: &[u8; MOD] = &include!("sgx_key_n.in");
const DEBUG_D: &[u8; MOD] = &include!("sgx_key_d.in");

fn sigstruct(segs: &[Seg], img: *const u8, size: u64) -> Box<[u8; SIGSTRUCT_LEN]> {
    let mut ss = Box::new([0u8; SIGSTRUCT_LEN]);

    // header (SDM Table 38-19): magic constants, vendor=0, date=0.
    ss[0..16].copy_from_slice(&[6, 0, 0, 0, 0xe1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0]);
    ss[24..40].copy_from_slice(&[1, 1, 0, 0, 0x60, 0, 0, 0, 0x60, 0, 0, 0, 1, 0, 0, 0]);
    // body @ 900: miscselect=0, misc_mask=0, attributes=MODE64BIT, xfrm=3.
    ss[928..936].copy_from_slice(&ATTR_MODE64BIT.to_le_bytes());
    ss[936..944].copy_from_slice(&XFRM_LEGACY.to_le_bytes());
    ss[960..992].copy_from_slice(&mrenclave(segs, img, size));

    // Signature is over header(128) ‖ body(128).
    let mut payload = [0u8; 256];
    payload[..128].copy_from_slice(&ss[0..128]);
    payload[128..].copy_from_slice(&ss[900..1028]);
    let digest: [u8; 32] = Sha256::digest(payload).into();

    // PKCS#1 v1.5: 00 01 FF.. 00 <DigestInfo(SHA-256)> <hash>, big-endian.
    let mut em = [0xffu8; MOD];
    em[0] = 0;
    em[1] = 1;
    const DI: [u8; 19] = [
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        0x05, 0x00, 0x04, 0x20,
    ];
    em[MOD - 52] = 0;
    em[MOD - 51..MOD - 32].copy_from_slice(&DI);
    em[MOD - 32..].copy_from_slice(&digest);

    let n = BigUint::from_bytes_le(DEBUG_N);
    let d = BigUint::from_bytes_le(DEBUG_D);
    let m = BigUint::from_bytes_be(&em);
    let s = m.modpow(&d, &n);
    debug_assert_eq!(s.modpow(&BigUint::from(3u8), &n), m);
    // q1 = ⌊s²/n⌋, q2 = ⌊s·(s² mod n)/n⌋ — precomputed so the CPU can do
    // s³ mod n with multiplies only during EINIT.
    let s2 = &s * &s;
    let q1 = &s2 / &n;
    let q2 = (&s * (&s2 % &n)) / &n;

    ss[128..128 + MOD].copy_from_slice(DEBUG_N);
    ss[512..516].copy_from_slice(&3u32.to_le_bytes());
    ss[516..516 + MOD].copy_from_slice(&le384(&s));
    ss[1040..1040 + MOD].copy_from_slice(&le384(&q1));
    ss[1424..1424 + MOD].copy_from_slice(&le384(&q2));
    ss
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

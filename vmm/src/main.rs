//! Minimal KVM launcher for the enclave unikernel.
//!
//! Loads the ELF, places the vCPU in the PVH initial state (32-bit protected
//! mode, flat segments, paging off, EIP = PHYS32_ENTRY), and runs it.
//! Emulated: COM1 (write-only, to stderr), the `isa-debug-exit` port, and a
//! single virtio-mmio vsock device whose data path is offloaded to
//! `/dev/vhost-vsock`. No firmware, no irqchip, no BIOS tables — the guest
//! never looks for any.
//!
//! This is the host-side half of "own the whole stack": the unikernel
//! hand-rolls virtio, this hand-rolls the VMM. SEV-SNP launch ioctls slot
//! in here later.

use std::io::{self, Write};
use std::os::fd::AsRawFd;

mod elf;
mod kvm;
mod mmio;
mod vhost;

const MEM_SIZE: usize = 8 * 1024 * 1024;
const COM1: u16 = 0x3f8;
const DEBUG_EXIT: u16 = 0xf4;

static ENCLAVE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/enclave"));

fn main() -> io::Result<()> {
    let cid: u64 = std::env::args()
        .nth(1)
        .map(|s| s.parse().expect("usage: vmm [guest-cid]"))
        .unwrap_or(42);

    let kvm = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/kvm")?;
    let api = kvm::ioctl(&kvm, kvm::KVM_GET_API_VERSION, 0)?;
    if api != 12 {
        return Err(io::Error::other("KVM API != 12"));
    }
    let vm = kvm::ioctl_fd(&kvm, kvm::KVM_CREATE_VM, 0)?;

    let mem = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            MEM_SIZE,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE,
            -1,
            0,
        )
    };
    if mem == libc::MAP_FAILED {
        return Err(io::Error::last_os_error());
    }
    let mem_slice = unsafe { std::slice::from_raw_parts_mut(mem as *mut u8, MEM_SIZE) };

    let mut region = kvm::UserMemRegion {
        slot: 0,
        flags: 0,
        guest_phys_addr: 0,
        memory_size: MEM_SIZE as u64,
        userspace_addr: mem as u64,
    };
    kvm::ioctl_ref(&vm, kvm::KVM_SET_USER_MEMORY_REGION, &mut region)?;

    let entry = elf::load(ENCLAVE, mem_slice)?;

    // vhost owns the data path; if /dev/vhost-vsock is unavailable we still
    // boot so the no-vsock path can be exercised.
    let mut vsock = match vhost::Vhost::open(cid, mem as u64, MEM_SIZE as u64) {
        Ok(v) => Some(mmio::VirtioVsock::new(v, cid)),
        Err(e) => {
            eprintln!("vmm: vhost-vsock unavailable ({e}), continuing without");
            None
        }
    };

    let vcpu = kvm::ioctl_fd(&vm, kvm::KVM_CREATE_VCPU, 0)?;
    let run_size = kvm::ioctl(&kvm, kvm::KVM_GET_VCPU_MMAP_SIZE, 0)? as usize;
    let run = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            run_size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            vcpu.as_raw_fd(),
            0,
        )
    };
    if run == libc::MAP_FAILED {
        return Err(io::Error::last_os_error());
    }
    let run_hdr = run as *mut kvm::RunHdr;

    kvm::passthrough_cpuid(&kvm, &vcpu)?;
    setup_pvh_cpu(&vcpu, entry)?;

    if vsock.is_some() {
        spawn_bridge(cid as u32);
    }

    loop {
        if let Err(e) = kvm::ioctl(&vcpu, kvm::KVM_RUN, 0) {
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        let hdr = unsafe { &mut *run_hdr };
        match hdr.exit_reason {
            kvm::EXIT_IO => {
                let io = unsafe { hdr.u.io };
                let data = unsafe { (run as *mut u8).add(io.data_offset as usize) };
                let n = io.size as usize * io.count as usize;
                match (io.port, io.direction) {
                    (COM1, kvm::IO_OUT) => {
                        let bytes = unsafe { std::slice::from_raw_parts(data, n) };
                        io::stderr().write_all(bytes)?;
                    }
                    // LSR: pretend transmitter is always empty so the guest's
                    // busy-wait in serial::print falls through.
                    (p, kvm::IO_IN) if p == COM1 + 5 => unsafe {
                        std::ptr::write_bytes(data, 0x60, n)
                    },
                    (DEBUG_EXIT, kvm::IO_OUT) => {
                        let code = unsafe { *(data as *const u32) };
                        // Match QEMU's isa-debug-exit encoding so callers
                        // (e2e tests) don't need to special-case the VMM.
                        std::process::exit(((code << 1) | 1) as i32);
                    }
                    (_, kvm::IO_IN) => unsafe { std::ptr::write_bytes(data, 0, n) },
                    _ => {}
                }
            }
            kvm::EXIT_MMIO => {
                let m = unsafe { &mut hdr.u.mmio };
                let off = m.phys_addr.wrapping_sub(mmio::BASE);
                if let Some(v) = vsock.as_mut().filter(|_| off < mmio::SIZE) {
                    if m.is_write != 0 {
                        v.write(off, u32::from_le_bytes(m.data[..4].try_into().unwrap()))?;
                    } else {
                        m.data[..4].copy_from_slice(&v.read(off).to_le_bytes());
                    }
                } else if m.is_write == 0 {
                    m.data = [0xff; 8];
                }
            }
            kvm::EXIT_HLT => return Ok(()),
            kvm::EXIT_SHUTDOWN => return Err(io::Error::other("guest triple-fault")),
            r => return Err(io::Error::other(format!("kvm exit {r}"))),
        }
    }
}

/// Connect to the guest over AF_VSOCK and run the uhid loop. The guest is
/// not listening yet when this is spawned (vCPU hasn't run), so retry until
/// the connect succeeds.
fn spawn_bridge(cid: u32) {
    std::thread::spawn(move || {
        let addr = vsock::VsockAddr::new(cid, 5555);
        let s = loop {
            match vsock::VsockStream::connect(&addr) {
                Ok(s) => break s,
                Err(_) => std::thread::sleep(std::time::Duration::from_millis(20)),
            }
        };
        let r = s.try_clone().expect("vsock clone");
        if let Err(e) = bridge::serve(r, s) {
            eprintln!("bridge: {e}");
            std::process::exit(1);
        }
    });
}

/// PVH initial state per `xen/include/public/arch-x86/hvm/start_info.h`:
/// flat 4 GiB segments, CR0.PE only, EBX = start_info (we pass 0; the guest
/// ignores it).
fn setup_pvh_cpu(vcpu: &impl AsRawFd, entry: u32) -> io::Result<()> {
    // GET first so reserved/KVM-populated fields (apic_base, tr) stay sane.
    let mut sr: kvm::Sregs = unsafe { std::mem::zeroed() };
    kvm::ioctl_ref(vcpu, kvm::KVM_GET_SREGS, &mut sr)?;

    let code = kvm::Segment {
        base: 0,
        limit: 0xffff_ffff,
        selector: 0x10,
        type_: 0b1011,
        present: 1,
        dpl: 0,
        db: 1,
        s: 1,
        l: 0,
        g: 1,
        avl: 0,
        unusable: 0,
        padding: 0,
    };
    let data = kvm::Segment {
        selector: 0x18,
        type_: 0b0011,
        ..code
    };
    sr.cs = code;
    sr.ds = data;
    sr.es = data;
    sr.fs = data;
    sr.gs = data;
    sr.ss = data;
    sr.cr0 = 1; // PE
    sr.cr4 = 0;
    sr.efer = 0;
    kvm::ioctl_ref(vcpu, kvm::KVM_SET_SREGS, &mut sr)?;

    let mut regs = kvm::Regs {
        rip: entry as u64,
        rflags: 2,
        ..Default::default()
    };
    kvm::ioctl_ref(vcpu, kvm::KVM_SET_REGS, &mut regs)
}

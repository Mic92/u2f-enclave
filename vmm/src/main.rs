//! Minimal KVM launcher for the enclave unikernel.
//!
//! Loads the ELF, places the vCPU in the PVH initial state (32-bit protected
//! mode, flat segments, paging off, EIP = PHYS32_ENTRY), and runs it. The
//! only emulated devices are COM1 (write-only, to stdout) and the
//! `isa-debug-exit` port. No firmware, no irqchip, no BIOS tables — the
//! guest never looks for any.
//!
//! This is the host-side half of "own the whole stack": the unikernel
//! hand-rolls virtio, this hand-rolls the VMM. SEV-SNP launch ioctls slot
//! in here later.

use std::io::{self, Write};
use std::os::fd::AsRawFd;

mod elf;
mod kvm;

const MEM_SIZE: usize = 8 * 1024 * 1024;
const COM1: u16 = 0x3f8;
const DEBUG_EXIT: u16 = 0xf4;

fn main() -> io::Result<()> {
    let path = std::env::args_os()
        .nth(1)
        .ok_or_else(|| io::Error::other("usage: vmm <enclave.elf>"))?;
    let img = std::fs::read(&path)?;

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

    let entry = elf::load(&img, mem_slice)?;

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

    let mut stdout = io::stdout().lock();
    loop {
        kvm::ioctl(&vcpu, kvm::KVM_RUN, 0)?;
        let hdr = unsafe { &*run_hdr };
        match hdr.exit_reason {
            kvm::EXIT_IO => {
                let io = hdr.io;
                let data = unsafe { (run as *mut u8).add(io.data_offset as usize) };
                let n = io.size as usize * io.count as usize;
                match (io.port, io.direction) {
                    (COM1, kvm::IO_OUT) => {
                        let bytes = unsafe { std::slice::from_raw_parts(data, n) };
                        stdout.write_all(bytes)?;
                        stdout.flush()?;
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
            kvm::EXIT_HLT => return Ok(()),
            kvm::EXIT_SHUTDOWN => return Err(io::Error::other("guest triple-fault")),
            kvm::EXIT_MMIO => {
                // No virtio backend yet: read-as-ones so the guest's MMIO
                // probe sees no magic and takes the "no vsock" path.
                let mmio = unsafe { (run as *mut u8).add(32) };
                let is_write = unsafe { *mmio.add(16) } != 0;
                if !is_write {
                    unsafe { std::ptr::write_bytes(mmio.add(8), 0xff, 8) };
                }
            }
            r => return Err(io::Error::other(format!("kvm exit {r}"))),
        }
    }
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

//! Minimal KVM launcher for the guest unikernel.
//!
//! Loads the ELF, places the vCPU in the PVH initial state (32-bit protected
//! mode, flat segments, paging off, EIP = PHYS32_ENTRY), and runs it.
//! Emulated: COM1 (write-only, to stderr), the `isa-debug-exit` port, and a
//! single virtio-mmio vsock device whose data path is offloaded to
//! `/dev/vhost-vsock`. With `--snp` the guest is launched as a SEV-SNP
//! confidential VM (see `snp.rs`). No firmware, no irqchip, no BIOS tables
//! — the guest never looks for any.

use std::io::{self, Write};
use std::os::fd::AsRawFd;

mod attest;
mod elf;
mod kvm;
mod measure;
mod mmio;
mod sgx;
mod sgx_layout;
mod snp;
mod snp_report;
mod verify;
mod vhost;

const MEM_SIZE: usize = 8 * 1024 * 1024;
const COM1: u16 = 0x3f8;
const DEBUG_EXIT: u16 = 0xf4;

static GUEST_ELF: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/guest"));
static SGX_ELF: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/sgx"));

const USAGE: &str = "\
FIDO2/CTAP2 authenticator running in a confidential VM or SGX enclave.

Usage:
  u2f-enclave [--snp|--sgx] [CID]    run; exposes the authenticator as a
                                     /dev/hidraw* device via uhid
  u2f-enclave --measure              print this build's SNP launch digest
                                     and SGX MRENCLAVE/MRSIGNER and exit
  u2f-enclave verify [--vcek FILE]   read a 1184-byte SNP report on stdin;
                                     check its VCEK signature and that its
                                     measurement matches this build; print
                                     report_data for the caller's binding
                                     check; exit 0 iff ok
  u2f-enclave vcek-url               read a report on stdin, print the AMD
                                     URL to fetch its chip's certificate
  u2f-enclave attest [DEVICE]        demo client: register a credential on
                                     the local hidraw device, check the
                                     report binds it, write the report to
                                     stdout (e.g. > report.bin, then
                                     `verify` it on another machine)

  --snp        launch under SEV-SNP (encrypted+measured); requires /dev/sev
  --sgx        run inside an SGX enclave instead of a VM (no vsock);
               requires /dev/sgx_enclave
  CID          AF_VSOCK context ID for the guest VM (default 42; ignored
               with --sgx)
  --vcek FILE  VCEK certificate (DER). Without it, verify looks in
               $XDG_CACHE_HOME/u2f-enclave and, on miss, prints the
               curl command to fetch it from AMD

--measure and verify need no /dev/* access and run on any x86_64 Linux.

Needs rw access to /dev/uhid plus, depending on mode, /dev/kvm +
/dev/vhost-vsock, /dev/sev, or /dev/sgx_enclave. One-time setup:
  sudo setfacl -m u:$USER:rw /dev/uhid /dev/kvm /dev/vhost-vsock \
                             /dev/sev /dev/sgx_enclave
";

fn main() -> io::Result<()> {
    let mut args = std::env::args().skip(1).peekable();
    if args.peek().is_some_and(|a| a == "--help" || a == "-h") {
        print!("{USAGE}");
        return Ok(());
    }
    if args.next_if_eq("attest").is_some() {
        std::process::exit(attest::cmd(args.next()));
    }
    if args.next_if_eq("vcek-url").is_some() {
        std::process::exit(verify::cmd_url());
    }
    if args.next_if_eq("verify").is_some() {
        let vcek = args.next_if_eq("--vcek").and_then(|_| args.next());
        if args.next().is_some() {
            eprint!("{USAGE}");
            std::process::exit(2);
        }
        std::process::exit(verify::cmd(vcek, expected_measurement()?));
    }
    if args.next_if_eq("--sgx").is_some() {
        return sgx::run(SGX_ELF);
    }
    let measure = args.next_if_eq("--measure").is_some();
    let snp = !measure && args.next_if_eq("--snp").is_some();
    let cid: u64 = match args.next().map(|s| s.parse()) {
        None => 42,
        Some(Ok(n)) if !measure => n,
        _ => {
            eprint!("{USAGE}");
            std::process::exit(2);
        }
    };
    if measure {
        return print_measure();
    }

    let kvm = open_dev("/dev/kvm")?;
    let api = kvm::ioctl(&kvm, kvm::KVM_GET_API_VERSION, 0)?;
    if api != 12 {
        return Err(io::Error::other("KVM API != 12"));
    }
    let vm_type = if snp { kvm::KVM_X86_SNP_VM } else { 0 };
    let vm = kvm::ioctl_fd(&kvm, kvm::KVM_CREATE_VM, vm_type).map_err(|e| {
        if snp {
            io::Error::other(format!(
                "KVM_CREATE_VM(SNP): {e} — needs an EPYC host with kvm_amd sev_snp=Y"
            ))
        } else {
            e
        }
    })?;

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

    // SEV_INIT2 must precede vCPU creation.
    let coco = if snp {
        kvm::enable_cap(
            &vm,
            kvm::KVM_CAP_EXIT_HYPERCALL,
            1 << kvm::KVM_HC_MAP_GPA_RANGE,
        )?;
        Some(snp::Snp::init(&vm, mem as *mut u8, MEM_SIZE as u64)?)
    } else {
        let mut region = kvm::UserMemRegion {
            slot: 0,
            flags: 0,
            guest_phys_addr: 0,
            memory_size: MEM_SIZE as u64,
            userspace_addr: mem as u64,
        };
        kvm::ioctl_ref(&vm, kvm::KVM_SET_USER_MEMORY_REGION, &mut region)?;
        None
    };

    let img = elf::load(GUEST_ELF, mem_slice)?;

    // vhost reads rings/buffers via the anon mmap; under SNP that is the
    // shared half of the memslot, so no special handling.
    let mut vsock = match vhost::Vhost::open(cid, mem as u64, MEM_SIZE as u64) {
        Ok(v) => Some(mmio::VirtioVsock::new(v, cid)),
        Err(e) => {
            eprintln!(
                "u2f-enclave: vhost-vsock unavailable ({e}); continuing without \
                 a HID device. Try: sudo setfacl -m u:$USER:rw /dev/vhost-vsock"
            );
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
    setup_pvh_cpu(&vcpu, img.entry, snp)?;
    if let Some(c) = &coco {
        c.launch(
            &vm,
            unsafe { (mem as *const u8).add(img.lo as usize) },
            img.lo,
            img.hi - img.lo,
        )?;
        eprintln!(
            "u2f-enclave: SEV-SNP launch ok ({} KiB measured)",
            (img.hi - img.lo) >> 10
        );
    }

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
            // SNP guest's page-state-change: flip KVM's private/shared
            // attribute for the range; KVM does the RMPUPDATE and writes
            // the GHCB-MSR response on resume.
            kvm::EXIT_HYPERCALL => {
                let hc = unsafe { &mut hdr.u.hypercall };
                if hc.nr == kvm::KVM_HC_MAP_GPA_RANGE {
                    let private = hc.args[2] & (1 << 4) != 0;
                    // args[2][1:0] = page-size order in 9-bit steps (4K/2M/1G).
                    let pg = 12 + 9 * (hc.args[2] & 3);
                    let mut attrs = kvm::MemAttrs {
                        address: hc.args[0],
                        size: hc.args[1] << pg,
                        attributes: if private {
                            kvm::KVM_MEMORY_ATTRIBUTE_PRIVATE
                        } else {
                            0
                        },
                        flags: 0,
                    };
                    kvm::ioctl_ref(&vm, kvm::KVM_SET_MEMORY_ATTRIBUTES, &mut attrs)?;
                    hc.ret = 0;
                }
            }
            kvm::EXIT_SYSTEM_EVENT => {
                let ev = unsafe { hdr.u.system_event };
                match ev.type_ {
                    kvm::SYSTEM_EVENT_SEV_TERM => {
                        let ghcb = ev.data[0];
                        let reason = (ghcb >> 16) & 0xff;
                        eprintln!("u2f-enclave: SEV terminate ghcb={ghcb:#x} reason={reason:#x}");
                        std::process::exit(reason as i32);
                    }
                    t => return Err(io::Error::other(format!("system event {t}"))),
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

/// Open a privileged device node with a hint at the fix on EACCES, since
/// that's the failure mode every first-time user hits.
pub fn open_dev(p: &str) -> io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(p)
        .map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("open {p}: {e} (try: sudo setfacl -m u:$USER:rw {p})"),
            )
        })
}

fn expected_measurement() -> io::Result<[u8; 48]> {
    let mut mem = vec![0u8; MEM_SIZE];
    let img = elf::load(GUEST_ELF, &mut mem)?;
    let vmsa = measure::vmsa_page(img.entry);
    Ok(measure::launch_digest(
        &mem,
        img.lo,
        img.hi,
        snp::SECRETS_GPA,
        &vmsa,
    ))
}

/// Recompute the launch measurement from the embedded ELF: hex to stdout
/// (composes with shell tooling), context to stderr.
fn print_measure() -> io::Result<()> {
    let mut mem = vec![0u8; MEM_SIZE];
    let img = elf::load(GUEST_ELF, &mut mem)?;
    let vmsa = measure::vmsa_page(img.entry);
    let ld = measure::launch_digest(&mem, img.lo, img.hi, snp::SECRETS_GPA, &vmsa);

    println!("snp           {}", verify::hex(&ld));
    println!("snp author    {}", verify::hex(snp::AUTHOR_KEY_DIGEST));
    println!("sgx mrenclave {}", verify::hex(sgx::mrenclave()));
    println!("sgx mrsigner  {}", verify::hex(&sgx::mrsigner()));
    io::stdout().flush()?;
    eprintln!(
        "↑ expected measurements for this build.\n  \
         attStmt[\"snp\"] (1184 B) carries the SNP digest at 0x90..0xc0\n    \
           and the author key digest at 0x110..0x140; check after verifying\n    \
           the VCEK signature.\n  \
         attStmt[\"sgx\"] (432 B) carries MRENCLAVE at 0x40 and MRSIGNER at 0x80.\n\
         SNP inputs:\n  \
         guest image  {:#x}..{:#x} ({} KiB, {} pages)\n  \
         entry        {:#x}\n  \
         secrets gpa  {:#x}\n  \
         vmsa gpa     {:#x}\n  \
         c-bit        {}\n\
         (also check report.policy == {:#x}; not part of the digest)",
        img.lo,
        img.hi,
        (img.hi - img.lo) >> 10,
        (img.hi - img.lo) >> 12,
        img.entry,
        snp::SECRETS_GPA,
        measure::VMSA_GPA,
        snp::C_BIT,
        snp::SNP_POLICY,
    );
    Ok(())
}

/// PVH initial state per `xen/include/public/arch-x86/hvm/start_info.h`:
/// flat 4 GiB segments, CR0.PE only, EBX = start_info (we pass 0; the guest
/// ignores it).
fn setup_pvh_cpu(vcpu: &impl AsRawFd, entry: u32, snp: bool) -> io::Result<()> {
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
        // ram32.s reads %esi: SEV C-bit position, 0 = plain VM.
        rsi: if snp { snp::C_BIT as u64 } else { 0 },
        ..Default::default()
    };
    kvm::ioctl_ref(vcpu, kvm::KVM_SET_REGS, &mut regs)
}

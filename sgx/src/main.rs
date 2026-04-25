//! Ring-3 SGX enclave — sibling of `guest/`, different isolation primitive
//! (EPC pages instead of a confidential VM).  The host EENTERs with `rdi`
//! pointing at a `Slot` in untrusted memory; one round-trip moves at most one
//! 64-byte CTAPHID report each way, so the enclave never blocks and never
//! does I/O.
//!
//! Build: `cargo build -p sgx --target x86_64-unknown-none --release`
#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec::Vec;
use core::arch::{global_asm, x86_64::_rdrand64_step};
use core::ptr::addr_of_mut;

use ctap::{Authenticator, Platform, Report, AAGUID};
use linked_list_allocator::LockedHeap;

global_asm!(include_str!("entry.s"), options(att_syntax));

const HEAP_SIZE: usize = 128 * 1024;
static mut HEAP: [u8; HEAP_SIZE] = [0; HEAP_SIZE];

#[global_allocator]
static ALLOC: LockedHeap = LockedHeap::empty();

/// Host-shared mailbox; layout mirrors `host/src/sgx.rs`.
#[repr(C)]
struct Slot {
    /// in: 1 = `buf` holds an OUTPUT report, process it then drain one;
    ///     2 = drain one.
    /// out: 0 = no output queued; 1 = `buf` holds an INPUT report.
    op: u32,
    _pad: u32,
    buf: Report,
}
const OP_INPUT: u32 = 1;

struct State {
    auth: Authenticator<Sgx>,
    out: Vec<Report>,
    cur: usize,
}

static mut STATE: Option<State> = None;

#[unsafe(no_mangle)]
extern "C" fn encl_main(slot: *mut Slot, base: usize, end: usize) {
    // The host chooses `slot`; if it points into our own pages it becomes a
    // write primitive over private state.  Anything in [end, base+SECS.size)
    // has no EPC page and just #PFs, so checking against the linked span is
    // enough.
    let p = slot as usize;
    if p < end && p.saturating_add(core::mem::size_of::<Slot>()) > base {
        return;
    }
    // SAFETY: single TCS, so every static is single-threaded across EENTERs.
    unsafe {
        let st = match (*addr_of_mut!(STATE)).as_mut() {
            Some(s) => s,
            None => {
                ALLOC.lock().init(addr_of_mut!(HEAP) as *mut u8, HEAP_SIZE);
                (*addr_of_mut!(STATE)).insert(State {
                    auth: Authenticator::new(Sgx::new(), AAGUID),
                    out: Vec::new(),
                    cur: 0,
                })
            }
        };
        // Snapshot through raw volatile ops: forming a Rust reference into
        // host-writable memory would assert it doesn't change under us.
        let op = (&raw const (*slot).op).read_volatile();
        if op == OP_INPUT {
            let buf = (&raw const (*slot).buf).read_volatile();
            st.out = st.auth.process_report(&buf);
            st.cur = 0;
        }
        let (op, buf) = match st.out.get(st.cur) {
            Some(r) => {
                st.cur += 1;
                (1, *r)
            }
            None => (0, [0u8; 64]),
        };
        (&raw mut (*slot).buf).write_volatile(buf);
        (&raw mut (*slot).op).write_volatile(op);
    }
}

struct Sgx {
    master: [u8; 32],
}

impl Sgx {
    fn new() -> Self {
        // EGETKEY yields 128 bits; the master keys HMAC-SHA256 over P-256
        // material, so 128-bit entropy already matches the curve's level.
        let mut master = [0u8; 32];
        master[..16].copy_from_slice(&seal_key());
        Self { master }
    }
}

impl Platform for Sgx {
    fn random_bytes(&mut self, buf: &mut [u8]) {
        rdrand(buf);
    }
    fn master_secret(&self) -> [u8; 32] {
        self.master
    }
    fn attestation(&mut self, rd: &[u8; 64]) -> Option<(&'static str, Vec<u8>)> {
        Some(("sgx", ereport(rd).to_vec()))
    }
}

// --- ENCLU --------------------------------------------------------------

#[repr(C, align(512))]
struct A512<const N: usize>([u8; N]);
#[repr(C, align(128))]
struct A128<const N: usize>([u8; N]);
#[repr(C, align(16))]
struct A16([u8; 16]);

/// rbx is LLVM-reserved, hence the xchg dance.
unsafe fn enclu(leaf: u64, b: *const u8, c: *mut u8, d: *mut u8) -> u64 {
    let ret;
    core::arch::asm!(
        "xchg {b}, rbx",
        ".byte 0x0f, 0x01, 0xd7",
        "xchg {b}, rbx",
        b = inout(reg) b => _,
        inout("rax") leaf => ret,
        in("rcx") c,
        in("rdx") d,
        options(nostack),
    );
    ret
}

/// Seal key bound to MRSIGNER (the build-time RSA key) so credentials
/// survive enclave updates as long as the same key signs them.  CPUSVN=0
/// trades microcode-rollback resistance for that same stability; the
/// SIGSTRUCT pins DEBUG=0, and we mask INIT|DEBUG into the derivation as
/// defence in depth.
fn seal_key() -> [u8; 16] {
    const KEY_SEAL: u16 = 4;
    const POLICY_MRSIGNER: u16 = 1 << 1;
    static mut KR: A512<512> = A512([0; 512]);
    static mut OUT: A16 = A16([0; 16]);
    unsafe {
        let kr = &mut (*addr_of_mut!(KR)).0;
        kr[0..2].copy_from_slice(&KEY_SEAL.to_le_bytes());
        kr[2..4].copy_from_slice(&POLICY_MRSIGNER.to_le_bytes());
        kr[24..32].copy_from_slice(&3u64.to_le_bytes()); // ATTRIBUTEMASK = INIT|DEBUG
        let r = enclu(
            1,
            kr.as_ptr(),
            addr_of_mut!(OUT) as _,
            core::ptr::null_mut(),
        );
        assert_eq!(r, 0);
        (*addr_of_mut!(OUT)).0
    }
}

/// EREPORT for `attStmt["sgx"]`.  TARGETINFO is all-zero so the MAC is for a
/// null target — the body (MRENCLAVE/MRSIGNER/ATTRIBUTES/REPORTDATA) is what
/// the verifier reads, and a host-side QE wraps a fresh one for DCAP.
fn ereport(report_data: &[u8; 64]) -> [u8; 432] {
    static mut TI: A512<512> = A512([0; 512]);
    static mut RD: A128<64> = A128([0; 64]);
    static mut REP: A512<432> = A512([0; 432]);
    unsafe {
        (*addr_of_mut!(RD)).0 = *report_data;
        enclu(
            0,
            addr_of_mut!(TI) as _,
            addr_of_mut!(RD) as _,
            addr_of_mut!(REP) as _,
        );
        (*addr_of_mut!(REP)).0
    }
}

/// RDRAND's DRNG is on-die and not exposed to the host OS, so it sits inside
/// the SGX trust boundary just as it does for SEV-SNP.
fn rdrand(buf: &mut [u8]) {
    for chunk in buf.chunks_mut(8) {
        let mut v = 0u64;
        while unsafe { _rdrand64_step(&mut v) } != 1 {}
        chunk.copy_from_slice(&v.to_ne_bytes()[..chunk.len()]);
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    // No I/O channel here; an AEX surfaces to the host as an exception via
    // the vDSO run struct, which is at least observable.
    unsafe { core::arch::asm!("ud2", options(noreturn)) }
}

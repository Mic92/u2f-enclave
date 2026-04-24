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
        let mut master = [0u8; 32];
        rdrand(&mut master);
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

//! Minimal virtio-mmio v2 (non-legacy) transport, polling only.
//!
//! Only what a single-connection vsock needs: feature negotiation
//! (VERSION_1), one split virtqueue per index, busy-poll for used buffers.
//! No interrupts, no indirect descriptors, no event idx. Under SEV-SNP each
//! register access is a GHCB round trip, so keeping this surface tiny
//! matters.

use core::ptr::{addr_of, addr_of_mut, read_volatile, write_volatile};

use crate::pv;
use core::sync::atomic::{compiler_fence, Ordering};

/// Where `host` places the single virtio-mmio window (and where QEMU microvm
/// happens to put slot 0 too, which is why we picked it).
pub const MMIO_BASE: usize = 0xfeb0_0000;

const VIRTIO_F_VERSION_1: u64 = 1 << 32;

const STATUS_ACK: u32 = 1;
const STATUS_DRIVER: u32 = 2;
const STATUS_DRIVER_OK: u32 = 4;
const STATUS_FEATURES_OK: u32 = 8;

mod reg {
    pub const MAGIC: usize = 0x000;
    pub const VERSION: usize = 0x004;
    pub const DEVICE_ID: usize = 0x008;
    pub const DRV_FEAT_SEL: usize = 0x024;
    pub const DRV_FEAT: usize = 0x020;
    pub const QUEUE_SEL: usize = 0x030;
    pub const QUEUE_NUM: usize = 0x038;
    pub const QUEUE_READY: usize = 0x044;
    pub const QUEUE_NOTIFY: usize = 0x050;
    pub const STATUS: usize = 0x070;
    pub const QUEUE_DESC_LO: usize = 0x080;
    pub const QUEUE_DESC_HI: usize = 0x084;
    pub const QUEUE_DRV_LO: usize = 0x090;
    pub const QUEUE_DRV_HI: usize = 0x094;
    pub const QUEUE_DEV_LO: usize = 0x0a0;
    pub const QUEUE_DEV_HI: usize = 0x0a4;
    pub const CONFIG: usize = 0x100;
}

pub struct Mmio {
    base: u64,
}

impl Mmio {
    pub const fn new(base: u64) -> Self {
        Self { base }
    }
    fn r(&self, off: usize) -> u32 {
        pv::mmio_read32(self.base + off as u64)
    }
    fn w(&self, off: usize, v: u32) {
        pv::mmio_write32(self.base + off as u64, v);
    }

    pub fn probe(&self) -> Option<u32> {
        if self.r(reg::MAGIC) != 0x7472_6976 || self.r(reg::VERSION) != 2 {
            return None;
        }
        let id = self.r(reg::DEVICE_ID);
        (id != 0).then_some(id)
    }

    /// Device init handshake up to FEATURES_OK; caller sets up queues then
    /// calls `driver_ok()`. Asks for VERSION_1 only.
    pub fn begin_init(&self) {
        self.w(reg::STATUS, 0);
        self.w(reg::STATUS, STATUS_ACK);
        self.w(reg::STATUS, STATUS_ACK | STATUS_DRIVER);
        self.w(reg::DRV_FEAT_SEL, 0);
        self.w(reg::DRV_FEAT, 0);
        self.w(reg::DRV_FEAT_SEL, 1);
        self.w(reg::DRV_FEAT, (VIRTIO_F_VERSION_1 >> 32) as u32);
        self.w(reg::STATUS, STATUS_ACK | STATUS_DRIVER | STATUS_FEATURES_OK);
    }

    pub fn driver_ok(&self) {
        self.w(
            reg::STATUS,
            STATUS_ACK | STATUS_DRIVER | STATUS_FEATURES_OK | STATUS_DRIVER_OK,
        );
    }

    pub fn config_read64(&self, off: usize) -> u64 {
        let lo = self.r(reg::CONFIG + off) as u64;
        let hi = self.r(reg::CONFIG + off + 4) as u64;
        lo | (hi << 32)
    }

    pub fn setup_queue(&self, idx: u16, q: &Virtq) {
        self.w(reg::QUEUE_SEL, idx as u32);
        self.w(reg::QUEUE_NUM, Q as u32);
        let desc = addr_of!(q.desc) as u64;
        let avail = addr_of!(q.avail) as u64;
        let used = addr_of!(q.used) as u64;
        self.w(reg::QUEUE_DESC_LO, desc as u32);
        self.w(reg::QUEUE_DESC_HI, (desc >> 32) as u32);
        self.w(reg::QUEUE_DRV_LO, avail as u32);
        self.w(reg::QUEUE_DRV_HI, (avail >> 32) as u32);
        self.w(reg::QUEUE_DEV_LO, used as u32);
        self.w(reg::QUEUE_DEV_HI, (used >> 32) as u32);
        self.w(reg::QUEUE_READY, 1);
    }

    pub fn notify(&self, idx: u16) {
        self.w(reg::QUEUE_NOTIFY, idx as u32);
    }
}

// --- split virtqueue ------------------------------------------------------

/// Queue size. 8 is plenty for our single-stream polling vsock and keeps
/// every queue inside one page.
pub const Q: usize = 8;

const VRING_DESC_F_NEXT: u16 = 1;
const VRING_DESC_F_WRITE: u16 = 2;

#[repr(C, align(16))]
#[derive(Clone, Copy)]
struct Desc {
    addr: u64,
    len: u32,
    flags: u16,
    next: u16,
}

#[repr(C, align(2))]
struct Avail {
    flags: u16,
    idx: u16,
    ring: [u16; Q],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct UsedElem {
    id: u32,
    len: u32,
}

#[repr(C, align(4))]
struct Used {
    flags: u16,
    idx: u16,
    ring: [UsedElem; Q],
}

#[repr(C, align(4096))]
pub struct Virtq {
    desc: [Desc; Q],
    avail: Avail,
    used: Used,
    last_used: u16,
    avail_idx: u16,
    free_head: u16,
}

impl Virtq {
    pub const fn new() -> Self {
        Self {
            desc: [Desc {
                addr: 0,
                len: 0,
                flags: 0,
                next: 0,
            }; Q],
            avail: Avail {
                flags: 0,
                idx: 0,
                ring: [0; Q],
            },
            used: Used {
                flags: 0,
                idx: 0,
                ring: [UsedElem { id: 0, len: 0 }; Q],
            },
            last_used: 0,
            avail_idx: 0,
            free_head: 0,
        }
    }

    /// Chain descriptors as a singly-linked free list. The last `next` is
    /// past-the-end so over-allocation panics on the index instead of
    /// silently double-allocating.
    pub fn init_free(&mut self) {
        for i in 0..Q {
            self.desc[i].next = i as u16 + 1;
        }
        self.free_head = 0;
    }

    fn alloc(&mut self) -> u16 {
        let h = self.free_head;
        self.free_head = self.desc[h as usize].next;
        h
    }

    fn free(&mut self, head: u16, n: u16) {
        let mut tail = head;
        for _ in 1..n {
            tail = self.desc[tail as usize].next;
        }
        self.desc[tail as usize].next = self.free_head;
        self.free_head = head;
    }

    /// Push a single device-writable buffer (for RX).
    pub fn push_write(&mut self, buf: *mut u8, len: u32) {
        let d = self.alloc();
        self.desc[d as usize] = Desc {
            addr: buf as u64,
            len,
            flags: VRING_DESC_F_WRITE,
            next: 0,
        };
        self.publish(d);
    }

    /// Push a two-part driver-readable chain (for TX: header + payload).
    pub fn push_read2(&mut self, a: *const u8, alen: u32, b: *const u8, blen: u32) {
        let d0 = self.alloc();
        let d1 = self.alloc();
        self.desc[d0 as usize] = Desc {
            addr: a as u64,
            len: alen,
            flags: VRING_DESC_F_NEXT,
            next: d1,
        };
        self.desc[d1 as usize] = Desc {
            addr: b as u64,
            len: blen,
            flags: 0,
            next: 0,
        };
        self.publish(d0);
    }

    pub fn push_read(&mut self, a: *const u8, alen: u32) {
        let d = self.alloc();
        self.desc[d as usize] = Desc {
            addr: a as u64,
            len: alen,
            flags: 0,
            next: 0,
        };
        self.publish(d);
    }

    fn publish(&mut self, head: u16) {
        self.avail.ring[(self.avail_idx as usize) % Q] = head;
        self.avail_idx = self.avail_idx.wrapping_add(1);
        compiler_fence(Ordering::Release);
        unsafe { write_volatile(addr_of_mut!(self.avail.idx), self.avail_idx) };
    }

    /// Pop one used element, returning (head, written_len).
    pub fn pop_used(&mut self) -> Option<(u16, u32)> {
        let device_idx = unsafe { read_volatile(addr_of!(self.used.idx)) };
        if self.last_used == device_idx {
            return None;
        }
        compiler_fence(Ordering::Acquire);
        let e = self.used.ring[(self.last_used as usize) % Q];
        self.last_used = self.last_used.wrapping_add(1);
        let mut n = 1u16;
        let mut d = e.id as u16;
        while self.desc[d as usize].flags & VRING_DESC_F_NEXT != 0 {
            d = self.desc[d as usize].next;
            n += 1;
        }
        self.free(e.id as u16, n);
        Some((e.id as u16, e.len))
    }
}

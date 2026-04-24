//! virtio-mmio v2 register window for the vsock device. Only the registers
//! the enclave's `virtio.rs` actually touches are implemented; everything
//! else reads as 0. State is captured per queue and pushed into vhost when
//! the guest writes QUEUE_READY / DRIVER_OK.

use std::io;

use crate::vhost::Vhost;

/// Single slot, at the address the guest's `virtio::MMIO_BASE` expects.
pub const BASE: u64 = 0xfeb0_0000;
pub const SIZE: u64 = 0x200;

const STATUS_DRIVER_OK: u32 = 4;
const VIRTIO_ID_VSOCK: u32 = 19;

#[derive(Default, Clone, Copy)]
struct Queue {
    num: u32,
    desc: u64,
    avail: u64,
    used: u64,
}

pub struct VirtioVsock {
    vhost: Vhost,
    cid: u64,
    status: u32,
    sel: u32,
    q: [Queue; 3],
}

impl VirtioVsock {
    pub fn new(vhost: Vhost, cid: u64) -> Self {
        Self {
            vhost,
            cid,
            status: 0,
            sel: 0,
            q: [Queue::default(); 3],
        }
    }

    pub fn read(&self, off: u64) -> u32 {
        match off {
            0x000 => 0x7472_6976, // magic
            0x004 => 2,           // version
            0x008 => VIRTIO_ID_VSOCK,
            0x070 => self.status,
            0x100 => self.cid as u32,
            0x104 => (self.cid >> 32) as u32,
            _ => 0,
        }
    }

    pub fn write(&mut self, off: u64, v: u32) -> io::Result<()> {
        let q = &mut self.q[self.sel as usize % 3];
        match off {
            0x030 => self.sel = v,
            0x038 => q.num = v,
            0x080 => q.desc = (q.desc & !0xffff_ffff) | v as u64,
            0x084 => q.desc = (q.desc & 0xffff_ffff) | ((v as u64) << 32),
            0x090 => q.avail = (q.avail & !0xffff_ffff) | v as u64,
            0x094 => q.avail = (q.avail & 0xffff_ffff) | ((v as u64) << 32),
            0x0a0 => q.used = (q.used & !0xffff_ffff) | v as u64,
            0x0a4 => q.used = (q.used & 0xffff_ffff) | ((v as u64) << 32),
            0x044 if v == 1 && self.sel < 2 => {
                self.vhost
                    .set_vring(self.sel, q.num, q.desc, q.avail, q.used)?;
            }
            0x050 if v < 2 => self.vhost.kick(v)?,
            0x070 => {
                let was_ok = self.status & STATUS_DRIVER_OK != 0;
                self.status = v;
                if !was_ok && v & STATUS_DRIVER_OK != 0 {
                    self.vhost.start()?;
                }
            }
            _ => {}
        }
        Ok(())
    }
}

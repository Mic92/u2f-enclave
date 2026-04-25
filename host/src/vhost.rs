//! vhost-vsock: hand the guest's RX/TX virtqueues to the kernel so the data
//! path is guest-memory ↔ kernel-vhost-thread with zero userspace hops.
//! The VMM only emulates virtio-mmio config registers and forwards
//! QUEUE_NOTIFY writes to the kick eventfds.
//!
//! The event queue (virtio-vsock queue 2) is not part of vhost; the guest
//! posts one buffer to it and we never signal — there is no transport-reset
//! event in this VMM's lifetime.

use std::io;
use std::os::fd::{AsRawFd, OwnedFd};

use crate::kvm::{ioc_raw, ioctl, ioctl_ref};

const VHOST: u32 = 0xAF;
const fn vio(dir: u32, nr: u32, sz: u32) -> libc::c_ulong {
    ioc_raw(dir, VHOST, nr, sz)
}
const VHOST_SET_FEATURES: libc::c_ulong = vio(1, 0x00, 8);
const VHOST_SET_OWNER: libc::c_ulong = vio(0, 0x01, 0);
const VHOST_SET_MEM_TABLE: libc::c_ulong = vio(1, 0x03, 8);
const VHOST_SET_VRING_NUM: libc::c_ulong = vio(1, 0x10, 8);
const VHOST_SET_VRING_ADDR: libc::c_ulong = vio(1, 0x11, 40);
const VHOST_SET_VRING_BASE: libc::c_ulong = vio(1, 0x12, 8);
const VHOST_SET_VRING_KICK: libc::c_ulong = vio(1, 0x20, 8);
const VHOST_SET_VRING_CALL: libc::c_ulong = vio(1, 0x21, 8);
const VHOST_VSOCK_SET_GUEST_CID: libc::c_ulong = vio(1, 0x60, 8);
const VHOST_VSOCK_SET_RUNNING: libc::c_ulong = vio(1, 0x61, 4);

#[repr(C)]
struct VringState {
    index: u32,
    num: u32,
}
#[repr(C)]
struct VringFile {
    index: u32,
    fd: i32,
}
#[repr(C)]
struct VringAddr {
    index: u32,
    flags: u32,
    desc_user_addr: u64,
    used_user_addr: u64,
    avail_user_addr: u64,
    log_guest_addr: u64,
}
#[repr(C)]
struct MemTable {
    nregions: u32,
    padding: u32,
    // single region inline (struct vhost_memory_region)
    guest_phys_addr: u64,
    memory_size: u64,
    userspace_addr: u64,
    flags_padding: u64,
}

pub struct Vhost {
    fd: OwnedFd,
    kick: [OwnedFd; 2],
    mem_base: u64,
}

/// First CID the kernel will hand out (`> VMADDR_CID_HOST`).
const CID_AUTO_BASE: u64 = 3;

impl Vhost {
    /// `cid = 0` probes for a free one so multiple instances coexist
    /// without the user coordinating IDs.
    pub fn open(cid: u64, mem_uaddr: u64, mem_size: u64) -> io::Result<(Self, u64)> {
        let fd: OwnedFd = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/vhost-vsock")?
            .into();
        ioctl(&fd, VHOST_SET_OWNER, 0)?;
        let mut feat = 1u64 << 32; // VIRTIO_F_VERSION_1
        ioctl_ref(&fd, VHOST_SET_FEATURES, &mut feat)?;
        let mut mt = MemTable {
            nregions: 1,
            padding: 0,
            guest_phys_addr: 0,
            memory_size: mem_size,
            userspace_addr: mem_uaddr,
            flags_padding: 0,
        };
        ioctl_ref(&fd, VHOST_SET_MEM_TABLE, &mut mt)?;
        let cid = if cid != 0 {
            let mut c = cid;
            ioctl_ref(&fd, VHOST_VSOCK_SET_GUEST_CID, &mut c)?;
            cid
        } else {
            let mut c = CID_AUTO_BASE;
            loop {
                match ioctl_ref(&fd, VHOST_VSOCK_SET_GUEST_CID, &mut c) {
                    Ok(_) => break c,
                    Err(e) if e.kind() == io::ErrorKind::AddrInUse && c < CID_AUTO_BASE + 1024 => {
                        c += 1
                    }
                    Err(e) => return Err(e),
                }
            }
        };
        Ok((
            Self {
                fd,
                kick: [eventfd()?, eventfd()?],
                mem_base: mem_uaddr,
            },
            cid,
        ))
    }

    /// Called when the guest sets QUEUE_READY for queue 0 or 1.
    pub fn set_vring(
        &self,
        idx: u32,
        num: u32,
        desc: u64,
        avail: u64,
        used: u64,
    ) -> io::Result<()> {
        let b = self.mem_base;
        ioctl_ref(
            &self.fd,
            VHOST_SET_VRING_NUM,
            &mut VringState { index: idx, num },
        )?;
        ioctl_ref(
            &self.fd,
            VHOST_SET_VRING_BASE,
            &mut VringState { index: idx, num: 0 },
        )?;
        ioctl_ref(
            &self.fd,
            VHOST_SET_VRING_ADDR,
            &mut VringAddr {
                index: idx,
                flags: 0,
                desc_user_addr: b + desc,
                used_user_addr: b + used,
                avail_user_addr: b + avail,
                log_guest_addr: 0,
            },
        )?;
        ioctl_ref(
            &self.fd,
            VHOST_SET_VRING_CALL,
            &mut VringFile { index: idx, fd: -1 },
        )?;
        ioctl_ref(
            &self.fd,
            VHOST_SET_VRING_KICK,
            &mut VringFile {
                index: idx,
                fd: self.kick[idx as usize].as_raw_fd(),
            },
        )
    }

    pub fn start(&self) -> io::Result<()> {
        let mut on = 1i32;
        ioctl_ref(&self.fd, VHOST_VSOCK_SET_RUNNING, &mut on)
    }

    pub fn kick(&self, idx: u32) -> io::Result<()> {
        let buf = 1u64.to_ne_bytes();
        let r = unsafe { libc::write(self.kick[idx as usize].as_raw_fd(), buf.as_ptr().cast(), 8) };
        if r == 8 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
}

fn eventfd() -> io::Result<OwnedFd> {
    let r = unsafe { libc::eventfd(0, libc::EFD_NONBLOCK | libc::EFD_CLOEXEC) };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { std::os::fd::FromRawFd::from_raw_fd(r) })
}

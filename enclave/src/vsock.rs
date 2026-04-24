//! Single-connection virtio-vsock STREAM server, polling.
//!
//! Just enough to accept one host connection and exchange 64-byte CTAP HID
//! reports: the bridge writes exactly 64 bytes per `write()`, and Linux
//! vsock has no Nagle, so each RX RW packet carries exactly one report and
//! we avoid a stream reassembly buffer entirely. Anything else (SEQPACKET,
//! multiple connections, partial reads) is out of scope.

use core::mem::size_of;
use core::ptr::addr_of_mut;

use crate::virtio::{Mmio, Virtq, MMIO_BASE, Q};

const DEVICE_ID_VSOCK: u32 = 19;
const TYPE_STREAM: u16 = 1;

const OP_REQUEST: u16 = 1;
const OP_RESPONSE: u16 = 2;
const OP_RST: u16 = 3;
const OP_SHUTDOWN: u16 = 4;
const OP_RW: u16 = 5;
const OP_CREDIT_UPDATE: u16 = 6;
const OP_CREDIT_REQUEST: u16 = 7;

/// Advertised receive buffer; effectively unlimited for 64-byte reports.
const BUF_ALLOC: u32 = 64 * 1024;
const RX_BUF: usize = 256;

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct Hdr {
    src_cid: u64,
    dst_cid: u64,
    src_port: u32,
    dst_port: u32,
    len: u32,
    typ: u16,
    op: u16,
    flags: u32,
    buf_alloc: u32,
    fwd_cnt: u32,
}
const HDR: usize = size_of::<Hdr>();
const _: () = assert!(HDR == 44);

struct Peer {
    cid: u64,
    port: u32,
    buf_alloc: u32,
    fwd_cnt: u32,
}

#[repr(C, align(4096))]
pub struct Vsock {
    rxq: Virtq,
    txq: Virtq,
    evq: Virtq,
    rx_bufs: [[u8; RX_BUF]; Q],
    ev_buf: [u8; 8],
    tx_hdr: Hdr,
    tx_data: [u8; 64],
    mmio: Mmio,
    cid: u64,
    port: u32,
    peer: Option<Peer>,
    fwd_cnt: u32,
    tx_cnt: u32,
}

impl Vsock {
    const fn empty() -> Self {
        Self {
            rxq: Virtq::new(),
            txq: Virtq::new(),
            evq: Virtq::new(),
            rx_bufs: [[0; RX_BUF]; Q],
            ev_buf: [0; 8],
            tx_hdr: Hdr {
                src_cid: 0,
                dst_cid: 0,
                src_port: 0,
                dst_port: 0,
                len: 0,
                typ: 0,
                op: 0,
                flags: 0,
                buf_alloc: 0,
                fwd_cnt: 0,
            },
            tx_data: [0; 64],
            // SAFETY: overwritten in `init` before any access.
            mmio: unsafe { Mmio::new(0) },
            cid: 0,
            port: 0,
            peer: None,
            fwd_cnt: 0,
            tx_cnt: 0,
        }
    }

    fn init(&mut self, mmio: Mmio, port: u32) {
        mmio.begin_init();
        self.cid = mmio.config_read64(0);
        self.port = port;
        self.rxq.init_free();
        self.txq.init_free();
        self.evq.init_free();
        mmio.setup_queue(0, &self.rxq);
        mmio.setup_queue(1, &self.txq);
        mmio.setup_queue(2, &self.evq);
        mmio.driver_ok();

        for i in 0..Q {
            self.rxq
                .push_write(self.rx_bufs[i].as_mut_ptr(), RX_BUF as u32);
        }
        mmio.notify(0);
        self.evq.push_write(self.ev_buf.as_mut_ptr(), 8);
        mmio.notify(2);

        self.mmio = mmio;
    }

    /// Send one packet, busy-waiting for the device to consume it. Reusing a
    /// single TX slot is fine because CTAP is request/response.
    fn send(&mut self, op: u16, dst_cid: u64, dst_port: u32, data: &[u8]) {
        self.tx_hdr = Hdr {
            src_cid: self.cid,
            dst_cid,
            src_port: self.port,
            dst_port,
            len: data.len() as u32,
            typ: TYPE_STREAM,
            op,
            flags: 0,
            buf_alloc: BUF_ALLOC,
            fwd_cnt: self.fwd_cnt,
        };
        let hdr = addr_of_mut!(self.tx_hdr) as *const u8;
        if data.is_empty() {
            self.txq.push_read(hdr, HDR as u32);
        } else {
            self.tx_data[..data.len()].copy_from_slice(data);
            self.txq
                .push_read2(hdr, HDR as u32, self.tx_data.as_ptr(), data.len() as u32);
        }
        self.mmio.notify(1);
        while self.txq.pop_used().is_none() {
            core::hint::spin_loop();
        }
        if op == OP_RW {
            self.tx_cnt = self.tx_cnt.wrapping_add(data.len() as u32);
        }
    }

    fn send_peer(&mut self, op: u16, data: &[u8]) {
        let p = self.peer.as_ref().unwrap();
        let (cid, port) = (p.cid, p.port);
        self.send(op, cid, port, data);
    }

    fn credit(&self) -> u32 {
        let p = self.peer.as_ref().unwrap();
        p.buf_alloc
            .wrapping_sub(self.tx_cnt.wrapping_sub(p.fwd_cnt))
    }

    /// Block until the next 64-byte report from the peer. Handles connection
    /// setup and credit bookkeeping inline.
    pub fn read_report(&mut self, out: &mut [u8; 64]) {
        loop {
            let Some((head, written, _)) = self.rxq.pop_used() else {
                core::hint::spin_loop();
                continue;
            };
            let bufp = self.rx_bufs[head as usize].as_mut_ptr();
            let buf = &self.rx_bufs[head as usize];
            // Re-post the slot before any early `continue`.
            macro_rules! repost {
                () => {{
                    self.rxq.push_write(bufp, RX_BUF as u32);
                    self.mmio.notify(0);
                }};
            }
            if (written as usize) < HDR {
                repost!();
                continue;
            }
            let hdr: Hdr = unsafe { core::ptr::read_unaligned(buf.as_ptr() as *const Hdr) };
            let len = hdr.len as usize;

            if hdr.dst_port != self.port || hdr.typ != TYPE_STREAM {
                self.send(OP_RST, hdr.src_cid, hdr.src_port, &[]);
                repost!();
                continue;
            }

            if let Some(p) = &mut self.peer {
                p.buf_alloc = hdr.buf_alloc;
                p.fwd_cnt = hdr.fwd_cnt;
            }

            match (hdr.op, self.peer.is_some()) {
                (OP_REQUEST, false) => {
                    self.peer = Some(Peer {
                        cid: hdr.src_cid,
                        port: hdr.src_port,
                        buf_alloc: hdr.buf_alloc,
                        fwd_cnt: hdr.fwd_cnt,
                    });
                    self.fwd_cnt = 0;
                    self.tx_cnt = 0;
                    self.send_peer(OP_RESPONSE, &[]);
                }
                (OP_REQUEST, true) => {
                    self.send(OP_RST, hdr.src_cid, hdr.src_port, &[]);
                }
                (OP_RW, true) if len == 64 && (written as usize) >= HDR + 64 => {
                    out.copy_from_slice(&buf[HDR..HDR + 64]);
                    self.fwd_cnt = self.fwd_cnt.wrapping_add(64);
                    repost!();
                    return;
                }
                (OP_RW, true) => {
                    // Non-64-byte payload breaks our framing assumption; the
                    // only sane recovery is to drop the connection.
                    self.fwd_cnt = self.fwd_cnt.wrapping_add(len as u32);
                    self.send_peer(OP_RST, &[]);
                    self.peer = None;
                }
                (OP_CREDIT_REQUEST, true) => self.send_peer(OP_CREDIT_UPDATE, &[]),
                (OP_SHUTDOWN, true) | (OP_RST, true) => {
                    self.send_peer(OP_RST, &[]);
                    self.peer = None;
                }
                _ => {}
            }
            repost!();
        }
    }

    pub fn write_report(&mut self, data: &[u8; 64]) {
        if self.peer.is_none() {
            return;
        }
        while self.credit() < 64 {
            self.send_peer(OP_CREDIT_REQUEST, &[]);
            // Peer's CREDIT_UPDATE arrives on RX; drain without consuming
            // RW (CTAP is half-duplex so there is none in flight).
            let mut dummy = [0u8; 64];
            self.read_report(&mut dummy);
        }
        self.send_peer(OP_RW, data);
    }
}

// `Virtq` alone is 4 KiB-aligned and there are three of them; this struct is
// far too large for our 32 KiB stack, so it lives in BSS.
static mut INSTANCE: Vsock = Vsock::empty();

/// Find the vsock device on any of QEMU microvm's MMIO slots and bring it up.
pub fn init(port: u32) -> Option<&'static mut Vsock> {
    let v = unsafe { &mut *addr_of_mut!(INSTANCE) };
    for slot in 0..32 {
        let m = unsafe { Mmio::new(MMIO_BASE + slot * 512) };
        if m.probe() == Some(DEVICE_ID_VSOCK) {
            v.init(m, port);
            return Some(v);
        }
    }
    None
}

pub fn guest_cid(v: &Vsock) -> u64 {
    v.cid
}

//! Top-level state machine: CTAPHID reassembly + command dispatch.

use crate::cred::MasterKeys;
use crate::ctap2;
use crate::hid::{self, Report, CID_BROADCAST};
use alloc::vec::Vec;

/// Hooks the embedder must provide. Kept deliberately tiny so the unikernel
/// implementation is a few lines.
pub trait Platform {
    /// Fill `buf` with cryptographically random bytes.
    fn random_bytes(&mut self, buf: &mut [u8]);
    /// 32-byte device secret from which all credential keys are derived.
    /// In the simulator this is random-at-boot; under SEV-SNP it is the
    /// PSP-derived key bound to the launch measurement.
    fn master_secret(&self) -> [u8; 32];
    /// Hardware attestation evidence to embed in `attStmt` under `key`
    /// (`"snp"`/`"sgx"`), or `None` for plain self-attestation.
    /// `report_data` is `SHA-512(authData || clientDataHash)` so the
    /// evidence binds to this exact registration.
    fn attestation(&mut self, report_data: &[u8; 64]) -> Option<(&'static str, Vec<u8>)> {
        let _ = report_data;
        None
    }
}

struct Pending {
    cid: u32,
    cmd: u8,
    buf: Vec<u8>,
    want: usize,
    next_seq: u8,
}

pub struct Authenticator<P: Platform> {
    platform: P,
    aaguid: [u8; 16],
    keys: MasterKeys,
    pending: Option<Pending>,
}

impl<P: Platform> Authenticator<P> {
    pub fn new(platform: P, aaguid: [u8; 16]) -> Self {
        let keys = MasterKeys::derive(&platform.master_secret());
        Self {
            platform,
            aaguid,
            keys,
            pending: None,
        }
    }

    /// Feed one 64-byte HID OUTPUT report; returns zero or more INPUT reports.
    pub fn process_report(&mut self, report: &Report) -> Vec<Report> {
        let cid = u32::from_be_bytes(report[0..4].try_into().unwrap());
        if cid == 0 {
            return hid::error(cid, hid::ERR_INVALID_CHANNEL);
        }
        let b4 = report[4];

        if b4 & 0x80 != 0 {
            let cmd = b4 & 0x7F;
            let bcnt = u16::from_be_bytes([report[5], report[6]]) as usize;

            // INIT is special: single packet, must be answered even while
            // another channel is mid-transaction (spec §11.2.9.1.3).
            if cmd == hid::CTAPHID_INIT {
                if let Some(p) = &self.pending {
                    if p.cid == cid {
                        self.pending = None;
                    }
                }
                if bcnt != 8 {
                    return hid::error(cid, hid::ERR_INVALID_LEN);
                }
                return self.handle_init(cid, &report[7..15]);
            }

            if bcnt > hid::MAX_MESSAGE_SIZE {
                return hid::error(cid, hid::ERR_INVALID_LEN);
            }
            if cid == CID_BROADCAST {
                return hid::error(cid, hid::ERR_INVALID_CHANNEL);
            }
            if let Some(p) = &self.pending {
                if p.cid != cid {
                    return hid::error(cid, hid::ERR_CHANNEL_BUSY);
                }
                // Same channel restarting; the half-assembled buffer is
                // discarded when `self.pending` is overwritten below.
            }

            let take = bcnt.min(hid::INIT_DATA_SIZE);
            let mut buf = Vec::with_capacity(bcnt);
            buf.extend_from_slice(&report[7..7 + take]);
            if buf.len() >= bcnt {
                self.pending = None;
                return self.dispatch(cid, cmd, buf);
            }
            self.pending = Some(Pending {
                cid,
                cmd,
                buf,
                want: bcnt,
                next_seq: 0,
            });
            Vec::new()
        } else {
            let seq = b4;
            let Some(p) = self.pending.as_mut() else {
                // Spurious CONT: spec says ignore.
                return Vec::new();
            };
            if p.cid != cid {
                return hid::error(cid, hid::ERR_CHANNEL_BUSY);
            }
            if seq != p.next_seq {
                self.pending = None;
                return hid::error(cid, hid::ERR_INVALID_SEQ);
            }
            let remaining = p.want - p.buf.len();
            let take = remaining.min(hid::CONT_DATA_SIZE);
            p.buf.extend_from_slice(&report[5..5 + take]);
            p.next_seq = p.next_seq.wrapping_add(1);
            if p.buf.len() >= p.want {
                let p = self.pending.take().unwrap();
                return self.dispatch(p.cid, p.cmd, p.buf);
            }
            Vec::new()
        }
    }

    fn dispatch(&mut self, cid: u32, cmd: u8, payload: Vec<u8>) -> Vec<Report> {
        match cmd {
            hid::CTAPHID_PING => hid::fragment(cid, hid::CTAPHID_PING, &payload),
            hid::CTAPHID_WINK => hid::fragment(cid, hid::CTAPHID_WINK, &[]),
            hid::CTAPHID_CBOR => {
                let mut cx = ctap2::Ctx {
                    platform: &mut self.platform,
                    aaguid: &self.aaguid,
                    keys: &self.keys,
                };
                let resp = ctap2::handle(&mut cx, &payload);
                hid::fragment(cid, hid::CTAPHID_CBOR, &resp)
            }
            hid::CTAPHID_CANCEL => Vec::new(),
            // CTAP1 (`CTAPHID_MSG`) intentionally unsupported for now; we
            // advertise CAPABILITY_NMSG so compliant clients won't try.
            _ => hid::error(cid, hid::ERR_INVALID_CMD),
        }
    }

    fn handle_init(&mut self, cid: u32, nonce: &[u8]) -> Vec<Report> {
        let new_cid = if cid == CID_BROADCAST {
            self.alloc_cid()
        } else {
            cid
        };
        let mut resp = [0u8; 17];
        resp[0..8].copy_from_slice(nonce);
        resp[8..12].copy_from_slice(&new_cid.to_be_bytes());
        resp[12] = 2; // CTAPHID protocol version
        resp[13] = 0; // device version major
        resp[14] = 0; // minor
        resp[15] = 1; // build
        resp[16] = hid::CAPABILITY_CBOR | hid::CAPABILITY_WINK | hid::CAPABILITY_NMSG;
        hid::fragment(cid, hid::CTAPHID_INIT, &resp)
    }

    fn alloc_cid(&mut self) -> u32 {
        loop {
            let mut b = [0u8; 4];
            self.platform.random_bytes(&mut b);
            let c = u32::from_be_bytes(b);
            if c != 0 && c != CID_BROADCAST {
                return c;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hid::*;

    struct Counter(u32);
    impl Platform for Counter {
        fn random_bytes(&mut self, buf: &mut [u8]) {
            self.0 = self.0.wrapping_add(1);
            let src = self.0.to_be_bytes();
            for (i, b) in buf.iter_mut().enumerate() {
                *b = src[i % 4];
            }
        }
        fn master_secret(&self) -> [u8; 32] {
            [0u8; 32]
        }
    }

    fn auth() -> Authenticator<Counter> {
        Authenticator::new(Counter(0x1000_0000), crate::AAGUID)
    }

    fn feed(a: &mut Authenticator<Counter>, pkts: Vec<Report>) -> Vec<Report> {
        let mut out = Vec::new();
        for p in pkts {
            out.extend(a.process_report(&p));
        }
        out
    }

    #[test]
    fn init_allocates_channel() {
        let mut a = auth();
        let nonce = [1, 2, 3, 4, 5, 6, 7, 8];
        let out = feed(&mut a, fragment(CID_BROADCAST, CTAPHID_INIT, &nonce));
        assert_eq!(out.len(), 1);
        let r = &out[0];
        assert_eq!(
            u32::from_be_bytes(r[0..4].try_into().unwrap()),
            CID_BROADCAST
        );
        assert_eq!(r[4], 0x80 | CTAPHID_INIT);
        assert_eq!(u16::from_be_bytes([r[5], r[6]]), 17);
        assert_eq!(&r[7..15], &nonce);
        let cid = u32::from_be_bytes(r[15..19].try_into().unwrap());
        assert_ne!(cid, 0);
        assert_ne!(cid, CID_BROADCAST);
    }

    #[test]
    fn ping_roundtrip_multi_packet() {
        let mut a = auth();
        let payload: Vec<u8> = (0..200).map(|i| i as u8).collect();
        let out = feed(&mut a, fragment(0x1234_5678, CTAPHID_PING, &payload));
        assert_eq!(out, fragment(0x1234_5678, CTAPHID_PING, &payload));
    }

    #[test]
    fn busy_channel_rejected() {
        let mut a = auth();
        // Start a 200-byte PING on cid A but only send the first packet.
        let pkts = fragment(0xAAAA_AAAA, CTAPHID_PING, &[0u8; 200]);
        assert!(a.process_report(&pkts[0]).is_empty());
        // Another channel tries to barge in.
        let out = feed(&mut a, fragment(0xBBBB_BBBB, CTAPHID_PING, &[0u8; 4]));
        assert_eq!(out.len(), 1);
        assert_eq!(out[0][4], 0x80 | CTAPHID_ERROR);
        assert_eq!(out[0][7], ERR_CHANNEL_BUSY);
    }

    #[test]
    fn cbor_routes_to_ctap2() {
        let mut a = auth();
        let out = feed(&mut a, fragment(0x42, CTAPHID_CBOR, &[ctap2::CMD_GET_INFO]));
        assert_eq!(out.len(), 1);
        assert_eq!(out[0][4], 0x80 | CTAPHID_CBOR);
        assert_eq!(out[0][7], ctap2::status::OK);
    }
}

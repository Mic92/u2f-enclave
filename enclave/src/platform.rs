//! `ctap::Platform` for the bare-metal target.

use alloc::vec::Vec;
use core::arch::x86_64::_rdrand64_step;

use crate::{greq, sev};

pub struct BareMetal {
    master: [u8; 32],
    snp: bool,
}

impl BareMetal {
    pub fn new() -> Self {
        if sev::active() {
            // Survives restarts; see `greq::derived_key`.
            if let Some(master) = greq::derived_key() {
                crate::serial::print("u2f-enclave: PSP-derived master key\n");
                return Self { master, snp: true };
            }
            crate::serial::print("u2f-enclave: MSG_KEY_REQ failed; ephemeral key\n");
        }
        // Plain-VM dev path: ephemeral.
        let mut master = [0u8; 32];
        fill_rdrand(&mut master);
        Self { master, snp: false }
    }
}

impl ctap::Platform for BareMetal {
    fn random_bytes(&mut self, buf: &mut [u8]) {
        fill_rdrand(buf);
    }
    fn master_secret(&self) -> [u8; 32] {
        self.master
    }
    fn attestation(&mut self, report_data: &[u8; 64]) -> Option<Vec<u8>> {
        if !self.snp {
            return None;
        }
        greq::report(report_data).map(|r| r.to_vec())
    }
}

/// RDRAND is inside the SEV-SNP trust boundary (the DRNG is on-die and not
/// hypervisor-mediated), so it is an acceptable entropy source here.
fn fill_rdrand(buf: &mut [u8]) {
    for chunk in buf.chunks_mut(8) {
        let mut v = 0u64;
        // Retry on transient underflow; the SDM bounds this at a handful of
        // iterations in practice.
        while unsafe { _rdrand64_step(&mut v) } != 1 {}
        chunk.copy_from_slice(&v.to_ne_bytes()[..chunk.len()]);
    }
}

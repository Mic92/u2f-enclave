//! CTAP2 command layer (carried inside `CTAPHID_CBOR`).

use crate::cbor::Writer;
use alloc::vec;
use alloc::vec::Vec;

// Command bytes (first byte of the CBOR request).
pub const CMD_MAKE_CREDENTIAL: u8 = 0x01;
pub const CMD_GET_ASSERTION: u8 = 0x02;
pub const CMD_GET_INFO: u8 = 0x04;
pub const CMD_CLIENT_PIN: u8 = 0x06;
pub const CMD_RESET: u8 = 0x07;

/// CTAP status codes (subset).
pub mod status {
    pub const OK: u8 = 0x00;
    pub const ERR_INVALID_COMMAND: u8 = 0x01;
    pub const ERR_INVALID_LENGTH: u8 = 0x03;
    pub const ERR_OPERATION_DENIED: u8 = 0x27;
    pub const ERR_NO_CREDENTIALS: u8 = 0x2E;
}

/// Dispatch a CTAP2 request. Returns `status || optional_cbor`.
pub fn handle(aaguid: &[u8; 16], payload: &[u8]) -> Vec<u8> {
    let Some((&cmd, _params)) = payload.split_first() else {
        return vec![status::ERR_INVALID_LENGTH];
    };
    match cmd {
        CMD_GET_INFO => get_info(aaguid),
        // M1: real implementations. For now return well-formed errors so a
        // probing client (e.g. `fido2-token -I`) gets sane behaviour.
        CMD_MAKE_CREDENTIAL => vec![status::ERR_OPERATION_DENIED],
        CMD_GET_ASSERTION => vec![status::ERR_NO_CREDENTIALS],
        CMD_RESET => vec![status::OK],
        _ => vec![status::ERR_INVALID_COMMAND],
    }
}

fn get_info(aaguid: &[u8; 16]) -> Vec<u8> {
    let mut w = Writer::with_prefix(status::OK);
    w.map(3);
    // 0x01: versions
    w.unsigned(0x01);
    w.array(1);
    w.text("FIDO_2_0");
    // 0x03: aaguid
    w.unsigned(0x03);
    w.bytes(aaguid);
    // 0x04: options
    w.unsigned(0x04);
    w.map(2);
    w.text("rk");
    w.bool(false);
    w.text("up");
    w.bool(true);
    w.into_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_info_is_canonical_cbor() {
        let r = handle(&[0xAA; 16], &[CMD_GET_INFO]);
        assert_eq!(r[0], status::OK);
        // map(3), key 1, array(1), text(8) "FIDO_2_0"
        assert_eq!(&r[1..4], &[0xA3, 0x01, 0x81]);
        assert_eq!(r[4], 0x68);
        assert_eq!(&r[5..13], b"FIDO_2_0");
        // key 3, bytes(16)
        assert_eq!(&r[13..15], &[0x03, 0x50]);
        assert_eq!(&r[15..31], &[0xAA; 16]);
        // key 4, map(2)
        assert_eq!(&r[31..33], &[0x04, 0xA2]);
    }
}

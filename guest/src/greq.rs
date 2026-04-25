//! SNP guest↔PSP messaging (`SVM_VMGEXIT_GUEST_REQUEST`).
//!
//! The PSP injects VMPCK0..3 (AES-256-GCM keys) into the secrets page at
//! launch; every request/response is wrapped with one so the hypervisor
//! can forward but not read or forge. KVM handles the NAE event entirely
//! in-kernel (`snp_handle_guest_req`: `kvm_read_guest` → PSP →
//! `kvm_write_guest`), so the host sees nothing.
//!
//! Refs: SNP firmware ABI §7 (guest messages), §8.14 (secrets page); Linux
//! `arch/x86/coco/sev/core.c::enc_payload`/`verify_and_dec_payload`.

use core::ptr::{addr_of, addr_of_mut, copy_nonoverlapping};

use aes_gcm::aead::AeadInPlace;
use aes_gcm::{Aes256Gcm, KeyInit};

use crate::sev::{self, Page};

/// Fixed GPA where the host injects `SNP_PAGE_TYPE_SECRETS`. Sits below 1 MiB
/// (outside the loaded ELF) and inside the 2 MiB PT0 window.
const SECRETS_GPA: u64 = 0x1000;
const VMPCK0_OFF: usize = 32; // version,flags,fms,rsvd,gosvw[16] precede it

const HDR_LEN: usize = 96;
const AAD_OFF: usize = 48; // algo field; everything from here to HDR_LEN is AAD
const AAD_LEN: usize = HDR_LEN - AAD_OFF;

const MSG_KEY_REQ: u8 = 3;
const MSG_REPORT_REQ: u8 = 5;

pub const REPORT_LEN: usize = 1184;

/// Mix `policy | measurement` into the derived key so it is bound to this
/// exact binary on this exact policy. The VCEK root is already chip-unique.
const KEY_FIELD_SELECT: u64 = (1 << 0) | (1 << 3);

/// Request/response pages must be shared so KVM's `kvm_{read,write}_guest`
/// see the (already-encrypted) bytes via the memslot's userspace_addr.
static mut REQ: Page = Page::ZERO;
static mut RESP: Page = Page::ZERO;
/// Private staging: requests are built+encrypted here before copying to
/// `REQ`, and responses are copied here from `RESP` before any header check
/// or decrypt — keeps both directions out of the host's race window.
static mut PRIV: Page = Page::ZERO;

static mut VMPCK: [u8; 32] = [0; 32];
static mut SEQNO: u64 = 1;

/// Read VMPCK0 out of the secrets page and flip the staging pages to shared.
/// Must run after `sev::init` (PT0/C-bit are up).
pub fn init() {
    // The secrets page is private and PSP-validated at launch; a plain read
    // through the C=1 mapping is correct.
    let s = (SECRETS_GPA + VMPCK0_OFF as u64) as *const u8;
    unsafe { copy_nonoverlapping(s, addr_of_mut!(VMPCK) as *mut u8, 32) };
    sev::share(addr_of!(REQ) as u64, 4096);
    sev::share(addr_of!(RESP) as u64, 4096);
}

/// IV = `msg_seqno` zero-extended to 12; AAD = header from `algo` onward.
fn iv_aad(m: &[u8; 4096]) -> ([u8; 12], [u8; AAD_LEN]) {
    let mut iv = [0u8; 12];
    iv[..8].copy_from_slice(&m[32..40]);
    (iv, m[AAD_OFF..HDR_LEN].try_into().unwrap())
}

/// One AES-GCM-wrapped round trip to the PSP. On success the decrypted
/// response payload sits at `&PRIV[HDR_LEN..]`; the caller knows its layout.
fn call(msg_type: u8, payload: &[u8]) -> Result<(), ()> {
    let seq = unsafe { SEQNO };
    let cipher = Aes256Gcm::new(unsafe { &*addr_of!(VMPCK) }.into());

    // Build and encrypt in the *private* staging page so the host never
    // observes plaintext nor a partially-built header.
    let m = unsafe { &mut (*addr_of_mut!(PRIV)).0 };
    m.fill(0);
    m[32..40].copy_from_slice(&seq.to_le_bytes()); // msg_seqno
    m[48] = 1; // algo = AES-256-GCM
    m[49] = 1; // hdr_version
    m[50..52].copy_from_slice(&(HDR_LEN as u16).to_le_bytes());
    m[52] = msg_type;
    m[53] = 1; // msg_version
    m[54..56].copy_from_slice(&(payload.len() as u16).to_le_bytes());
    // 56..60 rsvd, 60 vmpck=0, 61..96 rsvd
    m[HDR_LEN..HDR_LEN + payload.len()].copy_from_slice(payload);

    let (iv, aad) = iv_aad(m);
    let tag = cipher
        .encrypt_in_place_detached((&iv).into(), &aad, &mut m[HDR_LEN..HDR_LEN + payload.len()])
        .map_err(|_| ())?;
    m[..16].copy_from_slice(&tag);

    // Commit the IV *before* the ciphertext becomes host-visible: a
    // malicious host that fakes a VMM error to make us retry must not get a
    // second ciphertext under the same (key, IV) — that would leak the GHASH
    // key. The PSP may then reject our next seqno; that's DoS, not a leak.
    unsafe { SEQNO += 2 };
    unsafe { &mut (*addr_of_mut!(REQ)).0 }.copy_from_slice(m);

    if sev::guest_request(addr_of!(REQ) as u64, addr_of!(RESP) as u64) != 0 {
        // Low 32 = PSP firmware error; high 32 = VMM error (e.g. busy).
        return Err(());
    }

    // Copy out of shared memory before inspecting anything.
    m.copy_from_slice(unsafe { &(*addr_of!(RESP)).0 });

    let sz = u16::from_le_bytes([m[54], m[55]]) as usize;
    if u64::from_le_bytes(m[32..40].try_into().unwrap()) != seq + 1
        || m[52] != msg_type + 1
        || HDR_LEN + sz > 4096
    {
        return Err(());
    }
    let (iv, aad) = iv_aad(m);
    let tag: [u8; 16] = m[..16].try_into().unwrap();
    cipher
        .decrypt_in_place_detached(
            (&iv).into(),
            &aad,
            &mut m[HDR_LEN..HDR_LEN + sz],
            &tag.into(),
        )
        .map_err(|_| ())?;

    // Every response payload starts with a u32 status; non-zero = PSP refused
    // the inner request (e.g. bad VMPL).
    if u32::from_le_bytes(m[HDR_LEN..HDR_LEN + 4].try_into().unwrap()) != 0 {
        return Err(());
    }
    Ok(())
}

/// Hardware attestation: 1184-byte report whose `report_data` field is
/// `user_data`, signed by the chip's VCEK.
pub fn report(user_data: &[u8; 64]) -> Option<[u8; REPORT_LEN]> {
    // MSG_REPORT_REQ = user_data[64] || vmpl u32 || rsvd[28]
    let mut req = [0u8; 96];
    req[..64].copy_from_slice(user_data);
    call(MSG_REPORT_REQ, &req).ok()?;
    // MSG_REPORT_RSP = status u32 || report_size u32 || rsvd[24] || report
    let p = unsafe { &(*addr_of!(PRIV)).0 };
    let mut out = [0u8; REPORT_LEN];
    out.copy_from_slice(&p[HDR_LEN + 32..HDR_LEN + 32 + REPORT_LEN]);
    Some(out)
}

/// 32-byte key the PSP derives from the chip's VCEK root mixed with this
/// guest's launch measurement and policy.  Same binary on same chip ⇒ same
/// key across reboots, so it works as the KEK that seals the random master
/// to disk.  Different binary ⇒ different KEK ⇒ unseal tag fails.
pub fn derived_key() -> Option<[u8; 32]> {
    // MSG_KEY_REQ = root_key_select u32 || rsvd u32 || guest_field_select u64
    //             || vmpl u32 || guest_svn u32 || tcb_version u64
    let mut req = [0u8; 32];
    req[8..16].copy_from_slice(&KEY_FIELD_SELECT.to_le_bytes());
    call(MSG_KEY_REQ, &req).ok()?;
    // MSG_KEY_RSP = status u32 || rsvd[28] || key[32]
    let p = unsafe { &(*addr_of!(PRIV)).0 };
    let mut out = [0u8; 32];
    out.copy_from_slice(&p[HDR_LEN + 32..HDR_LEN + 64]);
    Some(out)
}

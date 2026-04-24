# u2f-enclave

A FIDO2/CTAP2 authenticator that runs as its own **confidential VM** (AMD
SEV-SNP, later Intel TDX) instead of as a USB dongle. The private keys never
leave VM-encrypted memory; the guest OS that wants to authenticate talks to it
over **vsock** and sees a normal `/dev/hidraw` FIDO device via a tiny uhid
bridge.

This is an open re-implementation of the idea behind *Hardware Authenticator
Binding* (Shiraishi & Shinagawa, COMPSAC 2025), built from scratch with a
minimal TCB rather than a fork of an existing SVSM.

```
┌──────────── consumer VM ───────────┐      ┌──── authenticator CVM (SEV-SNP) ───┐
│ browser → libfido2 → /dev/hidrawN  │      │                                    │
│                       ▲            │      │   ┌──────────────────────────┐     │
│                  uhid │            │      │   │  ctap (no_std)           │     │
│                ┌──────┴─────┐ vsock│◄────►│   │  CTAPHID + CTAP2 + keys  │     │
│                │  bridge    │──────┼──────┼──►│                          │     │
│                └────────────┘      │      │   └──────────────────────────┘     │
└────────────────────────────────────┘      │   SNP attestation report → attStmt │
                                            └────────────────────────────────────┘
```

## Crates

| crate    | target            | purpose                                                            |
| -------- | ----------------- | ------------------------------------------------------------------ |
| `ctap`   | `no_std` + alloc  | CTAPHID framing, CTAP2 commands, credential logic. Platform-agnostic, unit-tested on the host. |
| `sim`    | std (Linux/macOS) | Runs `ctap` over a Unix socket so the full stack can be exercised without SEV-SNP hardware. |
| `bridge` | std (Linux)       | Consumer-side daemon: connects to the authenticator socket and exposes it as a HID device via `/dev/uhid`. |
| `enclave`| `no_std` (TODO)   | The actual unikernel: boots as an SNP guest, drives virtio-vsock, requests attestation reports. See `enclave/DESIGN.md`. |

## Status / milestones

- **M0** – CTAPHID transport, `CTAPHID_INIT`/`PING`/`WINK`, CTAP2 `getInfo`.
- **M1** – `makeCredential` / `getAssertion` (ES256 via RustCrypto `p256`),
  stateless non-resident credentials, `fmt:"packed"` self-attestation.
  Verified against two independent stacks: Yubico `libfido2` and OpenSSH
  `sk-ecdsa` keygen+login (`cargo test -p e2e`).
- **M2 (in progress)** – bare-metal unikernel. PVH boot + hand-rolled
  virtio-mmio/vsock done: the `e2e::libfido2_kernel` test runs the full
  `libfido2` register/assert sequence against a ~100 KB `x86_64-unknown-none`
  ELF over `vhost-vsock`. Remaining: SEV-SNP `#VC`/GHCB + attestation report
  (needs an EPYC host).
- **M3** – resident keys, `clientPIN`, TDX.

## Try it (host simulation)

```bash
# terminal 1: authenticator (defaults to $XDG_RUNTIME_DIR/u2f-enclave.sock)
cargo run -p sim

# terminal 2: expose as /dev/hidrawN (needs rw on /dev/uhid)
sudo setfacl -m u:$USER:rw /dev/uhid
cargo run -p bridge

# terminal 3
fido2-token -L          # should list "u2f-enclave"
```

The full interop suite (libfido2 + OpenSSH against both `sim` and the
bare-metal kernel under QEMU) is `cargo test -p e2e`. Tests that need
`/dev/uhid` or `/dev/vhost-vsock` print `SKIP` and pass if those are not
writable, so plain `cargo test` works everywhere.

Same thing over AF_VSOCK (the transport the real enclave uses; CID 1 is the
kernel loopback so no VM is needed):

```bash
cargo run -p sim -- vsock:5995 &
cargo run -p bridge -- vsock:1:5995
```

## References

- CTAP 2.1 spec: <https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html>
- COCONUT-SVSM (SEV-SNP guest reference, MIT): <https://github.com/coconut-svsm/svsm>
- AMD SEV-SNP ABI spec: <https://www.amd.com/system/files/TechDocs/56860.pdf>

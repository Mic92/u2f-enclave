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
| `sim`    | std (Linux/macOS) | Runs `ctap` over a Unix socket so the full stack can be exercised without KVM/SEV hardware. |
| `bridge` | std (Linux)       | Consumer-side daemon: connects to the authenticator socket and exposes it as a HID device via `/dev/uhid`. |
| `vmm`    | std (Linux)       | The deployable: single binary that embeds the enclave ELF, launches it under KVM (no firmware), wires its virtqueues to `/dev/vhost-vsock`, and runs the uhid bridge in-process. With `--snp` the launch is encrypted+measured. `./vmm` → `/dev/hidrawN` FIDO2 device. |
| `enclave`| `no_std`          | The unikernel: PVH-boots, brings up a paravirt GHCB, hand-rolls virtio-vsock, serves CTAP. Cross-built and baked into `vmm` by `build.rs`. See `enclave/DESIGN.md`. |
| `e2e`    | std               | Integration tests that drive `libfido2` and OpenSSH against `sim` and `vmm` (plain and `--snp`). |

## Status / milestones

- **M0** – CTAPHID transport, `CTAPHID_INIT`/`PING`/`WINK`, CTAP2 `getInfo`.
- **M1** – `makeCredential` / `getAssertion` (ES256 via RustCrypto `p256`),
  stateless non-resident credentials, `fmt:"packed"` self-attestation.
  Verified against two independent stacks: Yubico `libfido2` and OpenSSH
  `sk-ecdsa` keygen+login (`cargo test -p e2e`).
- **M2 (done)** – bare-metal unikernel under SEV-SNP. Own ~1.1 kLoC KVM
  launcher (`KVM_SEV_*`, guest_memfd, vhost-vsock), own ~1.1 kLoC
  `x86_64-unknown-none` guest (PVH boot, paravirt GHCB IOIO/MMIO — no
  `#VC` handler — `PVALIDATE`/PSC, virtio-vsock over shared rings).
  ~110 KB of code, 436 KB measured launch image. `e2e::libfido2_vmm_snp`
  runs the full `libfido2` round-trip from inside encrypted RAM.
- **M3 (next)** – SNP attestation report in `attStmt`, expected-measurement
  computation, verifier; key persistence.
- **M4** – resident keys, `clientPIN`, TDX.

## Try it

```bash
sudo setfacl -m u:$USER:rw /dev/uhid /dev/vhost-vsock
cargo run -p vmm --release             # → /dev/hidrawN appears
fido2-token -L                         # "u2f-enclave"
ssh-keygen -t ecdsa-sk
```

On an EPYC host with SEV-SNP enabled in BIOS and `kvm_amd.sev_snp=Y`:

```bash
sudo setfacl -m u:$USER:rw /dev/sev
cargo run -p vmm --release -- --snp
```

No-KVM dev path (sim+bridge over a Unix socket):

```bash
cargo run -p sim &
cargo run -p bridge
```

`cargo test` runs the unit tests plus the e2e suite (libfido2 + OpenSSH).
Tests that need `/dev/kvm`, `/dev/uhid`, `/dev/vhost-vsock` or `/dev/sev`
print `SKIP` and pass if those are not writable.

## References

- CTAP 2.1 spec: <https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html>
- AMD GHCB spec rev 2.03: <https://www.amd.com/system/files/TechDocs/56421.pdf>
- AMD SEV-SNP ABI spec: <https://www.amd.com/system/files/TechDocs/56860.pdf>
- COCONUT-SVSM (SEV-SNP guest reference, MIT): <https://github.com/coconut-svsm/svsm>

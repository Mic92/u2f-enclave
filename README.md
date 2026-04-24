# u2f-enclave

A FIDO2/CTAP2 authenticator that runs as its own **confidential VM** (AMD
SEV-SNP, later Intel TDX) instead of as a USB dongle. Private keys never
leave VM-encrypted memory; the consumer talks to it over **vsock** and sees a
normal `/dev/hidraw` FIDO device via a tiny uhid bridge. Every
`makeCredential` carries an **SNP attestation report** that binds the new
credential's public key to the launch measurement of this exact binary.

Open re-implementation of the idea behind *Hardware Authenticator Binding*
(Shiraishi & Shinagawa, COMPSAC 2025), built from scratch with a minimal TCB
rather than as a fork of an existing SVSM.

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

## Usage

The whole project ships as a single ~800 KB Linux/x86_64 binary,
`u2f-enclave`, with the guest image baked in. Running it makes a
standard FIDO2 HID device appear; anything that speaks WebAuthn or CTAP2
(browsers, `ssh-keygen -t ecdsa-sk`, `pam_u2f`, `fido2-token`) will pick
it up like a USB key.

```console
$ # one-time: grant yourself the device nodes (or use a udev rule)
$ sudo setfacl -m u:$USER:rw /dev/kvm /dev/uhid /dev/vhost-vsock

$ u2f-enclave &
u2f-enclave: ready at /dev/hidraw3

$ fido2-token -L
/dev/hidraw3: vendor=0x1209, product=0x000a (u2f-enclave)

$ ssh-keygen -t ecdsa-sk
Generating public/private ecdsa-sk key pair.
...
```

Without `--snp` the guest runs as a plain KVM VM — functionally complete
and fine for development, but the host kernel is in the trust boundary
and keys do not survive a restart.

### Hardware-bound mode (SEV-SNP)

On an EPYC host (Milan or later) with SNP enabled in BIOS and `kvm_amd`
loaded with `sev_snp=Y`:

```console
$ sudo setfacl -m u:$USER:rw /dev/sev
$ u2f-enclave --snp &
u2f-enclave: SEV-SNP launch ok (492 KiB measured)
u2f-enclave: ready at /dev/hidraw3
```

Now the host cannot read the keys, every `makeCredential` carries a
PSP-signed attestation report, and the master secret is derived by the
PSP from this binary's launch measurement — same binary on same chip ⇒
same keys across restarts.

### For relying parties

```console
$ u2f-enclave --measure
70eabebbf79908ce762df385e22606ee97496e923305fd3fdff0f651309bf3dd463427edaa43dfa6092a1d365c6b6a8a
↑ expected SEV-SNP launch measurement for this build.
  An attStmt["snp"] report from `u2f-enclave --snp` carries this at
  bytes 0x90..0xc0; check it after verifying the VCEK signature.
inputs:
  guest image  0x100000..0x17b000 (492 KiB, 123 pages)
  entry        0x1000c8
  secrets gpa  0x1000
  vmsa gpa     0xfffffffff000
  c-bit        51
(also check report.policy == 0x30000; not part of this digest)
```

No AMD hardware required, no arguments — every input is fixed by the
binary. Run it in CI next to a reproducible build and you have the
allow-list value. The hex digest goes to stdout alone, so
`expected=$(u2f-enclave --measure)` works. See
[Attestation](#attestation-in-one-paragraph) below for the full check an
RP performs.

Run `u2f-enclave --help` for the rest.

## What's in the box

| crate    | target            | purpose                                                            |
| -------- | ----------------- | ------------------------------------------------------------------ |
| `ctap`   | `no_std` + alloc  | CTAPHID framing, CTAP2 commands, credential logic. Platform-agnostic, unit-tested on the host. |
| `enclave`| `no_std`          | The unikernel: PVH boot, paravirt GHCB (IOIO/MMIO/PSC/guest-request — no `#VC` handler), hand-rolled virtio-vsock, PSP attestation + derived-key. Cross-built and baked into `vmm` by `build.rs`. ~1.3 kLoC; see `enclave/DESIGN.md`. |
| `vmm`    | std (Linux)       | Builds the `u2f-enclave` binary: embeds the enclave ELF, launches it under KVM (`KVM_SEV_*`, guest_memfd, secrets-page), wires its virtqueues to `/dev/vhost-vsock`, runs the uhid bridge in-process, and recomputes the launch measurement offline. ~1.2 kLoC. |
| `bridge` | std (Linux)       | Consumer-side daemon: connects to the authenticator socket and exposes it as a HID device via `/dev/uhid`. Standalone for the cross-VM case; linked into `vmm` for the local case. |
| `sim`    | std (Linux/macOS) | Runs `ctap` over a Unix socket so the full stack can be exercised without KVM/SEV hardware. |
| `e2e`    | std               | Integration tests: drive `libfido2` and OpenSSH against `sim`/`vmm`; act as an SNP-aware relying party (raw-hidraw CTAPHID client, AMD KDS fetch, P-384 verify). |

No QEMU, no firmware, no IGVM, no `kvm-bindings`/`kvm-ioctls`, no SVSM
protocol, no `#VC` handler/instruction decoder. RustCrypto for the crypto.

## Attestation in one paragraph

`makeCredential` returns `fmt:"packed"` self-attestation (so stock
libfido2/WebAuthn verifiers accept it) with an extra `attStmt["snp"]`
byte string: a 1184-byte SNP attestation report whose
`report_data = SHA-512(authData ‖ clientDataHash)` — i.e. the same bytes the
ES256 self-attestation signs. A relying party that knows about the `"snp"`
key checks: report_data matches → P-384 signature verifies against the VCEK
for `(chip_id, reported_tcb)` from AMD KDS → `measurement` is on the
allow-list → done; the credential is bound to a genuine PSP-measured copy of
this binary. The master secret is the PSP-**derived key** with
`guest_field_select = policy|measurement`, so the same binary on the same
silicon yields the same key and credentials survive restarts with no
sealed-storage protocol. `vmm --measure` recomputes the expected digest
offline (no EPYC needed) so the allow-list can be derived from source.
`e2e::libfido2_vmm_snp` exercises every step — binding, VCEK signature,
predictor-vs-PSP equality, and cross-launch `getAssertion`.

## Status

- **CTAP** – CTAPHID, `getInfo`/`makeCredential`/`getAssertion` (ES256),
  stateless non-resident credentials. Verified against `libfido2` and
  OpenSSH `sk-ecdsa`.
- **SEV-SNP** – encrypted+measured launch, paravirt GHCB, virtio over shared
  rings, guest↔PSP messaging. ~145 KB text, 492 KB measured launch image.
- **Attestation** – report in `attStmt`, VCEK signature verified, measurement
  stable and offline-recomputable, master key persists.
- **Next** – resident keys / `clientPIN`; TDX.

## Building

```bash
nix develop          # rust toolchain with x86_64-unknown-none + libfido2
cargo build --release -p vmm     # → target/release/u2f-enclave
cargo test                        # unit + e2e (libfido2, OpenSSH, SNP RP)
```

Tests that need `/dev/kvm`, `/dev/uhid`, `/dev/vhost-vsock` or `/dev/sev`
print `SKIP` and pass if those are not writable; the SNP attestation test
soft-skips its signature check if AMD KDS is unreachable (cert cached after
first fetch). No-KVM dev loop: `cargo run -p sim & cargo run -p bridge`.

## References

- CTAP 2.1 spec: <https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html>
- AMD GHCB spec rev 2.03: <https://www.amd.com/system/files/TechDocs/56421.pdf>
- AMD SEV-SNP firmware ABI: <https://www.amd.com/system/files/TechDocs/56860.pdf>
- COCONUT-SVSM (SEV-SNP guest reference, MIT): <https://github.com/coconut-svsm/svsm>
- `sev-snp-measure` (offline measurement reference): <https://github.com/virtee/sev-snp-measure>

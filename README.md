# u2f-enclave

A FIDO2/CTAP2 authenticator that runs as its own **confidential VM** (AMD
SEV-SNP, later Intel TDX) instead of as a USB dongle. Private keys never
leave VM-encrypted memory; the consumer talks to it over **vsock** and sees a
normal `/dev/hidraw` FIDO device via a tiny uhid bridge. Every
`makeCredential` carries an **SNP attestation report** that binds the new
credential's public key to the launch measurement of this exact binary.

Open re-implementation of the idea behind *Hardware Authenticator Binding*
(Shiraishi & Shinagawa, COMPSAC 2025), built from scratch to keep the
trusted code small rather than forked from an existing firmware stack.

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

The whole project ships as a single Linux/x86_64 binary,
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

Now the host cannot read the keys, every `makeCredential` carries an
attestation report signed by the chip's security processor, and the
master secret is derived from this binary's launch measurement — same
binary on same chip ⇒ same keys across restarts.

### See it work

The point of attestation is that the **verifier doesn't trust the
authenticator's host** — so produce the report on the SNP machine, then
check it somewhere else.

On the SNP host (where `u2f-enclave --snp` is running):

```console
snp-host$ u2f-enclave attest > report.bin
attest: using /dev/hidraw3
attest: report_data == SHA-512(authData||cdh)
attest: cred_id      5e48c479276d74f3…
```

`attest` is a stand-in for a browser/SSH client: it registers a
credential over hidraw, checks the report binds it (check 1), and writes
the 1184-byte report to stdout.

Copy `report.bin` to any other Linux box with the same `u2f-enclave`
binary — your laptop, a CI runner, your server. No AMD hardware, no
`/dev/kvm`:

```console
laptop$ u2f-enclave verify < report.bin
report_data   6f020c9e5d1731ca…
measurement   70eabebbf79908ce…  ok
policy        0x30000  ok
chip_id       f59a25d8302ed76a
reported_tcb  0x581b00000000000a
vcek_sig      ok
laptop$ echo $?
0
```

`verify` fetches the chip's certificate from AMD and checks the
signature (check 2), then recomputes the measurement for the guest image
embedded in itself and compares (check 3). Exit status 0 means: a
genuine AMD chip signed this, and what it measured matches what this
binary would launch.

That's the whole loop. In a real deployment `attest` is replaced by a
browser posting a registration to your server —
[How attestation works](#how-attestation-works) shows that variant and
what each check proves. If you'd rather hard-code the expected
measurement in your own verifier instead of shelling out,
`u2f-enclave --measure` prints just the hex (it depends only on the
binary, so CI can produce it). On one box,
`u2f-enclave attest | u2f-enclave verify` runs the lot.

Run `u2f-enclave --help` for the rest.

## What's in the box

| crate    | target            | purpose                                                            |
| -------- | ----------------- | ------------------------------------------------------------------ |
| `ctap`   | `no_std` + alloc  | CTAPHID framing, CTAP2 commands, credential logic. Platform-agnostic, unit-tested on the host. |
| `enclave`| `no_std`          | The unikernel: PVH boot, paravirt GHCB (IOIO/MMIO/PSC/guest-request — no `#VC` handler), hand-rolled virtio-vsock, PSP attestation + derived-key. Cross-built and baked into `vmm`. See [DESIGN.md](enclave/DESIGN.md). |
| `vmm`    | std (Linux)       | Builds the `u2f-enclave` binary: embeds the enclave ELF, launches it under KVM (`KVM_SEV_*`, guest_memfd, secrets-page), wires its virtqueues to `/dev/vhost-vsock`, runs the uhid bridge in-process; also the `--measure`/`verify`/`attest` subcommands. |
| `bridge` | std (Linux)       | Consumer-side daemon: connects to the authenticator socket and exposes it as a HID device via `/dev/uhid`. Standalone for the cross-VM case; linked into `vmm` for the local case. |
| `sim`    | std (Linux/macOS) | Runs `ctap` over a Unix socket so the full stack can be exercised without KVM/SEV hardware. |
| `e2e`    | std               | Integration tests: drive `libfido2`, OpenSSH and `u2f-enclave verify` against the running binary. |

No QEMU, no firmware, no IGVM, no `kvm-bindings`/`kvm-ioctls`, no SVSM
protocol, no `#VC` handler/instruction decoder. RustCrypto for the crypto.

## How attestation works

The `makeCredential` response is standard WebAuthn `fmt:"packed"`
self-attestation — any FIDO2 library accepts it as-is. It also carries one
extra field, `attStmt["snp"]`: a 1184-byte report signed by the AMD chip's
security processor. Libraries that don't know about it ignore it.

A relying party that wants the hardware guarantee does three checks on
that report:

1. **Bound to this credential?** The report's `report_data` (bytes
   `0x50..0x90`) must equal `SHA-512(authData ‖ clientDataHash)`. Those
   are the exact bytes the credential's self-signature covers, so the
   report can't have been lifted from some other registration.
2. **Signed by real AMD silicon?** AMD publishes a certificate (the
   *VCEK*) for every chip and firmware version, looked up by the
   report's `chip_id` and `reported_tcb`. Fetch it and verify the
   report's signature against it.
3. **Running the code you audited?** The report's `measurement` (bytes
   `0x90..0xc0`) must match the build you reviewed.
   `u2f-enclave --measure` computes that value without AMD hardware; the
   test suite checks it against a real chip. If the computation were ever
   wrong you'd reject good reports, not accept bad ones.

If all three pass, the new credential's private key exists only inside
an encrypted VM running this exact binary on a genuine AMD chip. There
is no step four.

`u2f-enclave verify` does checks 2 and 3 for you. The 1184 bytes are
`attStmt["snp"]` in the WebAuthn `attestationObject` your server gets
from `navigator.credentials.create()`; whatever WebAuthn library you
already use will hand you `attStmt` as a map. In Python, the whole
relying-party check is:

```python
import cbor2, hashlib, subprocess
obj    = cbor2.loads(attestation_object)          # bytes from the browser
report = obj["attStmt"]["snp"]                    # 1184 bytes
r = subprocess.run(["u2f-enclave", "verify"], input=report,
                   capture_output=True, text=True)
bound = hashlib.sha512(obj["authData"] + client_data_hash).hexdigest()
ok = r.returncode == 0 and f"report_data   {bound}" in r.stdout
```

The certificate is fetched from AMD once and cached under
`$XDG_CACHE_HOME`; pass `--vcek FILE` to supply it yourself. Runs on any
x86_64 Linux box; same binary, no AMD hardware needed.

**Why keys survive a restart:** the authenticator never stores its
master secret. On every launch it asks the chip to re-derive it from a
key burned into the silicon plus the launch measurement. Same binary on
the same chip gives the same secret back; change either and old
credentials just stop working. No encrypted state files, no host-side
storage, nothing to back up.


## Status

- **CTAP** – CTAPHID, `getInfo`/`makeCredential`/`getAssertion` (ES256),
  stateless non-resident credentials. Verified against `libfido2` and
  OpenSSH `sk-ecdsa`.
- **SEV-SNP** – encrypted+measured launch, paravirt GHCB, virtio over shared
  rings, guest↔PSP messaging.
- **Attestation** – report in `attStmt`, VCEK signature verified, measurement
  stable and offline-recomputable, master key persists.
- **Next** – resident keys / `clientPIN`; TDX.

## Building

```bash
nix develop          # rust toolchain with x86_64-unknown-none + libfido2
cargo build --release -p vmm     # → target/release/u2f-enclave
cargo test                        # unit + e2e (libfido2, OpenSSH, attestation)
```

Tests that need `/dev/kvm`, `/dev/uhid`, `/dev/vhost-vsock` or `/dev/sev`
print `SKIP` and pass if those are not writable. No-KVM dev loop:
`cargo run -p sim & cargo run -p bridge`.

## References

- CTAP 2.1 spec: <https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html>
- AMD GHCB spec rev 2.03: <https://www.amd.com/system/files/TechDocs/56421.pdf>
- AMD SEV-SNP firmware ABI: <https://www.amd.com/system/files/TechDocs/56860.pdf>
- COCONUT-SVSM (SEV-SNP guest reference, MIT): <https://github.com/coconut-svsm/svsm>
- `sev-snp-measure` (offline measurement reference): <https://github.com/virtee/sev-snp-measure>

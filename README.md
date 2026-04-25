# u2f-enclave

A FIDO2/CTAP2 authenticator that runs inside a hardware-isolated
environment — an **AMD SEV-SNP** confidential VM or an **Intel SGX**
enclave — instead of as a USB dongle. Private keys never leave
CPU-encrypted memory; the consumer sees a normal `/dev/hidraw` FIDO
device via a tiny uhid bridge. Every `makeCredential` carries a
hardware **attestation report** that binds the new credential's public
key to the exact code that holds it.

Open re-implementation of the idea behind *Hardware Authenticator Binding*
(Shiraishi & Shinagawa, COMPSAC 2025), built from scratch to keep the
trusted code small rather than forked from an existing firmware stack.

> [!WARNING]
> This is research code. It has **not** been independently audited.
> Don't protect anything with it you aren't prepared to lose; use at
> your own risk.

```
┌────────────── consumer ─────────────┐      ┌────── SEV-SNP VM / SGX enclave ────┐
│ browser → libfido2 → /dev/hidrawN   │      │                                    │
│                       ▲             │      │   ┌──────────────────────────┐     │
│                  uhid │             │      │   │  ctap (no_std)           │     │
│                ┌──────┴─────┐       │◄────►│   │  CTAPHID + CTAP2 + keys  │     │
│                │  bridge    │───────┼──────┼──►│                          │     │
│                └────────────┘       │      │   └──────────────────────────┘     │
└─────────────────────────────────────┘      │   hardware attestation → attStmt   │
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

Without `--snp` or `--sgx` the guest runs as a plain KVM VM —
functionally complete and fine for development, but the host kernel is
in the trust boundary and keys do not survive a restart.

### AMD SEV-SNP

On an EPYC host (Milan or later) with SNP enabled in BIOS and `kvm_amd`
loaded with `sev_snp=Y`:

```console
$ sudo setfacl -m u:$USER:rw /dev/sev
$ u2f-enclave --snp &
u2f-enclave: SEV-SNP launch ok (492 KiB measured)
u2f-enclave: ready at /dev/hidraw3
```

Now the host cannot read the keys, every registration carries a signed
attestation report, and keys survive restarts (see
[Key persistence](#key-persistence)).

### Intel SGX

On an Intel host with SGX and Flexible Launch Control (Ice Lake or
later, `CONFIG_X86_SGX=y`):

```console
$ sudo setfacl -m u:$USER:rw /dev/sgx_enclave
$ u2f-enclave --sgx &
u2f-enclave: SGX EINIT ok (512 KiB EPC)
u2f-enclave: ready at /dev/hidraw3
```

No VM, no vsock; the host process loads the enclave directly and
shuttles 64-byte HID reports in and out via `EENTER`. Every registration
carries an SGX report binding it to the enclave's measurement and signer.

### See the attestation

The verifier doesn't trust the SNP host — so produce a report there and
check it somewhere else.

```console
snp-host$ u2f-enclave attest > report.bin
attest: using /dev/hidraw3
attest: report_data == SHA-512(authData||cdh)
attest: cred_id      5e48c479276d74f3…
```

`attest` stands in for a browser: it registers a credential over hidraw,
checks the report is tied to it, and writes the 1184-byte report.

Fetch the chip's AMD certificate (good until that chip's next microcode
update; whichever side has network can do this):

```console
$ curl -o vcek.der "$(u2f-enclave vcek-url < report.bin)"
```

Verify — any Linux box with the same binary, no AMD hardware needed:

```console
laptop$ u2f-enclave verify --vcek vcek.der < report.bin
report_data   6f020c9e5d1731ca…
measurement   70eabebbf79908ce…  ok (matches this build)
policy        0x30000  ok
chip_id       f59a25d8302ed76a
reported_tcb  0x581b00000000000a
vcek_sig      ok
laptop$ echo $?
0
```

Exit 0 means: a genuine AMD chip signed this, and what it measured
matches what this binary would launch. `--measure` prints the
measurement hex if you'd rather hard-code it; `--help` lists everything.

## How attestation works

The `makeCredential` response is standard WebAuthn `fmt:"packed"`
self-attestation — any FIDO2 library accepts it as-is — plus one extra
field, `attStmt["snp"]`: the 1184-byte report. Libraries that don't know
about it ignore it.

A relying party that wants the hardware guarantee does three checks on
that report:

1. **Bound to this credential?** `report_data` (bytes `0x50..0x90`) must
   equal `SHA-512(authData ‖ clientDataHash)` — the same bytes the
   credential's own signature covers, so the report can't have been
   lifted from another registration.
2. **Signed by real AMD silicon?** AMD publishes a certificate (the
   *VCEK*) for every chip and firmware version. `vcek-url` builds the
   fetch URL from the report; verify the report's signature against it.
3. **Running the code you audited?** `measurement` (bytes `0x90..0xc0`)
   must match the build you reviewed. `--measure` computes that value;
   the test suite checks it against a real chip. If the computation were
   ever wrong you'd reject good reports, not accept bad ones.

All three pass → the credential's private key exists only inside an
encrypted VM running this exact binary on a genuine AMD chip.

`verify` does 2 and 3; you do 1 (you have `authData`/`clientDataHash`,
it doesn't). Your server gets the report as `attStmt["snp"]` in the
WebAuthn `attestationObject` the browser posts; whatever WebAuthn
library you use exposes `attStmt` as a map. In Python:

```python
import cbor2, hashlib, subprocess
obj    = cbor2.loads(attestation_object)             # bytes from the browser
report = obj["attStmt"]["snp"]
r = subprocess.run(["u2f-enclave", "verify", "--vcek", "vcek.der"],
                   input=report, capture_output=True, text=True)
bound = hashlib.sha512(obj["authData"] + client_data_hash).hexdigest()
ok = r.returncode == 0 and f"report_data   {bound}" in r.stdout
```

On Intel, `attStmt["sgx"]` is the 432-byte SGX report. Its `REPORTDATA`
field (bytes `0x140..0x180`) carries the same SHA-512 binding as check
1; `MRENCLAVE` (bytes `0x40..0x60`) and `MRSIGNER` (bytes `0x80..0xa0`)
are what `--measure` prints. The raw report is locally checkable but
not remotely verifiable on its own — wrapping it as a DCAP Quote (so a
remote party can verify Intel's signature chain) is the next piece of
work.

## Key persistence

The authenticator never stores its master secret. On every launch it
asks the chip to re-derive it from a key burned into the silicon. No
encrypted state files, no host-side storage, nothing to back up.

Under **SEV-SNP** the chip mixes in the launch measurement: same binary
on the same chip ⇒ same secret ⇒ credentials keep working across
restarts; change either and old credentials stop resolving. The AMD
firmware has no way to bind the derived key to a *signing key* instead,
so a binary update means re-registering (or a one-time handoff between
old and new — not built yet).

Under **SGX** the chip mixes in the *signer* of the enclave (the
build-time RSA key, see [Building](#building)) rather than the
measurement. Any binary you sign with the same key on the same chip
derives the same secret, so credentials survive code updates. Keep that
key private: anyone who has it can sign an enclave that derives the same
secret.

## What's in the box

| crate    | target            | purpose                                                            |
| -------- | ----------------- | ------------------------------------------------------------------ |
| `ctap`   | `no_std` + alloc  | CTAPHID framing, CTAP2 commands, credential logic. Platform-agnostic, unit-tested on the host. |
| `guest`  | `no_std`          | SEV-SNP unikernel: PVH boot, paravirt GHCB (IOIO/MMIO/PSC/guest-request — no `#VC` handler), hand-rolled virtio-vsock, PSP attestation + derived-key. Cross-built and baked into `host`. See [DESIGN.md](guest/DESIGN.md). |
| `sgx`    | `no_std`          | SGX enclave: same `ctap` core, `EGETKEY` master, `EREPORT` attestation, asm entry stub with self-relocator and trust-boundary scrubbing. Cross-built, signed, and baked into `host`. |
| `host`   | std (Linux)       | Builds the `u2f-enclave` binary: embeds the guest and enclave images, launches under KVM (`KVM_SEV_*`, guest_memfd, secrets-page) or `/dev/sgx_enclave` (hand-rolled loader, vDSO `EENTER`), runs the uhid bridge in-process; also `--measure`/`verify`/`attest`/`vcek-url`. The build script computes MRENCLAVE and signs SIGSTRUCT. |
| `bridge` | std (Linux)       | Consumer-side daemon: connects to the authenticator socket and exposes it as a HID device via `/dev/uhid`. Standalone for the cross-VM case; linked into `host` for the local case. |
| `sim`    | std (Linux/macOS) | Runs `ctap` over a Unix socket so the full stack can be exercised without KVM/SEV hardware. |
| `e2e`    | std               | Integration tests: drive `libfido2`, OpenSSH and `u2f-enclave verify` against the running binary. |

## Status

- **CTAP** – CTAPHID, `getInfo`/`makeCredential`/`getAssertion` (ES256),
  stateless non-resident credentials. Verified against `libfido2` and
  OpenSSH `sk-ecdsa`.
- **SEV-SNP** – encrypted+measured launch, paravirt GHCB, virtio over shared
  rings, guest↔PSP messaging.
- **SGX** – hand-rolled loader/signer/vDSO call, `EGETKEY` signer-bound
  master key (survives updates), `EREPORT` in `attStmt`.
- **Attestation** – SNP report in `attStmt`, VCEK signature verified,
  measurement stable and offline-recomputable; SGX MRENCLAVE/MRSIGNER
  recomputable.
- **Next** – SGX DCAP Quote + `verify` arm; SNP cross-version key
  handoff; resident keys / `clientPIN`.

## Building

The build signs the SGX enclave, so it needs an RSA-3072 key with public
exponent 3 (an Intel hardware requirement). The build never reads the
private key itself — it shells out to a signer command — so the same
path works for a local file or a hardware token.

Local file key (default; `sgx_key.pem`/`sgx_pub.pem` are git-ignored):

```bash
nix develop          # rust toolchain with x86_64-unknown-none + libfido2 + openssl
openssl genrsa -3 3072 > sgx_key.pem
openssl rsa -in sgx_key.pem -pubout > sgx_pub.pem
cargo build --release -p host    # → target/release/u2f-enclave
cargo test                       # unit + e2e (libfido2, OpenSSH, attestation)
```

Hardware token (PKCS#11 HSM, TPM 2.0 — anything that can do RSA-3072
e=3; YubiKey PIV and the cloud KMS services cannot, they fix e=65537):

```bash
export U2FE_SGX_PUBKEY=/path/to/signer_pub.pem
export U2FE_SGX_SIGN='pkcs11-tool --sign -m SHA256-RSA-PKCS --id 01 --module …'
cargo build --release -p host
```

`$U2FE_SGX_SIGN` reads the 256-byte payload on stdin and writes the raw
384-byte signature to stdout. The build verifies the signature with e=3
and fails early if the token used a different exponent.

Tests that need `/dev/kvm`, `/dev/uhid`, `/dev/vhost-vsock` or `/dev/sev`
print `SKIP` and pass if those are not writable. No-KVM dev loop:
`cargo run -p sim & cargo run -p bridge`.

## References

- CTAP 2.1 spec: <https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html>
- AMD GHCB spec rev 2.03: <https://www.amd.com/system/files/TechDocs/56421.pdf>
- AMD SEV-SNP firmware ABI: <https://www.amd.com/system/files/TechDocs/56860.pdf>
- Intel SDM Vol. 3D ch. 38–40 (SGX): <https://www.intel.com/sdm>
- COCONUT-SVSM (SEV-SNP guest reference, MIT): <https://github.com/coconut-svsm/svsm>
- `sev-snp-measure` (offline measurement reference): <https://github.com/virtee/sev-snp-measure>

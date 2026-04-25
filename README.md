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
u2f-enclave: vsock cid=3
u2f-enclave: SEV-SNP launch ok (588 KiB measured)
u2f-enclave: fresh SNP master key (no prior state)
u2f-enclave: state → /home/alice/.local/share/u2f-enclave/snp.state
u2f-enclave: ready at /dev/hidraw3
```

Now the host cannot read the keys, every registration carries a signed
attestation report, and keys survive restarts and binary updates (see
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

Verify — any Linux box with the same binary, no AMD hardware needed:

```console
laptop$ u2f-enclave verify < report.bin
u2f-enclave: fetching VCEK → /home/alice/.cache/u2f-enclave/vcek-f59a25d8….der
report_data   6f020c9e5d1731ca…
measurement   59a1f701254792c1…  = this build
author_key    fdba2513c768b97b…  = this build's signer
policy        0x30000  ok
chip_id       f59a25d8302ed76a
reported_tcb  0x581b00000000000a
vcek_sig      ok
laptop$ echo $?
0
```

Exit 0 means: a genuine AMD chip signed this, and what it measured — or
the key that signed its launch — matches this binary. The chip's AMD
certificate is fetched once and cached; pass `--vcek FILE` (or drop it
at the printed path) on a machine without network. `--measure` prints
the expected hexes if you'd rather hard-code them; `vcek-url` prints the
fetch URL; `--help` lists everything.

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
3. **Running the code you audited?** Either `measurement` (bytes
   `0x90..0xc0`) matches the build you reviewed, or `author_key_digest`
   (bytes `0x110..0x140`) matches your build-time signing key — the
   first pins one exact binary, the second accepts any binary you
   signed. `--measure` prints both; the test suite checks them against
   a real chip.

All three pass → the credential's private key exists only inside an
encrypted VM running code you signed on a genuine AMD chip.

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

Under **SEV-SNP** the master secret is 32 random bytes generated on the
first run, then sealed (AES-256-GCM) and written to
`$XDG_DATA_HOME/u2f-enclave/snp.state` together with the guest image
and its signed launch block. The sealing key is what the AMD firmware
derives from the chip's burned-in secret mixed with the launch
measurement, so only this binary on this chip can open the file; the
seal also binds your build-time signing key (see
[Building](#building)), so a relaunch under anyone else's key can't
open it either.

On the next run the guest unseals and credentials keep working. After a
binary update unsealing fails (different measurement); the new binary
then briefly relaunches the *old* guest from `snp.state`, the two
guests check each other's AMD-signed attestation reports (same chip,
same signing key, no debug, new version ≥ old), and the old one hands
the master across an encrypted channel. From the outside this is just a
slightly slower start.

The handover needs the chip's AMD certificate; it is fetched and cached
automatically, or can be placed by hand on a machine without network
(the error message gives the exact path and URL). `--fresh` discards
`snp.state` and starts over with a new master.

Anyone with `snp.state` *and* a binary signed with your key can run an
authenticator with the same identity on the same chip. Keep both
private — the file is created mode 0600.

Under **SGX** the chip derives the master directly from a key burned
into the silicon mixed with the *signer* of the enclave (the build-time
RSA key). No state file: any binary you sign with the same key on the
same chip derives the same secret, so credentials survive code updates.
Keep that key private; anyone who has it can sign an enclave that
derives the same secret.

## What's in the box

| crate    | target            | purpose                                                            |
| -------- | ----------------- | ------------------------------------------------------------------ |
| `ctap`   | `no_std` + alloc  | CTAPHID framing, CTAP2 commands, credential logic. Platform-agnostic, unit-tested on the host. |
| `guest`  | `no_std`          | SEV-SNP unikernel: PVH boot, paravirt GHCB (IOIO/MMIO/PSC/guest-request — no `#VC` handler), hand-rolled virtio-vsock, PSP attestation + derived-key. Cross-built and baked into `host`. See [DESIGN.md](guest/DESIGN.md). |
| `sgx`    | `no_std`          | SGX enclave: same `ctap` core, `EGETKEY` master, `EREPORT` attestation, asm entry stub with self-relocator and trust-boundary scrubbing. Cross-built, signed, and baked into `host`. |
| `host`   | std (Linux)       | Builds the `u2f-enclave` binary: embeds the guest and enclave images, launches under KVM (`KVM_SEV_*`, guest_memfd, secrets-page) or `/dev/sgx_enclave` (hand-rolled loader, vDSO `EENTER`), runs the uhid bridge in-process; orchestrates the key handover; also `--measure`/`verify`/`attest`/`vcek-url`. The build script computes MRENCLAVE and the SNP launch digest and signs SIGSTRUCT and ID_BLOCK. |
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
  measurement and `author_key_digest` stable and offline-recomputable;
  SGX MRENCLAVE/MRSIGNER recomputable.
- **Persistence** – SNP: sealed `snp.state`, attested cross-version
  handover with downgrade refusal. SGX: signer-bound `EGETKEY`.
- **Next** – SGX DCAP Quote + `verify` arm; resident keys / `clientPIN`.

## Building

The build signs both backends: the SGX enclave (RSA-3072 with public
exponent 3 — an Intel hardware requirement) and the SEV-SNP launch
block (ECDSA P-384 — an AMD firmware requirement). The SGX signer
becomes `MRSIGNER`; the SNP signer becomes `author_key_digest` in every
report. Both are what [Key persistence](#key-persistence) and
[check 3](#how-attestation-works) hinge on. The build never reads a
private key itself — it shells out to a signer command — so the same
path works for a local file or a hardware token.

Local file keys (default; `*_key.pem`/`*_pub.pem` are git-ignored):

```bash
nix develop          # rust toolchain with x86_64-unknown-none + libfido2 + openssl
openssl genrsa -3 3072 > sgx_key.pem
openssl rsa -in sgx_key.pem -pubout > sgx_pub.pem
openssl ecparam -name secp384r1 -genkey -noout > snp_key.pem
openssl ec -in snp_key.pem -pubout > snp_pub.pem
cargo build --release -p host    # → target/release/u2f-enclave
cargo test                       # unit + e2e (libfido2, OpenSSH, attestation)
```

Hardware token (PKCS#11 HSM, TPM 2.0 — anything that can do RSA-3072
e=3; YubiKey PIV and the cloud KMS services cannot, they fix e=65537):

```bash
export U2FE_SGX_PUBKEY=/path/to/signer_pub.pem
export U2FE_SGX_SIGN='pkcs11-tool --sign -m SHA256-RSA-PKCS --id 01 --module …'
export U2FE_SNP_PUBKEY=/path/to/snp_pub.pem
export U2FE_SNP_SIGN='pkcs11-tool --sign -m ECDSA-SHA384 --id 02 --module …'
cargo build --release -p host
```

`$U2FE_SGX_SIGN` reads the 256-byte payload on stdin and writes the raw
384-byte signature to stdout; `$U2FE_SNP_SIGN` reads the payload and
writes a DER ECDSA signature. The build verifies both against the
public keys and fails early on a mismatch. ECDSA signatures are not
deterministic, so two builds of the same source with the same keys are
functionally identical but not byte-identical.

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

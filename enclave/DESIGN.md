# Enclave design

`x86_64-unknown-none` ELF that the `vmm` crate embeds and launches as a
single-vCPU SEV-SNP guest. ~145 KB `.text`; the on-disk ELF is ~490 KB
because `.bss`/`.stack` sit in PT_LOAD so they are part of the measured
launch image.

## Threat model

The host kernel, KVM, the `vmm` process, vhost-vsock and everything on the
vsock wire are the adversary. The AMD PSP firmware, CPU silicon (memory
encryption, RMP, `RDRAND`, `PVALIDATE`) and the ARK/ASK/VCEK key chain are
trusted. The goal is that a credential private key can only be exercised by
code with this binary's launch measurement on genuine AMD silicon, and that
a relying party can verify exactly that from the `makeCredential` response.

The host can deny service at will (drop vsock, refuse `VMGEXIT`, corrupt
shared rings). The design accepts DoS; everything below argues why each
host-reachable surface is DoS-only.

## No `#VC` handler

A conventional SEV-SNP guest takes `#VC` on `cpuid`/`rdtsc`/port-IO/MMIO
and runs an instruction decoder to re-issue the access via the GHCB. This
binary instead calls the GHCB directly at every privileged-instruction site
— there are exactly three kinds (COM1, the debug-exit port, virtio-mmio
registers) and we own all of them. RustCrypto on `target_os="none"`
compiles to soft implementations with no `cpuid` feature probes (`objdump`
shows zero `cpuid`/`rdtsc`/`wbinvd` in the ELF), so nothing else can
trigger `#VC`. That removes the IDT, exception-frame asm, and instruction
decoder from the TCB; `sev.rs` is ~300 LoC.

KVM forwards `SVM_EXIT_IOIO` and `SVM_VMGEXIT_MMIO_{READ,WRITE}` to its
ordinary handlers, which surface to the `vmm` as plain `KVM_EXIT_IO` /
`KVM_EXIT_MMIO`. The `vmm`'s emulation loop is therefore identical for
plain-KVM and SNP guests.

## Memory layout

```
GPA 0x0000_1000   SECRETS page (PSP-injected, private)
GPA 0x0010_0000   ELF PT_LOAD: .text .rodata .data .bss .stack (private)
                    ├── GHCB page             ← flipped shared at runtime
                    ├── greq REQ/RESP pages   ← flipped shared at runtime
                    └── Vsock rings+buffers   ← flipped shared at runtime
GPA 0xfeb0_0000   virtio-mmio register window (host-emulated, GHCB-MMIO)
```

All RAM is identity-mapped (4×1 GiB leaves) so VA = GPA; `sev::init()`
refines `[0, 2 MiB)` to 4 KiB so individual pages can have C=0. A page is
made shared by `PVALIDATE`-rescind → MSR-protocol PSC → clear the C-bit;
the `vmm` answers the resulting `KVM_HC_MAP_GPA_RANGE` with
`KVM_SET_MEMORY_ATTRIBUTES` and KVM does the RMPUPDATE.

## Shared-page discipline

Anything in a shared page is host-writable at any instant.

- **GHCB**: single static page. `ghcb_begin()` zeroes it and writes only the
  fields the next exit needs; on return only the documented output fields
  are read. No private state lives there between calls.
- **Vsock instance** (rings + buffers + small bookkeeping): shared as one
  block rather than carved up. Every byte that matters already transits the
  host, and the bookkeeping fields a hostile host could poison are either
  ring indices (bounds-checked → panic, not OOB) or overwritten in `init()`.
- **greq REQ/RESP**: see below — plaintext never touches them.

The heap and stack are private and disjoint from all of the above by
construction (separate Rust statics / linker sections).

## Boot

PVH: the `vmm` programs the vCPU's `KVM_SET_{REGS,SREGS,CPUID2}` to PVH
initial state and points `rip` at the 32-bit trampoline; under SNP, KVM's
`LAUNCH_FINISH` builds the VMSA from those same registers, so one boot
path serves both. The trampoline OR-s the C-bit (passed in `%esi`,
host-queried — the guest can't `cpuid` for it before the GHCB is up) into
the 1 GiB PTEs and jumps to 64-bit Rust. No firmware, no IGVM.

## vsock

Hand-rolled modern virtio-mmio transport + 8-entry split virtqueues,
polling, single STREAM connection. The `vmm` emulates the register window
and hands the virtqueues to `/dev/vhost-vsock`; vhost reads rings via the
anonymous userspace mapping that backs the shared half of the guest_memfd
memslot, so the SNP data path needs no special handling. CTAPHID frames are
64 bytes and each goes in its own RW packet, so no stream reassembly.

## PSP messaging (`greq.rs`)

The `vmm` injects an `SNP_PAGE_TYPE_SECRETS` page at GPA `0x1000`; the PSP
fills it with VMPCK0..3 at launch. `greq` reads VMPCK0, AES-256-GCM-wraps a
request, and issues `SVM_VMGEXIT_GUEST_REQUEST`, which KVM handles entirely
in-kernel (`kvm_read_guest` → PSP ring → `kvm_write_guest`).

IV discipline is the security-critical part: requests are built and
encrypted in a *private* staging page, and the sequence number is bumped
*before* the ciphertext is copied to the shared request page. A host that
fakes an error to force a retry never gets two ciphertexts under the same
(key, IV); it gets a seqno desync, i.e. DoS. Responses are likewise copied
to private memory before any header check or decrypt.

## Attestation surface

```text
attStmt = { "alg": -7,
            "sig": ecdsa(credKey, authData || clientDataHash),
            "snp": SNP_ATTESTATION_REPORT }                // 1184 B
report_data = sha512(authData || clientDataHash)
```

`fmt` stays `"packed"` so stock libfido2/WebAuthn accept the
self-attestation; the report rides under an extra map key they ignore.
`report_data` covers the same bytes the self-attestation signs, so the
PSP's signature transitively binds the credential public key, RP ID and
this registration's challenge to the launch measurement. An SNP-aware
relying party (`e2e/src/snp.rs`) checks `report_data`, fetches the VCEK
for `(chip_id, reported_tcb)` from AMD KDS, verifies the P-384 signature,
and matches `measurement` against an allow-list.

## Master secret

`MSG_KEY_REQ` with `guest_field_select = policy|measurement` and the VCEK
root: the PSP derives a 32-byte key from chip-unique material mixed with
this binary's launch digest. Same binary on same silicon ⇒ same key, so
credentials survive restarts with no sealed-storage protocol, no host-held
blob, no network. A different binary (or a tampered host that alters the
launch image) derives a different key and old credentials simply do not
resolve — the persistence and the binding are the same mechanism.

## Expected measurement

`u2f-enclave --measure` recomputes the launch digest from the embedded ELF
without an EPYC host: it lays out PT_LOADs, runs the SNP `PAGE_INFO`
SHA-384 chain over those pages, the SECRETS page metadata, and a VMSA
template. The template mirrors what KVM's `sev_es_sync_vmsa` produces for
our PVH register state (verified against a `dynamic_debug` hex-dump on a
6.18 kernel). The C-bit position travels in `%esi` and is therefore part
of the measured state; it is hard-coded to 51 (every shipping SNP part)
so the digest is a pure function of the binary, and `Snp::init()` asserts
the host agrees. `e2e::libfido2_vmm_snp` asserts the predictor equals the
PSP's measurement
on every run, so a kernel change to the VMSA construction shows up as a
test failure rather than silent drift.

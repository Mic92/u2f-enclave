# Enclave unikernel (M2)

The host-testable `ctap` crate is the authenticator; this directory will hold
the `no_std` kernel that boots it inside an SEV-SNP guest. Nothing here builds
yet — this document records the plan and the bits of COCONUT-SVSM worth
cribbing.

## Responsibilities

1. Bring up a single CPU, enable paging, set up a heap (`alloc`).
2. Handle `#VC` exceptions and speak the GHCB protocol so `CPUID`, MMIO and
   MSR accesses work under SEV-ES/SNP.
3. Drive **virtio-vsock** (MMIO transport) and accept one connection.
4. Issue `SNP_GUEST_REQUEST` to obtain an attestation report on demand.
5. Run `ctap::Authenticator::process_report` in a loop over the vsock stream.

No network stack, no filesystem, no multi-tasking.

## What to lift from COCONUT-SVSM (MIT)

| Need                | Where in coconut-svsm                          |
| ------------------- | ---------------------------------------------- |
| `#VC` handler, GHCB | `kernel/src/cpu/vc.rs`, `kernel/src/sev/ghcb.rs` |
| SNP guest request   | `kernel/src/greq/`                             |
| Early page tables   | `kernel/src/mm/`                               |
| virtio MMIO         | `virtio-drivers/` (already a separate crate)   |
| IGVM packaging      | `tools/igvmbuilder/`, `tools/igvmmeasure/`     |

We do **not** need their VMPL/SVSM-protocol layer, vTPM, or user-mode runtime.

## Boot artefact

Build as an IGVM image so QEMU/KVM (and Hyper-V) can launch it directly with a
deterministic launch measurement. `igvmmeasure` then gives the expected
measurement that relying parties pin in policy when verifying the
`fmt:"sev-snp"` attestation statement.

## Randomness

`RDRAND`/`RDSEED` are available inside the guest and are covered by the SNP
trust model. `Platform::random_bytes` maps to those directly.

## Persistence

M2 is stateless (non-resident credentials only: the credential ID *is* the
wrapped private key). Resident keys in M3 will need a sealed blob fed in via
fw_cfg or virtio-blk, encrypted under a key released only after successful
remote attestation — same pattern COCONUT-SVSM uses for vTPM NV state.

## TDX

TDX has no `#VC`; guest uses TDCALL/TDVMCALL instead. The GHCB layer becomes
a thin trait with two backends. virtio-vsock and the `ctap` crate are
unchanged. Attestation report shape differs (TDREPORT → Quote via QGS), so the
`fmt:"sev-snp"` attStmt becomes `fmt:"tee"` with a discriminator.

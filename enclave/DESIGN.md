# Enclave unikernel

The `ctap` crate links into a ~27 KB stripped `x86_64-unknown-none` ELF with a
heap, panic handler and RDRAND-backed `Platform`. What remains is boot glue
and two drivers. Everything below is additive on top of `src/main.rs`.

## Stage 1 — PVH boot — **done**

PVH ELF note + 32→64-bit trampoline (`ram32.s`) + linker script at 1 MiB.
The `vmm` crate's hand-rolled KVM launcher places the vCPU directly in PVH
initial state — no SeaBIOS/qboot in the path. Pattern lifted from
`cloud-hypervisor/rust-hypervisor-firmware`.

## Stage 2 — SEV-SNP enable

Under SEV-ES every `cpuid`/`in`/`out`/`rdmsr` raises `#VC`. The handler talks
to the hypervisor via the GHCB. Lift, trimmed to what we use:

| need | coconut-svsm source |
| --- | --- |
| `#VC` IDT entry + dispatcher | `kernel/src/cpu/vc.rs` |
| GHCB page setup, MSR proto | `kernel/src/sev/ghcb.rs`, `kernel/src/sev/msr_protocol.rs` |
| `PVALIDATE` / page-state change | `kernel/src/sev/status.rs`, `kernel/src/mm/validate.rs` |
| SNP `GUEST_REQUEST` (attestation report) | `kernel/src/greq/` |
| IGVM packaging + measurement | `tools/igvmbuilder/`, `tools/igvmmeasure/` |

We need only the IOIO, CPUID and MSR `#VC` cases plus GUEST_REQUEST — a few
hundred lines, not the full SVSM protocol layer.

Boot artefact becomes an IGVM file so the launch measurement is deterministic
and matches what the relying party pins.

## Stage 3 — virtio-vsock — **done**

Guest side: hand-rolled modern virtio-mmio transport + split virtqueue +
single-connection vsock STREAM, polling, ~450 LoC.

Host side: `vmm` emulates the virtio-mmio register window and offloads the
virtqueues to `/dev/vhost-vsock` so the data path is entirely in-kernel.
The enclave ELF is `include_bytes!`-embedded; `vmm` runs the uhid bridge
in-process. `e2e::libfido2_vmm` runs the full `libfido2`
register/attest/assert/verify sequence against this single binary.

## Stage 4 — attestation in attStmt

Replace `fmt:"packed"` self-attestation with `fmt:"sev-snp"` (working name):

```text
attStmt = {
  "alg": -7,
  "sig": ecdsa(credKey, authData || clientDataHash),     // unchanged
  "snp": SNP_ATTESTATION_REPORT,                         // report_data = sha512(credPubKey)
  "x5c": [VCEK, ASK, ARK]                                // AMD chain
}
```

`ctap2::make_credential` already has the hook; only `cred.rs` grows a
`snp_report(report_data: &[u8;64]) -> [u8;1184]` call.

## Non-SEV development loop

Stage 1 lets the whole vsock + CTAP path be exercised under plain QEMU
(`-machine microvm`) with `vhost-vsock-device` long before SNP hardware is in
the loop. Only stages 2/4 need an EPYC host.

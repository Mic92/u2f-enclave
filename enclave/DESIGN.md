# Enclave unikernel

The `ctap` crate links into a ~27 KB stripped `x86_64-unknown-none` ELF with a
heap, panic handler and RDRAND-backed `Platform`. What remains is boot glue
and two drivers. Everything below is additive on top of `src/main.rs`.

## Stage 1 — boot under plain QEMU (no SEV) — **done**

PVH ELF note + 32→64-bit trampoline (`ram32.s`) + linker script at 1 MiB +
one 2 MiB identity page. `e2e::boot_pvh` builds, boots under
`qemu -kernel`, checks the serial banner, and asserts the
`isa-debug-exit` status. Pattern lifted from
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

Hand-rolled (no `virtio-drivers` dep): modern virtio-mmio transport + split
virtqueue + single-connection vsock STREAM, polling, ~450 LoC total.
`e2e::libfido2_kernel` boots under `qemu -M microvm` with
`vhost-vsock-device`, `bridge` connects over AF_VSOCK, and the full
`libfido2` register/attest/assert/verify sequence passes against the
bare-metal kernel.

QEMU specifics that bit: `-global virtio-mmio.force-legacy=false` (default
is the v1 register layout), `-bios qboot.rom` (microvm's SeaBIOS doesn't do
PVH), `ioapic2=off` to cap transports at 8, and the device lands in the
*last* MMIO slot due to QOM bus assignment order — so we scan.

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

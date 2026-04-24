# Enclave unikernel

The `ctap` crate links into a ~27 KB stripped `x86_64-unknown-none` ELF with a
heap, panic handler and RDRAND-backed `Platform`. What remains is boot glue
and two drivers. Everything below is additive on top of `src/main.rs`.

## Stage 1 — boot under plain QEMU (no SEV)

Goal: `qemu-system-x86_64 -kernel enclave` prints the bring-up banner.

- `boot.S`: PVH entry note + 32→64-bit trampoline (static page tables
  identity-mapping the low 1 GiB, load CR3, set LME+PG, `lret` into `_start`).
  Reference: `coconut-svsm/stage1/` and any rust-osdev PVH example.
- `link.ld`: load at a fixed PA (e.g. `0x200000`), drop PIE.
- `serial.rs` already works once `out`/`in` reach the device.

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

## Stage 3 — virtio-vsock

- Transport: virtio-mmio (single device, no PCI enumeration). The
  `coconut-svsm/virtio-drivers/` crate already abstracts ring handling for a
  `no_std` environment; depend on it directly.
- Socket layer: implement `connect`-less listen on a fixed port, one stream,
  `read_exact(64)`/`write_all(64)`. ~200 LoC on top of the ring driver.
- `kmain()` becomes the obvious loop:
  ```rust
  let mut sock = vsock::accept(PORT);
  loop {
      sock.read_exact(&mut report)?;
      for r in auth.process_report(&report) { sock.write_all(&r)?; }
  }
  ```
  This is byte-identical to `sim`, so `bridge` needs no changes.

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

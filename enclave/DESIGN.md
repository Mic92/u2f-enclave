# Enclave unikernel

`x86_64-unknown-none` ELF: `ctap` + p256/sha2/hmac, heap, panic handler,
RDRAND-backed `Platform`, PVH boot stub, paravirt SEV-SNP guest support,
hand-rolled virtio-mmio + vsock. ~110 KB text+rodata; the ELF is 436 KB on
disk because `.bss`/`.stack` sit in the PT_LOAD so SNP `LAUNCH_UPDATE`
measures them. The host-side `vmm` crate embeds this ELF and is the only
supported launcher.

## Stage 1 — PVH boot — done

PVH ELF note + 32→64-bit trampoline (`ram32.s`) + linker script at 1 MiB.
`vmm`'s hand-rolled KVM launcher places the vCPU directly in PVH initial
state — no SeaBIOS/qboot in the path. Under SEV-SNP, KVM builds the VMSA
from the same `KVM_SET_{REGS,SREGS}` at `LAUNCH_FINISH`, so the trampoline
is shared verbatim; the only addition is OR-ing the C-bit (passed in
`%esi`) into the 1 GiB leaf PTEs before enabling paging.

## Stage 2 — SEV-SNP — done

**Paravirt, not `#VC`.** We own every privileged-instruction call site
(serial, debug-exit, virtio-mmio), and the binary contains no
`cpuid`/`rdtsc`/`wbinvd`, so instead of an IDT, exception-frame asm and an
instruction decoder, those sites call the GHCB directly (`sev::outb`/`inb`/
`outl`/`mmio_{read,write}32`). KVM forwards `SVM_EXIT_IOIO` and
`SVM_VMGEXIT_MMIO_*` to its ordinary handlers, which surface as plain
`KVM_EXIT_IO`/`KVM_EXIT_MMIO` — the vmm's emulation is identical for plain
and encrypted guests.

`sev::init()` runs first thing in 64-bit Rust: refine page tables to 4 KiB
for `[0, 2 MiB)`, `PVALIDATE`-rescind + MSR-protocol PSC + C-bit-clear the
GHCB page, register its GPA. After that the boot path is the same as
non-SEV. The vmm enables `KVM_CAP_EXIT_HYPERCALL` and answers
`KVM_HC_MAP_GPA_RANGE` with `KVM_SET_MEMORY_ATTRIBUTES`; KVM does the
RMPUPDATE.

Launch: `KVM_X86_SNP_VM` → `KVM_SEV_INIT2` → `guest_memfd` + memslot →
`SNP_LAUNCH_{START,UPDATE,FINISH}`. The vmm computes the measurement input
from the same `include_bytes!` ELF span, so IGVM is not needed.

## Stage 3 — virtio-vsock — done

Guest: hand-rolled modern virtio-mmio transport + split virtqueue +
single-connection STREAM, polling. Under SNP, register accesses go through
GHCB-MMIO and the whole `Vsock` instance (rings + buffers) is flipped to
shared pages before `DRIVER_OK`; the host already controls every byte that
flows through it, so sharing the bookkeeping fields too is DoS-only
(indices are bounds-checked).

Host: `vmm` emulates the virtio-mmio register window and offloads the
virtqueues to `/dev/vhost-vsock`. vhost reads rings via the anon mmap
that backs the shared half of the guest_memfd memslot, so no SNP-specific
handling. The uhid bridge runs in-process. `e2e::libfido2_vmm{,_snp}` run
the full `libfido2` register/attest/assert/verify against the single
binary.

## Stage 4 — attestation in attStmt — done

`fmt` stays `"packed"` so stock libfido2 verifies the self-attestation;
the SNP report rides alongside under an extra `"snp"` key it ignores:

```text
attStmt = {
  "alg": -7,
  "sig": ecdsa(credKey, authData || clientDataHash),     // self-attestation
  "snp": SNP_ATTESTATION_REPORT,                         // report_data =
}                                                        //   sha512(authData || cdh)
```

Guest: vmm injects a `SECRETS` page at `0x1000`; `greq.rs` reads VMPCK0,
AES-256-GCM-wraps `MSG_REPORT_REQ`/`MSG_KEY_REQ`, and issues
`SVM_VMGEXIT_GUEST_REQUEST` (handled entirely in-kernel by KVM). The
derived key (`guest_field_select = policy|measurement`) is the master
secret — same binary on same chip ⇒ credentials survive restarts.

Verifier (`e2e/src/snp.rs`): raw-hidraw CTAPHID client extracts the
report, checks `report_data` binds `authData||cdh`, fetches the VCEK
from AMD KDS by `(chip_id, reported_tcb)`, and verifies the P-384
signature. A second launch asserts the measurement is stable.

Not yet: an offline tool that recomputes the expected measurement from
the ELF + a VMSA template (à la `sev-snp-measure`). KVM's
`sev_es_sync_vmsa` packs FPU/VMCB-save-area defaults that are kernel-
version-specific, so this is its own small project.

## Non-SEV development loop

Stages 1+3 run on any KVM host: `cargo run -p vmm --release` exercises the
full vsock + CTAP path. The encrypted launch and stage 4 need an EPYC host
with SNP enabled.

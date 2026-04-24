#!/usr/bin/env bash
# Boot the bare-metal enclave under plain QEMU (no SEV) and check it reaches
# kmain. QEMU exits via isa-debug-exit: status 1 means qemu_exit(0).
set -euo pipefail
cd "$(dirname "$0")/.."

cargo build -p enclave --target x86_64-unknown-none --release
ELF=target/x86_64-unknown-none/release/enclave

rc=0
out=$(timeout 10 qemu-system-x86_64 \
	-kernel "$ELF" \
	-cpu max -m 8M -nographic -no-reboot \
	-device isa-debug-exit,iobase=0xf4,iosize=0x04 2>&1) || rc=$?

printf '%s\n' "$out"
grep -q 'ctap link ok' <<<"$out"
[ "$rc" -eq 1 ] || {
	echo "unexpected qemu exit $rc" >&2
	exit 1
}
echo "OK"

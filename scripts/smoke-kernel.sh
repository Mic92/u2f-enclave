#!/usr/bin/env bash
# Full libfido2 register+attest+assert+verify against the bare-metal
# unikernel over real virtio-vsock (vhost-vsock-device, QEMU microvm).
#
# This is the proof that the hand-rolled virtio-mmio + vsock + CTAP stack
# is correct end-to-end: an unmodified libfido2 talks to a ~100 KB no_std
# kernel that does its own page tables, virtqueue and ECDSA.
#
# Requires rw on /dev/uhid and /dev/vhost-vsock (kvm group).
set -euo pipefail
cd "$(dirname "$0")/.."

CID=42
PORT=5555
TMP="${XDG_RUNTIME_DIR:?}/u2fe-kern"
rm -rf "$TMP"
mkdir -p "$TMP"

cargo build --release -p bridge
cargo build -p enclave --target x86_64-unknown-none --release
ELF=target/x86_64-unknown-none/release/enclave

QBOOT="$(dirname "$(dirname "$(readlink -f "$(command -v qemu-system-x86_64)")")")/share/qemu/qboot.rom"

qemu-system-x86_64 -M microvm,pic=off,pit=off,rtc=off,ioapic2=off \
	-cpu max -m 8M -nographic -no-reboot \
	-bios "$QBOOT" -global virtio-mmio.force-legacy=false \
	-device vhost-vsock-device,guest-cid="$CID" \
	-kernel "$ELF" >"$TMP/qemu.log" 2>&1 &
QEMU=$!
sleep 0.7
grep -q 'vsock cid' "$TMP/qemu.log" || {
	cat "$TMP/qemu.log"
	echo "kernel did not bring up vsock" >&2
	kill "$QEMU" 2>/dev/null
	exit 1
}

./target/release/bridge "vsock:$CID:$PORT" >"$TMP/bridge.log" 2>&1 &
BRIDGE=$!
trap 'kill $BRIDGE $QEMU 2>/dev/null; wait 2>/dev/null; rm -rf "$TMP"' EXIT
sleep 0.7

HIDRAW=""
for h in /sys/class/hidraw/hidraw*; do
	grep -q 'HID_NAME=u2f-enclave' "$h/device/uevent" 2>/dev/null && HIDRAW=/dev/$(basename "$h")
done
[ -n "$HIDRAW" ] || {
	cat "$TMP/bridge.log"
	echo "no hidraw" >&2
	exit 1
}
echo "device: $HIDRAW"

fido2-token -I "$HIDRAW"

{
	head -c32 /dev/urandom | base64
	echo example.org
	echo smoke-user
	head -c16 /dev/urandom | base64
} >"$TMP/cred-in"

fido2-cred -M -i "$TMP/cred-in" "$HIDRAW" >"$TMP/cred-out"
fido2-cred -V -i "$TMP/cred-out" -o "$TMP/cred-pk"

CRED_ID=$(sed -n '5p' "$TMP/cred-out")
{
	head -c32 /dev/urandom | base64
	echo example.org
	echo "$CRED_ID"
} >"$TMP/assert-in"

fido2-assert -G -i "$TMP/assert-in" "$HIDRAW" >"$TMP/assert-out"
fido2-assert -V -i "$TMP/assert-out" "$TMP/cred-pk" es256

echo "OK: bare-metal register + attest + assert + verify"

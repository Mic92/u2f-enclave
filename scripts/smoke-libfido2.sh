#!/usr/bin/env bash
# End-to-end interop check against Yubico's libfido2.
#
# Starts sim+bridge, registers a credential with fido2-cred, verifies the
# self-attestation, gets an assertion, and verifies the signature with the
# registered public key. All four steps must return rc=0.
#
# Requires rw on /dev/uhid (e.g. `sudo setfacl -m u:$USER:rw /dev/uhid`).
# The created hidraw node is typically picked up by the distro's FIDO udev
# rule (usage page 0xF1D0) and granted to the seat user.
set -euo pipefail

cd "$(dirname "$0")/.."
SOCK="${XDG_RUNTIME_DIR:?}/u2f-enclave.sock"
TMP="${XDG_RUNTIME_DIR}/u2fe-smoke"
mkdir -p "$TMP"

cargo build --release -p sim -p bridge

./target/release/sim "$SOCK" &
SIM=$!
sleep 0.3
./target/release/bridge "$SOCK" &
BRIDGE=$!
trap 'kill $BRIDGE $SIM 2>/dev/null; wait 2>/dev/null; rm -rf "$TMP"' EXIT
sleep 0.7

HIDRAW=""
for h in /sys/class/hidraw/hidraw*; do
	if grep -q 'HID_NAME=u2f-enclave' "$h/device/uevent" 2>/dev/null; then
		HIDRAW=/dev/$(basename "$h")
	fi
done
[ -n "$HIDRAW" ] || {
	echo "no hidraw node found" >&2
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

echo "OK: register + attest + assert + verify all passed"

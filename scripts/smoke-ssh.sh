#!/usr/bin/env bash
# End-to-end OpenSSH sk- key check against the simulator.
#
# ssh-keygen -t ecdsa-sk drives makeCredential; the subsequent ssh login
# drives getAssertion and has sshd verify the ECDSA signature. Passing means
# our CTAPHID framing, CBOR, credential derivation and DER encoding are all
# accepted by an independent FIDO2 client *and* an independent verifier.
#
# Preconditions: rw on /dev/uhid (see smoke-libfido2.sh).
set -euo pipefail
cd "$(dirname "$0")/.."

SOCK="${XDG_RUNTIME_DIR:?}/u2f-enclave.sock"
TMP="${XDG_RUNTIME_DIR}/u2fe-ssh"
PORT=58022
rm -rf "$TMP"
mkdir -p "$TMP"
chmod 700 "$TMP"

cargo build --release -p sim -p bridge

./target/release/sim "$SOCK" 2>"$TMP/sim.log" &
SIM=$!
sleep 0.3
./target/release/bridge "$SOCK" 2>"$TMP/bridge.log" &
BRIDGE=$!
SSHD=""
trap 'kill $BRIDGE $SIM $SSHD 2>/dev/null; wait 2>/dev/null; rm -rf "$TMP"' EXIT
sleep 0.7

ssh-keygen -t ecdsa-sk -f "$TMP/id" -N "" -O application=ssh:u2fe

ssh-keygen -t ed25519 -f "$TMP/hostkey" -N "" -q
cat >"$TMP/sshd_config" <<EOF
Port $PORT
ListenAddress 127.0.0.1
HostKey $TMP/hostkey
PidFile $TMP/sshd.pid
AuthorizedKeysFile $TMP/authorized_keys
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
UsePAM no
StrictModes no
EOF
cp "$TMP/id.pub" "$TMP/authorized_keys"
chmod 600 "$TMP/authorized_keys"

"$(command -v sshd)" -f "$TMP/sshd_config" -D -e 2>"$TMP/sshd.log" &
SSHD=$!
sleep 0.5

ssh -p "$PORT" -i "$TMP/id" \
	-o IdentitiesOnly=yes -o IdentityAgent=none \
	-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
	"$USER@127.0.0.1" true

grep -q 'Accepted publickey.*ECDSA-SK' "$TMP/sshd.log"
echo "OK: ssh-keygen + ssh login via enclave authenticator"

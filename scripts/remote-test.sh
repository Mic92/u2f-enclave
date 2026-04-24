#!/usr/bin/env bash
# Sync the workspace to a remote host and run the test suite there.
#
#   U2FE_HOST=<host> U2FE_DIR=<abs-path> scripts/remote-test.sh [cargo-test-args...]
#
# Env (required):
#   U2FE_HOST  remote ssh target ([user@]host)
#   U2FE_DIR   remote checkout dir
# Env (optional):
#   U2FE_SSH   extra ssh options, word-split (e.g. "-J jump.example")
#
# Keeps the remote target/ dir between runs so only the first invocation
# pays for the toolchain fetch and full build.
set -euo pipefail

if [[ -z ${U2FE_HOST:-} || -z ${U2FE_DIR:-} ]]; then
  echo "error: U2FE_HOST and U2FE_DIR must be set" >&2
  echo "  U2FE_HOST=[user@]host  U2FE_DIR=/abs/path  ${0##*/} [cargo-test-args...]" >&2
  exit 2
fi
: "${U2FE_SSH:=}"

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)

# Multiplex rsync's ssh and the command ssh over one connection so we only
# pay one jump-host round-trip and one auth handshake per script run.
CTL="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/ssh-u2fenc-%C"
# shellcheck disable=SC2206
SSH=(ssh -o ControlMaster=auto -o "ControlPath=${CTL}" -o ControlPersist=10m ${U2FE_SSH})

echo ">> sync ${ROOT} -> ${U2FE_HOST}:${U2FE_DIR}"
rsync -az --delete --info=stats1 \
  -e "${SSH[*]}" \
  --exclude /target/ \
  --exclude '/result*' \
  --exclude /.direnv/ \
  "${ROOT}/" "${U2FE_HOST}:${U2FE_DIR}/"

# The cluster has no libfido2 udev rule, so the uhid-created /dev/hidrawN
# comes up 600 root and the e2e tests can't open it. We don't know N ahead
# of time (the bridge creates it mid-test), so run an ad-hoc root watcher
# alongside cargo that chmods any hidraw node whose HID parent is ours.
# Remote username comes from `id -un` on the remote — non-login shells on
# NixOS don't always export $USER.
# `printf %q` so extra cargo args survive the ssh word-splitting round-trip.
# shellcheck disable=SC2029,SC2016
"${SSH[@]}" "${U2FE_HOST}" "
  set -euo pipefail
  cd $(printf %q "${U2FE_DIR}")
  sudo -n setfacl -m u:\$(id -un):rw /dev/uhid
  sudo -n bash -c '
    while :; do
      for h in /sys/class/hidraw/hidraw*; do
        grep -qs HID_NAME=u2f-enclave \"\$h/device/uevent\" \
          && chmod 666 \"/dev/\${h##*/}\"
      done
      sleep 0.05
    done' &
  W=\$!
  trap 'sudo -n kill \$W 2>/dev/null' EXIT
  nix develop -c cargo test $(printf '%q ' "$@")
"

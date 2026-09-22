#!/usr/bin/env bash
#
# Pack a release binary with UPX and prove the packed result still runs.
#
#   pack-verify.sh <binary> <qemu-binary> [<qemu-cpu>]
#
# Shared by release.yml and release-dryrun.yml so the release path and the
# rehearsal cannot drift apart.
#
# `upx -t` only proves the payload round-trips. The failure that actually
# reaches users is a stub that packs cleanly and then dies on the target ABI,
# so the binary is executed for real -- before packing as well, because
# otherwise a broken emulator looks exactly like a passing check.
#
# <qemu-cpu> is for a build whose point is running without some extension:
# QEMU's default CPU has all of them, so a binary that needs one still passes.
set -euo pipefail

BIN="$1"
QEMU=("$2")
[[ -z "${3:-}" ]] || QEMU+=(-cpu "$3")
OUT="$(mktemp -d)"

test -f "$BIN"

check_runs() {
    # Not piped into grep: with `set -o pipefail` a short-circuiting `grep -q`
    # can take the producer down with SIGPIPE and fail the step spuriously.
    "${QEMU[@]}" "$BIN" --help > "${OUT}/$1.txt"
    grep -q "Usage: tg-ws-proxy" "${OUT}/$1.txt"
}

check_runs plain
BEFORE="$(stat -c %s "$BIN")"

upx -9 --lzma "$BIN"
upx -t "$BIN"

check_runs packed
AFTER="$(stat -c %s "$BIN")"

echo "${BIN}: ${BEFORE} -> ${AFTER} bytes on flash"

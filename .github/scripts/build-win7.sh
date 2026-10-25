#!/usr/bin/env bash
#
# Build the Windows 7 binary for one target, prove it asks Windows for nothing
# newer than 7, and zip it.
#
#   build-win7.sh <target> <out.zip>
#
# Shared by release.yml and release-dryrun.yml so the release path and the
# rehearsal cannot drift apart. Runs on a windows-latest runner, under bash.
#
# The regular Windows build cannot run on 7: since Rust 1.78 the standard
# library calls Windows 8/10 APIs directly (ProcessPrng, WaitOnAddress, ...).
# The `*-win7-windows-msvc` targets keep the old fallbacks, but they are tier 3
# -- no prebuilt std -- hence nightly and `-Z build-std` (#156).
#
# `+crt-static` links the C runtime into the binary. Left dynamic, the exe
# needs vcruntime140.dll and the Universal CRT, which a stock Windows 7 does
# not have.
set -euo pipefail

TARGET="$1"
OUT_ZIP="$2"

RUSTFLAGS="-C target-feature=+crt-static" \
    cargo +nightly build --release --locked --bin tg-ws-proxy \
    --target "$TARGET" -Z build-std=std,panic_abort

BIN="target/${TARGET}/release/tg-ws-proxy.exe"
test -f "$BIN"

# Nothing downstream runs this on Windows 7, so a regression would ship
# silently -- the import table is the one thing that can be checked here. These
# are the ways it has gone wrong before or would: a dynamic CRT, or a std/dep
# call into an API that only exists from Windows 8 on.
HOST="$(rustc +nightly -vV | sed -n 's/^host: //p')"
READOBJ="$(rustc +nightly --print sysroot)/lib/rustlib/${HOST}/bin/llvm-readobj.exe"
IMPORTS="$(mktemp)"
"$READOBJ" --coff-imports "$BIN" > "$IMPORTS"

echo "DLLs imported by ${BIN}:"
sed -n 's/^ *Name: //p' "$IMPORTS" | sort -fu

bad_dlls="$(sed -n 's/^ *Name: //p' "$IMPORTS" |
    grep -iE '^(api-ms-win-crt-|ucrtbase|vcruntime|msvcp|bcryptprimitives|api-ms-win-core-synch-l1-2-0)' || true)"
bad_symbols="$(sed -n 's/^ *Symbol: \([A-Za-z0-9_]*\).*/\1/p' "$IMPORTS" |
    grep -xE 'ProcessPrng|GetSystemTimePreciseAsFileTime|WaitOnAddress|WakeByAddressSingle|WakeByAddressAll|CreateFile2|GetTempPath2W' || true)"
if [[ -n "$bad_dlls$bad_symbols" ]]; then
    echo "::error::${BIN} imports something Windows 7 does not have: ${bad_dlls} ${bad_symbols}"
    exit 1
fi

# Not piped into grep: with `set -o pipefail` a short-circuiting `grep -q` can
# take the producer down with SIGPIPE and fail the step spuriously.
"$BIN" --help > "${IMPORTS}.help"
grep -q "Usage: tg-ws-proxy" "${IMPORTS}.help"

STAGE="$(mktemp -d)"
cp "$BIN" "${STAGE}/tg-ws-proxy.exe"
rm -f "$OUT_ZIP"
OUT_ABS="$(cd "$(dirname "$OUT_ZIP")" && pwd)/$(basename "$OUT_ZIP")"
(cd "$STAGE" && 7z a -tzip "$OUT_ABS" tg-ws-proxy.exe > /dev/null)
test -s "$OUT_ZIP"

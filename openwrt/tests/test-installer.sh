#!/usr/bin/env bash
# shellcheck disable=SC2034,SC2317,SC2329 # Globals and apk/opkg stubs are consumed by functions sourced from install.sh.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
INSTALLER="$ROOT/install.sh"
[[ -x "$INSTALLER" ]] || { printf 'FAIL: install.sh is missing or not executable\n' >&2; exit 1; }

help="$($INSTALLER --help)"
for token in '--archive' '--luci-package' '--upx' '--channel' 'stable' 'beta' 'apk' 'opkg'; do
    [[ "$help" == *"$token"* ]] || { printf 'FAIL: installer help misses %s\n' "$token" >&2; exit 1; }
done
if grep -Eq '(^|[[:space:]])install[[:space:]]+-m' "$INSTALLER"; then
    printf 'FAIL: installer requires the absent OpenWrt install command\n' >&2
    exit 1
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
: > "$tmp/core.tar.gz"
: > "$tmp/core-upx.tar.gz"
: > "$tmp/luci.apk"
: > "$tmp/luci.ipk"

out="$($INSTALLER --dry-run --archive "$tmp/core.tar.gz" --luci-package "$tmp/luci.apk" \
    --arch aarch64_cortex-a53 --package-manager apk)"
[[ "$out" == *'package_manager=apk'* && "$out" == *'target=aarch64-unknown-linux-musl'* && "$out" == *'variant=regular'* ]] || {
    printf 'FAIL: APK dry-run did not resolve regular AArch64 binary\n' >&2
    exit 1
}
out="$($INSTALLER --dry-run --archive "$tmp/core-upx.tar.gz" --luci-package "$tmp/luci.ipk" \
    --arch x86_64 --package-manager opkg)"
[[ "$out" == *'package_manager=opkg'* && "$out" == *'target=x86_64-unknown-linux-musl'* && "$out" == *'variant=upx'* ]] || {
    printf 'FAIL: IPK dry-run did not retain UPX selection\n' >&2
    exit 1
}

export TG_WS_PROXY_TEST_MODE=1
# shellcheck source=/dev/null
source "$INSTALLER"

for mapping in \
    aarch64_cortex-a53:aarch64-unknown-linux-musl \
    arm_cortex-a7_neon-vfpv4:armv7-unknown-linux-musleabihf \
    arm_cortex-a9_vfpv3-d16:armv7-unknown-linux-musleabihf \
    arm_cortex-a9:armv7-unknown-linux-musleabi \
    arm_cortex-a7:armv7-unknown-linux-musleabi \
    mips_24kc:mips-unknown-linux-musl \
    mipsel_24kc:mipsel-unknown-linux-musl \
    x86_64:x86_64-unknown-linux-musl; do
    arch="${mapping%%:*}"
    target="${mapping#*:}"
    [[ "$(binary_target "$arch")" == "$target" ]] || {
        printf 'FAIL: %s did not map to %s\n' "$arch" "$target" >&2
        exit 1
    }
done
if binary_target arm_arm1176jzf-s_vfp >/dev/null 2>&1; then
    printf 'FAIL: unsupported ARMv6 target was accepted\n' >&2
    exit 1
fi

TARGET=aarch64-unknown-linux-musl
USE_UPX=0
[[ "$(binary_archive_name)" == tg-ws-proxy-aarch64-unknown-linux-musl.tar.gz ]] || {
    printf 'FAIL: regular archive name is wrong\n' >&2; exit 1;
}
USE_UPX=1
[[ "$(binary_archive_name)" == tg-ws-proxy-aarch64-unknown-linux-musl-upx.tar.gz ]] || {
    printf 'FAIL: UPX archive name is wrong\n' >&2; exit 1;
}

# `musleabi` is a prefix of `musleabihf`, and the hard-float archive is listed
# first here: a lookup by target stem would hand a router without VFP the build
# that dies on it.
for variant in '' -upx; do
    want="tg-ws-proxy-armv7-unknown-linux-musleabi$variant.tar.gz"
    got="$(
        release_asset_urls() {
            printf 'https://example.invalid/%s\n' \
                "tg-ws-proxy-armv7-unknown-linux-musleabihf$variant.tar.gz" "$want"
        }
        find_release_asset release.json "$want" ''
    )"
    [[ "$got" == "https://example.invalid/$want" ]] || {
        printf 'FAIL: %s resolved to %s\n' "$want" "$got" >&2; exit 1;
    }
done

APK_ARGS=''
OPKG_ARGS=''
apk() { APK_ARGS="$*"; }
opkg() { OPKG_ARGS="$*"; }
LUCI_PACKAGE_FILE=/tmp/luci-package
PM=apk
install_luci_package
[[ "$APK_ARGS" == "--allow-untrusted --force-non-repository add $LUCI_PACKAGE_FILE" ]] || {
    printf 'FAIL: APK trust policy changed: %s\n' "$APK_ARGS" >&2; exit 1;
}
PM=opkg
install_luci_package
[[ "$OPKG_ARGS" == "install $LUCI_PACKAGE_FILE" ]] || {
    printf 'FAIL: IPK install uses unexpected options: %s\n' "$OPKG_ARGS" >&2; exit 1;
}

PM=apk
APK_ARGS=''
remove_luci_package
[[ "$APK_ARGS" == "del luci-app-tg-ws-proxy-rs" ]] || {
    printf 'FAIL: APK removal does not target the -rs package: %s\n' "$APK_ARGS" >&2; exit 1;
}
PM=opkg
OPKG_ARGS=''
remove_luci_package
[[ "$OPKG_ARGS" == "remove luci-app-tg-ws-proxy-rs" ]] || {
    printf 'FAIL: IPK removal does not target the -rs package: %s\n' "$OPKG_ARGS" >&2; exit 1;
}

# The unsuffixed names belong to the upstream tg-ws-proxy package unless this
# project's own 2.2.3 integration package claims them.
: > "$tmp/pm.log"
apk() { printf '%s\n' "$*" >> "$tmp/pm.log"; }
opkg() { printf '%s\n' "$*" >> "$tmp/pm.log"; printf 'Status: install ok installed\n'; }
PM=apk
luci_is_installed
legacy_luci_is_installed
PM=opkg
luci_is_installed
legacy_luci_is_installed
grep -Fxq 'info -e luci-app-tg-ws-proxy-rs' "$tmp/pm.log" || {
    printf 'FAIL: APK does not probe the -rs package\n' >&2; exit 1;
}
grep -Fxq 'status luci-app-tg-ws-proxy' "$tmp/pm.log" || {
    printf 'FAIL: IPK does not probe the legacy package\n' >&2; exit 1;
}

LEGACY_INIT="$tmp/legacy-init"
# shellcheck disable=SC2016 # $1 belongs to the generated stub, not to this shell.
printf '#!/bin/sh\nprintf "%%s\\n" "$1" >> "%s/legacy-init.log"\n' "$tmp" > "$LEGACY_INIT"
chmod +x "$LEGACY_INIT"
LEGACY_PACKAGE=0
if legacy_service_control stop >/dev/null 2>&1; then
    printf 'FAIL: the legacy init script is driven without proof that it is ours\n' >&2
    exit 1
fi
[[ ! -e "$tmp/legacy-init.log" ]] || {
    printf 'FAIL: the legacy init script ran while LEGACY_PACKAGE was 0\n' >&2
    exit 1
}
LEGACY_PACKAGE=1
legacy_service_control stop
grep -Fxq stop "$tmp/legacy-init.log" || {
    printf 'FAIL: the legacy init script was not driven once it is proven ours\n' >&2
    exit 1
}

for owner_output in 'tg-ws-proxy - 0.9.2-r1' 'tg-ws-proxy'; do
    PM=opkg
    # shellcheck disable=SC2317
    opkg() { printf '%s\n' "$owner_output"; }
    legacy_path_is_foreign /etc/config/tg-ws-proxy || {
        printf 'FAIL: a foreign owner (%s) was not detected\n' "$owner_output" >&2
        exit 1
    }
done
for owner_output in 'luci-app-tg-ws-proxy - 2.2.3-r1' ''; do
    PM=opkg
    # shellcheck disable=SC2317
    opkg() { [[ -z "$owner_output" ]] || printf '%s\n' "$owner_output"; }
    if legacy_path_is_foreign /etc/config/tg-ws-proxy; then
        printf 'FAIL: our own 2.2.3 package (%s) was treated as foreign\n' "$owner_output" >&2
        exit 1
    fi
done

PM=apk
apk() { printf '/usr/bin/tg-ws-proxy is owned by tg-ws-proxy-0.9.2-r1\n'; }
[[ "$(package_owning_path /usr/bin/tg-ws-proxy)" == 'tg-ws-proxy-0.9.2-r1' ]] || {
    printf 'FAIL: APK file ownership is not detected\n' >&2; exit 1;
}
PM=opkg
opkg() { printf 'tg-ws-proxy - 0.9.2-r1\n'; }
[[ "$(package_owning_path /usr/bin/tg-ws-proxy)" == 'tg-ws-proxy' ]] || {
    printf 'FAIL: IPK file ownership is not detected\n' >&2; exit 1;
}
opkg() { :; }
[[ -z "$(package_owning_path /usr/bin/tg-ws-proxy)" ]] || {
    printf 'FAIL: an unowned path was reported as package-owned\n' >&2; exit 1;
}

printf 'binary archive\n' > "$tmp/archive"
printf 'luci package\n' > "$tmp/luci"
(
    cd "$tmp"
    sha256sum archive luci > SHA256SUMS
)
ARCHIVE_FILE="$tmp/archive"
LUCI_PACKAGE_FILE="$tmp/luci"
CHECKSUMS_FILE="$tmp/SHA256SUMS"
verify_assets >/dev/null

printf 'trusted payload\n' > "$tmp/digest-payload"
payload_digest="sha256:$(sha256sum "$tmp/digest-payload" | sed 's/[[:space:]].*//')"
verify_asset_digest "$tmp/digest-payload" "$payload_digest" "test payload"
if (verify_asset_digest "$tmp/digest-payload" "sha256:$(printf '%064d' 0)" "test payload") >/dev/null 2>&1; then
    printf 'FAIL: a mismatched GitHub asset digest was accepted\n' >&2
    exit 1
fi

backup_root="$tmp/backups"
mkdir -p "$backup_root"
for n in 1 2 3 4 5; do mkdir "$backup_root/install-20260810-00000$n"; done
prune_backups "$backup_root" 3
[[ "$(find "$backup_root" -mindepth 1 -maxdepth 1 -type d | wc -l)" -eq 3 ]] || {
    printf 'FAIL: backup retention did not keep exactly three recovery points\n' >&2
    exit 1
}
for n in 3 4 5; do
    [[ -d "$backup_root/install-20260810-00000$n" ]] || {
        printf 'FAIL: backup retention removed a recent recovery point\n' >&2
        exit 1
    }
done

printf 'PASS: installer contract\n'

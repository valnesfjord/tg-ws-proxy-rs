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

# ---- Entware -----------------------------------------------------------------
#
# The Entware path is the one that cannot be exercised end to end here: it
# installs into /opt, drives rc.unslung and binds a port. What is pinned below
# is the part the CI runner can decide -- which platform is detected, which
# architecture Entware reports, what the release URL is built from, and that the
# LuCI package stops being required the moment the platform is not OpenWrt.

entware_root="$tmp/entware"
mkdir -p "$entware_root/bin" "$entware_root/etc" "$entware_root/etc/init.d"
: > "$entware_root/etc/opkg.conf"
# shellcheck disable=SC2016 # The %s are printf's, expanded when the stub runs.
printf '#!/bin/sh\nprintf "%%s\\n" "arch all 100" "arch mipsel-3.4 150" "arch mipsel-3.4_kn 200"\n' \
	> "$entware_root/bin/opkg"
chmod +x "$entware_root/bin/opkg"

out="$(env -u TG_WS_PROXY_TEST_MODE TG_WS_PROXY_ROOT="$entware_root" "$INSTALLER" \
	--dry-run --archive "$tmp/core.tar.gz")"
[[ "$out" == *'platform=entware'* ]] || {
	printf 'FAIL: an Entware root was not detected as Entware\n' >&2
	exit 1
}
# The Keenetic feed declares mipsel-3.4_kn at a higher priority than mipsel-3.4,
# and that is the name the box was installed from.
[[ "$out" == *'architecture=mipsel-3.4_kn'* && "$out" == *'target=mipsel-unknown-linux-musl'* ]] || {
	printf 'FAIL: Entware architecture resolution is wrong: %s\n' "$out" >&2
	exit 1
}
printf '%s\n' "$out" | grep -qx 'luci_package=' || {
	printf 'FAIL: the Entware dry-run is not the binary-only asset set: %s\n' "$out" >&2
	exit 1
}

# The release API is what needs jsonfilter, and Entware has none, so a beta has
# to name its tag.
if env -u TG_WS_PROXY_TEST_MODE TG_WS_PROXY_ROOT="$entware_root" "$INSTALLER" \
	--dry-run --channel beta --archive "$tmp/core.tar.gz" >"$tmp/entware-beta.log" 2>&1; then
	printf 'FAIL: a beta release was accepted on Entware without --tag\n' >&2
	exit 1
fi
grep -q -- '--tag' "$tmp/entware-beta.log" || {
	printf 'FAIL: the Entware beta refusal does not name --tag\n' >&2
	exit 1
}

for mapping in \
	mipsel:mipsel-unknown-linux-musl \
	mipsel-3.4:mipsel-unknown-linux-musl \
	mipsel-3.4_kn:mipsel-unknown-linux-musl \
	mipsel-3x:mipsel-unknown-linux-musl \
	mips-3.4:mips-unknown-linux-musl \
	mips-3x:mips-unknown-linux-musl \
	aarch64-3.10:aarch64-unknown-linux-musl \
	armv7-3.2:armv7-unknown-linux-musleabihf \
	armv7-2.6:armv7-unknown-linux-musleabihf \
	x64-3.2:x86_64-unknown-linux-musl; do
	arch="${mapping%%:*}"
	target="${mapping#*:}"
	[[ "$(entware_binary_target "$arch")" == "$target" ]] || {
		printf 'FAIL: %s did not map to %s\n' "$arch" "$target" >&2
		exit 1
	}
done
# A name with no release target is refused rather than installed and crashed:
# ARMv5, the 32-bit x86 feed, and x86_64-3.2 (Entware calls that arch x64-3.2).
# The ARMv7 feeds are soft-float builds reporting armv7-*, which map to
# musleabihf: a core without VFP is caught by the run check, not by the name.
for arch in armv5-3.2 x86-2.6 x86_64-3.2; do
	if entware_binary_target "$arch" >/dev/null 2>&1; then
		printf 'FAIL: unsupported Entware target %s was accepted\n' "$arch" >&2
		exit 1
	fi
done

# The archive comes from wherever GH_MIRROR says; the manifest it is checked
# against comes from the release itself, through the downloader that has no
# mirror branch at all.
TMP_DIR="$tmp/downloads"
mkdir -p "$TMP_DIR"
PLATFORM=entware
USE_UPX=0
TARGET=mipsel-unknown-linux-musl
TAG=''
backup_log="$tmp/downloads.log"
: > "$backup_log"
# shellcheck disable=SC2317 # Stubs for the downloaders, consumed by the sourced installer.
dl() { printf 'mirror-eligible %s\n' "$1" >> "$backup_log"; : > "$2"; }
# shellcheck disable=SC2317
dl_url() { printf 'github-only %s\n' "$1" >> "$backup_log"; : > "$2"; }
resolve_entware_assets
grep -Fxq 'mirror-eligible https://github.com/valnesfjord/tg-ws-proxy-rs/releases/latest/download/tg-ws-proxy-mipsel-unknown-linux-musl.tar.gz' "$backup_log" || {
	printf 'FAIL: the latest release URL is wrong: %s\n' "$(cat "$backup_log")" >&2
	exit 1
}
grep -Fxq 'github-only https://github.com/valnesfjord/tg-ws-proxy-rs/releases/latest/download/SHA256SUMS' "$backup_log" || {
	printf 'FAIL: the manifest is not fetched from the release itself: %s\n' "$(cat "$backup_log")" >&2
	exit 1
}

: > "$backup_log"
TAG=v2.4.2-beta.1
resolve_entware_assets
grep -Fxq 'mirror-eligible https://github.com/valnesfjord/tg-ws-proxy-rs/releases/download/v2.4.2-beta.1/tg-ws-proxy-mipsel-unknown-linux-musl.tar.gz' "$backup_log" || {
	printf 'FAIL: --tag does not address the tagged release: %s\n' "$(cat "$backup_log")" >&2
	exit 1
}
TAG=''

# The binary alone is the whole asset set, so a checksum manifest has to verify
# without a LuCI package beside it.
ARCHIVE_FILE="$tmp/archive"
LUCI_PACKAGE_FILE=''
CHECKSUMS_FILE="$tmp/SHA256SUMS"
verify_assets >/dev/null

# An upgrade keeps the port the box was told to listen on, and a fresh install
# gets the default.
ENTWARE_CONF_DIR="$tmp/entware-etc"
mkdir -p "$ENTWARE_CONF_DIR"
[[ "$(entware_configured_port)" == 1443 ]] || {
	printf 'FAIL: a missing config did not default to port 1443\n' >&2
	exit 1
}
printf 'HOST="0.0.0.0"\nPORT="2443"\n' > "$ENTWARE_CONF_DIR/config.conf"
[[ "$(entware_configured_port)" == 2443 ]] || {
	printf 'FAIL: an installed port was not preserved across an upgrade\n' >&2
	exit 1
}

# A link address the LAN can actually dial is written into the config rather
# than left to the binary's own detection, which reports a tunnel address on a
# router with one.
mkdir -p "$tmp/fakebin"
printf '#!/bin/sh\nprintf "    inet 192.0.2.1/24 brd 192.0.2.255 scope global br0\\n"\n' > "$tmp/fakebin/ip"
chmod +x "$tmp/fakebin/ip"
PATH="$tmp/fakebin:$PATH"
[[ "$(entware_lan_ip)" == 192.0.2.1 ]] || {
	printf 'FAIL: the bridge address was not read back\n' >&2
	exit 1
}

# The generated init script has to be valid shell with every placeholder
# substituted: it is sourced by rc.unslung at boot, and a syntax error there is
# a proxy that never starts.
ENTWARE_ROOT="$entware_root"
ENTWARE_INIT="$entware_root/etc/init.d/S99tg-ws-proxy-rs"
write_entware_init
[[ -x "$ENTWARE_INIT" ]] || {
	printf 'FAIL: the generated init script is not executable, which is what rc.unslung scans for\n' >&2
	exit 1
}
if grep -q '@ROOT@' "$ENTWARE_INIT"; then
	printf 'FAIL: the init script kept an unsubstituted placeholder\n' >&2
	exit 1
fi
bash -n "$ENTWARE_INIT" || {
	printf 'FAIL: the generated init script does not parse\n' >&2
	exit 1
}
# rc.unslung runs it with BusyBox sh, not bash, so it is checked as sh.
command -v shellcheck >/dev/null 2>&1 || {
	printf 'FAIL: shellcheck is required to check the generated init script\n' >&2
	exit 1
}
shellcheck -s sh "$ENTWARE_INIT" || {
	printf 'FAIL: shellcheck reported issues in the generated init script\n' >&2
	exit 1
}
grep -Fq "PROG=$entware_root/bin/tg-ws-proxy-rs" "$ENTWARE_INIT" || {
	printf 'FAIL: the init script does not point at the installed binary\n' >&2
	exit 1
}

# A rollback restores the state the box was in, and for an upgrade that state
# includes a running service: an install that fails must not leave the router
# with no proxy at all. The two halves are checked separately because the
# platform makes them separate -- the files come back from the backup, the
# process comes back only if it was there before.
rt="$tmp/rollback"
mkdir -p "$rt/bin" "$rt/etc/init.d" "$rt/etc/tg-ws-proxy-rs"
ENTWARE_BIN="$rt/bin/tg-ws-proxy-rs"
ENTWARE_INIT="$rt/etc/init.d/S99tg-ws-proxy-rs"
ENTWARE_CONF_DIR="$rt/etc/tg-ws-proxy-rs"
ENTWARE_LOGFILE="$rt/var/log/tg-ws-proxy-rs.log"
BACKUP_DIR="$tmp/rollback-backup"
mkdir -p "$BACKUP_DIR$rt/bin" "$BACKUP_DIR$rt/etc/init.d" "$BACKUP_DIR$rt/etc/tg-ws-proxy-rs"
printf 'old binary\n' > "$BACKUP_DIR$ENTWARE_BIN"
printf 'old init\n' > "$BACKUP_DIR$ENTWARE_INIT"
printf 'old config\n' > "$BACKUP_DIR$ENTWARE_CONF_DIR/config.conf"
printf 'old secret\n' > "$BACKUP_DIR$ENTWARE_CONF_DIR/secret.conf"
printf 'new binary\n' > "$ENTWARE_BIN"
printf 'new init\n' > "$ENTWARE_INIT"
printf 'new config\n' > "$ENTWARE_CONF_DIR/config.conf"
LEGACY_ENTWARE_DISABLED=0
# shellcheck disable=SC2317 # Stubs for the service controls, consumed by the sourced installer.
entware_service_control() { printf '%s\n' "$1" >> "$tmp/rollback-control.log"; }

: > "$tmp/rollback-control.log"
ENTWARE_WAS_RUNNING=1
rollback_entware >/dev/null 2>&1
[[ "$(cat "$ENTWARE_BIN")" == 'old binary' ]] || {
	printf 'FAIL: the rollback did not restore the binary\n' >&2
	exit 1
}
[[ "$(cat "$ENTWARE_INIT")" == 'old init' ]] || {
	printf 'FAIL: the rollback did not restore the init script\n' >&2
	exit 1
}
[[ "$(cat "$ENTWARE_CONF_DIR/config.conf")" == 'old config' ]] || {
	printf 'FAIL: the rollback did not restore the config\n' >&2
	exit 1
}
grep -Fxq stop "$tmp/rollback-control.log" || {
	printf 'FAIL: the rollback did not stop the service before restoring it\n' >&2
	exit 1
}
grep -Fxq start "$tmp/rollback-control.log" || {
	printf 'FAIL: the rollback left a service that was running before it down\n' >&2
	exit 1
}

# A install that failed from nothing restores nothing running.
: > "$tmp/rollback-control.log"
ENTWARE_WAS_RUNNING=0
rollback_entware >/dev/null 2>&1
if grep -Fxq start "$tmp/rollback-control.log"; then
	printf 'FAIL: the rollback started a service that was not running before\n' >&2
	exit 1
fi

printf 'PASS: installer contract\n'

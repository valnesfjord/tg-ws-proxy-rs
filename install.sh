#!/bin/sh
# Installs a tg-ws-proxy-rs release binary on OpenWrt 24.10+ (with its LuCI
# integration) or on an Entware box -- the userland Keenetic and other routers
# run at /opt -- where the same release binary is driven by an Entware init
# script and configured through a file instead of UCI.
#
# Every installed path is suffixed with -rs so this port coexists with an
# upstream tg-ws-proxy package; releases up to 2.2.3 used the unsuffixed names
# and are migrated here.

G='\033[0;32m'; R='\033[0;31m'; Y='\033[0;33m'; C='\033[0;36m'; N='\033[0m'
ok()   { printf "${G}%s${N}\n" "$1"; }
info() { printf "${C}%s${N}\n" "$1"; }
warn() { printf "${Y}%s${N}\n" "$1"; }
die()  { printf "${R}error: %s${N}\n" "$1" >&2; exit 1; }

REPOSITORY="${TG_WS_PROXY_REPOSITORY:-valnesfjord/tg-ws-proxy-rs}"
CHANNEL="${TG_WS_PROXY_RELEASE_CHANNEL:-stable}"
USE_UPX="${TG_WS_PROXY_UPX:-0}"
ARCHIVE_FILE=''
ARCHIVE_URL=''
ARCHIVE_DIGEST=''
LUCI_PACKAGE_FILE=''
LUCI_PACKAGE_URL=''
LUCI_PACKAGE_DIGEST=''
CHECKSUMS_FILE=''
ARCH_OVERRIDE=''
PM_OVERRIDE=''
ARCH=''
TARGET=''
PM=''
EXT=''
DRY_RUN=0
TMP_DIR=''
STAGED_BINARY=''
BACKUP_DIR=''
OLD_CONFIG=0
OLD_LUCI_PACKAGE=0
OLD_RUNNING=0
OLD_ENABLED=0
LEGACY_INIT=/etc/init.d/tg-ws-proxy
LEGACY_PACKAGE=0
LEGACY_RUNNING=0
LEGACY_ENABLED=0
LEGACY_CONFIG_MIGRATED=0

# Platform selection. The Entware root is /opt on every Entware box; the
# override exists so the contract tests can point the installer at a fixture.
PLATFORM=''
PLATFORM_OVERRIDE=''
TAG=''
ENTWARE_ROOT="${TG_WS_PROXY_ROOT:-/opt}"
ENTWARE_BIN=''
ENTWARE_INIT=''
ENTWARE_CONF_DIR=''
ENTWARE_LOGFILE=''
ENTWARE_BACKUP_ROOT=''
ENTWARE_PORT=''
ENTWARE_WAS_RUNNING=0
LEGACY_ENTWARE_INIT=''
LEGACY_ENTWARE_DISABLED=0

usage() {
	cat <<'EOF'
Usage: sh install.sh [options]

Options:
  --archive PATH       Install a local release .tar.gz archive
  --luci-package PATH  Install a local luci-app-tg-ws-proxy-rs APK/IPK
  --upx                Select the smaller UPX-packed release binary
  --channel stable|beta
                       Select latest stable (default) or beta release
  --dry-run            Resolve architecture and assets without installing
  --arch ARCH          Override the detected architecture (tests/manual use)
  --package-manager apk|opkg
                       Override detected package manager (tests/manual use)
  --platform openwrt|entware
                       Force the platform instead of detecting it
  --tag TAG            Install an exact release tag, e.g. v2.4.2-beta.1
  -h, --help           Show this help

Two platforms are supported, detected by their own markers:

  OpenWrt 24.10+   /etc/openwrt_release. The binary plus a LuCI APK (25.12+) or
                   IPK (24.10) that provides the UCI/procd service.
  Entware          <root>/etc/opkg.conf, as on Keenetic. Only the binary is
                   installed: the service is an Entware init script under
                   <root>/etc/init.d, configured through
                   <root>/etc/tg-ws-proxy-rs/config.conf. There is no LuCI and
                   no UCI, so nothing is asked of an opkg feed.

Without --archive, assets are downloaded from GitHub Releases. The regular
binary is selected by default; --upx selects the matching *-upx.tar.gz asset.
APK install uses --allow-untrusted explicitly after SHA-256 verification.

On OpenWrt the expected digest comes from the GitHub release API, which needs
jsonfilter. Entware ships no jsonfilter, so there the archive is verified
against the release's own SHA256SUMS -- fetched from github.com rather than
from a mirror -- and the installed binary is then run, which is what a digest
alone cannot do on a network that answers a mirror's cached release. That same
absence is why --channel beta needs --tag on Entware: the tag names the release
directly, with no API to list the prereleases.

--tag is Entware-only: on OpenWrt the LuCI package's filename carries the
version and its package revision, so the API is what finds it.

Set GH_MIRROR=https://mirror.example to retry release-asset downloads through a
mirror. TG_WS_PROXY_RELEASE_CHANNEL and TG_WS_PROXY_UPX provide env equivalents,
and TG_WS_PROXY_ROOT overrides the Entware root (default /opt; tests/manual use).
EOF
}

while [ "$#" -gt 0 ]; do
	case "$1" in
		--archive) [ "$#" -ge 2 ] || die "--archive requires a path"; ARCHIVE_FILE="$2"; shift 2 ;;
		--luci-package) [ "$#" -ge 2 ] || die "--luci-package requires a path"; LUCI_PACKAGE_FILE="$2"; shift 2 ;;
		--upx) USE_UPX=1; shift ;;
		--channel) [ "$#" -ge 2 ] || die "--channel requires stable or beta"; CHANNEL="$2"; shift 2 ;;
		--dry-run) DRY_RUN=1; shift ;;
		--arch) [ "$#" -ge 2 ] || die "--arch requires a value"; ARCH_OVERRIDE="$2"; shift 2 ;;
		--package-manager) [ "$#" -ge 2 ] || die "--package-manager requires apk or opkg"; PM_OVERRIDE="$2"; shift 2 ;;
		--platform) [ "$#" -ge 2 ] || die "--platform requires openwrt or entware"; PLATFORM_OVERRIDE="$2"; shift 2 ;;
		--tag) [ "$#" -ge 2 ] || die "--tag requires a release tag"; TAG="$2"; shift 2 ;;
		-h|--help) usage; exit 0 ;;
		*) die "unknown argument: $1" ;;
	esac
done

case "$CHANNEL" in stable|beta) ;; *) die "unsupported release channel: $CHANNEL" ;; esac
case "$PLATFORM_OVERRIDE" in ''|openwrt|entware) ;; *) die "unsupported platform: $PLATFORM_OVERRIDE (expected openwrt or entware)" ;; esac
case "$USE_UPX" in 0|false|no|off|'') USE_UPX=0 ;; 1|true|yes|on) USE_UPX=1 ;; *) die "TG_WS_PROXY_UPX must be 0 or 1" ;; esac

cleanup() {
	[ -n "$TMP_DIR" ] && rm -rf "$TMP_DIR"
}
if [ "${TG_WS_PROXY_TEST_MODE:-0}" != 1 ]; then
	trap cleanup EXIT INT TERM
fi

load_openwrt_release() {
	[ -r /etc/openwrt_release ] || return 1
	# shellcheck disable=SC1091
	. /etc/openwrt_release 2>/dev/null
}

binary_target() {
	case "$1" in
		aarch64|aarch64_*) printf '%s' aarch64-unknown-linux-musl ;;
		armv7|arm_cortex-a5_vfpv4|arm_cortex-a7_vfpv4|arm_cortex-a7_neon-vfpv4|\
		arm_cortex-a8_vfpv3|arm_cortex-a9_vfpv3-d16|arm_cortex-a9_neon|\
		arm_cortex-a15_neon-vfpv4) printf '%s' armv7-unknown-linux-musleabihf ;;
		mipsel|mipsel_24kc|mipsel_74kc) printf '%s' mipsel-unknown-linux-musl ;;
		mips|mips_24kc) printf '%s' mips-unknown-linux-musl ;;
		x86_64) printf '%s' x86_64-unknown-linux-musl ;;
		*) return 1 ;;
	esac
}

# Entware names its architectures after the ABI they were built for, with a
# version suffix and, on the Keenetic feeds, a `_kn` tag: mipsel-3.4_kn,
# aarch64-3.10, armv7-3.2, x64-3.2. Each maps onto one of the release's musl
# targets, so Entware answers the question /etc/openwrt_release answers on
# OpenWrt -- which is why uname is not consulted: on MIPS it says "mips" for
# both endians, and every Entware name already says which one it is. A name with
# no release target falls through and is refused (armv5-3.2, x86-2.6). Entware's
# ARMv7 feeds are soft-float builds that report armv7-3.2, which maps to
# musleabihf here: a core without VFP is caught by the run check, not the name.
entware_binary_target() {
	case "$1" in
		aarch64|aarch64-[0-9]*) printf '%s' aarch64-unknown-linux-musl ;;
		armv7|armv7-[0-9]*) printf '%s' armv7-unknown-linux-musleabihf ;;
		mipsel|mipsel-[0-9]*) printf '%s' mipsel-unknown-linux-musl ;;
		mips|mips-[0-9]*) printf '%s' mips-unknown-linux-musl ;;
		x64|x64-[0-9]*) printf '%s' x86_64-unknown-linux-musl ;;
		*) return 1 ;;
	esac
}

# Entware keeps opkg under its own root, which is not on PATH for a
# non-interactive shell on every firmware.
entware_opkg() {
	if [ -x "$ENTWARE_ROOT/bin/opkg" ]; then
		printf '%s' "$ENTWARE_ROOT/bin/opkg"
	else
		printf '%s' opkg
	fi
}

# The architecture Entware itself is configured for. `opkg print-architecture`
# lists `arch <name> <priority>` exactly as opkg.conf declares them, and several
# names can share a priority band (mipsel-3.4 at 150, mipsel-3.4_kn at 200), so
# the highest is the one this box was installed from. `all` is not a machine.
entware_arch() {
	arch_list="$("$(entware_opkg)" print-architecture 2>/dev/null)" || return 1
	best=''
	best_priority=''
	while read -r _keyword name priority; do
		[ -n "$name" ] || continue
		[ "$name" = all ] && continue
		if [ -z "$best_priority" ] || [ "$priority" -gt "$best_priority" ] 2>/dev/null; then
			best="$name"
			best_priority="$priority"
		fi
	done <<EOF
$arch_list
EOF
	[ -n "$best" ] || return 1
	printf '%s' "$best"
}

# Which platform this is. OpenWrt wins wherever it is present: /opt can exist
# there as an extroot, and the LuCI integration is still the right service
# model. The --arch/--package-manager pair is what the contract tests drive the
# installer with on a runner that has neither marker, and it describes the
# OpenWrt asset set -- a binary beside a LuCI package -- so it selects OpenWrt.
detect_platform() {
	if [ -n "$PLATFORM_OVERRIDE" ]; then
		printf '%s' "$PLATFORM_OVERRIDE"
		return 0
	fi
	if [ -r /etc/openwrt_release ]; then
		printf '%s' openwrt
		return 0
	fi
	if [ -r "$ENTWARE_ROOT/etc/opkg.conf" ]; then
		printf '%s' entware
		return 0
	fi
	if [ -n "$ARCH_OVERRIDE" ] && [ -n "$PM_OVERRIDE" ]; then
		printf '%s' openwrt
		return 0
	fi
	return 1
}

binary_archive_name() {
	upx_suffix=''
	[ "$USE_UPX" -eq 0 ] || upx_suffix=-upx
	printf 'tg-ws-proxy-%s%s.tar.gz' "$TARGET" "$upx_suffix"
}

resolve_environment() {
	PLATFORM="$(detect_platform)" ||
		die "neither OpenWrt (/etc/openwrt_release) nor Entware ($ENTWARE_ROOT/etc/opkg.conf) was found"
	if [ "$PLATFORM" = entware ]; then
		resolve_entware_environment
		return 0
	fi

	if [ -n "$PM_OVERRIDE" ]; then PM="$PM_OVERRIDE"
	elif command -v apk >/dev/null 2>&1; then PM=apk
	elif command -v opkg >/dev/null 2>&1; then PM=opkg
	else die "supported package manager not found (apk/opkg)"; fi
	case "$PM" in apk) EXT=apk ;; opkg) EXT=ipk ;; *) die "unsupported package manager: $PM" ;; esac

	if [ -n "$ARCH_OVERRIDE" ]; then
		ARCH="$ARCH_OVERRIDE"
	elif load_openwrt_release && [ -n "${DISTRIB_ARCH:-}" ]; then
		ARCH="$DISTRIB_ARCH"
	else
		die "cannot read OpenWrt DISTRIB_ARCH"
	fi
	TARGET="$(binary_target "$ARCH")" || die "unsupported OpenWrt architecture: $ARCH"
}

resolve_entware_environment() {
	[ -n "$TAG" ] || case "$CHANNEL" in
		beta) die "--channel beta needs --tag on Entware: listing prereleases is a release-API call, and Entware ships no jsonfilter" ;;
	esac

	PM=opkg
	EXT=ipk
	ENTWARE_BIN="$ENTWARE_ROOT/bin/tg-ws-proxy-rs"
	ENTWARE_INIT="$ENTWARE_ROOT/etc/init.d/S99tg-ws-proxy-rs"
	ENTWARE_CONF_DIR="$ENTWARE_ROOT/etc/tg-ws-proxy-rs"
	ENTWARE_LOGFILE="$ENTWARE_ROOT/var/log/tg-ws-proxy-rs.log"

	if [ -n "$ARCH_OVERRIDE" ]; then
		ARCH="$ARCH_OVERRIDE"
	else
		ARCH="$(entware_arch)" ||
			die "cannot read the Entware architecture from $(entware_opkg) print-architecture (pass --arch, e.g. mipsel-3.4)"
	fi
	TARGET="$(entware_binary_target "$ARCH")" || die "unsupported Entware architecture: $ARCH"
}

# One attempt at one URL, through whichever downloader this box has: a box may
# carry curl and no wget or the reverse, and either may be built without TLS
# (BusyBox wget answers "not an http or ftp url" for an https URL).
#
# What is bounded is the silence, not the total time: this fetches a couple of
# megabytes from GitHub, which on a filtered network is minutes of progress
# rather than a stall, so curl's --speed-time/--speed-limit pair is the same
# guard as wget's --timeout=30.
dl_url() {
	url="$1"
	out="$2"
	if command -v wget >/dev/null 2>&1; then
		wget -qO "$out" --timeout=30 "$url" 2>/dev/null && [ -s "$out" ] && return 0
	fi
	if command -v curl >/dev/null 2>&1; then
		curl -fsSL --connect-timeout 15 --speed-time 30 --speed-limit 1024 \
			-o "$out" "$url" 2>/dev/null && [ -s "$out" ] && return 0
	fi
	rm -f "$out"
	return 1
}

# The payload may be served by a mirror. The digest it is checked against is
# not taken from one: a mirror's copy travels the same channel as the payload
# it describes, so reading it there would replace a check with the appearance
# of one. GH_MIRROR is therefore only ever tried for the payload.
dl() {
	url="$1"
	out="$2"
	dl_url "$url" "$out" && return 0
	if [ -n "${GH_MIRROR:-}" ]; then
		mirror="${GH_MIRROR%/}"
		dl_url "$mirror${url#https://github.com}" "$out" && return 0
	fi
	return 1
}

release_asset_urls() {
	jsonfilter -i "$1" -e '@.assets[*].browser_download_url'
}

find_release_asset() {
	json_file="$1"
	prefix="$2"
	suffix="$3"
	release_asset_urls "$json_file" | while IFS= read -r url; do
		name="${url##*/}"
		case "$name" in "$prefix"*"$suffix") printf '%s\n' "$url"; break ;; esac
	done
}

release_asset_digest() {
	json_file="$1"
	name="$2"
	jsonfilter -i "$json_file" -e "@.assets[@.name=\"$name\"].digest"
}

latest_beta_tag() {
	jsonfilter -i "$1" -e '@[*].tag_name' | while IFS= read -r tag; do
		case "$tag" in v*-beta.[1-9]*) printf '%s\n' "$tag"; break ;; esac
	done
}

# Entware has no jsonfilter, so the release API is not an option: the release is
# addressed by its own download URL and verified against the SHA256SUMS asset
# published beside the binaries. That is a weaker trust anchor than the API's
# digest -- the manifest comes from the same origin as the payload -- and it is
# paired with the run check in stage_binary, which is the part a digest cannot
# do anyway: a network that answers a latest URL from a cache serves a manifest
# and a binary that agree with each other and with nothing else.
resolve_entware_assets() {
	TMP_DIR="$(mktemp -d /tmp/tg-ws-proxy-install.XXXXXX)" || die "cannot create temporary directory"
	release_path=latest/download
	[ -z "$TAG" ] || release_path="download/$TAG"
	release_base="https://github.com/$REPOSITORY/releases/$release_path"

	archive_name="$(binary_archive_name)"
	ARCHIVE_URL="$release_base/$archive_name"
	ARCHIVE_FILE="$TMP_DIR/$archive_name"
	dl "$ARCHIVE_URL" "$ARCHIVE_FILE" || die "cannot download $archive_name (set GH_MIRROR if GitHub is blocked)"

	CHECKSUMS_FILE="$TMP_DIR/SHA256SUMS"
	dl_url "$release_base/SHA256SUMS" "$CHECKSUMS_FILE" ||
		die "cannot download the SHA256SUMS for this release; without it there is nothing to verify the binary against"
}

resolve_remote_assets() {
	if [ "$PLATFORM" = entware ]; then
		resolve_entware_assets
		return 0
	fi
	if [ -n "$TAG" ]; then
		die "--tag is Entware-only: on OpenWrt the LuCI package name carries the version and its package revision, so the release API is what finds it"
	fi
	command -v jsonfilter >/dev/null 2>&1 || die "jsonfilter is required"
	TMP_DIR="$(mktemp -d /tmp/tg-ws-proxy-install.XXXXXX)" || die "cannot create temporary directory"
	api_file="$TMP_DIR/release.json"
	if [ "$CHANNEL" = beta ]; then
		releases_file="$TMP_DIR/releases.json"
		wget -qO "$releases_file" --timeout=30 \
			"https://api.github.com/repos/$REPOSITORY/releases?per_page=100" 2>/dev/null || \
			die "cannot query GitHub beta releases (the unauthenticated API may be rate-limited; retry later)"
		release_tag="$(latest_beta_tag "$releases_file")"
		[ -n "$release_tag" ] || die "no beta release found"
		api_url="https://api.github.com/repos/$REPOSITORY/releases/tags/$release_tag"
	else
		api_url="https://api.github.com/repos/$REPOSITORY/releases/latest"
	fi
	wget -qO "$api_file" --timeout=30 "$api_url" 2>/dev/null || \
		die "cannot query GitHub release API (the unauthenticated API may be rate-limited; retry later)"

	archive_name="$(binary_archive_name)"
	ARCHIVE_URL="$(find_release_asset "$api_file" "$archive_name" '')"
	[ -n "$ARCHIVE_URL" ] || die "release asset is missing: $archive_name"
	ARCHIVE_DIGEST="$(release_asset_digest "$api_file" "$archive_name")"
	[ -n "$ARCHIVE_DIGEST" ] || die "GitHub API digest is missing: $archive_name"
	LUCI_PACKAGE_URL="$(find_release_asset "$api_file" luci-app-tg-ws-proxy-rs ".$EXT")"
	[ -n "$LUCI_PACKAGE_URL" ] || die "release LuCI $EXT package is missing (this installer needs release 2.2.4 or newer)"
	luci_package_name="${LUCI_PACKAGE_URL##*/}"
	LUCI_PACKAGE_DIGEST="$(release_asset_digest "$api_file" "$luci_package_name")"
	[ -n "$LUCI_PACKAGE_DIGEST" ] || die "GitHub API digest is missing: $luci_package_name"

	ARCHIVE_FILE="$TMP_DIR/$archive_name"
	LUCI_PACKAGE_FILE="$TMP_DIR/$luci_package_name"
	dl "$ARCHIVE_URL" "$ARCHIVE_FILE" || die "cannot download binary archive (set GH_MIRROR if GitHub is blocked)"
	dl "$LUCI_PACKAGE_URL" "$LUCI_PACKAGE_FILE" || die "cannot download LuCI APK"
}

resolve_local_assets() {
	# The LuCI package only exists on OpenWrt; Entware installs the binary alone.
	if [ "$PLATFORM" = openwrt ]; then
		[ -n "$LUCI_PACKAGE_FILE" ] || die "--luci-package is required with --archive"
	fi
	case "$ARCHIVE_FILE" in
		*-upx.tar.gz) USE_UPX=1 ;;
		*) [ "$USE_UPX" -eq 0 ] || die "--upx selects remote assets; pass the local *-upx.tar.gz archive directly" ;;
	esac
	case "$ARCHIVE_FILE" in */*) asset_dir="${ARCHIVE_FILE%/*}" ;; *) asset_dir=. ;; esac
	[ -f "$asset_dir/SHA256SUMS" ] && CHECKSUMS_FILE="$asset_dir/SHA256SUMS"
}

verify_release_checksum() {
	file="$1"
	label="$2"
	name="${file##*/}"
	expected="$(while read -r sum listed; do
		listed="${listed#\*}"
		[ "$listed" = "$name" ] && { printf '%s' "$sum"; break; }
	done < "$CHECKSUMS_FILE")"
	[ -n "$expected" ] || die "$label is missing from SHA256SUMS: $name"
	actual="$(sha256sum "$file" | sed 's/[[:space:]].*//')"
	[ "$actual" = "$expected" ] || die "$label SHA-256 mismatch"
}

verify_asset_digest() {
	file="$1"
	digest="$2"
	label="$3"
	case "$digest" in sha256:*) expected="${digest#sha256:}" ;; *) die "$label has an unsupported GitHub digest" ;; esac
	[ "${#expected}" -eq 64 ] || die "$label has an invalid GitHub SHA-256 digest"
	case "$expected" in *[!0-9a-fA-F]*) die "$label has an invalid GitHub SHA-256 digest" ;; esac
	actual="$(sha256sum "$file" | sed 's/[[:space:]].*//')"
	[ "$actual" = "$expected" ] || die "$label SHA-256 mismatch"
}

verify_assets() {
	if [ -n "$ARCHIVE_DIGEST" ] || [ -n "$LUCI_PACKAGE_DIGEST" ]; then
		if [ -z "$ARCHIVE_DIGEST" ] || [ -z "$LUCI_PACKAGE_DIGEST" ]; then
			die "GitHub API digests are incomplete"
		fi
		verify_asset_digest "$ARCHIVE_FILE" "$ARCHIVE_DIGEST" "binary archive"
		verify_asset_digest "$LUCI_PACKAGE_FILE" "$LUCI_PACKAGE_DIGEST" "LuCI package"
		ok "SHA-256 verified against GitHub release asset digests."
	elif [ -n "$CHECKSUMS_FILE" ]; then
		verify_release_checksum "$ARCHIVE_FILE" "binary archive"
		if [ -n "$LUCI_PACKAGE_FILE" ]; then
			verify_release_checksum "$LUCI_PACKAGE_FILE" "LuCI package"
			ok "SHA-256 verified for binary and LuCI package."
		else
			ok "SHA-256 verified for the binary archive."
		fi
	else
		warn "Local assets have no SHA256SUMS; continuing because the paths were supplied explicitly."
	fi
}

stage_binary() {
	entries="$(tar -tzf "$ARCHIVE_FILE")" || die "cannot read binary archive"
	case "$entries" in tg-ws-proxy|./tg-ws-proxy) ;; *) die "binary archive has unexpected contents" ;; esac
	[ -n "$TMP_DIR" ] || TMP_DIR="$(mktemp -d /tmp/tg-ws-proxy-install.XXXXXX)" || die "cannot create temporary directory"
	stage_dir="$TMP_DIR/binary"
	mkdir -p "$stage_dir"
	tar -xzf "$ARCHIVE_FILE" -C "$stage_dir" || die "cannot extract binary archive"
	STAGED_BINARY="$stage_dir/tg-ws-proxy"
	[ -f "$STAGED_BINARY" ] || STAGED_BINARY="$stage_dir/./tg-ws-proxy"
	[ -x "$STAGED_BINARY" ] || die "release binary is not executable"
	"$STAGED_BINARY" --version >/dev/null 2>&1 || die "release binary cannot run on this router"
}

backup_path() {
	path="$1"
	[ -e "$path" ] || return 0
	mkdir -p "$BACKUP_DIR$(dirname "$path")"
	cp -p "$path" "$BACKUP_DIR$path"
}

restore_path() {
	path="$1"
	rm -f "$path"
	if [ -e "$BACKUP_DIR$path" ]; then
		mkdir -p "$(dirname "$path")"
		cp -p "$BACKUP_DIR$path" "$path"
	fi
}

prune_backups() {
	backup_root="$1"
	keep="$2"
	set -- "$backup_root"/install-*
	[ -e "$1" ] || return 0
	first_old=$((keep + 1))
	printf '%s\n' "$@" | sort -r | sed -n "${first_old},\$p" | while IFS= read -r backup; do
		[ -n "$backup" ] && rm -rf "$backup"
	done
}

read_old_env() {
	name="$1"
	[ -f "$BACKUP_DIR/process.env" ] || return 0
	sed -n "s/^${name}=//p" "$BACKUP_DIR/process.env" | sed -n '1p'
}

set_from_env() {
	value="$(read_old_env "$1")"
	[ -n "$value" ] && uci -q set "tg-ws-proxy-rs.main.$2=$value"
	return 0
}

set_list_from_env() {
	value="$(read_old_env "$1")"
	[ -n "$value" ] || return 0
	uci -q delete "tg-ws-proxy-rs.main.$2"
	old_ifs="$IFS"; IFS=','
	for item in $value; do [ -n "$item" ] && uci -q add_list "tg-ws-proxy-rs.main.$2=$item"; done
	IFS="$old_ifs"
}

migrate_log_level() {
	value="$(read_old_env RUST_LOG)"
	case "$value" in off|error|warn|info|debug|trace) ;;
		*) quiet="$(read_old_env TG_QUIET)"; verbose="$(read_old_env TG_VERBOSE)"
			case "$quiet" in 1|true|yes|on) value=off ;;
				*) case "$verbose" in 1|true|yes|on) value=debug ;; *) value=info ;; esac ;;
			esac ;;
	esac
	uci -q set "tg-ws-proxy-rs.main.log_level=$value"
}

migrate_command_args() {
	[ -f "$BACKUP_DIR/process.cmd" ] || return 0
	pending=''; dc_reset=0; cf_worker_reset=0
	while IFS= read -r arg; do
		if [ -n "$pending" ]; then
			case "$pending" in
				cf_worker_domain)
					[ "$cf_worker_reset" -eq 1 ] || { uci -q delete tg-ws-proxy-rs.main.cf_worker_domain; cf_worker_reset=1; }
					uci -q add_list "tg-ws-proxy-rs.main.cf_worker_domain=$arg" ;;
				dc_ip)
					[ "$dc_reset" -eq 1 ] || { uci -q delete tg-ws-proxy-rs.main.dc_ip; dc_reset=1; }
					uci -q add_list "tg-ws-proxy-rs.main.dc_ip=$arg" ;;
			esac
			pending=''
			continue
		fi
		case "$arg" in --cf-worker-domain|--cfproxy-worker-domain) pending=cf_worker_domain ;; --dc-ip) pending=dc_ip ;; esac
	done < "$BACKUP_DIR/process.cmd"
}

ensure_secret() {
	secret="$(uci -q get tg-ws-proxy-rs.main.secret)"
	[ -n "$secret" ] && return 0
	secret="$(dd if=/dev/urandom bs=16 count=1 2>/dev/null | hexdump -v -e '1/1 "%02x"')"
	case "$secret" in
		????????????????????????????????) uci -q set "tg-ws-proxy-rs.main.secret=$secret" ;;
		*) return 1 ;;
	esac
}

migrate_manual_config() {
	uci -q set tg-ws-proxy-rs.main=tg-ws-proxy-rs
	uci -q set tg-ws-proxy-rs.main.enabled=1
	if [ "$OLD_CONFIG" -eq 1 ]; then
		ensure_secret || return 1
		uci -q commit tg-ws-proxy-rs
		return 0
	fi

	set_from_env TG_HOST host
	set_from_env TG_PORT port
	set_from_env TG_SECRET secret
	set_from_env TG_LINK_IP link_ip
	set_from_env TG_LISTEN_FAKETLS_DOMAIN listen_faketls_domain
	set_from_env TG_BUF_KB buf_kb
	set_from_env TG_POOL_SIZE pool_size
	set_from_env TG_MAX_CONNECTIONS max_connections
	set_list_from_env TG_CF_WORKER_DOMAIN cf_worker_domain
	set_from_env TG_WS_CONNECT_TIMEOUT ws_connect_timeout
	set_from_env TG_WS_FAIL_PROBE_TIMEOUT ws_fail_probe_timeout
	set_from_env TG_WS_FAIL_COOLDOWN ws_fail_cooldown
	set_from_env TG_WS_REDIRECT_COOLDOWN ws_redirect_cooldown
	set_from_env TG_IP_FAIL_COOLDOWN ip_fail_cooldown
	set_from_env TG_HANDSHAKE_TIMEOUT handshake_timeout
	set_from_env TG_TCP_FALLBACK_TIMEOUT tcp_fallback_timeout
	set_from_env TG_UPSTREAM_CONNECT_TIMEOUT upstream_connect_timeout
	set_from_env TG_UPSTREAM_FAIL_COOLDOWN upstream_fail_cooldown
	set_from_env TG_CF_CONNECT_TIMEOUT cf_connect_timeout
	set_from_env TG_CF_FAIL_COOLDOWN cf_fail_cooldown
	set_from_env TG_FRONTING_DOMAIN fronting_domain
	set_from_env TG_FRONTING_COOLDOWN fronting_cooldown
	set_from_env TG_FRONTING_FAIL_COOLDOWN fronting_fail_cooldown
	set_from_env TG_POOL_MAX_AGE pool_max_age
	set_from_env TG_OUTBOUND_PROXY outbound_proxy
	set_from_env TG_NO_PROXY no_proxy
	set_from_env TG_SKIP_TLS_VERIFY danger_accept_invalid_certs
	set_from_env TG_CF_PRIORITY cf_priority
	set_from_env TG_CF_BALANCE cf_balance
	set_from_env TG_DEFAULT_DOMAINS default_domains
	set_from_env TG_NO_OUTBOUND_PROXY no_outbound_proxy
	set_list_from_env TG_MTPROTO_PROXY mtproto_proxy
	set_list_from_env TG_CF_DOMAIN cf_domain
	migrate_log_level
	migrate_command_args
	ensure_secret || return 1
	uci -q commit tg-ws-proxy-rs
}

service_control() {
	/etc/init.d/tg-ws-proxy-rs "$1"
}

# Releases up to 2.2.3 installed the unsuffixed names. They are only ever
# touched when luci-app-tg-ws-proxy is installed and no other package claims
# them; an upstream tg-ws-proxy package owns those names on some routers.
legacy_service_control() {
	[ "$LEGACY_PACKAGE" -eq 1 ] || return 1
	[ -x "$LEGACY_INIT" ] || return 1
	"$LEGACY_INIT" "$1"
}

# Fails closed: any output counts as "owned", because apk only prints the
# "<path> is owned by <package>" form at verbosity >= 1 and the bare package
# name below it, and an unparsed name must not read as an unowned path.
package_owning_path() {
	if [ "$PM" = apk ]; then
		owner_line="$(apk info --who-owns "$1" 2>/dev/null | sed -n 1p)"
		case "$owner_line" in *' is owned by '*) owner_line="${owner_line##* is owned by }" ;; esac
	else
		owner_line="$(opkg search "$1" 2>/dev/null | sed -n 1p)"
		case "$owner_line" in *' - '*) owner_line="${owner_line%% - *}" ;; esac
	fi
	printf '%s' "$owner_line"
}

# opkg reports the package name, apk reports name-version-release.
legacy_path_is_foreign() {
	owner="$(package_owning_path "$1")"
	[ -n "$owner" ] || return 1
	case "$owner" in luci-app-tg-ws-proxy|luci-app-tg-ws-proxy-[0-9]*) return 1 ;; esac
	return 0
}

legacy_process_pid() {
	for candidate in $(pidof tg-ws-proxy 2>/dev/null); do
		case "$(readlink "/proc/$candidate/exe" 2>/dev/null || true)" in
			/usr/bin/tg-ws-proxy) printf '%s' "$candidate"; return 0 ;;
		esac
	done
	return 1
}

# A pre-package manual installation is only imported when the running process
# runs from a path no package claims: /usr/bin/tg-ws-proxy can belong to an
# upstream tg-ws-proxy package, whose configuration is none of our business.
manual_process_pid() {
	for candidate in $(pidof tg-ws-proxy-rs 2>/dev/null) $(pidof tg-ws-proxy 2>/dev/null); do
		exe="$(readlink "/proc/$candidate/exe" 2>/dev/null || true)"
		case "$exe" in
			/usr/bin/tg-ws-proxy-rs) printf '%s' "$candidate"; return 0 ;;
			/usr/bin/tg-ws-proxy)
				[ -n "$(package_owning_path /usr/bin/tg-ws-proxy)" ] || {
					printf '%s' "$candidate"; return 0
				}
			;;
		esac
	done
	return 1
}

luci_is_installed() {
	if [ "$PM" = apk ]; then apk info -e luci-app-tg-ws-proxy-rs >/dev/null 2>&1
	else opkg status luci-app-tg-ws-proxy-rs 2>/dev/null | grep -q 'Status:.*installed'; fi
}

legacy_luci_is_installed() {
	if [ "$PM" = apk ]; then apk info -e luci-app-tg-ws-proxy >/dev/null 2>&1
	else opkg status luci-app-tg-ws-proxy 2>/dev/null | grep -q 'Status:.*installed'; fi
}

install_luci_package() {
	if [ "$PM" = apk ]; then
		apk --allow-untrusted --force-non-repository add "$LUCI_PACKAGE_FILE"
	else
		opkg install "$LUCI_PACKAGE_FILE"
	fi
}

remove_luci_package() {
	if [ "$PM" = apk ]; then apk del luci-app-tg-ws-proxy-rs >/dev/null 2>&1 || true
	else opkg remove luci-app-tg-ws-proxy-rs >/dev/null 2>&1 || true; fi
}

remove_legacy_installation() {
	[ "$LEGACY_PACKAGE" -eq 1 ] || return 0
	# A 2.2.3 process still holding the listening port means the readiness
	# probe above may have matched its socket rather than ours, so nothing it
	# depends on may be deleted yet.
	if [ -n "$(legacy_process_pid)" ]; then
		warn "The 2.2.3 process is still running; its package and files were left in place."
		warn "Stop it, verify tg-ws-proxy-rs, then remove luci-app-tg-ws-proxy by hand."
		return 0
	fi
	legacy_service_control disable >/dev/null 2>&1 || true
	if [ "$PM" = apk ]; then apk del luci-app-tg-ws-proxy >/dev/null 2>&1 || true
	else opkg remove luci-app-tg-ws-proxy >/dev/null 2>&1 || true; fi
	if legacy_luci_is_installed; then
		warn "luci-app-tg-ws-proxy could not be removed; its files were left in place."
		return 0
	fi
	if [ "$LEGACY_CONFIG_MIGRATED" -eq 1 ]; then
		rm -f /etc/config/tg-ws-proxy /etc/config/tg-ws-proxy.apk-new /etc/config/tg-ws-proxy-opkg
	elif [ -e /etc/config/tg-ws-proxy ]; then
		warn "/etc/config/tg-ws-proxy was not carried over and is left in place;"
		warn "the service now reads /etc/config/tg-ws-proxy-rs."
	fi
	owner="$(package_owning_path /usr/bin/tg-ws-proxy)"
	if [ -z "$owner" ]; then
		rm -f /usr/bin/tg-ws-proxy
	elif [ -e /usr/bin/tg-ws-proxy ]; then
		warn "/usr/bin/tg-ws-proxy belongs to package $owner and was left untouched."
		warn "Reinstall that package if an earlier tg-ws-proxy-rs release overwrote its binary."
	fi
	ok "Removed the previous luci-app-tg-ws-proxy integration."
}

restore_service_state() {
	if [ -x /etc/init.d/tg-ws-proxy-rs ]; then
		if [ "$OLD_ENABLED" -eq 1 ]; then service_control enable >/dev/null 2>&1 || true
		else service_control disable >/dev/null 2>&1 || true; fi
		if [ "$OLD_RUNNING" -eq 1 ]; then service_control start >/dev/null 2>&1 || true
		else service_control stop >/dev/null 2>&1 || true; fi
	fi
	[ "$LEGACY_PACKAGE" -eq 1 ] || return 0
	if [ "$LEGACY_ENABLED" -eq 1 ]; then legacy_service_control enable >/dev/null 2>&1 || true
	else legacy_service_control disable >/dev/null 2>&1 || true; fi
	if [ "$LEGACY_RUNNING" -eq 1 ]; then legacy_service_control start >/dev/null 2>&1 || true
	else legacy_service_control stop >/dev/null 2>&1 || true; fi
}

rollback() {
	warn "Installation failed; restoring the previous binary, UCI config and service state."
	service_control stop >/dev/null 2>&1 || true
	restore_path /usr/bin/tg-ws-proxy-rs
	if [ "$OLD_CONFIG" -eq 1 ]; then restore_path /etc/config/tg-ws-proxy-rs; fi
	if [ "$OLD_LUCI_PACKAGE" -eq 0 ]; then
		remove_luci_package
		for path in /etc/init.d/tg-ws-proxy-rs \
			/usr/share/luci/menu.d/luci-app-tg-ws-proxy-rs.json \
			/usr/share/rpcd/acl.d/luci-app-tg-ws-proxy-rs.json \
			/usr/share/ucitrack/luci-app-tg-ws-proxy-rs.json \
			/www/luci-static/resources/view/tg-ws-proxy-rs/settings.js; do
			restore_path "$path"
		done
		[ "$OLD_CONFIG" -eq 1 ] || rm -f /etc/config/tg-ws-proxy-rs
	else
		warn "The LuCI integration package remains at its upgraded version."
	fi
	uci -q revert tg-ws-proxy-rs
	restore_service_state
	warn "Recovery files are retained in $BACKUP_DIR"
}

listener_ready() {
	port="$1"
	netstat -lnt 2>/dev/null | (
		while IFS= read -r line; do
			case "$line" in *":$port "*) exit 0 ;; esac
		done
		exit 1
	)
}

wait_ready() {
	port="$(uci -q get tg-ws-proxy-rs.main.port)"; [ -n "$port" ] || port=1443
	i=0
	while [ "$i" -lt 15 ]; do
		service_control status >/dev/null 2>&1 && listener_ready "$port" && return 0
		i=$((i + 1)); sleep 1
	done
	return 1
}

# ---- Entware -----------------------------------------------------------------
#
# The service model here is rc.unslung: at boot the firmware sources every
# executable S* file under <root>/etc/init.d, so the executable bit is the
# on/off switch and the init script is the whole integration -- no UCI, no
# procd, no LuCI, and no opkg feed asked for anything.

# The address the generated tg:// link should advertise. The binary detects one
# itself when --link-ip is absent, and that is not always the one a LAN client
# can dial: a Keenetic with a router-side tunnel reports the tunnel address
# (100.90.x.x), and the link then points somewhere no phone can reach. The
# bridge address is what the LAN actually has, so it is written into the config
# and the detection stays the binary's fallback rather than the primary.
entware_lan_ip() {
	for device in br0 br-lan lan; do
		address="$(ip -4 addr show dev "$device" 2>/dev/null | sed -n 's/.*inet \([0-9][0-9.]*\)\/.*/\1/p' | sed -n '1p')"
		if [ -z "$address" ]; then
			address="$(ifconfig "$device" 2>/dev/null | sed -n 's/.*inet addr:\([0-9][0-9.]*\).*/\1/p' | sed -n '1p')"
		fi
		if [ -n "$address" ]; then
			printf '%s' "$address"
			return 0
		fi
	done
	return 1
}

# An upgrade must keep listening where the box was told to listen, so the port
# comes out of the config that is already there.
entware_configured_port() {
	port=''
	if [ -f "$ENTWARE_CONF_DIR/config.conf" ]; then
		port="$(sed -n 's/^PORT=["]\{0,1\}\([0-9][0-9]*\)["]\{0,1\}.*/\1/p' "$ENTWARE_CONF_DIR/config.conf" | sed -n '1p')"
	fi
	[ -n "$port" ] || port=1443
	printf '%s' "$port"
}

# A secret is 16 bytes of urandom as 32 hex characters. `tr` rather than `od`:
# BusyBox od has no -A, so `od -An -tx1` dies with "od: invalid option -- 'A'"
# on the routers this path exists for, and the firmware's od has no -t either
# (both checked on a Keenetic, kernel 4.9, BusyBox 1.37). Each character tr
# keeps is uniform over the sixteen it accepts, so the result still carries the
# same 128 bits. The OpenWrt path keeps hexdump, whose -e was checked to work
# on the same BusyBox.
entware_new_secret() {
	secret="$(tr -dc 'a-f0-9' < /dev/urandom | head -c 32)"
	case "$secret" in
		????????????????????????????????) printf '%s' "$secret" ;;
		*) return 1 ;;
	esac
}

write_entware_config() {
	mkdir -p "$ENTWARE_CONF_DIR" || return 1
	# A secret that is already installed is never replaced: it is what every
	# device on the LAN is paired with.
	if [ ! -f "$ENTWARE_CONF_DIR/secret.conf" ]; then
		secret="$(entware_new_secret)" || return 1
		printf 'SECRET=%s\n' "$secret" > "$ENTWARE_CONF_DIR/secret.conf" || return 1
	fi
	chmod 0600 "$ENTWARE_CONF_DIR/secret.conf" || return 1

	# An existing config is the operator's, including the port and any
	# Cloudflare fallback they configured; only a missing one is written.
	[ -f "$ENTWARE_CONF_DIR/config.conf" ] && return 0

	port="$(entware_configured_port)"
	link_ip="$(entware_lan_ip)" || link_ip=''
	cat > "$ENTWARE_CONF_DIR/config.conf" <<EOF
# tg-ws-proxy-rs configuration.
#
# Read by this directory's init script, which passes each setting to the binary
# as its TG_* environment variable. After an edit:
#   $ENTWARE_INIT restart
#
# The MTProto secret lives in secret.conf beside this file.

# Address and port the proxy listens on. 0.0.0.0 accepts every LAN device.
HOST="0.0.0.0"
PORT="$port"

# Address advertised in the generated tg:// link. The proxy binds HOST; this is
# only what the link says, and it has to be reachable from the devices that use
# the link.
LINK_IP="$link_ip"

# Fetch the upstream Cloudflare-proxy domain list at startup and use it as the
# routing fallbacks.
DEFAULT_DOMAINS="true"

# quiet | info | verbose -- written to $ENTWARE_ROOT/var/log/tg-ws-proxy-rs.log
# below here. "quiet" writes nothing at all, so status has no link to print.
LOG_LEVEL="info"

# Direct WebSocket target per DC, as DC:IP pairs, comma-separated, e.g.
# "2:149.154.167.220,4:149.154.167.220". Empty by default: where TCP to
# Telegram's DC addresses is filtered, a configured target makes every
# connection wait out --ws-connect-timeout before falling back to Cloudflare.
DC_IP=""

# Cloudflare fallback routes, comma-separated. CF_DOMAIN is tried ahead of the
# fetched default list, in the order written -- empty it to use that list's own
# order, or put a zone of your own here (kws1..kws5 A records, see
# docs/CfProxy.md). CF_WORKER_DOMAIN is a deployed Cloudflare Worker tunnel
# (docs/CfWorker.md).
CF_DOMAIN=""
CF_WORKER_DOMAIN=""

# Upstream MTProto proxies tried when the WebSocket path fails,
# HOST:PORT:SECRET, comma-separated.
MTPROTO_PROXY=""

# Extra command-line arguments appended verbatim, e.g.
#   EXTRA_ARGS="--fronting-domain sprinthost.ru --max-connections 64"
EXTRA_ARGS=""
EOF
	chmod 0600 "$ENTWARE_CONF_DIR/config.conf" || return 1
	return 0
}

write_entware_init() {
	# The root is substituted rather than written literally so that the script
	# and this installer agree on where Entware lives, and the body is a quoted
	# here-document because every $ in it belongs to the script at run time.
	sed "s|@ROOT@|$ENTWARE_ROOT|g" > "$ENTWARE_INIT" <<'EOF'
#!/bin/sh
# shellcheck disable=SC3037 # echo -e is BusyBox's; rc.unslung runs this with BusyBox sh.
# Entware init script for tg-ws-proxy-rs.
#
# The executable bit is the switch: rc.unslung sources every executable S* file
# in this directory at boot, so `chmod -x` disables the proxy without deleting
# anything.
#
# config.conf and secret.conf hold shell assignments and are read rather than
# parsed, so a value lives in exactly one place. They are read through a
# scratch copy with the carriage returns stripped: a config saved by an editor
# on Windows would otherwise run a stray CR after every assignment.

PROCS=tg-ws-proxy-rs
DESC="TG WS Proxy (Rust)"
PATH=@ROOT@/sbin:@ROOT@/bin:@ROOT@/usr/sbin:@ROOT@/usr/bin:/usr/sbin:/usr/bin:/sbin:/bin

ACTION=$1
CALLER=$2

PROG=@ROOT@/bin/tg-ws-proxy-rs
CONFIG_DIR=@ROOT@/etc/tg-ws-proxy-rs
CONFIG_FILE=$CONFIG_DIR/config.conf
SECRET_FILE=$CONFIG_DIR/secret.conf
LOGFILE=@ROOT@/var/log/tg-ws-proxy-rs.log

ansi_white="\033[1;37m"
ansi_green="\033[1;32m"
ansi_yellow="\033[1;33m"
ansi_red="\033[1;31m"
ansi_blue="\033[1;34m"
ansi_std="\033[m"

log() {
	command -v logger >/dev/null 2>&1 && logger -t tg-ws-proxy-rs "$1"
	return 0
}

load_config() {
	if [ ! -f "$CONFIG_FILE" ]; then
		echo "Config file not found: $CONFIG_FILE" >&2
		return 1
	fi
	if [ ! -f "$SECRET_FILE" ]; then
		echo "Secret file not found: $SECRET_FILE" >&2
		return 1
	fi

	SCRATCH="/tmp/tg-ws-proxy-rs.conf.$$"
	# The scratch copy holds the secret, so it is written under a mask that keeps
	# it to root, and removed whether or not sourcing it worked.
	scratch_umask="$(umask)"
	umask 077
	scrub_and_source() {
		if command -v tr >/dev/null 2>&1; then
			tr -d '\r' < "$1" > "$SCRATCH"
		else
			sed 's/\r$//' < "$1" > "$SCRATCH"
		fi
		# shellcheck source=/dev/null
		. "$SCRATCH"
	}
	scrub_and_source "$CONFIG_FILE" || { rm -f "$SCRATCH"; umask "$scratch_umask"; return 1; }
	scrub_and_source "$SECRET_FILE" || { rm -f "$SCRATCH"; umask "$scratch_umask"; return 1; }
	rm -f "$SCRATCH"
	umask "$scratch_umask"

	[ -n "${HOST+x}" ] || HOST=""
	[ -n "${PORT+x}" ] || PORT=""
	[ -n "${LINK_IP+x}" ] || LINK_IP=""
	[ -n "${DEFAULT_DOMAINS+x}" ] || DEFAULT_DOMAINS=""
	[ -n "${LOG_LEVEL+x}" ] || LOG_LEVEL="info"
	[ -n "${DC_IP+x}" ] || DC_IP=""
	[ -n "${CF_DOMAIN+x}" ] || CF_DOMAIN=""
	[ -n "${CF_WORKER_DOMAIN+x}" ] || CF_WORKER_DOMAIN=""
	[ -n "${MTPROTO_PROXY+x}" ] || MTPROTO_PROXY=""
	[ -n "${EXTRA_ARGS+x}" ] || EXTRA_ARGS=""
	return 0
}

# Every knob is exported explicitly rather than inherited: rc.unslung sources
# this file, so the proxy starts from this shell's environment and not from
# whatever the boot left lying around.
export_environment() {
	[ -n "$HOST" ] && export TG_HOST="$HOST"
	[ -n "$PORT" ] && export TG_PORT="$PORT"
	[ -n "$LINK_IP" ] && export TG_LINK_IP="$LINK_IP"
	export TG_SECRET="$SECRET"
	export TG_LOG_FILE="$LOGFILE"

	case "$LOG_LEVEL" in
		quiet) export TG_QUIET=true ;;
		verbose) export TG_VERBOSE=true ;;
	esac

	[ -n "$DEFAULT_DOMAINS" ] && export TG_DEFAULT_DOMAINS="$DEFAULT_DOMAINS"
	[ -n "$CF_DOMAIN" ] && export TG_CF_DOMAIN="$CF_DOMAIN"
	[ -n "$CF_WORKER_DOMAIN" ] && export TG_CF_WORKER_DOMAIN="$CF_WORKER_DOMAIN"
	[ -n "$MTPROTO_PROXY" ] && export TG_MTPROTO_PROXY="$MTPROTO_PROXY"
	return 0
}

# One run per log file, the previous kept as .1: print_link reads the link out of
# the log, and a link from an earlier run must not be able to answer for this
# one. A run's log over LOG_MAX is kept as its last LOG_TAIL bytes instead --
# the proxy holds the file open while it runs, so a cap can only be applied
# here, and /opt is often a small partition or a stick.
LOG_MAX=1048576
LOG_TAIL=65536
rotate_log() {
	[ -s "$LOGFILE" ] || return 0
	size="$(wc -c < "$LOGFILE" 2>/dev/null || echo 0)"
	if [ "$size" -gt "$LOG_MAX" ]; then
		tail -c "$LOG_TAIL" "$LOGFILE" > "$LOGFILE.1" 2>/dev/null || rm -f "$LOGFILE.1"
		rm -f "$LOGFILE"
		return 0
	fi
	mv -f "$LOGFILE" "$LOGFILE.1"
	return 0
}

print_link() {
	link="$(grep -o 'tg://proxy?[0-9A-Za-z?=&._-]*' "$LOGFILE" 2>/dev/null | tail -n 1)"
	[ -n "$link" ] || return 1
	echo -e "$ansi_blue Connect link: $link $ansi_std"
	log "Connect link: $link"
	return 0
}

# A bound listener is what readiness means here, not a line in the log: with
# LOG_LEVEL="quiet" the proxy writes nothing at all, so waiting on a banner
# would call a healthy proxy failed. The banner is only where the link comes
# from, which is why a start with no link still succeeds.
listener_ready() {
	port="$PORT"
	[ -n "$port" ] || port=1443
	netstat -lnt 2>/dev/null | (
		while IFS= read -r line; do
			case "$line" in *":$port "*) exit 0 ;; esac
		done
		exit 1
	)
}

start() {
	load_config || return 1

	if [ -z "$SECRET" ]; then
		echo "SECRET is empty in $SECRET_FILE" >&2
		return 1
	fi

	echo -e -n "$ansi_white Starting $DESC... $ansi_std"

	if pidof $PROCS >/dev/null 2>&1; then
		echo -e "            $ansi_yellow already running. $ansi_std"
		print_link
		return 0
	fi

	rotate_log
	export_environment

	set --
	if [ -n "$DC_IP" ]; then
		old_ifs="$IFS"
		IFS=','
		for item in $DC_IP; do set -- "$@" --dc-ip "$item"; done
		IFS="$old_ifs"
	fi

	# shellcheck disable=SC2086 # EXTRA_ARGS is a list of arguments, not one.
	"$PROG" "$@" $EXTRA_ARGS >/dev/null 2>&1 &

	tries=0
	while [ "$tries" -lt 15 ]; do
		pidof $PROCS >/dev/null 2>&1 || break
		listener_ready && break
		sleep 1
		tries=$((tries + 1))
	done

	if pidof $PROCS >/dev/null 2>&1 && listener_ready; then
		echo -e "            $ansi_green done. $ansi_std"
		log "Started $DESC${CALLER:+ from $CALLER}."
		print_link || true
		return 0
	fi

	echo -e "            $ansi_red failed. $ansi_std"
	echo "Last log lines from $LOGFILE:" >&2
	tail -n 5 "$LOGFILE" >&2 2>/dev/null
	log "Failed to start $DESC${CALLER:+ from $CALLER}."
	return 255
}

stop() {
	echo -e -n "$ansi_white Shutting down $PROCS... $ansi_std"
	killall $PROCS 2>/dev/null

	tries=0
	while [ "$tries" -lt 10 ]; do
		pidof $PROCS >/dev/null 2>&1 || break
		sleep 1
		tries=$((tries + 1))
	done

	if pidof $PROCS >/dev/null 2>&1; then
		killall -9 $PROCS 2>/dev/null
		sleep 1
	fi

	if pidof $PROCS >/dev/null 2>&1; then
		echo -e "            $ansi_red failed. $ansi_std"
		return 255
	fi

	echo -e "            $ansi_green done. $ansi_std"
	return 0
}

status() {
	echo -e -n "$ansi_white Checking $DESC... $ansi_std"
	if ! pidof $PROCS >/dev/null 2>&1; then
		echo -e "            $ansi_red dead. $ansi_std"
		return 1
	fi
	echo -e "            $ansi_green alive. $ansi_std"
	load_config || return 1
	print_link
	return 0
}

case "$ACTION" in
	start) start ;;
	stop) stop ;;
	restart) stop && start ;;
	status) status ;;
	*)
		echo -e "$ansi_white Usage: $0 (start|stop|restart|status)$ansi_std"
		exit 1
		;;
esac
EOF
	chmod 0755 "$ENTWARE_INIT"
}

entware_service_control() {
	[ -x "$ENTWARE_INIT" ] || return 1
	"$ENTWARE_INIT" "$1"
}

# S*tg-ws-proxy does not match S99tg-ws-proxy-rs: the name has to end there, so
# the -rs suffix keeps this port's script clear of the other build's, exactly as
# it does for every other installed path.
find_entware_legacy_init() {
	for init in "$ENTWARE_ROOT"/etc/init.d/S*tg-ws-proxy; do
		[ -e "$init" ] || continue
		printf '%s' "$init"
		return 0
	done
	return 1
}

# Another MTProto proxy on this box -- the Go port, the one whose process is
# named tg-ws-proxy -- wants the port this one is about to bind, and a proxy
# that cannot bind has not failed loudly: it starts, logs a bind error and does
# nothing while the caller sees a healthy process. So it is stopped and its init
# script's executable bit cleared, leaving its files and configuration alone; a
# rollback puts the bit back.
#
# Called after this port's own service is down, so a port still held at that
# point is held by the other build and the check cannot mistake this one for it.
disable_entware_legacy() {
	port="$1"
	[ -n "$(pidof tg-ws-proxy 2>/dev/null)" ] || return 0
	listener_ready "$port" || return 0
	LEGACY_ENTWARE_INIT="$(find_entware_legacy_init)" || {
		warn "another tg-ws-proxy holds port $port and no init script of its own was found"
		return 0
	}
	warn "another tg-ws-proxy holds port $port: stopping it and clearing $LEGACY_ENTWARE_INIT"
	"$LEGACY_ENTWARE_INIT" stop >/dev/null 2>&1 || killall tg-ws-proxy 2>/dev/null || true
	if chmod -x "$LEGACY_ENTWARE_INIT"; then
		LEGACY_ENTWARE_DISABLED=1
	fi
	return 0
}

entware_wait_ready() {
	port="$1"
	tries=0
	while [ "$tries" -lt 15 ]; do
		if [ -n "$(pidof tg-ws-proxy-rs 2>/dev/null)" ] && listener_ready "$port"; then
			return 0
		fi
		tries=$((tries + 1))
		sleep 1
	done
	return 1
}

entware_print_link() {
	link="$(grep -o 'tg://proxy?[0-9A-Za-z?=&._-]*' "$ENTWARE_LOGFILE" 2>/dev/null | tail -n 1)"
	[ -n "$link" ] && info "Proxy link: $link"
	return 0
}

rollback_entware() {
	warn "Installation failed; restoring the previous binary, init script and config."
	entware_service_control stop >/dev/null 2>&1 || killall tg-ws-proxy-rs 2>/dev/null || true
	restore_path "$ENTWARE_BIN"
	restore_path "$ENTWARE_INIT"
	restore_path "$ENTWARE_CONF_DIR/config.conf"
	restore_path "$ENTWARE_CONF_DIR/secret.conf"
	if [ "$LEGACY_ENTWARE_DISABLED" -eq 1 ] && [ -n "$LEGACY_ENTWARE_INIT" ]; then
		chmod +x "$LEGACY_ENTWARE_INIT" 2>/dev/null || true
		"$LEGACY_ENTWARE_INIT" start >/dev/null 2>&1 || true
	fi
	# An upgrade that fails must not take the working proxy down with it: the
	# state being restored includes a running service, so it is started again
	# from the init script the rollback just put back.
	if [ "$ENTWARE_WAS_RUNNING" -eq 1 ]; then
		entware_service_control start >/dev/null 2>&1 || true
	fi
	warn "Recovery files are retained in $BACKUP_DIR"
}

install_entware() {
	[ "$(id -u)" = 0 ] || die "run as root"
	command -v sha256sum >/dev/null 2>&1 || die "sha256sum is required"
	case "$ARCHIVE_FILE" in *.tar.gz) ;; *) die "binary archive must end in .tar.gz" ;; esac
	[ -s "$ARCHIVE_FILE" ] || die "binary archive is missing: $ARCHIVE_FILE"
	verify_assets
	stage_binary

	ENTWARE_PORT="$(entware_configured_port)"
	stamp="$(date +%Y%m%d-%H%M%S)"
	ENTWARE_BACKUP_ROOT="$ENTWARE_ROOT/var/tg-ws-proxy-backups"
	BACKUP_DIR="$ENTWARE_BACKUP_ROOT/install-$stamp"
	mkdir -p "$BACKUP_DIR" || die "cannot create $BACKUP_DIR"
	chmod 0700 "$ENTWARE_BACKUP_ROOT" "$BACKUP_DIR"
	backup_path "$ENTWARE_BIN"
	backup_path "$ENTWARE_INIT"
	backup_path "$ENTWARE_CONF_DIR/config.conf"
	backup_path "$ENTWARE_CONF_DIR/secret.conf"

	info "Backup: $BACKUP_DIR"
	[ -n "$(pidof tg-ws-proxy-rs 2>/dev/null)" ] && ENTWARE_WAS_RUNNING=1
	entware_service_control stop >/dev/null 2>&1 || true
	disable_entware_legacy "$ENTWARE_PORT"

	write_entware_config || { rollback_entware; die "cannot write $ENTWARE_CONF_DIR/config.conf"; }
	write_entware_init || { rollback_entware; die "cannot write $ENTWARE_INIT"; }

	binary_tmp="$ENTWARE_BIN.$$"
	cp "$STAGED_BINARY" "$binary_tmp" || { rollback_entware; die "cannot stage binary"; }
	chmod 0755 "$binary_tmp" || { rm -f "$binary_tmp"; rollback_entware; die "cannot make binary executable"; }
	mv -f "$binary_tmp" "$ENTWARE_BIN" || { rm -f "$binary_tmp"; rollback_entware; die "cannot install binary"; }

	entware_service_control restart >/dev/null 2>&1 || true
	entware_wait_ready "$ENTWARE_PORT" || { rollback_entware; die "service did not become ready (see $ENTWARE_LOGFILE)"; }

	new_pid="$(pidof tg-ws-proxy-rs 2>/dev/null || true)"
	[ -n "$new_pid" ] || { rollback_entware; die "new process is missing"; }
	new_pid="${new_pid%% *}"
	new_exe="$(readlink "/proc/$new_pid/exe" 2>/dev/null || true)"
	[ "$new_exe" = "$ENTWARE_BIN" ] || { rollback_entware; die "unexpected running executable: $new_exe"; }

	prune_backups "$ENTWARE_BACKUP_ROOT" 3
	variant=regular; [ "$USE_UPX" -eq 0 ] || variant=upx
	ok "tg-ws-proxy-rs installed and running."
	ok "Service: $ENTWARE_INIT (started at boot by rc.unslung)"
	info "Binary: $TARGET ($variant) at $ENTWARE_BIN | PID: $new_pid"
	info "Config: $ENTWARE_CONF_DIR/config.conf, secret beside it (both 0600)"
	info "Log: $ENTWARE_LOGFILE"
	info "Rollback backup: $BACKUP_DIR"
	entware_print_link
}

main() {
	resolve_environment
	if [ -z "$ARCHIVE_FILE" ]; then resolve_remote_assets; else resolve_local_assets; fi

	if [ "$DRY_RUN" -eq 1 ]; then
		variant=regular; [ "$USE_UPX" -eq 0 ] || variant=upx
		printf 'platform=%s\npackage_manager=%s\narchitecture=%s\ntarget=%s\nvariant=%s\narchive=%s\nluci_package=%s\n' \
			"$PLATFORM" "$PM" "$ARCH" "$TARGET" "$variant" "$ARCHIVE_FILE" "$LUCI_PACKAGE_FILE"
		exit 0
	fi

	if [ "$PLATFORM" = entware ]; then
		install_entware
		return 0
	fi

	[ "$(id -u)" = 0 ] || die "run as root"
	load_openwrt_release || die "this is not OpenWrt"
	command -v "$PM" >/dev/null 2>&1 || die "$PM is required"
	command -v uci >/dev/null 2>&1 || die "uci is required"
	[ -s "$ARCHIVE_FILE" ] || die "binary archive is missing: $ARCHIVE_FILE"
	[ -s "$LUCI_PACKAGE_FILE" ] || die "LuCI package is missing: $LUCI_PACKAGE_FILE"
	case "$ARCHIVE_FILE" in *.tar.gz) ;; *) die "binary archive must end in .tar.gz" ;; esac
	case "$LUCI_PACKAGE_FILE" in *.$EXT) ;; *) die "LuCI package must end in .$EXT" ;; esac
	verify_assets
	stage_binary

	stamp="$(date +%Y%m%d-%H%M%S)"
	BACKUP_DIR="/root/tg-ws-proxy-backups/install-$stamp"
	mkdir -p "$BACKUP_DIR"
	chmod 0700 /root/tg-ws-proxy-backups "$BACKUP_DIR"
	[ -e /etc/config/tg-ws-proxy-rs ] && OLD_CONFIG=1
	luci_is_installed && OLD_LUCI_PACKAGE=1
	legacy_luci_is_installed && LEGACY_PACKAGE=1
	if [ "$LEGACY_PACKAGE" -eq 1 ] && { legacy_path_is_foreign "$LEGACY_INIT" ||
		legacy_path_is_foreign /etc/config/tg-ws-proxy; }; then
		LEGACY_PACKAGE=0
		warn "Another package owns the unsuffixed tg-ws-proxy files; leaving them untouched."
	fi
	service_control status >/dev/null 2>&1 && OLD_RUNNING=1
	service_control enabled >/dev/null 2>&1 && OLD_ENABLED=1
	legacy_service_control status >/dev/null 2>&1 && LEGACY_RUNNING=1
	legacy_service_control enabled >/dev/null 2>&1 && LEGACY_ENABLED=1

	for path in /usr/bin/tg-ws-proxy-rs /etc/init.d/tg-ws-proxy-rs \
		/etc/config/tg-ws-proxy-rs \
		/usr/share/luci/menu.d/luci-app-tg-ws-proxy-rs.json \
		/usr/share/rpcd/acl.d/luci-app-tg-ws-proxy-rs.json \
		/usr/share/ucitrack/luci-app-tg-ws-proxy-rs.json \
		/www/luci-static/resources/view/tg-ws-proxy-rs/settings.js; do
		backup_path "$path"
	done
	if [ "$LEGACY_PACKAGE" -eq 1 ]; then
		for path in /usr/bin/tg-ws-proxy /etc/init.d/tg-ws-proxy /etc/config/tg-ws-proxy; do
			backup_path "$path"
		done
	fi
	pid="$(manual_process_pid)"
	if [ "$OLD_CONFIG" -eq 0 ] && [ "$LEGACY_PACKAGE" -eq 0 ] && [ -n "$pid" ]; then
		tr '\0' '\n' < "/proc/$pid/environ" > "$BACKUP_DIR/process.env"
		tr '\0' '\n' < "/proc/$pid/cmdline" > "$BACKUP_DIR/process.cmd"
		chmod 0600 "$BACKUP_DIR/process.env" "$BACKUP_DIR/process.cmd"
	fi

	info "Backup: $BACKUP_DIR"
	service_control stop >/dev/null 2>&1 || true
	# The 2.2.3 service binds the same port, so it goes down before the renamed
	# one comes up. It is only restarted again if this installation rolls back.
	legacy_service_control stop >/dev/null 2>&1 || true
	if [ "$OLD_LUCI_PACKAGE" -eq 0 ]; then
		rm -f /etc/init.d/tg-ws-proxy-rs /etc/init.d/tg-ws-proxy-rs.apk-new \
			/etc/init.d/tg-ws-proxy-rs-opkg
	fi
	if ! install_luci_package; then
		rollback; die "LuCI package installation failed"
	fi
	rm -f /etc/config/tg-ws-proxy-rs.apk-new /etc/config/tg-ws-proxy-rs-opkg
	# After the package install, so that no apk/opkg conffile policy decides
	# which copy of the config survives.
	if [ "$OLD_CONFIG" -eq 0 ] && [ "$LEGACY_PACKAGE" -eq 1 ] && [ -f /etc/config/tg-ws-proxy ]; then
		cp -p /etc/config/tg-ws-proxy /etc/config/tg-ws-proxy-rs || {
			rollback; die "cannot carry the previous UCI config over to tg-ws-proxy-rs"
		}
		OLD_CONFIG=1
		LEGACY_CONFIG_MIGRATED=1
		info "Carried /etc/config/tg-ws-proxy over to /etc/config/tg-ws-proxy-rs."
	fi
	if [ -x /etc/uci-defaults/95_luci-tg-ws-proxy-rs ]; then
		/etc/uci-defaults/95_luci-tg-ws-proxy-rs || { rollback; die "OpenWrt migration failed"; }
		rm -f /etc/uci-defaults/95_luci-tg-ws-proxy-rs
	fi
	migrate_manual_config || { rollback; die "manual configuration migration failed"; }
	chmod 0600 /etc/config/tg-ws-proxy-rs || { rollback; die "cannot restrict UCI config permissions"; }

	binary_tmp="/usr/bin/.tg-ws-proxy-rs.$$"
	cp "$STAGED_BINARY" "$binary_tmp" || { rollback; die "cannot stage binary"; }
	chmod 0755 "$binary_tmp" || { rm -f "$binary_tmp"; rollback; die "cannot make binary executable"; }
	mv -f "$binary_tmp" /usr/bin/tg-ws-proxy-rs || { rm -f "$binary_tmp"; rollback; die "cannot install binary"; }
	service_control enable >/dev/null 2>&1 || { rollback; die "cannot enable service"; }
	service_control restart >/dev/null 2>&1 || { rollback; die "cannot restart service"; }
	wait_ready || { rollback; die "service did not become ready"; }

	new_pid="$(pidof tg-ws-proxy-rs 2>/dev/null || true)"
	[ -n "$new_pid" ] || { rollback; die "new process is missing"; }
	new_pid="${new_pid%% *}"
	new_exe="$(readlink "/proc/$new_pid/exe" 2>/dev/null || true)"
	[ "$new_exe" = /usr/bin/tg-ws-proxy-rs ] || { rollback; die "unexpected running executable: $new_exe"; }
	[ -s /usr/share/luci/menu.d/luci-app-tg-ws-proxy-rs.json ] || { rollback; die "LuCI menu is missing"; }
	[ -s /www/luci-static/resources/view/tg-ws-proxy-rs/settings.js ] || { rollback; die "LuCI view is missing"; }
	remove_legacy_installation
	rm -f /tmp/luci-indexcache
	rm -rf /tmp/luci-modulecache
	/etc/init.d/rpcd reload >/dev/null 2>&1 || warn "rpcd reload failed; LuCI may need a manual reload"

	variant=regular; [ "$USE_UPX" -eq 0 ] || variant=upx
	prune_backups /root/tg-ws-proxy-backups 3
	ok "tg-ws-proxy-rs installed and running."
	ok "LuCI page installed under Services → Telegram WS Proxy (Rust)."
	info "Binary: $TARGET ($variant) | PID: $new_pid"
	info "Rollback backup: $BACKUP_DIR"
}

if [ "${TG_WS_PROXY_TEST_MODE:-0}" != 1 ]; then
	main
fi

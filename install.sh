#!/bin/sh
# Installs a tg-ws-proxy-rs release binary and LuCI integration on OpenWrt 24.10+.
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
  --arch ARCH          Override detected OpenWrt architecture (tests/manual use)
  --package-manager apk|opkg
                       Override detected package manager (tests/manual use)
  -h, --help           Show this help

Without --archive, both assets are downloaded from GitHub Releases. The regular
binary is selected by default; --upx selects the matching *-upx.tar.gz asset.
OpenWrt 25.12+ uses the LuCI APK; OpenWrt 24.10 uses the LuCI IPK. APK install
uses --allow-untrusted explicitly after SHA-256 verification.

Set GH_MIRROR=https://mirror.example to retry release-asset downloads through a
mirror. TG_WS_PROXY_RELEASE_CHANNEL and TG_WS_PROXY_UPX provide env equivalents.
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
		-h|--help) usage; exit 0 ;;
		*) die "unknown argument: $1" ;;
	esac
done

case "$CHANNEL" in stable|beta) ;; *) die "unsupported release channel: $CHANNEL" ;; esac
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
		# OpenWrt builds these two without an FPU (bcm53xx is a Cortex-A9 with no
		# VFP), and a musleabihf binary dies with SIGILL there.
		arm_cortex-a7|arm_cortex-a9) printf '%s' armv7-unknown-linux-musleabi ;;
		mipsel|mipsel_24kc|mipsel_74kc) printf '%s' mipsel-unknown-linux-musl ;;
		mips|mips_24kc) printf '%s' mips-unknown-linux-musl ;;
		x86_64) printf '%s' x86_64-unknown-linux-musl ;;
		*) return 1 ;;
	esac
}

binary_archive_name() {
	upx_suffix=''
	[ "$USE_UPX" -eq 0 ] || upx_suffix=-upx
	printf 'tg-ws-proxy-%s%s.tar.gz' "$TARGET" "$upx_suffix"
}

resolve_environment() {
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

dl() {
	url="$1"
	out="$2"
	wget -qO "$out" --timeout=30 "$url" 2>/dev/null && [ -s "$out" ] && return 0
	if [ -n "${GH_MIRROR:-}" ]; then
		mirror="${GH_MIRROR%/}"
		mirror_url="$mirror${url#https://github.com}"
		wget -qO "$out" --timeout=30 "$mirror_url" 2>/dev/null && [ -s "$out" ] && return 0
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

resolve_remote_assets() {
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
	[ -n "$LUCI_PACKAGE_FILE" ] || die "--luci-package is required with --archive"
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
		verify_release_checksum "$LUCI_PACKAGE_FILE" "LuCI package"
		ok "SHA-256 verified for binary and LuCI package."
	else
		warn "Local assets have no SHA256SUMS; continuing because both paths were supplied explicitly."
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

main() {
	resolve_environment
	if [ -z "$ARCHIVE_FILE" ]; then resolve_remote_assets; else resolve_local_assets; fi

	if [ "$DRY_RUN" -eq 1 ]; then
		variant=regular; [ "$USE_UPX" -eq 0 ] || variant=upx
		printf 'package_manager=%s\narchitecture=%s\ntarget=%s\nvariant=%s\narchive=%s\nluci_package=%s\n' \
			"$PM" "$ARCH" "$TARGET" "$variant" "$ARCHIVE_FILE" "$LUCI_PACKAGE_FILE"
		exit 0
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

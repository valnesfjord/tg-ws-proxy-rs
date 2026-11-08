#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

for file in \
    install.sh \
    openwrt/build-luci-package.sh \
    openwrt/luci-app/Makefile \
    openwrt/luci-app/root/etc/config/tg-ws-proxy-rs \
    openwrt/luci-app/root/etc/capabilities/tg-ws-proxy-rs.json \
    openwrt/luci-app/root/etc/init.d/tg-ws-proxy-rs \
    .github/workflows/release.yml; do
    [[ -f "$ROOT/$file" ]] || fail "missing $file"
done
for obsolete in openwrt/Makefile openwrt/build-package.sh openwrt/release-architectures.tsv; do
    [[ ! -e "$ROOT/$obsolete" ]] || fail "obsolete core packaging remains: $obsolete"
done

makefile="$ROOT/openwrt/luci-app/Makefile"
grep -Eq '^[[:space:]]*PKGARCH:=all$' "$makefile" || fail 'LuCI recipe must declare OpenWrt PKGARCH=all'
# shellcheck disable=SC2016 # Match a literal OpenWrt make variable.
grep -Fq 'include $(INCLUDE_DIR)/package.mk' "$makefile" || fail 'LuCI package does not use the standard package recipe'
if grep -Fq '+tg-ws-proxy' "$makefile"; then fail 'architecture-independent LuCI package must not depend on a core package'; fi
grep -Fq 'PKG_NAME:=luci-app-tg-ws-proxy-rs' "$makefile" || fail 'LuCI package is not named luci-app-tg-ws-proxy-rs'
grep -Fq 'USERID:=tg-ws-proxy-rs:tg-ws-proxy-rs' "$makefile" || fail 'dedicated service user/group is missing'
grep -Fq '+procd-ujail' "$makefile" || fail 'privileged-port helper is not a package dependency'
python3 - "$ROOT/openwrt/luci-app/root/etc/capabilities/tg-ws-proxy-rs.json" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as source:
    profile = json.load(source)
assert set(profile) == {"bounding", "effective", "permitted", "inheritable", "ambient"}
assert all(value == ["CAP_NET_BIND_SERVICE"] for value in profile.values())
from pathlib import Path
for name, caps in [("mark", ["CAP_NET_RAW"]),
                   ("mark-bind", ["CAP_NET_RAW", "CAP_NET_BIND_SERVICE"])]:
    marked = json.loads(Path(sys.argv[1]).with_name(f"tg-ws-proxy-rs-{name}.json").read_text())
    assert marked.keys() == profile.keys()
    assert all(value == caps for value in marked.values())
PY
grep -Fq '/etc/config/tg-ws-proxy-rs' "$makefile" || fail 'UCI conffile is not declared'
# shellcheck disable=SC2016 # Match the literal package staging path in the recipe.
grep -Fq 'chmod 0600 $(1)/etc/config/tg-ws-proxy-rs' "$makefile" || \
    fail 'packaged UCI config secret is not mode 0600'
# shellcheck disable=SC2016 # Match the literal config variable in the installation hook.
grep -Fq 'chmod 0600 "/etc/config/$config"' \
    "$ROOT/openwrt/luci-app/root/etc/uci-defaults/95_luci-tg-ws-proxy-rs" || \
    fail 'UCI config secret is not restricted to mode 0600'

stray="$(find "$ROOT/openwrt/luci-app" -name '*tg-ws-proxy*' ! -name '*tg-ws-proxy-rs*')"
[[ -z "$stray" ]] || fail "packaged path collides with the upstream tg-ws-proxy package: $stray"

cargo_version="$(python3 -c 'import tomllib,sys; print(tomllib.load(open(sys.argv[1], "rb"))["package"]["version"])' "$ROOT/Cargo.toml")"
# shellcheck disable=SC2016 # Match literal OpenWrt make variables.
grep -Fq 'PKG_VERSION:=$(TG_PACKAGE_VERSION)' "$makefile" || fail 'LuCI recipe does not use the supplied package version'
if grep -Eq '^PKG_VERSION:.*[0-9]+\.[0-9]+\.[0-9]+' "$makefile"; then
    fail 'LuCI recipe duplicates the Cargo package version'
fi
builder="$ROOT/openwrt/build-luci-package.sh"
grep -Fq 'tomllib.load(open(sys.argv[1], "rb"))["package"]["version"]' "$builder" || \
    fail 'LuCI builder does not default to the Cargo package version'
# shellcheck disable=SC2016 # Match the literal exported shell variable.
grep -Fq 'export TG_PACKAGE_VERSION="$VERSION"' "$builder" || \
    fail 'LuCI builder does not supply its version to every SDK make invocation'
[[ -f "$ROOT/docs/release-notes/$cargo_version.md" ]] || fail "release notes for $cargo_version are missing"
# shellcheck disable=SC2016 # Match a literal Bash parameter expansion.
grep -Fq 'output_name="${output_name//\~/.}"' "$builder" || \
    fail 'beta IPK release filename is not normalized before checksums'

workflow="$ROOT/.github/workflows/release.yml"
grep -Fq 'openwrt/build-luci-package.sh' "$workflow" || fail 'release does not build LuCI through the SDK recipe'
grep -Fq -- '--format apk' "$workflow" || fail 'release misses LuCI APK build'
grep -Fq -- '--format ipk' "$workflow" || fail 'release misses LuCI IPK build'
# SHA256SUMS used to be built inside `openwrt-luci`, from the musl tarballs it
# downloaded plus its own two packages -- so this contract could be a grep for
# that one command line. It has its own job now, which hashes what the draft
# release actually serves; what has to hold is that the job waits for the LuCI
# packages and the binaries to be uploaded before it reads the release back,
# and that nothing publishes ahead of it.
job_needs() {
    awk -v job="$1" \
        '$0 ~ "^[[:space:]]*" job ":[[:space:]]*$" { found = 1 }
         found && /needs:/ { print; exit }' "$workflow"
}
checksums_needs="$(job_needs checksums)"
[[ -n "$checksums_needs" ]] || fail 'release has no checksums job'
for upstream in upload-assets openwrt-luci; do
    grep -Fq "$upstream" <<<"$checksums_needs" || \
        fail "checksums does not wait on $upstream, so its assets would ship unhashed"
done
grep -Fq 'SHA256SUMS' "$workflow" || fail 'release does not publish SHA256SUMS'
grep -Fq checksums <<<"$(job_needs publish-release)" || \
    fail 'release can publish before SHA256SUMS is uploaded'
if grep -Eq 'build-package\.sh|release-architectures|dist/openwrt/tg-ws-proxy_|set -- tg-ws-proxy_' "$workflow"; then
    fail 'release workflow still builds core OpenWrt packages'
fi

printf 'PASS: minimal OpenWrt package contract\n'

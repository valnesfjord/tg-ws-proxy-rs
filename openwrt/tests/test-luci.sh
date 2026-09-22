#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LUCI="$ROOT/openwrt/luci-app"
VIEW="$LUCI/htdocs/luci-static/resources/view/tg-ws-proxy-rs/settings.js"
MENU="$LUCI/root/usr/share/luci/menu.d/luci-app-tg-ws-proxy-rs.json"
ACL="$LUCI/root/usr/share/rpcd/acl.d/luci-app-tg-ws-proxy-rs.json"
UCITRACK="$LUCI/root/usr/share/ucitrack/luci-app-tg-ws-proxy-rs.json"
CONFIG="$LUCI/root/etc/config/tg-ws-proxy-rs"
INIT="$LUCI/root/etc/init.d/tg-ws-proxy-rs"
MAKEFILE="$LUCI/Makefile"

fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
for path in "$VIEW" "$MENU" "$ACL" "$UCITRACK" "$CONFIG" "$INIT" "$MAKEFILE"; do
    [[ -f "$path" ]] || fail "missing ${path#"$ROOT/"}"
done

node --check "$VIEW"
python3 - "$MENU" "$ACL" "$UCITRACK" <<'PY'
import json, sys
menu = json.load(open(sys.argv[1]))
acl = json.load(open(sys.argv[2]))["luci-app-tg-ws-proxy-rs"]
track = json.load(open(sys.argv[3]))
entry = menu["admin/services/tg-ws-proxy-rs"]
assert entry["action"] == {"type": "view", "path": "tg-ws-proxy-rs/settings"}
assert entry["depends"]["uci"] == {"tg-ws-proxy-rs": True}
assert "luci-app-tg-ws-proxy-rs" in entry["depends"]["acl"]
assert "tg-ws-proxy-rs" in acl["read"]["uci"]
assert "tg-ws-proxy-rs" in acl["write"]["uci"]
assert "/sbin/logread -e tg-ws-proxy-rs" in acl["read"]["file"]
# Read-only probes: which release the binary is, and whether a stopped
# service's port is held by another program.
for probe in ("/usr/bin/tg-ws-proxy-rs --version", "/bin/netstat -lnt"):
    assert acl["read"]["file"].get(probe) == ["exec"], probe
assert "list" in acl["read"]["ubus"]["service"]
assert "rc" not in acl["write"].get("ubus", {})
service_commands = acl["write"]["file"]
assert set(service_commands) == {
    "/etc/init.d/tg-ws-proxy-rs start",
    "/etc/init.d/tg-ws-proxy-rs restart",
    "/etc/init.d/tg-ws-proxy-rs stop",
}
assert all(actions == ["exec"] for actions in service_commands.values())
assert track == {"config": "tg-ws-proxy-rs", "init": "tg-ws-proxy-rs"}
PY

grep -Fq "new form.Map('tg-ws-proxy-rs'" "$VIEW" || fail 'view is not bound to UCI'
grep -Fq "const SERVICE = 'tg-ws-proxy-rs';" "$VIEW" || fail 'service name is not the -rs one'
grep -Fq "o.password = true" "$VIEW" || fail 'secret is not a password field'
grep -Fq "form.ListValue, 'log_level'" "$VIEW" || fail 'log-level selector is missing'
grep -Fq "fs.exec_direct('/sbin/logread', ['-e', SERVICE], 'text')" "$VIEW" || fail 'filtered live log is missing'
grep -Fq "node.textContent = visible || _('Log is empty.')" "$VIEW" || fail 'log output is not rendered as text'
grep -Fq "node.textContent = _('Log is not available yet: %s').format(error.message)" "$VIEW" || fail 'log errors are not rendered as text'
if grep -Fq 'dom.content(node, visible' "$VIEW"; then fail 'untrusted log output still reaches dom.content'; fi
grep -Fq 'statusPollRegistered' "$VIEW" || fail 'service status poller is not guarded against duplicate registration'
grep -Fq "fs.exec('/etc/init.d/tg-ws-proxy-rs', [action])" "$VIEW" || fail 'service controls do not use the scoped init script'
grep -Fq "const BINARY = '/usr/bin/tg-ws-proxy-rs';" "$VIEW" || fail 'version probe does not ask the -rs binary'
grep -Fq "fs.exec(BINARY, ['--version'])" "$VIEW" || fail 'installed version is not shown'
grep -Fq "fs.exec('/bin/netstat', ['-lnt'])" "$VIEW" || fail 'a port held by another program is not diagnosed'
grep -Fq "form.DynamicList, 'cf_worker_domain'" "$VIEW" || fail 'Worker domains are not repeatable'
for action in start stop restart; do
    grep -Fq "'$action'" "$VIEW" || fail "$action action is missing"
done
# The syslog identity follows the init script, so a log line of the upstream
# tg-ws-proxy package must not survive this filter.
grep -Fq 'tg-ws-proxy-rs\[\d+\]' "$VIEW" || fail 'log formatter does not pin the -rs syslog tag'

grep -Fq 'PROG="/usr/bin/tg-ws-proxy-rs"' "$INIT" || fail 'init script does not run the -rs binary'
grep -Fq 'CONFIG="tg-ws-proxy-rs"' "$INIT" || fail 'init script does not read the -rs UCI config'
grep -Fq "config tg-ws-proxy-rs 'main'" "$CONFIG" || fail 'packaged config section is not the -rs type'

while read -r kind option _; do
    case "$kind" in option|list)
        grep -Eq "['\"]${option}['\"]" "$VIEW" || fail "UCI option $option is not exposed"
        grep -Eq "(^|[[:space:]])${option}([[:space:]]|$)" "$INIT" || fail "UCI option $option is not mapped by init"
    esac
done < "$CONFIG"

grep -Eq '^[[:space:]]*PKGARCH:=all$' "$MAKEFILE" || fail 'package is not architecture-independent'
grep -Fq 'DEPENDS:=+luci-base' "$MAKEFILE" || fail 'luci-base dependency is missing'
if grep -Fq '+tg-ws-proxy' "$MAKEFILE"; then fail 'architecture-independent LuCI package must not depend on a core package'; fi

printf 'PASS: LuCI contract\n'

#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
INIT="$ROOT/openwrt/luci-app/root/etc/init.d/tg-ws-proxy-rs"
[[ -f "$INIT" ]] || { printf 'FAIL: missing packaged init script\n' >&2; exit 1; }

declare -A CFG=()
declare -A LISTS=()
declare -a EVENTS=()
declare -a ENVS=()


config_load() { EVENTS+=("config_load:$1"); }
config_get() {
    local __out="$1" section="$2" option="$3" default="${4-}"
    local __value="${CFG[$section.$option]-$default}"
    printf -v "$__out" '%s' "$__value"
}
config_get_bool() {
    local __out="$1" section="$2" option="$3" default="${4-0}" __value
    __value="${CFG[$section.$option]-$default}"
    case "$__value" in 1|true|yes|on|enabled) __value=1;; *) __value=0;; esac
    printf -v "$__out" '%s' "$__value"
}
config_list_foreach() {
    local section="$1" option="$2" callback="$3" value
    while IFS= read -r value; do
        if [[ -n "$value" ]]; then "$callback" "$value"; fi
    done <<< "${LISTS[$section.$option]-}"
}
procd_open_instance() { EVENTS+=("open:${1-}"); }
procd_set_param() {
    local kind="$1"; shift
    EVENTS+=("set:$kind:$*")
    if [[ "$kind" == env ]]; then ENVS+=("$@"); fi
}
procd_append_param() {
    local kind="$1"; shift
    EVENTS+=("append:$kind:$*")
    if [[ "$kind" == env ]]; then ENVS+=("$@"); fi
}
procd_close_instance() { EVENTS+=("close"); }
procd_add_reload_trigger() { EVENTS+=("trigger:$1"); }
uci() {
    local key
    EVENTS+=("uci:$*")
    if [[ "${1-}" == -q && "${2-}" == get ]]; then
        key="${3#tg-ws-proxy-rs.}"
        [[ -v "CFG[$key]" ]]
        return
    fi
}
logger() { EVENTS+=("logger:$*"); }

# shellcheck source=/dev/null
source "$INIT"

has_event() {
    local expected="$1" item
    for item in "${EVENTS[@]-}"; do [[ "$item" == "$expected" ]] && return 0; done
    return 1
}
has_env() {
    local expected="$1" item
    for item in "${ENVS[@]-}"; do [[ "$item" == "$expected" ]] && return 0; done
    return 1
}

# Disabled by default: loading config is allowed, but procd must not be opened.
CFG[main.enabled]=0
start_service
if has_event 'open:tg-ws-proxy-rs.main'; then
    printf 'FAIL: disabled service opened a procd instance\n' >&2
    exit 1
fi

EVENTS=(); ENVS=(); CFG=(); LISTS=()
CFG[main.enabled]=1
CFG[main.host]=0.0.0.0
CFG[main.port]=3443
CFG[main.secret]=0123456789abcdef0123456789abcdef
CFG[main.link_ip]=proxy.example.test
CFG[main.listen_faketls_domain]=www.google.com
CFG[main.outbound_proxy]=socks5h://127.0.0.1:5330
CFG[main.log_level]=trace
CFG[main.cf_priority]=1
LISTS[main.dc_ip]=$'2:149.154.167.220\n4:149.154.167.220'
LISTS[main.cf_domain]=$'one.example\ntwo.example'
LISTS[main.cf_worker_domain]=$'worker-one.example\nworker-two.example'
start_service
has_event 'open:tg-ws-proxy-rs.main' || { printf 'FAIL: enabled service did not open procd\n' >&2; exit 1; }
has_event 'set:command:/usr/bin/tg-ws-proxy-rs' || { printf 'FAIL: wrong procd command\n' >&2; exit 1; }
for expected in \
    'TG_HOST=0.0.0.0' \
    'TG_PORT=3443' \
    'TG_SECRET=0123456789abcdef0123456789abcdef' \
    'TG_LINK_IP=proxy.example.test' \
    'TG_LISTEN_FAKETLS_DOMAIN=www.google.com' \
    'TG_OUTBOUND_PROXY=socks5h://127.0.0.1:5330' \
    'TG_CF_WORKER_DOMAIN=worker-one.example,worker-two.example' \
    'RUST_LOG=warn,tg_ws_proxy=trace,tg_ws_proxy_rs=trace' \
    'TG_CF_PRIORITY=true' \
    'TG_CF_DOMAIN=one.example,two.example'; do
    has_env "$expected" || { printf 'FAIL: missing env %s\n' "$expected" >&2; exit 1; }
done

for legacy_env in TG_LOG_FILE TG_VERBOSE TG_QUIET; do
    for item in "${ENVS[@]}"; do
        [[ "$item" != "$legacy_env="* ]] || { printf 'FAIL: legacy env %s is still passed\n' "$legacy_env" >&2; exit 1; }
    done
done
has_event 'append:command:--dc-ip 2:149.154.167.220' || { printf 'FAIL: missing DC2 command argument\n' >&2; exit 1; }
has_event 'append:command:--dc-ip 4:149.154.167.220' || { printf 'FAIL: missing DC4 command argument\n' >&2; exit 1; }

# A scalar cf_worker_domain from an earlier local package remains accepted.
EVENTS=(); ENVS=(); CFG=(); LISTS=()
CFG[main.enabled]=1
CFG[main.secret]=0123456789abcdef0123456789abcdef
CFG[main.cf_worker_domain]=legacy-worker.example
start_service
has_env 'TG_CF_WORKER_DOMAIN=legacy-worker.example' || {
    printf 'FAIL: legacy scalar Worker domain was not preserved\n' >&2
    exit 1
}

# Legacy quiet/verbose remains readable, but normal service start must not mutate UCI.
EVENTS=(); ENVS=(); CFG=(); LISTS=()
CFG[main.enabled]=1
CFG[main.secret]=0123456789abcdef0123456789abcdef
CFG[main.verbose]=1
start_service
has_env 'RUST_LOG=warn,tg_ws_proxy=debug,tg_ws_proxy_rs=debug' || { printf 'FAIL: legacy verbose=1 did not map to app-only debug\n' >&2; exit 1; }
for item in "${EVENTS[@]}"; do
    [[ "$item" != uci:-q\ set* && "$item" != uci:-q\ delete* && "$item" != 'uci:-q commit'* ]] || {
        printf 'FAIL: start_service mutates UCI: %s\n' "$item" >&2; exit 1;
    }
done

EVENTS=(); ENVS=(); CFG=(); LISTS=()
CFG[main.enabled]=1
CFG[main.secret]=0123456789abcdef0123456789abcdef
CFG[main.verbose]=1
CFG[main.quiet]=1
start_service
has_env 'RUST_LOG=off' || { printf 'FAIL: legacy quiet=1 did not take precedence as off\n' >&2; exit 1; }

# A missing secret is an installation error, not a reason to mutate UCI on start.
EVENTS=(); ENVS=(); CFG=(); LISTS=()
CFG[main.enabled]=1
CFG[main.host]=127.0.0.1
CFG[main.port]=1443
start_service || true
if has_event 'open:tg-ws-proxy-rs.main'; then
    printf 'FAIL: missing secret still started the service\n' >&2; exit 1
fi
has_event 'logger:-t tg-ws-proxy-rs proxy secret is missing; rerun install.sh or set tg-ws-proxy-rs.main.secret' || {
    printf 'FAIL: missing secret error was not logged\n' >&2; exit 1;
}

EVENTS=()
service_triggers
has_event 'trigger:tg-ws-proxy-rs' || { printf 'FAIL: reload trigger missing\n' >&2; exit 1; }

# Disabled SOCKS must not pick up stale addresses/mappings from UCI.
EVENTS=(); ENVS=(); CFG=(); LISTS=()
CFG[main.enabled]=1
CFG[main.secret]=0123456789abcdef0123456789abcdef
CFG[main.socks_host]=not-an-ip
LISTS[main.socks_dc]='invalid'
start_service
has_env 'TG_SOCKS_ENABLED=false' || { printf 'FAIL: SOCKS not disabled by default\n' >&2; exit 1; }
if has_env 'TG_SOCKS_HOST=not-an-ip' || has_env 'TG_SOCKS_DC=invalid'; then
    printf 'FAIL: disabled SOCKS passed stale configuration\n' >&2; exit 1
fi

EVENTS=(); ENVS=()
CFG[main.socks_enabled]=1
CFG[main.socks_host]=127.0.0.1
CFG[main.socks_port]=1081
LISTS[main.socks_dc]=$'-2:149.154.167.222\n4:149.154.167.91'
start_service
for expected in 'TG_SOCKS_ENABLED=true' 'TG_SOCKS_HOST=127.0.0.1' 'TG_SOCKS_PORT=1081' \
    'TG_SOCKS_DC=-2:149.154.167.222,4:149.154.167.91'; do
    has_env "$expected" || { printf 'FAIL: missing SOCKS env %s\n' "$expected" >&2; exit 1; }
done

printf 'PASS: init/UCI mapping\n'

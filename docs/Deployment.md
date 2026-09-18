# Deployment

## Docker

Images are published to Docker Hub as
[`valnesfjord/tg-ws-proxy-rs`](https://hub.docker.com/r/valnesfjord/tg-ws-proxy-rs)
for `linux/amd64` and `linux/arm64`. Tags follow the releases: `latest`, plus
`X.Y.Z` and `X.Y` per version.

```bash
docker run -d --name tg-ws-proxy -p 1443:1443 valnesfjord/tg-ws-proxy-rs
```

The image is built `FROM scratch` and runs as UID 1000 — it contains the static
binary and a CA bundle, nothing else. Flags go after the image name, and every
flag also has a `TG_*` environment variable:

```bash
docker run -d --name tg-ws-proxy -p 1443:1443 \
  -e TG_SECRET=0123456789abcdef0123456789abcdef \
  -e TG_DEFAULT_DOMAINS=true \
  valnesfjord/tg-ws-proxy-rs --link-ip 203.0.113.10
```

Two things worth setting explicitly in a container:

- **`TG_SECRET`** — without it a fresh random secret is generated on every
  start, so the `tg://` link changes each time the container restarts.
- **`--link-ip`** — host auto-detection sees the container's bridge address
  (something like `172.17.0.2`), which nobody can reach. Pass the address
  clients should actually connect to. Using `--network host` avoids this
  instead.

## Router deployment

Run the proxy on your router without `--host` (or with `--host 0.0.0.0`) so it
accepts connections from all LAN devices:

```bash
tg-ws-proxy --port 1443
```

When no `--host` is given and a LAN IP can be auto-detected, the proxy binds
`0.0.0.0` (all interfaces) and uses the detected LAN IP in the generated
`tg://` link, so the link is actually reachable and you can share it with every
device on your network.

If auto-detection picks the wrong interface, override it explicitly:

```bash
tg-ws-proxy --host 0.0.0.0 --link-ip 192.168.1.1
```

> **Note:** Passing `--host 127.0.0.1` explicitly restricts connections to the
> machine running the proxy. Other devices on the network will not be able to
> connect unless you use `0.0.0.0` (or omit `--host` entirely) so it binds to
> the router's LAN IP.

On flash-tight routers, grab the `-upx` release asset — it is about 70% smaller
on disk. See [Building.md](Building.md#shrinking-the-binary-for-flash-constrained-devices)
for what that costs in RAM.

### OpenWrt package (recommended)

This repository installs the existing static musl release binary directly and
packages only the matching `luci-app-tg-ws-proxy-rs` integration as APK/IPK. It
provides a UCI-managed procd service and a BusyBox-compatible installer. Configure
it at **Services → Telegram WS Proxy (Rust)**; the Logging tab shows filtered entries
from the bounded OpenWrt `logd` ring buffer. See
[OpenWrtPackage.md](OpenWrtPackage.md) for local builds, installation,
configuration, upgrades, and rollback.

### Manual OpenWrt procd init script

Create `/etc/init.d/tg-ws-proxy-rs` (the `-rs` suffix keeps the script clear of
an upstream `tg-ws-proxy` package):

```sh
#!/bin/sh /etc/rc.common
USE_PROCD=1
START=90
STOP=10

PROG=/usr/local/bin/tg-ws-proxy

start_service() {
    procd_open_instance
    procd_set_param command "$PROG" --host 0.0.0.0 --port 1443
    procd_set_param respawn
    procd_set_param stdout 1
    procd_set_param stderr 1
    procd_close_instance
}
```

```bash
chmod +x /etc/init.d/tg-ws-proxy-rs
/etc/init.d/tg-ws-proxy-rs enable
/etc/init.d/tg-ws-proxy-rs start
```

## Configuration via environment

Every CLI flag has a matching `TG_*` variable, which is usually the easier way
to configure Docker and systemd units:

```bash
TG_HOST=0.0.0.0
TG_PORT=1443
TG_SECRET=0123456789abcdef0123456789abcdef
TG_LINK_IP=192.168.1.1
TG_LISTEN_FAKETLS_DOMAIN=www.yandex.ru
TG_POOL_SIZE=4
TG_BUF_KB=256
TG_MAX_CONNECTIONS=64
TG_QUIET=true
TG_VERBOSE=false
TG_SKIP_TLS_VERIFY=false
TG_CF_DOMAIN=yourdomain.com
TG_CF_WORKER_DOMAIN=random-symbols-1234.username.workers.dev
TG_CF_PRIORITY=false
TG_CF_BALANCE=false
TG_CF_IP=104.16.1.1,2606:4700::1
TG_DEFAULT_DOMAINS=false
TG_CHECK=false
TG_FRONTING_DOMAIN=sprinthost.ru
TG_FRONTING_COOLDOWN=1800
TG_FRONTING_FAIL_COOLDOWN=60
TG_OUTBOUND_PROXY=socks5h://user:pass@192.168.1.1:1080
TG_NO_OUTBOUND_PROXY=false
TG_NO_PROXY=localhost,127.0.0.1
TG_LOG_FILE=/var/log/tg-ws-proxy.log
TG_MTPROTO_PROXY=proxy.example.com:443:ddabcdef1234567890abcdef1234567890
```

When `TG_OUTBOUND_PROXY` is not set, the standard `HTTPS_PROXY`, `ALL_PROXY`,
`HTTP_PROXY` and `NO_PROXY` variables are honored as well — see
[Fallbacks.md](Fallbacks.md#outbound-proxy).

## Windows console — no garbled characters

On Windows the console does not enable ANSI/VT colour codes by default, which
caused log lines to show symbols like `←[32m` around the log level. This is
fixed: ANSI escape codes are automatically disabled when running on Windows or
when stderr is not a terminal (e.g. output is piped or redirected).

If you prefer completely clean logs or want to capture them to a file, use
`--log-file`:

```bash
tg-ws-proxy --log-file proxy.log
# or
set TG_LOG_FILE=proxy.log && tg-ws-proxy
```

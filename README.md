# tg-ws-proxy-rs

**Telegram MTProto WebSocket Bridge Proxy** — a Rust **vibecoded** port of
[Flowseal/tg-ws-proxy](https://github.com/Flowseal/tg-ws-proxy).

Listens for Telegram Desktop's MTProto connections on a local port and
tunnels them through WebSocket (TLS) connections to Telegram's DC servers.

```
Telegram Desktop → MTProto (TCP 1443) → tg-ws-proxy-rs → WS (TLS 443) → Telegram DC
                                                         ↘ CF proxy (kws{N}.{cf-domain}) → Telegram DC  (WS via Cloudflare)
                                                         ↘ CF Worker (*.workers.dev) → Telegram DC  (TCP tunnel via Cloudflare)
                                                         ↘ upstream MTProto proxy → Telegram DC  (WS fallback)
                                                         ↘ direct TCP :443 → Telegram DC          (last resort)
```

## Why Rust?

| | Python original | This port |
|---|---|---|
| Runtime | CPython required | Single static binary |
| Memory | ~30–50 MB | ~3–5 MB |
| CPU | Higher | Lower (compiled) |
| OpenWrt | Needs Python install | Just copy the binary |
| Static build | No | Yes (musl) |

## Quick Start

### Pre-built binaries

Download from the [Releases](../../releases) page. Linux musl targets also ship
a `-upx` variant that is ~70% smaller on disk, for routers where flash is
tight — see [docs/Building.md](docs/Building.md#shrinking-the-binary-for-flash-constrained-devices)
for the RAM trade-off that comes with it.

### Docker

Published to Docker Hub as
[`valnesfjord/tg-ws-proxy-rs`](https://hub.docker.com/r/valnesfjord/tg-ws-proxy-rs)
(`linux/amd64` + `linux/arm64`):

```bash
docker run -d --name tg-ws-proxy -p 1443:1443 valnesfjord/tg-ws-proxy-rs
```

Set `TG_SECRET` so the secret survives restarts, and `--link-ip` so the printed
`tg://` link points at a reachable address — see
[docs/Deployment.md](docs/Deployment.md#docker).

### Build from source

```bash
cargo build --release
```

The binary lands in `target/release/tg-ws-proxy`. Cross-compiling for OpenWrt
(MIPS/ARM/ARM64) is covered in [docs/Building.md](docs/Building.md).

### Android

A Jetpack Compose app in `android/` runs the same core as a library: paste the
CLI flags, start/stop, open the `tg://proxy` link. See
[docs/Android.md](docs/Android.md).

### OpenWrt

Raw release binaries, LuCI packages and a one-line installer are available. See
[OpenWrt installation](#openwrt-installation) below.

### Telegram Desktop setup

1. **Settings → Advanced → Connection type → Use custom proxy**
2. Add MTProto proxy:
   - **Server:** `127.0.0.1`
   - **Port:** `1443` (or your `--port`)
   - **Secret:** shown in the proxy startup log

Or use the `tg://proxy?...` link that is printed on startup.

## OpenWrt installation

### Requirements

- **OpenWrt 25.12+ (APK)** or **ImmortalWrt 25.12+ (APK)**.
- **OpenWrt 24.10 (opkg)** or **ImmortalWrt 24.10 (opkg)**.
- Root SSH access and a supported musl target: AArch64, ARMv7, MIPS, MIPSel or
  x86_64. Python is not required.

The proxy itself is the existing static musl release binary, not an OpenWrt
package. Only the architecture-independent LuCI/service integration is packaged:
`luci-app-tg-ws-proxy-rs` is published as APK (`noarch`) and IPK (`all`). Every
installed path carries the `-rs` suffix, so a router can keep an upstream
`tg-ws-proxy` package installed alongside this port.

### Quick install (one-liner)

Run over SSH **on the router**:

```sh
wget -qO- https://raw.githubusercontent.com/valnesfjord/tg-ws-proxy-rs/main/install.sh | sh
```

The installer detects APK/opkg and `DISTRIB_ARCH`, downloads the matching raw
musl archive and LuCI package, verifies both against immutable SHA-256 digests
from the GitHub release API, migrates a known manual configuration and starts
the procd service. Re-run it to upgrade.

To trade higher runtime memory use for a smaller file on flash, explicitly
select the existing UPX release asset:

```sh
wget -qO- https://raw.githubusercontent.com/valnesfjord/tg-ws-proxy-rs/main/install.sh | \
  sh -s -- --upx
```

If GitHub release downloads require a mirror, put the variable on `sh` (not on
`wget`):

```sh
wget -qO- https://raw.githubusercontent.com/valnesfjord/tg-ws-proxy-rs/main/install.sh | \
  GH_MIRROR=https://your.mirror sh
```

The mirror may provide the payload, but the expected digest always comes from
`api.github.com`; the mirror is not part of the trust boundary.

### Beta releases

Beta tags (`vX.Y.Z-beta.N`) are normal GitHub prereleases. Stable is the default;
beta installation is explicit and can be combined with `--upx`:

```sh
wget -qO- https://raw.githubusercontent.com/valnesfjord/tg-ws-proxy-rs/main/install.sh | \
  sh -s -- --channel beta
```

Publishing a beta does not change the stable `releases/latest` channel.

### Local install

Put the matching `tg-ws-proxy-<target>[-upx].tar.gz`, LuCI APK/IPK and
`SHA256SUMS` in one directory, then run:

```sh
sh install.sh --archive /tmp/tg-ws-proxy-<target>.tar.gz \
  --luci-package /tmp/luci-app-tg-ws-proxy-rs.<apk-or-ipk>
```

### Configure and operate

After installation, open **Services → Telegram WS Proxy (Rust)** in LuCI. Configure the
listener, advertised link address, secret and any outbound/Cloudflare fallback,
then use **Save & Apply**. The page includes service controls and a filtered live
view of the bounded OpenWrt `logd` ring buffer. The package does not open a WAN
firewall port automatically.

![Telegram WS Proxy LuCI demo](docs/assets/openwrt-demo.gif)

For UCI examples, firewall guidance and rollback details, see the full
[OpenWrt guide](docs/OpenWrtPackage.md).

## Usage

```
tg-ws-proxy [OPTIONS]
```

| Flag | Default | Description |
|---|---|---|
| `--port <PORT>` | `1443` | Listen port |
| `--host <HOST>` | auto-detected | Listen address. Binds `0.0.0.0` if a LAN IP is detected (so it matches the auto-detected link IP below), otherwise `127.0.0.1` |
| `--link-ip <IP>` | auto-detected | IP shown in the `tg://` link (see [Router deployment](docs/Deployment.md#router-deployment)) |
| `--secret <HEX>` | random | 32 hex-char MTProto secret (repeatable / comma-separated for per-user secrets) |
| `--listen-faketls-domain <DOMAIN>` | — | Accept inbound clients with `ee` FakeTLS and advertise this SNI domain in the link |
| `--dc-ip <DC:IP>` | DC2 + DC4 | Target IP per DC (repeatable); omit when using `--cf-domain` to let CF proxy handle all DCs |
| `--buf-kb <KB>` | `256` | Socket buffer size (accepted but currently unused) |
| `--pool-size <N>` | `4` | Pre-warmed WS connections per DC |
| `--cf-domain <DOMAIN>` | — | Cloudflare-proxied domain(s) for alternative WS routing, comma-separated |
| `--cf-worker-domain <DOMAIN>` | — | Cloudflare Worker domain(s) for TCP-tunnel fallback, comma-separated/repeatable |
| `--default-domains` | off | Fetch and use the built-in CF proxy domain list from GitHub (no Cloudflare setup needed) |
| `--cf-priority` | off | Try the CF tiers (Worker, then CF proxy) **before** direct WS for all DCs |
| `--cf-balance` | off | Round-robin load balance across multiple `--cf-domain` and `--cf-worker-domain` values |
| `--ip-fail-cooldown <SECS>` | `3600` | How long to skip the direct WS path for a `--dc-ip` address whose TCP connect timed out, when a Cloudflare/upstream fallback is configured |
| `--fronting-domain <DOMAIN>` | off | Domain-fronting fallback SNI, e.g. `sprinthost.ru` |
| `--fronting-cooldown <SECS>` | `1800` | How long the fronting fallback stays active after it last succeeded |
| `--fronting-fail-cooldown <SECS>` | `60` | How long to stop retrying fronting after it fails for a DC (protects against networks that block Telegram's DC IPs outright, where fronting can never succeed) |
| `--max-connections <N>` | auto | Max concurrent client connections (auto-computed from `ulimit -n`) |
| `--mtproto-proxy <HOST:PORT:SECRET>` | — | Upstream MTProto proxy fallback (repeatable) |
| `--outbound-proxy <URL>` | — | Proxy for all outgoing connections: `http://`, `socks5://`, or `socks5h://`; `https://` proxy URLs are not supported |
| `--no-outbound-proxy` | off | Ignore standard outbound proxy environment variables |
| `--no-proxy <LIST>` | — | Comma-separated host bypass list for `--outbound-proxy` |
| `--check` | off | Test every configured CF domain and MTProto proxy, print OK/FAIL with latency, then exit `0` if all pass and `1` otherwise |
| `--log-file <PATH>` | — | Write logs to a file instead of stderr (no ANSI color codes) |
| `-q / --quiet` | off | Suppress all log output |
| `-v / --verbose` | off | Debug logging |
| `--danger-accept-invalid-certs` | off | Skip TLS verification |
| `-V / --version` | — | Print the version and exit |

Every flag has a matching `TG_*` environment variable (`TG_PORT`, `TG_HOST`,
`TG_SECRET`, …) — the full list is in
[docs/Deployment.md](docs/Deployment.md#configuration-via-environment).

On startup the proxy prints a `tg://proxy?...` link you can paste into
Telegram Desktop to configure it automatically. With `--listen-faketls-domain`,
the printed link uses `secret=ee<key><domain_hex>`; otherwise it uses the
classic `dd<key>` padded MTProto secret.

To issue separate credentials per user, pass multiple `--secret` values — the
proxy accepts all of them and prints an individual `tg://` link for each:

```bash
tg-ws-proxy --host 0.0.0.0 --port 443 \
  --secret 11111111111111111111111111111111 \
  --secret 22222222222222222222222222222222
```

### Examples

```bash
# Standard run (random secret, DC 2 + 4)
tg-ws-proxy

# Custom port and extra DCs
tg-ws-proxy --port 9050 --dc-ip 1:149.154.175.205 --dc-ip 2:149.154.167.220

# Use default CF domains from GitHub — no Cloudflare setup required
tg-ws-proxy --default-domains

# Default domains + CF priority (try CF first, fall back to direct WS)
tg-ws-proxy --default-domains --cf-priority

# Your own Cloudflare-proxied domain
tg-ws-proxy --cf-domain yourdomain.com

# Multiple CF domains with round-robin load balancing
tg-ws-proxy --cf-domain proxy.net,example.com --cf-balance

# Free workers.dev TCP tunnel fallback
tg-ws-proxy --cf-worker-domain random-symbols-1234.username.workers.dev

# Upstream MTProto proxy fallback
tg-ws-proxy --mtproto-proxy proxy.example.com:443:ddabcdef1234567890abcdef1234567890

# Route all outbound connections through a SOCKS5 proxy with remote DNS
tg-ws-proxy --outbound-proxy socks5h://user:pass@192.168.1.1:1080

# Router deployment: listen on all interfaces, let all LAN devices use the proxy
tg-ws-proxy --host 0.0.0.0

# Public home server: inbound ee FakeTLS, backend still WSS to Telegram Web
tg-ws-proxy --host 0.0.0.0 --port 443 --listen-faketls-domain www.yandex.ru

# Log to a file instead of stderr (no garbled ANSI codes — useful on Windows)
tg-ws-proxy --log-file proxy.log

# All options via environment variables (useful for Docker / systemd)
TG_PORT=1443 TG_SECRET=deadbeef... tg-ws-proxy
```

## How it works

1. Telegram Desktop connects to the proxy on `127.0.0.1:1443`.
2. The proxy reads the 64-byte MTProto obfuscation handshake, validates the
   secret, and extracts the target DC id and transport protocol.
3. A WebSocket connection is opened to `wss://kwsN.web.telegram.org/apiws`
   (using the DC-specific domain as TLS SNI but routing TCP to the configured
   IP).
4. The relay init packet is sent to Telegram, and bidirectional bridging
   begins with AES-256-CTR re-encryption (client keys ↔ relay keys).
5. If that path fails, each configured fallback tier is tried in turn —
   Cloudflare Worker, Cloudflare proxy, upstream MTProto proxy, then direct
   TCP on port 443.
6. A small pool of pre-connected WebSocket connections is maintained per DC to
   reduce connection latency for subsequent clients.

The tier order, how to configure each one, and when a failing tier goes into
cooldown are all documented in [docs/Fallbacks.md](docs/Fallbacks.md).

## Documentation

| Guide | Covers |
|---|---|
| [docs/Fallbacks.md](docs/Fallbacks.md) | Routing tiers: Cloudflare proxy/Worker, default domains, domain fronting, upstream MTProto proxies, inbound FakeTLS, outbound proxy |
| [docs/Building.md](docs/Building.md) | Building, cross-compiling for OpenWrt, and shrinking the binary with UPX |
| [docs/Deployment.md](docs/Deployment.md) | Docker, router deployment, OpenWrt init script, environment variables |
| [docs/OpenWrtPackage.md](docs/OpenWrtPackage.md) | Standalone APK/IPK builds, UCI/procd configuration, installer, upgrades and rollback |
| [docs/CfProxy.md](docs/CfProxy.md) | Cloudflare DNS proxy setup, step by step |
| [docs/CfWorker.md](docs/CfWorker.md) | Cloudflare Worker TCP tunnel setup |
| [AGENTS.md](AGENTS.md) | Repository layout and conventions for contributors |

## License

MIT

# tg-ws-proxy-rs

**Telegram MTProto WebSocket Bridge Proxy** — a Rust **vibecoded** port of
[Flowseal/tg-ws-proxy](https://github.com/Flowseal/tg-ws-proxy).

Listens for Telegram Desktop's MTProto connections on a local port and
tunnels them through WebSocket (TLS) connections to Telegram's DC servers.

```
Telegram Desktop → MTProto (TCP 1443) → tg-ws-proxy-rs → WS (TLS 443) → Telegram DC
                                                         ↘ CF proxy (kws{N}.{cf-domain}) → Telegram DC  (WS via Cloudflare)
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

Download from the [Releases](../../releases) page.

### Build from source

```bash
# Debug build
cargo build

# Optimised release build
cargo build --release

# Static binary for Linux x86_64 (e.g. for Docker scratch images)
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
```

The release binary is at `target/release/tg-ws-proxy` (or
`target/<target>/release/tg-ws-proxy` for cross-compiled targets).

## Cross-platform builds with `cargo-zigbuild`

[`cargo-zigbuild`](https://github.com/rust-cross/cargo-zigbuild) uses the Zig
compiler as a drop-in C cross-linker so you can build for every platform from
a single Linux or macOS host without installing any platform SDKs.

```bash
# Install cargo-zigbuild and Zig
pip install ziglang        # or: brew install zig
cargo install cargo-zigbuild

# Add all required Rust targets in one shot
rustup target add \
  x86_64-unknown-linux-musl \
  aarch64-unknown-linux-musl \
  armv7-unknown-linux-musleabihf \
  mipsel-unknown-linux-musl \
  x86_64-apple-darwin \
  aarch64-apple-darwin \
  x86_64-pc-windows-gnu

# Build for all platforms
cargo zigbuild --release --target x86_64-unknown-linux-musl       # Linux x86-64 (musl static)
cargo zigbuild --release --target aarch64-unknown-linux-musl      # Linux / OpenWrt ARM64
cargo zigbuild --release --target armv7-unknown-linux-musleabihf  # OpenWrt ARMv7
cargo zigbuild --release --target mipsel-unknown-linux-musl       # OpenWrt MIPS LE
cargo zigbuild --release --target x86_64-apple-darwin             # macOS Intel
cargo zigbuild --release --target aarch64-apple-darwin            # macOS Apple Silicon
cargo zigbuild --release --target x86_64-pc-windows-gnu           # Windows x86-64
```

> **Note:** Building macOS targets (`*-apple-darwin`) requires the macOS SDK
> (XCode Command Line Tools). On Linux you can use
> [`osxcross`](https://github.com/tpoechtrager/osxcross) to supply the SDK
> and then set `SDKROOT` / `MACOSX_DEPLOYMENT_TARGET` appropriately before
> running `cargo zigbuild`.

## Usage

```
tg-ws-proxy [OPTIONS]
```

| Flag | Default | Description |
|---|---|---|
| `--port <PORT>` | `1443` | Listen port |
| `--host <HOST>` | `127.0.0.1` | Listen address |
| `--link-ip <IP>` | auto-detected | IP shown in the `tg://` link (see [Router deployment](#router-deployment)) |
| `--secret <HEX>` | random | 32 hex-char MTProto secret |
| `--listen-faketls-domain <DOMAIN>` | — | Accept inbound clients with `ee` FakeTLS and advertise this SNI domain in the link |
| `--dc-ip <DC:IP>` | DC2 + DC4 | Target IP per DC (repeatable); omit when using `--cf-domain` to let CF proxy handle all DCs |
| `--buf-kb <KB>` | `256` | Socket buffer size |
| `--pool-size <N>` | `4` | Pre-warmed WS connections per DC |
| `--cf-domain <DOMAIN>` | — | Cloudflare-proxied domain(s) for alternative WS routing, comma-separated (see [CF Proxy](#cloudflare-proxy)) |
| `--default-domains` | off | Fetch and use the built-in CF proxy domain list from GitHub (no Cloudflare setup needed, see [Default domains](#default-domains)) |
| `--cf-priority` | off | Try CF proxy **before** direct WS for all DCs (see [CF Proxy](#cloudflare-proxy)) |
| `--cf-balance` | off | Round-robin load balance across multiple `--cf-domain` values (see [CF Proxy](#cloudflare-proxy)) |
| `--max-connections <N>` | auto | Max concurrent client connections (auto-computed from `ulimit -n`) |
| `--mtproto-proxy <HOST:PORT:SECRET>` | — | Upstream MTProto proxy fallback (repeatable) |
| `--log-file <PATH>` | — | Write logs to a file instead of stderr (no ANSI color codes) |
| `-q / --quiet` | off | Suppress all log output |
| `-v / --verbose` | off | Debug logging |
| `--danger-accept-invalid-certs` | off | Skip TLS verification |

Every flag has a matching environment variable (`TG_PORT`, `TG_HOST`,
`TG_SECRET`, `TG_BUF_KB`, `TG_POOL_SIZE`, `TG_MAX_CONNECTIONS`, `TG_QUIET`,
`TG_VERBOSE`, `TG_SKIP_TLS_VERIFY`, `TG_LINK_IP`, `TG_LISTEN_FAKETLS_DOMAIN`, `TG_MTPROTO_PROXY`,
`TG_LOG_FILE`, `TG_CF_DOMAIN`, `TG_CF_PRIORITY`, `TG_CF_BALANCE`, `TG_DEFAULT_DOMAINS`).

### Examples

```bash
# Standard run (random secret, DC 2 + 4)
tg-ws-proxy

# Custom port and extra DCs
tg-ws-proxy --port 9050 --dc-ip 1:149.154.175.205 --dc-ip 2:149.154.167.220

# With upstream MTProto proxy fallback
tg-ws-proxy --mtproto-proxy proxy.example.com:443:ddabcdef1234567890abcdef1234567890

# With Cloudflare proxy domain (WS fallback via Cloudflare CDN)
tg-ws-proxy --cf-domain yourdomain.com

# CF proxy only: omit --dc-ip so CF proxy handles all DCs
tg-ws-proxy --cf-domain yourdomain.com --cf-priority

# Use default CF domains from GitHub — no Cloudflare setup required
tg-ws-proxy --default-domains

# Default domains + CF priority (try CF first, fall back to direct WS)
tg-ws-proxy --default-domains --cf-priority

# Default domains + your own domain (yours goes first)
tg-ws-proxy --cf-domain yourdomain.com --default-domains

# Multiple CF domains (tried in order) with CF priority over direct WS
tg-ws-proxy --cf-domain proxy.net,example.com --cf-priority

# Multiple CF domains with round-robin load balancing
tg-ws-proxy --cf-domain proxy.net,example.com --cf-balance

# CF balance + priority: round-robin across CF domains, tried before direct WS
tg-ws-proxy --cf-domain proxy.net,example.com --cf-balance --cf-priority

# CF priority: CF proxy is tried first, falls back to direct WS on failure
tg-ws-proxy --dc-ip 2:149.154.167.220 --cf-domain yourdomain.com --cf-priority

# Multiple upstream proxies (tried in order until one succeeds)
tg-ws-proxy \
  --mtproto-proxy proxy.example.com:443:ddabcdef1234567890abcdef1234567890 \
  --mtproto-proxy other.example.net:8888:dddeadbeef01234567deadbeef01234567

# Router deployment: listen on all interfaces, let all LAN devices use the proxy
tg-ws-proxy --host 0.0.0.0

# Public home server: inbound ee FakeTLS, backend still WSS to Telegram Web
tg-ws-proxy --host 0.0.0.0 --port 443 --listen-faketls-domain www.yandex.ru

# Equivalent: pass a full ee secret directly
tg-ws-proxy --host 0.0.0.0 --port 443 --secret ee<32-hex-key><hex-encoded-domain>

# Verbose logging
tg-ws-proxy -v

# Log to a file instead of stderr (no garbled ANSI codes — useful on Windows)
tg-ws-proxy --log-file proxy.log

# All options via environment variables (useful for Docker / systemd)
TG_PORT=1443 TG_SECRET=deadbeef... tg-ws-proxy
```

On startup the proxy prints a `tg://proxy?...` link you can paste into
Telegram Desktop to configure it automatically. With `--listen-faketls-domain`,
the printed link uses `secret=ee<key><domain_hex>`; otherwise it uses the
classic `dd<key>` padded MTProto secret.

### Inbound FakeTLS listener

For public home servers where DPI blocks raw inbound MTProto, enable inbound
FakeTLS:

```bash
tg-ws-proxy --host 0.0.0.0 --port 443 --listen-faketls-domain www.yandex.ru
```

This changes only the client-facing transport:

```
Telegram client → ee FakeTLS → tg-ws-proxy-rs → WSS/TLS → kws*.web.telegram.org
```

The proxy accepts the TLS ClientHello, validates the FakeTLS HMAC, sends a
synthetic TLS ServerHello, unwraps TLS Application Data records, and then
passes the recovered MTProto init into the existing WebSocket backend path.

### Upstream MTProto proxy fallback

When WebSocket connections to Telegram are blocked, the proxy can route
traffic through an external MTProto proxy before falling back to direct TCP:

```
WS (preferred) → upstream MTProto proxy → direct TCP (last resort)
```

Pass one or more `--mtproto-proxy HOST:PORT:SECRET` flags (or a
comma-separated list in `TG_MTPROTO_PROXY`).  Proxies are tried in the order
given; if one fails it enters a 60-second cooldown so subsequent connections
skip it without delay.

```bash
# Padded-intermediate proxy (dd prefix)
tg-ws-proxy --mtproto-proxy proxy.example.com:443:ddabcdef1234567890abcdef1234567890

# FakeTLS proxy (ee prefix — domain-fronting transport)
tg-ws-proxy --mtproto-proxy proxy.example.com:443:ee<32-hex-key><hex-encoded-hostname>

# Multiple proxies (tried in order until one succeeds)
tg-ws-proxy \
  --mtproto-proxy proxy.example.com:443:ddabcdef1234567890abcdef1234567890 \
  --mtproto-proxy other.example.net:8888:dddeadbeef01234567deadbeef01234567

# Or via environment variable (comma-separated)
TG_MTPROTO_PROXY="proxy.example.com:443:ddabcdef1234...,other.example.net:8888:dddeadbeef..." tg-ws-proxy
```

> **ℹ️ Secret format — pass the secret exactly as shown in the `tg://proxy` link**
>
> Public MTProto proxies advertise secrets with a 1-byte prefix that tells the
> proxy which transport mode to use.  **Copy the full secret as-is — prefix included:**
>
> | Prefix | Meaning | Example |
> |--------|---------|---------|
> | `dd` | Padded-intermediate transport | `ddabcdef1234567890abcdef1234567890` |
> | `ee` | FakeTLS (domain-fronting) transport | `ee` + 32 hex key chars + hex-encoded hostname |
> | *(none)* | Plain transport (legacy, 32 hex chars) | `abcdef1234567890abcdef1234567890` |
>
> In the `tg://proxy?server=...&secret=` link the `secret=` value already
> contains the correct prefix.  Copy everything after `secret=` and pass it
> directly to `--mtproto-proxy`.

### Cloudflare Proxy

When Telegram's IP ranges are blocked by your ISP, you can route WebSocket
traffic through Cloudflare using `--cf-domain`.  This requires only a domain
name — no server-side component.

```bash
# Use your own Cloudflare-proxied domain
tg-ws-proxy --cf-domain yourdomain.com

# Multiple domains (tried in order, first has highest priority)
tg-ws-proxy --cf-domain primary.net,backup.com

# Multiple domains with round-robin load balancing
tg-ws-proxy --cf-domain primary.net,backup.com --cf-balance

# CF-only mode: omit --dc-ip so CF proxy handles all DCs
tg-ws-proxy --cf-domain yourdomain.com

# CF priority: try CF proxy before direct WS, with WS as fallback
tg-ws-proxy --dc-ip 2:149.154.167.220 --cf-domain yourdomain.com --cf-priority

# Or via environment variable
TG_CF_DOMAIN=yourdomain.com tg-ws-proxy
```

The proxy will try the CF path as a fallback after direct WebSocket fails, and
as the primary path for DCs that have no `--dc-ip` configured.  With
`--cf-priority`, the CF proxy is tried **before** direct WebSocket for all DCs.

#### `--cf-balance` — round-robin load balancing

When multiple `--cf-domain` values are given, connections normally always start
with the first domain.  Adding `--cf-balance` distributes connections evenly
across all configured CF domains using round-robin selection:

```bash
tg-ws-proxy --cf-domain d1.example.com,d2.example.com,d3.example.com --cf-balance
# connection 0 → tries d1, then d2, then d3
# connection 1 → tries d2, then d3, then d1
# connection 2 → tries d3, then d1, then d2
```

The remaining domains still serve as ordered fallbacks if the primary one
fails, so resilience is unchanged.  Has no effect when only one CF domain is
configured.  Can be combined with `--cf-priority`:

```bash
# Round-robin CF load balancing, tried before direct WS
tg-ws-proxy --cf-domain d1.example.com,d2.example.com --cf-balance --cf-priority
```

**One-time domain setup** (do this in the Cloudflare dashboard):

1. In **SSL/TLS → Overview** set mode to **Flexible**.
2. In **DNS → Records** add these proxied (`🔶`) A records:

   | Name      | IPv4 address      |
   |-----------|-------------------|
   | `kws1`    | `149.154.175.50`  |
   | `kws1-1`  | `149.154.175.50`  |
   | `kws2`    | `149.154.167.51`  |
   | `kws2-1`  | `149.154.167.51`  |
   | `kws3`    | `149.154.175.100` |
   | `kws3-1`  | `149.154.175.100` |
   | `kws4`    | `149.154.167.91`  |
   | `kws4-1`  | `149.154.167.91`  |
   | `kws5`    | `149.154.171.5`   |
   | `kws5-1`  | `149.154.171.5`   |
   | `kws203`  | `91.105.192.100`  |
   | `kws203-1`| `91.105.192.100`  |

See [docs/CfProxy.md](docs/CfProxy.md) for full instructions.

### Default domains

Don't want to configure your own Cloudflare DNS zone?  Use `--default-domains`
to automatically fetch a pre-configured, working list of CF proxy domains from
the upstream repository:

```bash
# No Cloudflare account or DNS setup required
tg-ws-proxy --default-domains

# Enable CF priority so CF path is tried first
tg-ws-proxy --default-domains --cf-priority

# Combine with your own domain (yours gets highest priority)
tg-ws-proxy --cf-domain yourdomain.com --default-domains

# Test the fetched domains before starting the proxy
tg-ws-proxy --default-domains --check
```

Or via environment variable:

```bash
TG_DEFAULT_DOMAINS=true tg-ws-proxy
```

At startup the proxy fetches an obfuscated domain list from
[Flowseal/tg-ws-proxy](https://github.com/Flowseal/tg-ws-proxy/blob/main/.github/cfproxy-domains.txt),
deobfuscates it, and appends the decoded domains after any explicit
`--cf-domain` entries.  If the fetch fails (network not yet available,
GitHub unreachable) the proxy falls back to a small built-in list and logs a
warning — it will still start normally.

> **Note:** These are community-maintained domains; availability may change
> over time.  For maximum reliability, consider setting up your own
> Cloudflare zone (see [docs/CfProxy.md](docs/CfProxy.md)).

### Router deployment

Run the proxy on your router with `--host 0.0.0.0` so it accepts connections
from all LAN devices:

```bash
tg-ws-proxy --host 0.0.0.0 --port 1443
```

When `--host 0.0.0.0` is used, the proxy **auto-detects** the router's LAN IP
address and uses it in the generated `tg://` link, so you can share the same
link with every device on your network.

If auto-detection picks the wrong interface, override it explicitly:

```bash
tg-ws-proxy --host 0.0.0.0 --link-ip 192.168.1.1
```

> **Note:** The default `--host 127.0.0.1` only accepts connections from the
> machine running the proxy. Other devices on the network will not be able to
> connect unless you change this to `0.0.0.0` (or the router's LAN IP).

## Telegram Desktop Setup

1. **Settings → Advanced → Connection type → Use custom proxy**
2. Add MTProto proxy:
   - **Server:** `127.0.0.1`
   - **Port:** `1443` (or your `--port`)
   - **Secret:** shown in the proxy startup log

Or use the `tg://proxy?...` link that is printed on startup.

## Cross-compilation for OpenWrt

OpenWrt uses musl libc and runs on MIPS, ARM, and ARM64 CPUs.  Building a
fully static Rust binary requires:

1. A C cross-compiler for your target (used by `ring`/`aws-lc-sys`)
2. The matching Rust target

### ARM64 (aarch64) — e.g. GL.iNet MT6000, Banana Pi R4

```bash
# Install the cross toolchain (Ubuntu/Debian)
apt-get install gcc-aarch64-linux-gnu

# Add the Rust target
rustup target add aarch64-unknown-linux-musl

# Uncomment the [target.aarch64-unknown-linux-musl] section in .cargo/config.toml,
# then build:
cargo build --release --target aarch64-unknown-linux-musl
```

### ARM (armv7) — e.g. older GL.iNet routers, some TP-Link models

```bash
apt-get install gcc-arm-linux-gnueabihf
rustup target add armv7-unknown-linux-musleabihf
# Uncomment the armv7 section in .cargo/config.toml
cargo build --release --target armv7-unknown-linux-musleabihf
```

### MIPS LE — e.g. TP-Link WR series

```bash
apt-get install gcc-mipsel-linux-gnu
rustup target add mipsel-unknown-linux-musl
# Uncomment the mipsel section in .cargo/config.toml
cargo build --release --target mipsel-unknown-linux-musl
```

### Using `cross` (easier alternative)

[`cross`](https://github.com/cross-rs/cross) uses Docker to manage toolchains:

```bash
cargo install cross
cross build --release --target aarch64-unknown-linux-musl
```

### OpenWrt procd init script

Create `/etc/init.d/tg-ws-proxy`:

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
chmod +x /etc/init.d/tg-ws-proxy
/etc/init.d/tg-ws-proxy enable
/etc/init.d/tg-ws-proxy start
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
5. If WebSocket is unavailable, the proxy tries the Cloudflare proxy path
   (`wss://kwsN.{cf-domain}/apiws`) if `--cf-domain` is configured —
   Cloudflare terminates TLS and forwards plain WebSocket traffic to Telegram.
6. If CF proxy is unavailable or not configured, each upstream MTProto proxy
   is tried in order (generating a fresh client handshake with the upstream's
   secret so it can route to the correct DC).
7. If no upstream proxy is configured or all fail, the proxy falls back to
   direct TCP on port 443.
8. A small pool of pre-connected WebSocket connections is maintained per DC to
   reduce connection latency for subsequent clients.

## Project structure

```
src/
  main.rs              — Entry point, CLI parsing, server startup, banner
  config.rs            — ProxyConfig struct, argument parsing, env-var aliases
  crypto.rs            — MTProto obfuscation: handshake parsing, relay init generation,
                         AES-256-CTR key derivation and cipher construction
  splitter.rs          — MTProto packet splitter for correct WebSocket framing
  ws_client.rs         — WebSocket client for Telegram DC connections (IP routing + SNI)
  pool.rs              — Pre-warmed WebSocket connection pool per DC
  proxy.rs             — Client handler, re-encryption bridge, TCP fallback logic
  default_domains.rs   — Fetches and deobfuscates the default CF proxy domain list
.cargo/
  config.toml          — Cross-compilation target presets (commented out)
```

## Configuration via environment

```bash
TG_HOST=0.0.0.0
TG_PORT=1443
TG_SECRET=0123456789abcdef0123456789abcdef
TG_POOL_SIZE=4
TG_BUF_KB=256
TG_MAX_CONNECTIONS=64
TG_QUIET=true
TG_VERBOSE=false
TG_CF_DOMAIN=yourdomain.com
TG_CF_PRIORITY=false
TG_CF_BALANCE=false
TG_DEFAULT_DOMAINS=false
TG_LOG_FILE=/var/log/tg-ws-proxy.log
TG_MTPROTO_PROXY=proxy.example.com:443:ddabcdef1234567890abcdef1234567890
```

## Windows console — no garbled characters

On Windows the console does not enable ANSI/VT colour codes by default, which
caused log lines to show symbols like `←[32m` around the log level.  This is
fixed: ANSI escape codes are automatically disabled when running on Windows or
when stderr is not a terminal (e.g. output is piped or redirected).

If you prefer completely clean logs or want to capture them to a file, use
`--log-file`:

```bash
tg-ws-proxy --log-file proxy.log
# or
set TG_LOG_FILE=proxy.log && tg-ws-proxy
```

## License

MIT

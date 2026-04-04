# tg-ws-proxy-rs

**Telegram MTProto WebSocket Bridge Proxy** — a Rust **vibecoded** port of
[Flowseal/tg-ws-proxy](https://github.com/Flowseal/tg-ws-proxy).

Listens for Telegram Desktop's MTProto connections on a local port and
tunnels them through WebSocket (TLS) connections to Telegram's DC servers.

```
Telegram Desktop → MTProto (TCP 1443) → tg-ws-proxy-rs → WS (TLS 443) → Telegram DC
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
| `--dc-ip <DC:IP>` | DC2 + DC4 | Target IP per DC (repeatable) |
| `--buf-kb <KB>` | `256` | Socket buffer size |
| `--pool-size <N>` | `4` | Pre-warmed WS connections per DC |
| `-q / --quiet` | off | Suppress all log output |
| `-v / --verbose` | off | Debug logging |
| `--danger-accept-invalid-certs` | off | Skip TLS verification |

Every flag has a matching environment variable (`TG_PORT`, `TG_HOST`,
`TG_SECRET`, `TG_BUF_KB`, `TG_POOL_SIZE`, `TG_QUIET`, `TG_VERBOSE`,
`TG_SKIP_TLS_VERIFY`, `TG_LINK_IP`).

### Examples

```bash
# Standard run (random secret, DC 2 + 4)
tg-ws-proxy

# Custom port and extra DCs
tg-ws-proxy --port 9050 --dc-ip 1:149.154.175.205 --dc-ip 2:149.154.167.220

# Router deployment: listen on all interfaces, let all LAN devices use the proxy
tg-ws-proxy --host 0.0.0.0

# Verbose logging
tg-ws-proxy -v

# All options via environment variables (useful for Docker / systemd)
TG_PORT=1443 TG_SECRET=deadbeef... tg-ws-proxy
```

On startup the proxy prints a `tg://proxy?...` link you can paste into
Telegram Desktop to configure it automatically.

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
   begins with AES-256-CTR re-encryption (client keys <=> relay keys).
5. If WebSocket is unavailable (redirect response), the proxy falls back to
   direct TCP on port 443.
6. A small pool of pre-connected WebSocket connections is maintained per DC to
   reduce connection latency for subsequent clients.

## Project structure

```
src/
  main.rs       — Entry point, CLI parsing, server startup, banner
  config.rs     — ProxyConfig struct, argument parsing, env-var aliases
  crypto.rs     — MTProto obfuscation: handshake parsing, relay init generation,
                  AES-256-CTR key derivation and cipher construction
  splitter.rs   — MTProto packet splitter for correct WebSocket framing
  ws_client.rs  — WebSocket client for Telegram DC connections (IP routing + SNI)
  pool.rs       — Pre-warmed WebSocket connection pool per DC
  proxy.rs      — Client handler, re-encryption bridge, TCP fallback logic
.cargo/
  config.toml   — Cross-compilation target presets (commented out)
```

## Configuration via environment

```bash
TG_HOST=0.0.0.0
TG_PORT=1443
TG_SECRET=0123456789abcdef0123456789abcdef
TG_POOL_SIZE=4
TG_BUF_KB=256
TG_QUIET=true
TG_VERBOSE=false
```

## License

MIT

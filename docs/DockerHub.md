# tg-ws-proxy-rs

**Telegram MTProto ↔ WebSocket bridge proxy**, written in Rust.

It listens for Telegram Desktop's MTProto connections on a local port and tunnels
them to Telegram's DC servers over WebSocket (TLS) — useful on networks where raw
TCP to Telegram is blocked. Cloudflare, upstream MTProto proxy and direct TCP
fallbacks are built in.

```
Telegram Desktop → MTProto (TCP 1443) → tg-ws-proxy-rs → WS (TLS 443) → Telegram DC
                                                         ↘ CF proxy (kws{N}.{cf-domain}) → Telegram DC
                                                         ↘ CF Worker (*.workers.dev)     → Telegram DC
                                                         ↘ upstream MTProto proxy        → Telegram DC
                                                         ↘ direct TCP :443               → Telegram DC
```

- **Source, issues, full documentation:** https://github.com/valnesfjord/tg-ws-proxy-rs
- **License:** MIT — https://github.com/valnesfjord/tg-ws-proxy-rs/blob/main/LICENSE
- Rust port of [Flowseal/tg-ws-proxy](https://github.com/Flowseal/tg-ws-proxy)

---

## Supported tags

| Tag | Contents |
|---|---|
| `latest` | Rebuilt on every release **and** on every push to `main`, so it can be ahead of the newest release. |
| `X.Y.Z` (e.g. `2.2.2`) | Exact release. Pin this if you want reproducible deployments. |
| `X.Y` (e.g. `2.2`) | Latest patch inside a minor series. |
| `main`, `feature-*` | Development builds. Not recommended for real use. |
| `buildcache-amd64`, `buildcache-arm64` | CI build cache — **not runnable images**, ignore them. |

Architectures: `linux/amd64`, `linux/arm64`.

## Quick start

```bash
docker run -d --name tg-ws-proxy -p 1443:1443 valnesfjord/tg-ws-proxy-rs
```

The proxy prints its secret and a ready-to-use `tg://proxy?...` link on startup —
read them from the container log:

```bash
docker logs tg-ws-proxy
```

Then in **Telegram Desktop → Settings → Advanced → Connection type → Use custom
proxy → Add MTProto proxy**:

- **Server:** the host running the container (`127.0.0.1` if it is your own machine)
- **Port:** `1443`
- **Secret:** from the log

Or just open the `tg://proxy?...` link.

## Three things that only matter in a container

**1. Set `TG_SECRET`.** Without it a new random secret is generated on every start,
so the `tg://` link changes each time the container restarts.

**2. Set `--link-ip` / `TG_LINK_IP`.** Host auto-detection sees the container's
bridge address (something like `172.17.0.2`), which nobody can reach. Pass the
address clients should actually connect to. `--network host` avoids the problem
instead.

**3. Don't make the container bind a privileged port.** The image runs as UID 1000,
so binding `:443` inside the container fails. Publish it from the host instead:

```bash
docker run -d --name tg-ws-proxy -p 443:1443 valnesfjord/tg-ws-proxy-rs
```

If the container itself really must listen on 443 (e.g. with `--network host`), run
it as root with `--user 0:0`, or — bridge networking only — add
`--sysctl net.ipv4.ip_unprivileged_port_start=0`.

Putting it together:

```bash
docker run -d --name tg-ws-proxy \
  --restart unless-stopped \
  -p 1443:1443 \
  -e TG_SECRET=0123456789abcdef0123456789abcdef \
  -e TG_LINK_IP=203.0.113.10 \
  -e TG_DEFAULT_DOMAINS=true \
  valnesfjord/tg-ws-proxy-rs
```

## docker compose

```yaml
services:
  tg-ws-proxy:
    image: valnesfjord/tg-ws-proxy-rs:2.2
    container_name: tg-ws-proxy
    restart: unless-stopped
    ports:
      - "1443:1443"
    environment:
      TG_SECRET: "0123456789abcdef0123456789abcdef"
      TG_LINK_IP: "203.0.113.10"
      TG_DEFAULT_DOMAINS: "true"
    # Flags without a TG_* variable (e.g. --dc-ip) go here:
    # command: ["--dc-ip", "2:149.154.167.220", "--dc-ip", "4:149.154.167.220"]
```

## Configuration

The entrypoint is the binary itself, so **flags go after the image name**:

```bash
docker run --rm valnesfjord/tg-ws-proxy-rs --help
docker run --rm valnesfjord/tg-ws-proxy-rs --version
```

Every flag except `--dc-ip` also has a `TG_*` environment variable. Booleans accept
`true` / `false`; repeatable values are comma-separated.

| Env var | Flag | Default | Description |
|---|---|---|---|
| `TG_PORT` | `--port` | `1443` | Listen port |
| `TG_HOST` | `--host` | auto | Listen address. Leave unset in a container — it binds `0.0.0.0` |
| `TG_LINK_IP` | `--link-ip` | auto | IP shown in the `tg://` link. **Set this** (see above) |
| `TG_SECRET` | `--secret` | random | 32 hex-char secret; comma-separated for per-user secrets. **Set this** |
| `TG_LISTEN_FAKETLS_DOMAIN` | `--listen-faketls-domain` | — | Accept inbound clients with `ee` FakeTLS and advertise this SNI domain |
| — | `--dc-ip <DC:IP>` | DC2 + DC4 | Target IP per DC (repeatable). No env var — pass it as an argument |
| `TG_POOL_SIZE` | `--pool-size` | `4` | Pre-warmed WS connections per DC |
| `TG_MAX_CONNECTIONS` | `--max-connections` | auto | Max concurrent client connections |
| `TG_BUF_KB` | `--buf-kb` | `256` | Socket buffer size (accepted, currently unused) |
| `TG_DEFAULT_DOMAINS` | `--default-domains` | `false` | Use the built-in Cloudflare domain list from GitHub — no Cloudflare account needed |
| `TG_CF_DOMAIN` | `--cf-domain` | — | Your own Cloudflare-proxied domain(s), comma-separated |
| `TG_CF_WORKER_DOMAIN` | `--cf-worker-domain` | — | Cloudflare Worker domain(s) for the TCP-tunnel fallback |
| `TG_CF_PRIORITY` | `--cf-priority` | `false` | Try the Cloudflare tiers before direct WS |
| `TG_CF_BALANCE` | `--cf-balance` | `false` | Round-robin across multiple CF domains/workers |
| `TG_MTPROTO_PROXY` | `--mtproto-proxy` | — | Upstream MTProto proxy fallback, `HOST:PORT:SECRET` |
| `TG_FRONTING_DOMAIN` | `--fronting-domain` | — | Domain-fronting fallback SNI, e.g. `sprinthost.ru` |
| `TG_IP_FAIL_COOLDOWN` | `--ip-fail-cooldown` | `3600` | Seconds to skip a `--dc-ip` whose direct TCP connect timed out |
| `TG_OUTBOUND_PROXY` | `--outbound-proxy` | — | Send all outgoing traffic via `http://`, `socks5://` or `socks5h://` |
| `TG_NO_OUTBOUND_PROXY` | `--no-outbound-proxy` | `false` | Ignore the standard proxy environment variables |
| `TG_NO_PROXY` | `--no-proxy` | — | Comma-separated bypass list for `--outbound-proxy` |
| `TG_CHECK` | `--check` | `false` | Probe every configured CF domain / MTProto proxy, print OK/FAIL, exit |
| `TG_LOG_FILE` | `--log-file` | — | Write logs to a file instead of stderr (needs a mounted, writable volume) |
| `TG_VERBOSE` | `-v` / `--verbose` | `false` | Debug logging |
| `TG_QUIET` | `-q` / `--quiet` | `false` | Suppress all log output |
| `TG_SKIP_TLS_VERIFY` | `--danger-accept-invalid-certs` | `false` | Skip TLS verification |

Additional timeout and cooldown knobs (`TG_WS_CONNECT_TIMEOUT`,
`TG_CF_FAIL_COOLDOWN`, `TG_POOL_MAX_AGE`, …) are listed in `--help`.

When `TG_OUTBOUND_PROXY` is unset, the standard `HTTPS_PROXY`, `ALL_PROXY`,
`HTTP_PROXY` and `NO_PROXY` variables are honored too.

## Common setups

```bash
# Cloudflare routing with zero setup — domain list fetched from GitHub
docker run -d -p 1443:1443 -e TG_DEFAULT_DOMAINS=true valnesfjord/tg-ws-proxy-rs

# Same, but try Cloudflare first and fall back to direct WS
docker run -d -p 1443:1443 \
  -e TG_DEFAULT_DOMAINS=true -e TG_CF_PRIORITY=true valnesfjord/tg-ws-proxy-rs

# Your own Cloudflare-proxied domains, load balanced
docker run -d -p 1443:1443 \
  -e TG_CF_DOMAIN=proxy.net,example.com -e TG_CF_BALANCE=true valnesfjord/tg-ws-proxy-rs

# Free workers.dev TCP tunnel fallback
docker run -d -p 1443:1443 \
  -e TG_CF_WORKER_DOMAIN=random-symbols-1234.username.workers.dev valnesfjord/tg-ws-proxy-rs

# Public server: inbound ee FakeTLS on 443, WSS to Telegram behind it
docker run -d -p 443:1443 \
  -e TG_SECRET=0123456789abcdef0123456789abcdef \
  -e TG_LISTEN_FAKETLS_DOMAIN=www.yandex.ru \
  -e TG_LINK_IP=203.0.113.10 valnesfjord/tg-ws-proxy-rs

# Separate credentials per user — one tg:// link is printed for each secret
docker run -d -p 1443:1443 \
  -e TG_SECRET=11111111111111111111111111111111,22222222222222222222222222222222 \
  valnesfjord/tg-ws-proxy-rs

# Check a configuration without starting the proxy (exit 0 = all probes passed)
docker run --rm valnesfjord/tg-ws-proxy-rs --check --default-domains
```

## About the image

- Built `FROM scratch`: a statically linked musl binary plus a CA bundle, nothing
  else — a few MB, no shell, no package manager, no libc.
- Runs as **UID/GID 1000**, `EXPOSE 1443`, `ENTRYPOINT ["tg-ws-proxy"]`.
- Because there is no shell, `docker exec tg-ws-proxy sh` does not work, and neither
  does a shell-form `HEALTHCHECK`. Use exec form with the absolute path:

  ```yaml
  healthcheck:
    test: ["CMD", "/usr/local/bin/tg-ws-proxy", "--check", "--cf-domain", "example.com"]
    interval: 5m
    timeout: 30s
  ```

  Note that `--check` only probes the *configured fallback tiers* (Cloudflare
  domains, workers, upstream MTProto proxies) — it says nothing about the direct
  WebSocket path, so it is only a useful health signal when those are configured.
  Point it at your own domains rather than at `--default-domains`, which probes
  the whole fetched list.
- The proxy keeps no state on disk. A volume is only needed for `TG_LOG_FILE`, and
  the mounted directory must be writable by UID 1000.

## Documentation

| Guide | Covers |
|---|---|
| [README](https://github.com/valnesfjord/tg-ws-proxy-rs#readme) | Overview, all flags, how it works |
| [Deployment](https://github.com/valnesfjord/tg-ws-proxy-rs/blob/main/docs/Deployment.md) | Docker, router deployment, OpenWrt init script, environment variables |
| [Fallbacks](https://github.com/valnesfjord/tg-ws-proxy-rs/blob/main/docs/Fallbacks.md) | Routing tiers, default domains, domain fronting, FakeTLS, outbound proxy |
| [Cloudflare proxy](https://github.com/valnesfjord/tg-ws-proxy-rs/blob/main/docs/CfProxy.md) | Cloudflare DNS proxy setup, step by step |
| [Cloudflare Worker](https://github.com/valnesfjord/tg-ws-proxy-rs/blob/main/docs/CfWorker.md) | Worker TCP tunnel setup |
| [Building](https://github.com/valnesfjord/tg-ws-proxy-rs/blob/main/docs/Building.md) | Building from source, cross-compiling for OpenWrt, UPX |

Not using Docker? Pre-built binaries for Linux (glibc/musl, incl. MIPS/ARM for
routers), Windows and macOS are on the
[Releases page](https://github.com/valnesfjord/tg-ws-proxy-rs/releases).

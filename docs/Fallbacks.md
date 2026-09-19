# Routing and fallbacks

Every client connection is routed through the first tier that works. Tiers that
are not configured are skipped entirely.

```
direct WS to the DC              ← default
  ↓ Cloudflare Worker            ← --cf-worker-domain
  ↓ Cloudflare proxy             ← --cf-domain / --default-domains
  ↓ upstream MTProto proxy       ← --mtproto-proxy
  ↓ direct TCP :443              ← last resort
```

Domain fronting is a modifier on the direct-WS tier rather than a tier of its
own; the whole order can also be [pinned per traffic class](#pinning-the-tier-order-per-traffic-class).

A small pool of pre-connected WebSocket connections is kept per DC
(`--pool-size`) so later clients skip the handshake latency.

## Pinning the tier order per traffic class

Every client handshake says whether it wants a **media DC** (negative DC index)
— where Telegram clients already put photo/video/file transfers — or not.
`--pinned-upstream` pins the tier order for both classes as a comma-separated
list tried in the order given; `--pinned-media-upstream` overrides it for media
connections only:

| Name | Tier |
|---|---|
| `ws` | direct WebSocket (needs a `--dc-ip` target for the DC) |
| `cfworker` | Cloudflare Worker tunnel (`--cf-worker-domain`) |
| `cfproxy` | Cloudflare proxy (`--cf-domain` / `--default-domains`) |
| `mtproto` | upstream MTProto proxy (`--mtproto-proxy`) |
| `tcp` | raw TCP :443 to the DC |

```bash
# Media transfers over raw TCP only; everything else keeps the default ladder
tg-ws-proxy --pinned-media-upstream tcp

# Control traffic pinned to upstream MTProto proxies, media to the CF proxy
tg-ws-proxy --pinned-upstream mtproto --pinned-media-upstream cf

# Both classes over Tor via a SOCKS outbound proxy — the pins only pick tiers,
# the outbound proxy applies to every tier alike
tg-ws-proxy --outbound-proxy socks5h://127.0.0.1:9050 \
            --pinned-upstream tcp --pinned-media-upstream ws
```

Pin semantics:

- The listed order **is** the fallback chain: a tier that fails (connect
  error, cooldown) hands over to the next tier listed, with the same pool,
  cooldown and fronting behavior each tier has in the default ladder.
  Unpinned classes keep the default order above.
- A pin naming `cfworker`, `cfproxy` or `mtproto` with nothing configured
  behind it refuses to start (`--cf-worker-domain` / `--cf-domain` /
  `--default-domains` / `--mtproto-proxy`), because that class would
  otherwise drop every connection at runtime. `ws` is judged per connection
  instead — it is skipped with a log line for a DC without a `--dc-ip`
  target, since availability differs per DC.
- When every listed tier fails, the connection is **dropped** — the tiers
  left out are not quietly re-added as fallbacks. That is deliberate: if you
  pinned media to raw TCP so bulk transfers leave from a particular egress,
  silently rerouting them through Cloudflare on a bad day would undo the
  reason for the pin. List more tiers (or `tcp` last) if you want fallback
  breadth instead.
- `tcp` is terminal: the raw-TCP upstream is chosen without probing (the
  connect happens in the bridge), so anything listed after it is never
  reached — startup warns about a pin that does this.
- Pool warm-up is skipped for a class pinned without `ws`, since its bucket
  can never be used.

Note the split is by *connection*, not by individual packet: the proxy cannot
see inside the MTProto session, so "media" means "a connection to a media DC",
which is where Telegram clients put bulk transfers anyway.

## Cloudflare Proxy

When Telegram's IP ranges are blocked by your ISP, you can route WebSocket
traffic through Cloudflare using `--cf-domain`. This requires only a domain
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

# CF-first: pin the CF tiers in front of the default ladder
tg-ws-proxy --dc-ip 2:149.154.167.220 --cf-domain yourdomain.com \
            --pinned-upstream cfworker,cfproxy,ws,mtproto,tcp

# Or via environment variable
TG_CF_DOMAIN=yourdomain.com tg-ws-proxy
```

A `--dc-ip` address whose TCP connect *times out* is stepped over for
`--ip-fail-cooldown` seconds (default one hour) whenever a fallback tier is
configured, instead of costing every later connection another connect timeout.
A refused or redirected connection does not count — only a timeout, which is
what a DPI-blocked address looks like, and only at the full connect timeout
(not the short probe a DC in cooldown gets).

Stepped over, not written off: if every fallback tier is also failing, the
address is re-probed rather than leaving the client on raw TCP for the rest of
the window, and the first direct connect that succeeds clears the cooldown.

Every connection retries every configured CF domain fresh — a failure isn't
remembered across connections (matching upstream tg-ws-proxy), so one flaky
domain can never block the others, or the whole DC, from being tried.

### `--cf-balance` — round-robin load balancing

When multiple `--cf-domain` values are given, connections normally always start
with the first domain. Adding `--cf-balance` distributes connections evenly
across all configured CF domains using round-robin selection:

```bash
tg-ws-proxy --cf-domain d1.example.com,d2.example.com,d3.example.com --cf-balance
# connection 0 → tries d1, then d2, then d3
# connection 1 → tries d2, then d3, then d1
# connection 2 → tries d3, then d1, then d2
```

The remaining domains still serve as ordered fallbacks if the primary one
fails, so resilience is unchanged. Has no effect when only one CF domain is
configured. Can be combined with a CF-first pin:

```bash
# Round-robin CF load balancing, tried before direct WS
tg-ws-proxy --cf-domain d1.example.com,d2.example.com --cf-balance \
            --pinned-upstream cfworker,cfproxy,ws,mtproto,tcp
```

### One-time domain setup

Do this in the Cloudflare dashboard:

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

See [CfProxy.md](CfProxy.md) for full instructions.

## Cloudflare Worker

Cloudflare Worker mode is an alternative to `--cf-domain` when you do not own a
domain. Deploy the Worker script from [CfWorker.md](CfWorker.md), copy its
`*.workers.dev` domain, and pass it to the proxy:

```bash
tg-ws-proxy --cf-worker-domain random-symbols-1234.username.workers.dev
```

Multiple Worker domains are supported (comma-separated or repeated flag).
With `--cf-balance`, each new connection starts from a different Worker and
falls back to the remaining Workers if the first one fails.

```bash
tg-ws-proxy --cf-worker-domain w1.user.workers.dev,w2.user.workers.dev --cf-balance
```

Or via environment variable:

```bash
TG_CF_WORKER_DOMAIN=random-symbols-1234.username.workers.dev tg-ws-proxy
```

The Worker accepts an outer WebSocket connection from `tg-ws-proxy-rs`, opens a
raw TCP connection to the selected Telegram DC IP, and forwards WebSocket
message payloads as TCP bytes:

```
tg-ws-proxy-rs → wss://<worker>/apiws?dst=<dc-ip>&dc=<dc>&media=<0|1>
Cloudflare Worker → TCP <dc-ip>:443
```

For DCs with a configured direct WebSocket target, direct WS is tried first and
the Worker is used only after that path fails. For DCs without a direct WS
target, the Worker is tried before the regular Cloudflare proxy/default domains
and the remaining fallbacks.

## Default domains

Don't want to configure your own Cloudflare DNS zone? Use `--default-domains`
to automatically fetch a pre-configured, working list of CF proxy domains from
the upstream repository:

```bash
# No Cloudflare account or DNS setup required
tg-ws-proxy --default-domains

# Enable a CF-first pin so the CF path is tried first
tg-ws-proxy --default-domains --pinned-upstream cfworker,cfproxy,ws,mtproto,tcp

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
`--cf-domain` entries. If the fetch fails (network not yet available, GitHub
unreachable) the proxy falls back to a small built-in list and logs a warning —
it will still start normally.

> **Note:** These are community-maintained domains; availability may change
> over time. For maximum reliability, consider setting up your own Cloudflare
> zone (see [CfProxy.md](CfProxy.md)).

## Domain fronting

On networks where SNI-based DPI blocks Telegram, **domain fronting** presents
an unrelated, presumably-unblocked domain as the TLS SNI while still connecting
to the real Telegram DC IP and using the real DC domain as the HTTP `Host`.
DPI that filters by SNI sees the fronted name; the actual (TLS-encrypted)
request still reaches Telegram normally.

```bash
tg-ws-proxy --dc-ip 2:149.154.167.220 --fronting-domain sprinthost.ru
```

**Only takes effect when `--dc-ip` is configured for a DC** — this matches
upstream tg-ws-proxy exactly: fronting is purely a direct-connection technique
and is never applied to CF proxy, CF Worker, or upstream MTProto proxy
connections. If you rely solely on `--cf-domain`/`--default-domains` — the
common way to route around a block, and what suppresses the built-in `--dc-ip`
default — `--fronting-domain` has no effect, by design. Upstream's own guidance
for a network that blocks Telegram's IPs outright (where fronting can't help
either, since it still needs a real TCP connection to that IP) is to leave
`--dc-ip` unset entirely.

Disabled unless `--fronting-domain` is set. When set, fronting is
**unconditional**: every direct-WebSocket attempt — including pool pre-connects
— starts with the fronted SNI. An earlier version fronted reactively (real SNI
first, fronted retry after a timeout), which never worked on networks that
RST the real `telegram.org` SNI on sight: the leak happened before the retry
could help (#111). If a fronted attempt fails, it counts as a normal direct-WS
failure (`--ws-fail-cooldown`) and the ladder moves on.

> **Note:** TLS certificate verification is unconditionally skipped on
> fronted connections, regardless of `--danger-accept-invalid-certs` — the
> real Telegram certificate can never match a fronted SNI, so hostname
> verification would always fail. This is inherent to the technique, not a
> bug, and only applies to the direct-WS path (not CF proxy/Worker
> connections).

## Upstream MTProto proxy fallback

When WebSocket connections to Telegram are blocked, the proxy can route traffic
through an external MTProto proxy before falling back to direct TCP.

Pass one or more `--mtproto-proxy HOST:PORT:SECRET` flags (or a comma-separated
list in `TG_MTPROTO_PROXY`). Proxies are tried in the order given; if one fails
it enters a 60-second cooldown so subsequent connections skip it without delay.

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
> proxy which transport mode to use. **Copy the full secret as-is — prefix included:**
>
> | Prefix | Meaning | Example |
> |--------|---------|---------|
> | `dd` | Padded-intermediate transport | `ddabcdef1234567890abcdef1234567890` |
> | `ee` | FakeTLS (domain-fronting) transport | `ee` + 32 hex key chars + hex-encoded hostname |
> | *(none)* | Plain transport (legacy, 32 hex chars) | `abcdef1234567890abcdef1234567890` |
>
> In the `tg://proxy?server=...&secret=` link the `secret=` value already
> contains the correct prefix. Copy everything after `secret=` and pass it
> directly to `--mtproto-proxy`.

## Inbound FakeTLS listener

This one is about the *client-facing* side rather than a fallback tier. For
public home servers where DPI blocks raw inbound MTProto, enable inbound
FakeTLS:

```bash
tg-ws-proxy --host 0.0.0.0 --port 443 --listen-faketls-domain www.yandex.ru
```

This changes only the client-facing transport:

```
Telegram client → ee FakeTLS → tg-ws-proxy-rs → WSS/TLS → kws*.web.telegram.org
```

The proxy accepts the TLS ClientHello, validates the FakeTLS HMAC, sends a
synthetic TLS ServerHello, unwraps TLS Application Data records, and then passes
the recovered MTProto init into the existing WebSocket backend path.

## Outbound proxy

If the host running tg-ws-proxy-rs can reach the internet only through another
proxy, route all outgoing connections through `--outbound-proxy`:

```bash
tg-ws-proxy --outbound-proxy http://user:pass@192.168.1.1:3128
tg-ws-proxy --outbound-proxy socks5://user:pass@192.168.1.1:1080
tg-ws-proxy --outbound-proxy socks5h://user:pass@192.168.1.1:1080
```

`socks5://` resolves hostnames locally before sending the CONNECT request.
`socks5h://` sends the hostname to the SOCKS proxy and lets it resolve DNS
remotely. The setting applies to direct Telegram WS, Cloudflare proxy,
Cloudflare Worker, upstream MTProto proxies, direct TCP fallback, `--check`,
and the `--default-domains` fetch.

The same setting can be supplied through `TG_OUTBOUND_PROXY`. If it is not set,
standard `HTTPS_PROXY`, `ALL_PROXY`, `HTTP_PROXY` variables are used in that
order. `https://` proxy URLs from those standard environment variables are
ignored when a later supported fallback exists; an explicit
`--outbound-proxy https://...` remains an error.

Use `TG_OUTBOUND_PROXY=direct` (also accepts `none` or `off`) or
`--no-outbound-proxy` to disable environment proxy discovery explicitly. Use
`--no-proxy` / `TG_NO_PROXY` / `NO_PROXY` to bypass the proxy for specific
hosts. The bypass list follows standard `NO_PROXY` domain semantics: bare domain
entries such as `example.com` may match both `example.com` and subdomains such
as `api.example.com`. It also accepts `*`, suffix entries such as
`.example.com` or `*.example.com`, IP/CIDR entries such as `127.0.0.0/8`, and
bracketed IPv6 entries. Host and IP entries may include a port, for example
`example.com:443` or `[2001:db8::1]:443`; when a port is present, only that
target port bypasses the proxy.

```bash
TG_OUTBOUND_PROXY=socks5h://user:pass@192.168.1.1:1080 \
TG_NO_PROXY=localhost,127.0.0.1,127.0.0.0/8,.lan,example.com:443 \
tg-ws-proxy
```

# SOCKS5 input and Forkop

[Русская инструкция](Forkop.ru.md)

The optional SOCKS5 listener lets a local router service send Telegram **TCP
MTProto** connections into the existing WebSocket bridge. It runs alongside the
MTProto/FakeTLS listener, sharing the pool, connection limit, outbound connector
and configured fallback ladder. It does not create a TUN/netifd interface.
Any router service that can send selected TCP traffic to a SOCKS5 outbound can
use it; the steps below use Forkop, a sing-box-based OpenWrt routing service.

```text
Telegram (no app proxy) → Forkop / sing-box → 127.0.0.1:1080 SOCKS5
                                            → existing WSS / CF / fallback ladder
```

SOCKS input needs **v2.4.6 or newer**, for both the binary and the LuCI package;
the [one-line installer](../README.md#quick-install-one-liner) upgrades them
together. Editing UCI on an older installation does not add SOCKS support.

## Enable on OpenWrt

In **Services → Telegram WS Proxy (Rust) → General**, enable **SOCKS5 input**.
Keep **SOCKS5 listen address = 127.0.0.1** and **port = 1080**, then Save & Apply
and restart the service. Existing MTProto port/secret settings stay in place.
Equivalent SSH commands for an already installed/configured service:

```sh
uci set tg-ws-proxy-rs.main.socks_enabled='1'
uci set tg-ws-proxy-rs.main.socks_host='127.0.0.1'
uci set tg-ws-proxy-rs.main.socks_port='1080'
uci commit tg-ws-proxy-rs
/etc/init.d/tg-ws-proxy-rs restart
logread -e tg-ws-proxy-rs
```

Look for `SOCKS5 Telegram listener: 127.0.0.1:1080`. The page's **Connection
links** block lists every listener's links with a **Copy** button: the
`socks5://` URL for Forkop and, when SOCKS is bound beyond loopback, a
`tg://socks` link for Telegram apps. A bind failure (for example,
port already in use) fails service startup rather than pretending SOCKS is ready.
Both listeners share the same service enable/autostart setting.

CLI equivalents:

```sh
tg-ws-proxy --socks-enabled --socks-host 127.0.0.1 --socks-port 1080
```

| CLI | Environment | UCI |
| --- | --- | --- |
| `--socks-enabled` | `TG_SOCKS_ENABLED=true` | `socks_enabled '1'` |
| `--socks-host` | `TG_SOCKS_HOST` | `socks_host` |
| `--socks-port` | `TG_SOCKS_PORT` | `socks_port` |
| `--socks-dc` (repeatable or comma-separated) | `TG_SOCKS_DC` | `list socks_dc` |

There is no SOCKS username/password authentication. Keep loopback for Forkop on
the same router. To configure SOCKS directly in a LAN Telegram app, bind to the
router's LAN IP and use that IP and port in Telegram's SOCKS5 settings. Only trusted
LAN clients should reach it; no WAN port forwarding is needed.

## Configure Forkop

Start with one LAN computer and keep the old working route available for rollback.

1. Create a section named `telegram_ws`, action **Connection**, connection URL
   `socks5://127.0.0.1:1080` (no credentials). Do not enable Forkop's **Mixed Proxy**:
   that creates another listener, rather than using this one as an outbound.
2. Set **Device filter** to the test client's address, e.g. `192.168.1.171/32`.
   Do **not** use **Forced device routing**, which sends unrelated traffic here.
   Do not include the router's own addresses. This source restriction is important:
   locally generated WSS and TCP-fallback connections must not re-enter this section.
3. Match Telegram **DC IP traffic**, not every Telegram website/domain. The listener
   is not an HTTP proxy and cannot forward `t.me` or Telegram Web HTTPS. For a TCP-only
   match, use a custom source rule set such as the example below. In Forkop's rule-set
   settings enable subnet/IP matching (custom rule-set subnets may be ignored by default).
4. Make this section take precedence over existing routes matching the same client
   and destinations. Leave UDP/calls and Telegram web traffic on a suitable separate
   route (e.g. your existing VPN). Do not set this SOCKS outbound as the default route.
5. Disable the app's MTProto/SOCKS proxy for the transparent test, fully restart
   Telegram, then check messages, downloads and uploads. An app still using an MTProxy
   sends a secret-dependent transport, which this SOCKS entrance does not decode.

Example `/etc/forkop/telegram-ws.json` (a **small DC2 test list**, not all Telegram):

```json
{
  "version": 3,
  "rules": [{
    "network": "tcp",
    "ip_cidr": ["149.154.167.50/32", "149.154.167.51/32", "149.154.167.222/32"]
  }]
}
```

Select that local file in Forkop's **Rule sets** field. Extend `ip_cidr` to the
actual DC destinations used by your clients, using the built-in mapping in
[`src/inbound/socks.rs`](../src/inbound/socks.rs) or explicit mappings below. Do not infer a DC
from an entire Telegram subnet: different DCs can share a subnet.

If other broad rules also capture router-originated traffic, exclude the bridge's
outbound destinations from those rules or route them through a separate working
outbound. Never set this proxy's **Outbound proxy URL** back to its own SOCKS port.
A source-restricted test section avoids a loop without changing firewall marks.

The SOCKS request must contain the **real Telegram destination IP**, not a FakeIP
or hostname. For domain-based routing resolve to a real IP before sending to SOCKS
(Forkop has **Resolve real IP for routing**), and verify the resulting request.
Unrelated DNS and VPN settings do not need to change for this feature.

## Destination mapping and limitations

Built-in exact mappings cover common IPv4 DC1–5 and DC203 endpoints, media
included, and the IPv6 DC1–5 addresses the official clients ship with. Other
destinations, IPv6 media addresses among them, can be configured in **SOCKS5
destination DC mappings**:

```sh
# Example only: marks 203.0.113.10 as a DC2 media address.
uci add_list tg-ws-proxy-rs.main.socks_dc='-2:203.0.113.10'
uci commit tg-ws-proxy-rs
/etc/init.d/tg-ws-proxy-rs restart
```

A negative DC means a media connection. Explicit mappings override the built-in
map; the last mapping for an IP wins. They identify **client destinations**, unlike
`--dc-ip`, which changes **upstream** targets. Only add a mapping when you know the
correct DC; guessing can break authorization or media. Unknown destinations are
rejected, with no generic direct proxy fallback. The first attempt for each such
address is logged as a warning, and repeats at debug level, since Telegram retries
a refused DC every few seconds.

Supported: SOCKS5 no-auth CONNECT, IPv4/IPv6 addresses (including IP literals encoded
as SOCKS DOMAIN) on any destination port, MTProto abridged/intermediate/padded
intermediate, with or without secretless transport obfuscation. The port does not
matter: the bridge reaches the DC over its own routes. MTProto content
remains encrypted end-to-end; transport obfuscation is not message encryption.

Not supported: SOCKS UDP ASSOCIATE/BIND, arbitrary DNS names/web browsing,
MTProto Full/HTTP transport, inbound FakeTLS or MTProxy-secret traffic on the SOCKS
port. Calls are not provided by this TCP bridge.

SOCKS CONNECT is acknowledged after destination validation, before MTProto/WSS
negotiation, because Telegram waits for that acknowledgement before sending its
transport header. A subsequent upstream failure closes the tunnel. A successful
SOCKS reply alone therefore does not prove that Telegram or WSS works.

## Verify, troubleshoot, roll back

- Forkop should show the client's connection assigned to `telegram_ws`.
- Proxy logs must show the selected WS/CF route and transferred bytes. A successful
  app session using `TCP fallback` does not prove that the WSS route works.
- `has no DC mapping`: check the **real destination IP**, then add its known DC mapping.
  Each address is warned about once; enable debug logs to see every attempt.
- `unsupported MTProto transport`: enable debug logs; confirm the app proxy is off
  and that the traffic is native MTProto, not HTTPS/MTProxy or a call.
- Connection storm/zero data: inspect the device filter and outbound exclusions for
  a routing loop; disable the Forkop test section first.
- Latency checks aimed at a generic HTTP URL are not meaningful for this Telegram-only
  SOCKS service. Test with Telegram, not `curl https://example.com` through the proxy.

To roll back, first disable `telegram_ws` / restore the previous Telegram route,
then turn off **SOCKS5 input** and restart the service. Existing MTProto proxy clients
can keep using the original port. Restarting this shared service drops active sessions.

OpenWrt configuration backups normally include `/etc/config/tg-ws-proxy-rs` and
`/etc/config/forkop`. Include `/etc/forkop/telegram-ws.json` if using the example;
`/etc/forkop/` already covers it. A configuration backup does not reinstall binaries
and package dependencies: retain the matching build separately.

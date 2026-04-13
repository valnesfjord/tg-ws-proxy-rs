# Cloudflare Proxy

For data centres that are unreachable directly (e.g. Telegram IPs blocked by
your ISP), you can use an alternative free routing method: proxying through
Cloudflare.  **You only need a domain name.**  A default domain is built into
the application, but you can (and should) replace it with your own.

The proxy restores access to content that was not loading (reactions, certain
stickers).  If photos/videos were not loading on a non-premium account, remove
everything except `4:149.154.167.220` from the `DC -> IP` settings and check
whether the CF proxy fixes it.

## Why set up your own domain?

Cloudflare has limits on concurrent WebSocket connections per domain.  The
default domain can stop working at any time.

## Setting up your own domain

1. Add your domain to Cloudflare (either registered through them, or by
   changing the NS servers to Cloudflare's:
   <https://developers.cloudflare.com/dns/zone-setups/full-setup/setup/>).

2. In **SSL/TLS → Overview** set the mode to **Flexible**.

3. In **DNS → Records** import all records at once using the provided
   zone file:

   - Click **"Import DNS Records"** (or **Advanced → Import zone file**).
   - Upload [`cloudflare-dns-import.txt`](cloudflare-dns-import.txt).
   - After importing, **enable the orange cloud** (Proxy status →
     Proxied) for every imported record — zone file imports create
     DNS-only records by default.

   Alternatively, add the following `A` records manually via
   **+ Add Record**:

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

   Make sure the **orange cloud** (Proxy status) is **enabled** for each record.

4. If Cloudflare's own IP ranges are also blocked by your ISP, add your
   domain to [zapret](https://github.com/Flowseal/zapret-discord-youtube/)
   or another bypass tool.

5. Pass your domain to `tg-ws-proxy` via `--cf-domain`:

   ```sh
   tg-ws-proxy --cf-domain yourdomain.com
   ```

   Multiple domains can be specified as a comma-separated list.  They are
   tried in the order given (first domain has highest priority):

   ```sh
   tg-ws-proxy --cf-domain primary.net,backup.com
   ```

   Or set the environment variable:

   ```sh
   export TG_CF_DOMAIN=yourdomain.com
   tg-ws-proxy
   ```

## How it works

When `--cf-domain` is configured the proxy:

1. Tries the normal direct WebSocket connection to the Telegram DC first.
2. If that fails, connects to `kws{N}.{cf_domain}:443` and `kws{N}-1.{cf_domain}:443`
   (where `N` is the DC number) for each configured domain in order.
   DNS resolves to Cloudflare's anycast IP.
   Cloudflare terminates TLS and forwards the WebSocket traffic as plain HTTP
   to the origin (Flexible SSL mode) — which is Telegram's actual DC server.
3. If the CF proxy also fails, falls back to upstream MTProto proxies (if
   configured) and finally direct TCP.

When no `--dc-ip` is configured for a DC, the CF proxy is tried as the
**primary** path (before upstreams / TCP fallback).  If `--dc-ip` is omitted
entirely and `--cf-domain` is set, CF proxy becomes the primary path for
**all** DCs.

### `--cf-priority`

When `--cf-priority` is set, the CF proxy is tried **before** the normal
direct WebSocket connection for **all** DCs (even those with `--dc-ip`
configured).  If the CF proxy fails, the proxy falls back to the normal WS
path, then upstream MTProto proxies, then direct TCP.

```sh
tg-ws-proxy --dc-ip 2:149.154.167.220 --cf-domain yourdomain.com --cf-priority
```

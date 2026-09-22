# OpenWrt installation

OpenWrt uses the normal static musl binaries already published by this project.
The proxy binary is **not** wrapped in APK/IPK. Only the architecture-independent
LuCI and service integration is packaged:

- OpenWrt 25.12+: `luci-app-tg-ws-proxy-rs` APK (`noarch` metadata);
- OpenWrt 24.10: `luci-app-tg-ws-proxy-rs` IPK (`all` metadata).

Every installed path carries the `-rs` suffix. An unrelated upstream
`tg-ws-proxy` package owns the unsuffixed names on some routers, and this port
must never claim or overwrite them; see
[Upgrading from 2.2.3](#upgrading-from-223).

The single package recipe declares `PKGARCH:=all`. OpenWrt 25.12's package
backend converts that declaration to APK's native `noarch` metadata; the 24.10
backend keeps IPK's `all` metadata.

No installer or package script creates firewall rules or modifies
HomeProxy/nftables. Listening-port exposure and outbound routing remain explicit
administrator decisions.

## Installed files

The release binary is installed directly as:

```text
/usr/bin/tg-ws-proxy-rs
```

The archive itself holds `tg-ws-proxy`, the name the binary has on every other
platform and in existing scripts; only the OpenWrt integration renames it, so
that it cannot collide with the upstream package. `install.sh` does the rename.
Installing by hand means doing it yourself:

```sh
tar -xzf tg-ws-proxy-<target>.tar.gz -C /tmp
mv /tmp/tg-ws-proxy /usr/bin/tg-ws-proxy-rs
```

The LuCI/integration package owns:

```text
/etc/init.d/tg-ws-proxy-rs
/etc/config/tg-ws-proxy-rs
/usr/share/luci/menu.d/luci-app-tg-ws-proxy-rs.json
/usr/share/rpcd/acl.d/luci-app-tg-ws-proxy-rs.json
/usr/share/ucitrack/luci-app-tg-ws-proxy-rs.json
/www/luci-static/resources/view/tg-ws-proxy-rs/settings.js
```

`/etc/config/tg-ws-proxy-rs` is a conffile. Package upgrades preserve it. Secret
generation and legacy logging migration run from versioned OpenWrt installation
hooks or `install.sh`; the procd init script only reads UCI and starts the
process.

## Release assets

Each GitHub release contains the existing regular and UPX Linux musl archives
for these Rust targets:

- `aarch64-unknown-linux-musl`;
- `armv7-unknown-linux-musleabihf`;
- `armv7-unknown-linux-musleabi` — soft-float, for the ARMv7 cores OpenWrt
  builds without an FPU: `arm_cortex-a9` (bcm53xx) and `arm_cortex-a7`. The
  `musleabihf` binary dies with `SIGILL` there;
- `mips-unknown-linux-musl`;
- `mipsel-unknown-linux-musl`;
- `x86_64-unknown-linux-musl`.

It additionally contains one LuCI APK, one LuCI IPK and a shared `SHA256SUMS`
covering all twelve Linux archives and both LuCI packages. There are no core APKs,
core IPKs, per-router optimization wrappers or package feeds.

## Install or upgrade

Run on the router as root:

```sh
wget -qO- https://raw.githubusercontent.com/valnesfjord/tg-ws-proxy-rs/main/install.sh | sh
```

The regular binary is the default. UPX is an explicit choice because it saves
flash space at the cost of higher non-evictable runtime memory:

```sh
wget -qO- https://raw.githubusercontent.com/valnesfjord/tg-ws-proxy-rs/main/install.sh | \
  sh -s -- --upx
```

Install the latest beta, optionally with UPX:

```sh
wget -qO- https://raw.githubusercontent.com/valnesfjord/tg-ws-proxy-rs/main/install.sh | \
  sh -s -- --channel beta --upx
```

Environment equivalents are available for automation:

```sh
TG_WS_PROXY_RELEASE_CHANNEL=beta TG_WS_PROXY_UPX=1 sh install.sh
```

Set `TG_WS_PROXY_REPOSITORY=owner/repository` to test a fork release. Set
`GH_MIRROR=https://mirror.example` when GitHub release downloads need a mirror.
The mirror may provide payload files, but their expected immutable SHA-256
digests are always read from `api.github.com`.

The installer:

1. detects APK/opkg and maps `DISTRIB_ARCH` to the compatible Rust musl target;
2. selects the regular or `-upx` archive and the matching LuCI APK/IPK;
3. verifies both against the SHA-256 digests supplied by the GitHub release API;
4. extracts the archive and runs the staged binary with `--version` before
   touching the running service;
5. backs up the previous binary, UCI config and service state under
   `/root/tg-ws-proxy-backups/`;
6. installs the LuCI package, migrates a known manual `TG_*` configuration and
   atomically replaces `/usr/bin/tg-ws-proxy-rs`;
7. enables/restarts procd and verifies both the process and listening socket.

Only the three newest installer backup directories are retained after a
successful installation. Process command and environment snapshots are captured
only when importing a pre-existing manual installation without a UCI config.

If the new binary cannot start, the previous binary, UCI config and service state
are restored. A newly introduced LuCI package is removed as well. When an
already-installed LuCI package was upgraded, it remains upgraded because neither
APK nor opkg guarantees that the previous package artifact is locally available;
the installer reports this limitation instead of claiming a full package
rollback.

## Upgrading from 2.2.3

Release 2.2.3 installed `/usr/bin/tg-ws-proxy`, `/etc/init.d/tg-ws-proxy`,
`/etc/config/tg-ws-proxy` and the package `luci-app-tg-ws-proxy`. On a router
that also runs the unrelated upstream `tg-ws-proxy` package those names are
already taken: opkg refuses the install with `trying to overwrite
etc/config/tg-ws-proxy owned by tg-ws-proxy`, and since the installer writes the
binary itself, `/usr/bin/tg-ws-proxy` was replaced without the package manager
noticing. From 2.2.4 on, every installed path is suffixed with `-rs`.

`install.sh` moves an existing installation over when `luci-app-tg-ws-proxy` is
installed and no other package claims `/etc/init.d/tg-ws-proxy` or
`/etc/config/tg-ws-proxy`:

1. stops the 2.2.3 service, which binds the same port;
2. installs `luci-app-tg-ws-proxy-rs` plus the binary, then copies
   `/etc/config/tg-ws-proxy` to `/etc/config/tg-ws-proxy-rs` with the secret and
   every setting intact — after the package install, so that no APK/opkg
   conffile policy decides which copy survives;
3. verifies the process, the listening socket and the LuCI files;
4. only then removes `luci-app-tg-ws-proxy`, `/etc/config/tg-ws-proxy` and
   `/usr/bin/tg-ws-proxy`.

Failing anywhere before step 4 restores the 2.2.3 binary, config and service
state, and keeps the backup under `/root/tg-ws-proxy-backups/`.

Step 4 is skipped, with a message, in every case where removal could destroy
something the installer did not replace: a `/usr/bin/tg-ws-proxy` owned by
another package (reinstall that package if 2.2.3 overwrote its binary), a
package removal that fails, a `/etc/config/tg-ws-proxy` that was not carried
over because `/etc/config/tg-ws-proxy-rs` already existed, and a 2.2.3 process
that is still running — that last one could otherwise be the process holding the
listening port the readiness check just matched.

Nothing is migrated when `luci-app-tg-ws-proxy` is absent, because the
unsuffixed files are then either not package-managed or not this project's. To
carry a hand-managed configuration over, copy it before installing:

```sh
cp /etc/config/tg-ws-proxy /etc/config/tg-ws-proxy-rs
```

The LuCI page moves from **Services → Telegram WS Proxy** to
**Services → Telegram WS Proxy (Rust)**.

## Local assets

Put the archive, LuCI package and `SHA256SUMS` in one directory and copy them to
the router. Minimal images may lack SFTP, so stdin over SSH is reliable:

```bash
ROUTER=root@openwrt.lan
ARCHIVE=tg-ws-proxy-aarch64-unknown-linux-musl.tar.gz
LUCI=luci-app-tg-ws-proxy-rs-2.2.4-r1.apk # use the .ipk on OpenWrt 24.10

ssh "$ROUTER" "dd of=/tmp/$ARCHIVE 2>/dev/null" < "$ARCHIVE"
ssh "$ROUTER" "dd of=/tmp/$LUCI 2>/dev/null" < "$LUCI"
ssh "$ROUTER" 'dd of=/tmp/SHA256SUMS 2>/dev/null' < SHA256SUMS
ssh "$ROUTER" 'dd of=/tmp/install.sh 2>/dev/null' < install.sh
ssh "$ROUTER" "chmod 700 /tmp/install.sh && /tmp/install.sh \
  --archive /tmp/$ARCHIVE --luci-package /tmp/$LUCI"
```

`--dry-run`, `--arch` and `--package-manager` are available for deterministic
asset-resolution checks without installation.

## Package trust

The LuCI APK is intentionally installed with `--allow-untrusted`; this project
does not operate an APK signing-key lifecycle. The installer does not perform a
misleading strict-signature attempt first. Remote installation verifies the
immutable SHA-256 digest returned by the GitHub release API before invoking APK;
local installation uses the supplied `SHA256SUMS`. In this model, repository
control and GitHub API HTTPS are the source-authentication boundary. A download
mirror can supply an asset but cannot supply or override its expected digest.

IPK installation uses ordinary `opkg install`. Because the IPK contains only
architecture-independent integration files, no `--force-architecture` bypass is
required.

## Configure and operate

Open:

```text
Services → Telegram WS Proxy (Rust)
```

The page exposes UCI settings, status/control actions and a live filtered view of
the bounded OpenWrt `logd` ring buffer. The log-level selector maps to
`off|error|warn|info|debug|trace`; application debug/trace can be enabled without
turning on dependency-crate noise.

The status block shows the version `/usr/bin/tg-ws-proxy-rs --version` reports,
or says that the binary is missing or does not run on this router. A stopped
service whose TCP port is held by another program is reported as such, see
[Troubleshooting](#troubleshooting).

Example UCI changes:

```sh
uci set tg-ws-proxy-rs.main.enabled='1'
uci set tg-ws-proxy-rs.main.host='0.0.0.0'
uci set tg-ws-proxy-rs.main.port='3443'
uci set tg-ws-proxy-rs.main.outbound_proxy='socks5h://127.0.0.1:5330'
uci set tg-ws-proxy-rs.main.log_level='info'
uci commit tg-ws-proxy-rs
/etc/init.d/tg-ws-proxy-rs restart
```

The secret is persistent in `/etc/config/tg-ws-proxy-rs`; do not include that
file in public logs.

## Troubleshooting

### The service stays STOPPED and Start does not help

The proxy exits at once when its TCP port is already taken, and procd only sees
that it stopped. The LuCI status says when another program holds the port. Most
often that is the upstream `tg-ws-proxy` package, which listens on 1443 by
default as well. Stop and disable it, or move one of the two to another port:

```sh
/etc/init.d/tg-ws-proxy stop
/etc/init.d/tg-ws-proxy disable
```

### `apk add` fails with `breaks: world[…><Q1…]`

```text
ERROR: unable to select packages:
  tg-ws-proxy-0.9.3-r2:
    breaks: world[tg-ws-proxy><Q16ikvzQeX+6jdG5KlIoCXgdFp9jw=]
```

The package to fix is the one named in the error, not `luci-app-tg-ws-proxy-rs`.
`apk add ./file.apk` pins that exact file in `/etc/apk/world` (the `><Q1…`
part). Once the installed package no longer matches the pin, apk refuses every
transaction, whatever it was asked to install. Remove that package if it is not
needed:

```sh
apk del tg-ws-proxy
```

or keep it and drop the pin:

```sh
sed -i 's/^tg-ws-proxy><.*/tg-ws-proxy/' /etc/apk/world
```

## Uninstall

Remove the LuCI/integration package and the separately managed binary:

```sh
if command -v apk >/dev/null 2>&1; then
  apk del luci-app-tg-ws-proxy-rs
else
  opkg remove luci-app-tg-ws-proxy-rs
fi
rm -f /usr/bin/tg-ws-proxy-rs
```

Package-manager removal may preserve the modified UCI conffile. Delete it only
when its secret and settings are intentionally no longer needed.

## Build and validate the LuCI packages

Use the matching official SDK; no application binary is compiled or packaged:

```bash
openwrt/build-luci-package.sh \
  --sdk /path/to/openwrt-sdk-25.12.5 \
  --format apk

openwrt/build-luci-package.sh \
  --sdk /path/to/openwrt-sdk-24.10.5 \
  --format ipk
```

The script copies the single recipe into the SDK, invokes the normal OpenWrt
package target and validates package name, version and architecture metadata.
The stable package version is read from `Cargo.toml`; `--version` remains
available for release CI to supply APK/IPK-compatible beta versions.
Repository checks are:

```bash
shellcheck install.sh openwrt/build-luci-package.sh openwrt/luci-app/root/etc/init.d/tg-ws-proxy-rs \
  openwrt/luci-app/root/etc/uci-defaults/95_luci-tg-ws-proxy-rs openwrt/tests/*.sh
node --check openwrt/luci-app/htdocs/luci-static/resources/view/tg-ws-proxy-rs/settings.js
openwrt/tests/run.sh
```

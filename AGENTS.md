# AGENTS.md

Guidance for AI coding agents (and humans) working in this repository.

## What this project is

`tg-ws-proxy-rs` is a Rust port of [Flowseal/tg-ws-proxy](https://github.com/Flowseal/tg-ws-proxy): a local
MTProto proxy that tunnels Telegram Desktop traffic through WebSocket connections to Telegram's
data centers. It exists for networks where raw TCP to Telegram is blocked but WebSocket/HTTPS to
`web.telegram.org` still works (common in Russia and other censored networks).

At a high level: a Telegram client (Desktop, or any MTProto-speaking client) connects to this
proxy over plain MTProto (optionally disguised as FakeTLS). The proxy de-obfuscates the MTProto
transport frame, re-encrypts it for the target DC, and forwards it — preferring a WebSocket
tunnel to `wss://kwsN.web.telegram.org/apiws`, with Cloudflare-proxy, Cloudflare-Worker, upstream
MTProto proxy, and raw TCP as successive fallbacks.

## Repository layout

```
src/
  main.rs              Thin CLI wrapper: clap parse, tracing, then server::run
  server.rs            Process-level bind / banner / accept loop (shared by the binary and embedders)
  android.rs           JNI start/stop + log callback; compiled only for target_os = "android"
  config.rs            clap-derived Config struct; all CLI flags + TG_* env var fallbacks
  proxy.rs              Core per-connection logic: client handshake, DC routing, WS/CF/TCP fallback chain
  crypto.rs             MTProto obfuscated-transport crypto (AES-256-CTR key derivation, secret layout)
  faketls.rs            0xee FakeTLS camouflage: fake TLS 1.3 handshake for inbound + upstream proxies
  splitter.rs            Splits/reassembles MTProto transport frames from WebSocket message boundaries
  ws_client.rs           WebSocket client that dials Telegram DC endpoints (kwsN.web.telegram.org)
  pool.rs                Pre-warmed pool of idle WebSocket connections per DC (cuts handshake latency)
  check.rs               `--check` connectivity tester for CF domains and upstream MTProto proxies
  limits.rs              Connection cap derived from the process file-descriptor budget
  default_domains.rs      Fetches + deobfuscates the community CF-proxy domain list from GitHub
  runtime.rs              Shared runtime state (outbound connector, fronting window, DC metadata)
  outbound/               Outbound TCP connector: HTTP/SOCKS5(h) proxy support, NO_PROXY matching
  default_domains/http.rs  Minimal HTTPS GET used only to fetch the default domain list

tests/                   Integration tests (one file per subsystem, mirrors src/ module names)
tests/common/mod.rs      Shared integration fixtures (fake HTTP CONNECT proxy, proxy-connection driver)
docs/                    User-facing guides. README stays an overview and links here rather than growing:
                         Fallbacks.md (routing tiers), Building.md (cross-compiling, UPX), Deployment.md
                         (Docker, OpenWrt, env vars), CfProxy.md + CfWorker.md (Cloudflare setup),
                         Android.md (Compose app + NDK build)
android/                 Jetpack Compose app (Gradle catalog + build-logic convention; see docs/Android.md)
```

Modules whose *private* internals need testing keep a `#[cfg(test)] mod tests;` in a sibling
`src/<module>/tests.rs` file (see `proxy/`, `ws_client/`, `limits/`, `default_domains/`).  Anything
reachable through `src/lib.rs` is tested from `tests/` instead.

`src/lib.rs` re-exports the crate's internals so integration tests in `tests/` can exercise them
directly; almost all logic lives in the library, `main.rs` is a thin binary wrapper.

## Build, test, lint

```bash
cargo build                        # debug build
cargo test                         # unit + integration tests (tests/*.rs)
cargo clippy --all-targets         # CI runs this; keep it clean of new warnings
cargo fmt                          # run before committing — CI does not auto-format
cargo build --release              # CI also does a release build with LTO (see Cargo.toml profile)
```

CI (`.github/workflows/ci.yml`) additionally enforces that `Cargo.toml`'s `package.version` is
strictly greater than the base branch's version on every PR, and matches the git tag on release
builds. **Any change destined for `main` must bump the `version` field in `Cargo.toml`** (and let
`cargo build` regenerate the matching line in `Cargo.lock`) — the CI job `release-version` fails
the PR otherwise.

## Releases

Pushing a `v*` tag runs `.github/workflows/release.yml`, which needs nothing done by hand
afterwards — **but the release notes have to be in the commit being tagged.**

**Every PR that bumps the version also writes `docs/release-notes/<version>.md`** (no `v`, e.g.
`docs/release-notes/2.2.2.md`). `create-release` feeds that file to `parse-changelog` and uses the
result as the release body; `allow-missing-changelog` is left at `false`, so a missing or
misnamed file fails the release *after* the tag has been pushed. Two constraints on the file:

- **The heading must be a bare `# vX.Y.Z`.** `# tg-ws-proxy-rs v2.2.2` is not recognised as a
  version heading, and `prefix-format` does not fix it. The crate name lives in the workflow's
  `title:` input. Everything below the heading is the body verbatim, so `##` sections, tables and
  `<details>` blocks work — match the tone of the existing notes: what changed, why it matters,
  and honestly what it costs.
- **Check it before tagging** with `parse-changelog docs/release-notes/<version>.md <version>`,
  which prints exactly what the release will show.

If a version is bumped past without ever being tagged, **fold its notes into the new version's
file** rather than leaving both — only the tagged version's file is ever read, and the skipped
one's changes would silently go unannounced.

The release is created as a draft and published by the `publish-release` job only once every
asset (plain and UPX) has uploaded. A failed target therefore leaves a draft rather than a
half-populated public release: fix or re-run the failed leg, and the same draft is completed and
published. Anything in `release.yml` that addresses the release by tag name is addressing a draft
— `.github/workflows/release-dryrun.yml` rehearses those calls on pull requests, so add a
rehearsal there when adding one.

## Conventions to follow

- **CLI flags mirror env vars.** Every `#[arg(...)]` in `config.rs` has an `env = "TG_*"` fallback.
  New flags should follow the same pattern so Docker/systemd deployments stay config-file-free.
- **Module-level `//!` doc comments explain the *protocol/why*, not the *what*.** Look at the top
  of `crypto.rs`, `faketls.rs`, `splitter.rs`, `pool.rs` for the expected level of detail — they
  describe non-obvious protocol framing/timing reasons, not restate the code.
- **All outbound TCP connections go through `src/outbound/`.** Direct WS, Cloudflare, Cloudflare
  Worker, TCP fallback, `--check`, and the default-domain fetch all call into the shared outbound
  connector so proxy/NO_PROXY behavior stays consistent. Don't open a raw `TcpStream::connect`
  elsewhere.
- **Integration tests are organized by subsystem**, one file per `src/` module area (e.g.
  `tests/config.rs`, `tests/outbound.rs`, `tests/faketls.rs`). Add new tests to the matching file
  rather than creating a new one per feature. Fixtures shared across those files belong in
  `tests/common/mod.rs`, not duplicated per file.
- **This proxy runs on routers and other low-RAM devices.** Anything allocated per connection (relay
  buffers, splitter buffers, pooled sockets) is multiplied by every concurrent client, so prefer a
  fixed small buffer plus more syscalls over a large one. Per-connection work on the routing path
  should also avoid rebuilding lookup tables — see `Config::dc_target_ip` / `config::websocket_dc`
  versus the `HashMap`-returning helpers they replaced on that path.
- **No comments that restate code.** Only comment on non-obvious protocol constraints, timing
  workarounds, or invariants — consistent with the existing style throughout `src/`.
- Follow the general engineering discipline already in place in this repo: small, focused diffs;
  don't add abstractions or config knobs beyond what's needed for the task at hand.

## Gotchas specific to this codebase

- The MTProto transport and the WebSocket transport have different framing guarantees — see
  `splitter.rs`. Never assume one WebSocket message == one MTProto packet without going through
  the splitter. The one exception is the Cloudflare **Worker** tunnel: its far end is a raw TCP
  socket, so message boundaries mean nothing there and packet-aligning is actively harmful —
  Cloudflare drops WebSocket messages over 1 MiB, which a media upload's MTProto packets exceed.
  `proxy.rs`'s `WsFraming` is what keeps the two apart; add a new WebSocket upstream to the wrong
  arm and uploads break only for large files.
- `--host` auto-detection (`Config::bind_host`/`Config::link_host` in `config.rs`) intentionally
  keeps the bind address and the advertised `tg://` link address consistent. If you touch this
  logic, verify both by actually starting the binary (`cargo run -- --port <N>`) and reading the
  startup banner — a passing `cargo test` alone won't catch a bind/link mismatch a user would see.
- FakeTLS (`0xee` secrets) affects both the inbound listener (`--listen-faketls-domain`) and
  upstream MTProto proxies (`--mtproto-proxy` with an `ee`-prefixed secret) — they share
  `faketls.rs` but are configured independently; don't conflate the two when making changes.

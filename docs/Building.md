# Building

Pre-built binaries for every supported target are on the
[Releases](../../releases) page — this guide is for building your own.

## From source

```bash
# Debug build
cargo build

# Optimised release build
cargo build --release

# Static binary for Linux x86_64 (e.g. for Docker scratch images)
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
```

The binary lands in `target/release/tg-ws-proxy`, or
`target/<target>/release/tg-ws-proxy` when cross-compiling.

## Cross-platform builds with `cargo-zigbuild`

[`cargo-zigbuild`](https://github.com/rust-cross/cargo-zigbuild) uses the Zig
compiler as a drop-in C cross-linker, so you can build for every platform from
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

## Cross-compilation for OpenWrt

OpenWrt uses musl libc and runs on MIPS, ARM, and ARM64 CPUs. A fully static
Rust binary needs two things:

1. A C cross-compiler for your target (used by `ring`/`aws-lc-sys`)
2. The matching Rust target

`.cargo/config.toml` ships a commented-out `[target.*]` block per platform —
uncomment the one you need before building.

### ARM64 (aarch64) — e.g. GL.iNet MT6000, Banana Pi R4

```bash
apt-get install gcc-aarch64-linux-gnu
rustup target add aarch64-unknown-linux-musl
# Uncomment the aarch64 section in .cargo/config.toml
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

MIPS targets are tier-3 in Rust and have no pre-built `std`, so release CI
builds them on nightly with `-Z build-std=std,panic_abort` under
[`cross`](https://github.com/cross-rs/cross). Do the same locally if a plain
`cargo build` complains about a missing `std` for the target.

They also need two extra flags to come out static, because `crt-static` is not
their default the way it is for every other musl target:

```bash
RUSTFLAGS="-C target-feature=+crt-static -C link-self-contained=no" \
cross +nightly build --release --bin tg-ws-proxy \
  --target mipsel-unknown-linux-musl -Z build-std=std,panic_abort
```

`link-self-contained=no` is the non-obvious half. Turning on `crt-static` alone
makes rustc reach for `crt1.o`/`crti.o`/`crtn.o` from the `self-contained`
directory that ships with `rust-std` — which tier-3 targets do not have and
`-Z build-std` does not produce, so the link fails on missing files. Handing
that job back to gcc fixes it, and then leaves rustc asking the linker for
`-lunwind`: the LLVM unwinder, where these GCC toolchains carry `libgcc_eh.a`.
`Cross.toml` in the repo root aliases one to the other in the container. A
toolchain of your own needs the same alias somewhere on its library path.

Verify the result rather than assuming it — `readelf -d` should print no
`NEEDED` entries at all:

```bash
readelf -d target/mipsel-unknown-linux-musl/release/tg-ws-proxy | grep NEEDED
```

### Using `cross` (easier alternative)

[`cross`](https://github.com/cross-rs/cross) uses Docker to manage toolchains,
so you don't need any host cross-compiler:

```bash
cargo install cross
cross build --release --target aarch64-unknown-linux-musl
```

## Shrinking the binary for flash-constrained devices

A release build is around 4.8 MB, which is a lot on a router with 8 or 16 MB of
flash. The releases page carries a `-upx` variant of every Linux musl asset
(`tg-ws-proxy-<target>-upx.tar.gz`) for exactly this case — on mipsel that is
**4.85 MB → 1.43 MB**, a 70% cut.

To pack a binary you built yourself:

```bash
upx -9 --lzma target/mipsel-unknown-linux-musl/release/tg-ws-proxy
upx -t      target/mipsel-unknown-linux-musl/release/tg-ws-proxy   # verify
```

Use **UPX 4.2.4**, not the latest, for router targets. Every 5.x unpacking stub
calls `memfd_create` before anything else, which needs Linux 3.17 or newer, and
router firmwares ship much older kernels — there a 5.x-packed binary dies with
`Trace/breakpoint trap` before the proxy's first instruction. 4.2.4 works
through `/proc/self/exe` and `mmap` instead and packs to the same ratio, which is
why the `-upx` assets on the releases page are built with it. `upx -t` unpacks in
memory and compares, so it passes on either version and will not catch this.

### The trade-off

UPX buys flash with RAM. A normal ELF maps its code straight from the file, so
only the pages actually touched are resident and the kernel can evict them
under pressure and re-read them later. The UPX stub instead decompresses the
entire image into anonymous memory at startup — nothing is file-backed, and a
router has no swap to page it out to, so it stays resident for the life of the
process.

| | Plain build | UPX `-9 --lzma` |
|---|---|---|
| Flash | ~4.8 MB | ~1.4 MB |
| RSS | ~3–5 MB (working set, evictable) | roughly +4 MB on top, permanently resident |
| Startup | instant | one LZMA decompression, ~1 s on a slow MIPS CPU |
| Throughput | unchanged | unchanged |

So it is a good trade on a device with plenty of RAM and little flash, and a
bad one on a 32 MB-RAM device — which is why the packed builds ship as separate
assets rather than replacing the normal ones.

If the startup delay bothers you more than the last few hundred KB, drop
`--lzma`: plain `-9` decompresses several times faster for about 5–8% more
size.

**Not for Windows or macOS.** UPX-packed PE files trip antivirus heuristics,
which is a real problem for a tool of this kind, and packing a Mach-O
invalidates its code signature — arm64 macOS then refuses to run it at all.

### Why not `opt-level = "z"`?

Optimising for size is the obvious alternative, and it does shrink the binary
by roughly a third. But it costs throughput on exactly the machines that need
the flash: every relayed byte is decrypted with the client's key and
re-encrypted with the DC's key, and MIPS/ARMv7 have no AES instructions, so
that runs on the `aes` crate's software backend.

Measured on that software backend (`--cfg aes_force_soft`, the same code path a
router executes):

| Profile | AES-256-CTR relay throughput | Binary size |
|---|---|---|
| `opt-level = 3` (shipped) | ~135 MiB/s | baseline |
| `opt-level = "z"` | ~103 MiB/s | −34% |

A quarter of the proxy's throughput for a third of the size is a worse deal
than UPX's, which gives 70% for no steady-state cost at all. The release
profile therefore stays at `opt-level = 3`, and `panic = "abort"` is left off
for a similar reason: it would save about 18%, but today a panic while parsing
a malformed connection is caught by the tokio runtime and kills only that
connection, whereas with `abort` it would take down the proxy for every
connected user.

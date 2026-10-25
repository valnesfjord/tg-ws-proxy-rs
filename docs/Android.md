# Android app

A minimal Jetpack Compose wrapper around the same core the CLI runs. Type the
flags you would pass to `tg-ws-proxy`, tap **Start**, and when the `tg://proxy`
link appears tap it (or let the app open it) to add the proxy in Telegram.

The listen address should be `127.0.0.1` so Telegram on the same phone can
connect.

Add `--secret <32 hex chars>` if you want the link to stay the same across
restarts. `--log-file` is ignored; logs go to the on-screen view and logcat
(`tg-ws-proxy`).

The default arguments carry `--quiet`, so the on-screen **Log** panel stays
empty until you remove it. That is the default and not a failed start: drop
`--quiet` (or swap it for `--verbose`) before tapping **Start** to see log
lines. The `tg://` link appears either way — it reaches the UI from the listen
callback rather than by scraping the log, so `--quiet` never hides it.

## Quick Settings tile

Pull down the notification shade, open the tile editor (the pencil icon) and
drag **TG WS Proxy** into the active tiles. Tapping it starts or stops the
proxy with the arguments last saved in the app, so set them up there once.
The tile shows the same running state as the app's Start/Stop button.

If the system refuses to start the proxy from the tile (some vendor builds
restrict starting a foreground service outside the app), the tile opens the
app instead, and **Start** there works as usual.

## Requirements

- JDK 17+ already on `PATH`. The Gradle wrapper downloads *Gradle*, not a JDK:
  there is no toolchain block and no foojay resolver in this build, so a missing
  or older JDK fails the build instead of provisioning one.
- Android SDK at `ANDROID_HOME`, `ANDROID_SDK_ROOT`, or `~/Android/Sdk`
  (compile SDK 37)
- The Android NDK version pinned in `android/gradle/libs.versions.toml`
  (currently `28.1.13356709`) under `$ANDROID_HOME/ndk/`, or set
  `ANDROID_NDK_HOME` / `ANDROID_NDK` to an explicit NDK directory
- Rust with `rustup` and `cargo` on `PATH`
- To run it: a device or emulator on Android 8.0 (API 26) or newer. That is the
  app's `minSdk`, set from `android/gradle/libs.versions.toml`, and it is a hard
  floor — the released APKs refuse to install below it.

Gradle installs the required Rust targets with `rustup target add` as part of
its native build task. Unless `ANDROID_NDK_HOME` or `ANDROID_NDK` is set, it
uses exactly the NDK version pinned in the version catalog and fails with the
required `sdkmanager --install` command when that version is absent.

The app's `versionName` and base `versionCode` come from `Cargo.toml`, the
repo's single source of truth (CI enforces a version bump on every PR). Update
`package.version` and `package.metadata.android.version_code` together. The
base code must be `(MAJOR*10000 + MINOR*100 + PATCH)*10`; the
`tgwsproxy.android` convention plugin validates that relationship and adds the
per-ABI offset: `0` for universal, `1` for armeabi-v7a, `2` for arm64-v8a, and
`3` for x86_64.

Do not add XML comments to `android/app/src/main/AndroidManifest.xml`. An A/B
build of the same commit confirmed that AGP's manifest merger can format a
comment differently between GitHub Actions and the F-Droid buildserver. The
decoded manifests remain identical, but the shifted source line numbers in the
binary AXML make the APKs differ byte for byte. Put explanations in this guide
or beside the code that enforces the manifest setting instead.

Plugin, SDK and AndroidX versions live in `android/gradle/libs.versions.toml`.
The Cargo NDK task, version mapping and release signing live under
`android/build-logic/` so `android/app/build.gradle.kts` stays the module identity
and dependencies.

## Build

From the repository root on Linux/macOS:

```sh
cd android
./gradlew :app:assembleDebug
```

From Windows PowerShell or `cmd.exe`:

```bat
cd android
gradlew.bat :app:assembleDebug
```

The Gradle `:app:cargoNdk` task cross-compiles `libtg_ws_proxy_jni.so` first and
puts generated libraries under `android/app/build/generated/rustJniLibs`. The
debug APKs land in `android/app/build/outputs/apk/debug/`: one per ABI
(`app-arm64-v8a-debug.apk`, `app-armeabi-v7a-debug.apk`, `app-x86_64-debug.apk`)
plus `app-universal-debug.apk`, which carries every ABI at roughly three times
the size. `output-metadata.json` in the same directory lists what was written.

The embedded native library is built in release mode even for a debug APK. A
debug `.so` is roughly 90 MB per ABI and too slow for normal proxy use. Override
with `TG_ANDROID_RUST_PROFILE=debug` if you need native debug symbols.

`TG_ANDROID_API` (default 26) selects the NDK clang wrapper the cross-compile
runs — `aarch64-linux-android<API>-clang` and its siblings — and so is the API
level the native library itself is built against. The convention plugin reads
it; it is *not* wired to `minSdk`, which lives in
`android/gradle/libs.versions.toml`. Raise the two together or not at all: a
`.so` built against a newer API can bind symbols that the older devices
`minSdk` still admits do not have, and that failure only appears on the device.

Build only the native libraries:

```sh
cd android
./gradlew :app:cargoNdk
```

Release (R8-minified and resource-shrunk, so `NativeProxy`'s keep rule in
`proguard-rules.pro` is exercised; unsigned unless you add a signing config —
see below):

```sh
cd android
./gradlew :app:assembleRelease
```

The outputs are the same per-ABI plus universal set under
`android/app/build/outputs/apk/release/`, named `app-<abi>-release-unsigned.apk`
unless a keystore is configured and `app-<abi>-release.apk` when one is.

## Signing a release

A release APK is only signed when a keystore is configured. Put the path and
secrets in `android/keystore.properties` (gitignored, never commit it):

```properties
storeFile=/home/user/keystore.jks
storePassword=change-me
keyAlias=tgwsproxy
keyPassword=change-me
```

The same values can be passed as the environment variables
`TG_ANDROID_STORE_FILE`, `TG_ANDROID_STORE_PASSWORD`, `TG_ANDROID_KEY_ALIAS`
and `TG_ANDROID_KEY_PASSWORD`, which is how a deploy pipeline signs without
checking in a properties file. A value set in `keystore.properties` wins over
the matching environment variable; with neither, `assembleRelease` produces an
unsigned APK as before. With one configured the outputs are the same per-ABI
plus universal set, written as `app-<abi>-release.apk` — the `-unsigned` suffix
AGP appends is simply gone. There has been no single `app-release.apk` since
the ABI splits landed.

Generate a keystore once and keep it backed up. Android identifies an installed
app by its package name *and* its signing key, and it accepts an update only
when the key matches, so replacing the key later means every existing install
has to be removed and reinstalled — taking its saved arguments with it. (The
`tg://proxy` link has no part in this: it carries a host, a port and a secret,
and nothing about the app that printed it.)

## Deploy

Use the Android Gradle Plugin install tasks instead of a separate deploy script.
With one device or emulator connected:

```sh
cd android
./gradlew :app:installDebug
```

On Windows, use `gradlew.bat` with the same task names. `installRelease` is
registered only when a keystore is configured (unsigned release APKs cannot
be installed).

Limit native and packaged ABIs with `TG_ANDROID_ABIS`; names may be separated by
spaces or commas:

```sh
cd android
TG_ANDROID_ABIS=arm64-v8a ./gradlew :app:assembleDebug
TG_ANDROID_ABIS=arm64-v8a,x86_64 ./gradlew :app:cargoNdk
```

The supported ABI names are `arm64-v8a`, `armeabi-v7a`, `x86_64`, and `x86`.
The APK default remains `arm64-v8a`, `armeabi-v7a`, and `x86_64`. The split set
follows the same list, so `TG_ANDROID_ABIS=arm64-v8a` yields exactly
`app-arm64-v8a-debug.apk` and a universal APK holding only that one ABI.

## CI

Two jobs in `.github/workflows/ci.yml` cover the app, on every pull request and
on pushes to `main` and to release tags.

**`android` — it builds.** Assembles both the debug and the release APKs
(release additionally runs R8, which is what exercises `NativeProxy`'s keep rule
in `proguard-rules.pro`), uploads them as build artifacts, and runs the Gradle
wrapper JAR checksum validation via `gradle/actions/setup-gradle`. Two shape
checks follow the build, because both things they look for fail silently:

- *the split APK set* — a `splits` block that stopped applying still yields one
  perfectly valid fat APK, and a split for an ABI that was never cross-compiled
  still yields a perfectly valid APK with an empty `lib/`. The job asserts the
  four expected outputs exist and that each carries exactly the
  `libtg_ws_proxy_jni.so` set its name claims. Keep its ABI list in sync with
  `AndroidAbi.defaultAbis`.
- *the packaged JNI symbols* — a JNI entry point binds by name at the first
  call, not at link time, so the Kotlin package and the hand-written `Java_…`
  symbols in `crates/android-jni/src/android.rs` are a contract nothing in the
  build enforces. The job derives the mangled names from `android.namespace`,
  checks them against the shipped `.so`'s `.dynsym`, and checks
  `NATIVE_CLASS_NAME` and the four R8-kept callbacks against the packaged dex.

**`android-emulator` — it runs.** A matrix over API 26 (the `minSdk` floor, and
the only level that takes `ProxyService`'s pre-O notification-channel and
pre-34 foreground-service-type branches) and API 36 (`targetSdk`: `specialUse`
foreground-service enforcement and the `POST_NOTIFICATIONS` path). It pins
`TG_ANDROID_ABIS=x86_64` at job level and runs the connected suite through
`.github/scripts/run-connected-tests.sh` — a script file rather than inline
`script:` lines, because the emulator action wraps each line in its own
`sh -c`. The suite is `android/app/src/androidTest/`: the JNI contract tests and
the `nativeStop()` ANR regression. A final step hashes the APK the device was
actually given against the build's own outputs, so a green run cannot mean the
emulator quietly installed the universal APK instead of the per-ABI split the
symbol checks are about.

Both jobs pin the NDK because the hosted runner images swap their installed NDK
without notice. The pin has one source of truth: the `ndk` entry in
`android/gradle/libs.versions.toml`. CI, release builds, the convention plugin,
and the F-Droid recipe all read that value, so bumping the NDK means editing
that one line.

The Rust toolchain comes from `dtolnay/rust-toolchain`, and `Swatinem/rust-cache`
keeps the Android cross-compile outputs across runs, under a separate key per
job so the two ABI sets cannot evict each other.

The `android` job in `.github/workflows/release.yml` attaches the whole APK set
to every release, named `tg-ws-proxy-rs-android-<version>-<abi>.apk` — the
`-android-` is there because the OpenWrt LuCI packages on the same release page
are also called `.apk`. It runs beside `upload-assets` rather than after it, and
`publish-release` waits on it, so a failed APK build leaves the release a draft
instead of publishing one without an APK.

Signing is optional and off by default. With none of the secrets below set, the
job still succeeds and uploads
`tg-ws-proxy-rs-android-<version>-<abi>-unsigned.apk`, which Android will not
install without `adb install` and a manual signature — that is the current state
of this repository. To ship signed APKs, create four repository secrets:

| Secret | Value |
| --- | --- |
| `TG_ANDROID_KEYSTORE_BASE64` | the keystore itself, base64-encoded: `base64 -w0 keystore.jks` on Linux, `base64 -i keystore.jks` on macOS |
| `TG_ANDROID_STORE_PASSWORD` | `storePassword` |
| `TG_ANDROID_KEY_ALIAS` | `keyAlias` |
| `TG_ANDROID_KEY_PASSWORD` | `keyPassword` |

`TG_ANDROID_STORE_FILE` is deliberately not a secret: it is a path, and the
workflow computes it when it decodes the keystore into the runner's temporary
directory (mode 600, deleted when the job ends).

## What the core change is

`src/server.rs` is the accept loop that used to live only in `main.rs`. The
Android JNI module is its own crate, `crates/android-jni` (compiled only for
`target_os = "android"`), which parses the text field with
`Config::try_from_cli_line` and runs that loop on a background Tokio runtime.
Stop completes a watch channel, which breaks the accept loop.

It is a separate crate and not a `cdylib` on the root library because
`crate-type` is a per-package setting: with the shim in the root crate every
desktop and Docker `cargo build` also linked an `.so` nobody loads. The
workspace's `default-members` is the root package alone, so `cargo
build`/`test`/`clippy` at the repository root never touch it; `:app:cargoNdk`
selects it with `cargo build -p tg-ws-proxy-jni --lib`.

The proxy keeps running in a foreground service so Android does not kill it
when you switch to Telegram.

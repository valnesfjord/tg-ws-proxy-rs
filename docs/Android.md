# Android app

A minimal Jetpack Compose wrapper around the same core the CLI runs. Type the
flags you would pass to `tg-ws-proxy`, tap **Start**, and when the `tg://proxy`
link appears tap it (or let the app open it) to add the proxy in Telegram.

The listen address should be `127.0.0.1` so Telegram on the same phone can
connect.

Add `--secret <32 hex chars>` if you want the link to stay the same across
restarts. `--log-file` is ignored; logs go to the on-screen view and logcat
(`tg-ws-proxy`).

## Requirements

- JDK 17+ (the Gradle wrapper downloads a toolchain if needed)
- Android SDK at `ANDROID_HOME`, `ANDROID_SDK_ROOT`, or `~/Android/Sdk`
  (compile SDK 37)
- Android NDK (r27 or newer under `$ANDROID_HOME/ndk/`, or set
  `ANDROID_NDK_HOME` / `ANDROID_NDK`)
- Rust with `rustup` and `cargo` on `PATH`

Gradle installs the required Rust targets with `rustup target add` as part of
its native build task. If more than one NDK is installed under the SDK, the
newest version directory is used unless `ANDROID_NDK_HOME` or `ANDROID_NDK` is
set.

The app's `versionName` and `versionCode` come from `Cargo.toml`, the repo's
single source of truth (CI enforces a bump on every PR): `MAJOR*10000 +
MINOR*100 + PATCH`. Never hand-edit those values; they are wired by the
`tgwsproxy.android` convention plugin. Bump `Cargo.toml` instead.

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

The Gradle `:app:cargoNdk` task cross-compiles `libtg_ws_proxy_rs.so` first and
puts generated libraries under `android/app/build/generated/rustJniLibs`. The
debug APK lands at `android/app/build/outputs/apk/debug/app-debug.apk`.

The embedded native library is built in release mode even for a debug APK. A
debug `.so` is roughly 90 MB per ABI and too slow for normal proxy use. Override
with `TG_ANDROID_RUST_PROFILE=debug` if you need native debug symbols.

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

The output is `android/app/build/outputs/apk/release/app-release-unsigned.apk`
unless a keystore is configured.

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
unsigned APK as before. The signed APK lands at `app-release.apk`.

Generate a keystore once and keep it backed up; Telegram proxy links reference
the app by package name, and a Play-Store-style upgrade keeps the signing key,
so replacing the key later means an uninstall/reinstall.

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
The APK default remains `arm64-v8a`, `armeabi-v7a`, and `x86_64`.

## CI

The `android` job in `.github/workflows/ci.yml` builds both the debug and
release APKs on every push and pull request, uploads them as build artifacts,
and runs the Gradle wrapper JAR checksum validation via
`gradle/actions/setup-gradle`. It pins the NDK (`28.1.13356709`) because the
hosted runner images swap their single installed NDK without notice; update
both the `sdkmanager --install` line and the `ANDROID_NDK_HOME` export together
if you bump the pin. The Rust toolchain comes from `dtolnay/rust-toolchain`,
and `Swatinem/rust-cache` keeps the Android cross-compile outputs across runs.

The release pipeline does not publish an APK; the signing key is
maintainer-held, so a signed APK is produced manually with the instructions
above.

## What the core change is

`src/server.rs` is the accept loop that used to live only in `main.rs`. The
Android JNI module (`src/android.rs`, compiled only for `target_os = "android"`)
parses the text field with `Config::try_from_cli_line` and runs that loop on a
background Tokio runtime. Stop completes a watch channel, which breaks the
accept loop.

The proxy keeps running in a foreground service so Android does not kill it
when you switch to Telegram.

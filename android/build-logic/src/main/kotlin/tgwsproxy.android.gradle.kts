import com.android.build.api.dsl.ApplicationExtension
import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import org.jetbrains.kotlin.gradle.dsl.KotlinAndroidProjectExtension
import tgwsproxy.gradle.AndroidAbi
import tgwsproxy.gradle.CargoNdkBuildTask
import tgwsproxy.gradle.cargoAppVersion
import tgwsproxy.gradle.releaseSigning
import java.io.File

// Cargo NDK, Cargo.toml versioning, and optional release signing live here so
// :app's build script can stay the module identity + dependencies.

val libs = extensions.getByType<VersionCatalogsExtension>().named("libs")
val repositoryRoot = layout.settingsDirectory.dir("..")
val generatedJniLibsDir = layout.buildDirectory.dir("generated/rustJniLibs")

// Native code is always release unless TG_ANDROID_RUST_PROFILE=debug because a
// debug libtg_ws_proxy_rs.so is roughly 90 MB per ABI and too slow for a proxy.
val rustProfileProvider = providers.environmentVariable("TG_ANDROID_RUST_PROFILE").orElse("release")
val rustAbisProvider = providers.environmentVariable("TG_ANDROID_ABIS")
    .map { value -> value.split(Regex("[,\\s]+")).filter(String::isNotBlank) }
    .orElse(AndroidAbi.defaultAbis)
val androidApiProvider = providers.environmentVariable("TG_ANDROID_API")
    .map(String::toInt)
    .orElse(26)
val androidSdkRootProvider = providers.environmentVariable("ANDROID_HOME")
    .orElse(providers.environmentVariable("ANDROID_SDK_ROOT"))
    .orElse(providers.provider { File(System.getProperty("user.home"), "Android/Sdk").absolutePath })
val androidNdkRootProvider = providers.environmentVariable("ANDROID_NDK_HOME")
    .orElse(providers.environmentVariable("ANDROID_NDK"))
    .orElse("")

// The app version always tracks Cargo.toml, the repo's single source of truth
// (CI bumps it on every PR). Keep versionCode deterministic and collision-free
// for any X.Y.Z: MAJOR*10000 + MINOR*100 + PATCH.
val cargoVersion = providers.cargoAppVersion(repositoryRoot.file("Cargo.toml"))

// Release signing. Keep android/keystore.properties out of version control and
// fill in storeFile/storePassword/keyAlias/keyPassword; CI and scripts can pass
// the same values as the TG_ANDROID_STORE_FILE / TG_ANDROID_STORE_PASSWORD /
// TG_ANDROID_KEY_ALIAS / TG_ANDROID_KEY_PASSWORD environment variables. With no
// keystore configured the release APK is left unsigned, as before. Providers
// are used (not System.getenv) so the configuration cache invalidates when the
// keystore or environment changes.
val signing = providers.releaseSigning(layout.settingsDirectory.file("keystore.properties"))

val cargoNdk = tasks.register<CargoNdkBuildTask>("cargoNdk") {
    group = "build"
    description = "Cross-compile libtg_ws_proxy_rs.so into generated Android jniLibs"
    repoRoot.set(repositoryRoot)
    rustSources.set(repositoryRoot.dir("src"))
    cargoToml.set(repositoryRoot.file("Cargo.toml"))
    cargoLock.set(repositoryRoot.file("Cargo.lock"))
    cargoConfig.fileProvider(
        providers.provider {
            repositoryRoot.file(".cargo/config.toml").asFile.takeIf(File::isFile)
        },
    )
    jniLibsDir.set(generatedJniLibsDir)
    profile.set(rustProfileProvider)
    abis.set(rustAbisProvider)
    apiLevel.set(androidApiProvider)
    androidSdkRoot.set(androidSdkRootProvider)
    androidNdkRoot.set(androidNdkRootProvider)
}

pluginManager.withPlugin("com.android.application") {
    extensions.configure<ApplicationExtension>("android") {
        compileSdk = libs.findVersion("compileSdk").get().requiredVersion.toInt()

        defaultConfig {
            minSdk = libs.findVersion("minSdk").get().requiredVersion.toInt()
            targetSdk = libs.findVersion("targetSdk").get().requiredVersion.toInt()
            versionCode = cargoVersion.versionCode.get()
            versionName = cargoVersion.versionName.get()
            ndk {
                abiFilters += rustAbisProvider.get()
            }
        }

        sourceSets.named("main") {
            jniLibs.directories.clear()
            jniLibs.directories.add(generatedJniLibsDir.get().asFile.absolutePath)
        }

        if (signing.isConfigured.get()) {
            signingConfigs.register("release") {
                storeFile = File(signing.storeFile.get())
                storePassword = signing.storePassword.get()
                keyAlias = signing.keyAlias.get()
                keyPassword = signing.keyPassword.get()
            }
        }

        buildTypes.named("release") {
            // R8 strips the NativeProxy callbacks only if told not to; the
            // native side reaches them by class name. See proguard-rules.pro.
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
            if (signing.isConfigured.get()) {
                signingConfig = signingConfigs.getByName("release")
            }
        }

        compileOptions {
            sourceCompatibility = JavaVersion.VERSION_17
            targetCompatibility = JavaVersion.VERSION_17
        }

        buildFeatures {
            compose = true
        }
    }

    tasks.named("preBuild") {
        dependsOn(cargoNdk)
    }
}

pluginManager.withPlugin("org.jetbrains.kotlin.plugin.compose") {
    extensions.configure<KotlinAndroidProjectExtension>("kotlin") {
        compilerOptions {
            jvmTarget.set(JvmTarget.JVM_17)
        }
    }
}

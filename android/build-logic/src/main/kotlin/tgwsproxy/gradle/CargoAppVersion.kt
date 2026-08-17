package tgwsproxy.gradle

import org.gradle.api.GradleException
import org.gradle.api.file.RegularFile
import org.gradle.api.provider.Provider
import org.gradle.api.provider.ProviderFactory

class CargoAppVersion(
    val versionName: Provider<String>,
    val versionCode: Provider<Int>,
)

fun ProviderFactory.cargoAppVersion(cargoToml: RegularFile): CargoAppVersion {
    val parts = fileContents(cargoToml).asText.map { text ->
        Regex("""^version\s*=\s*"(\d+)\.(\d+)\.(\d+)"""", RegexOption.MULTILINE)
            .find(text)
            ?.groupValues
            ?.drop(1)
            ?: throw GradleException("could not parse package.version from Cargo.toml")
    }
    return CargoAppVersion(
        versionName = parts.map { it.joinToString(".") },
        versionCode = parts.map { versionParts ->
            val (major, minor, patch) = versionParts.map(String::toInt)
            major * 10000 + minor * 100 + patch
        },
    )
}

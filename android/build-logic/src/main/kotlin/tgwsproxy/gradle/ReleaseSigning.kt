package tgwsproxy.gradle

import org.gradle.api.file.RegularFile
import org.gradle.api.provider.Provider
import org.gradle.api.provider.ProviderFactory
import java.util.Properties

class ReleaseSigning(
    val storeFile: Provider<String>,
    val storePassword: Provider<String>,
    val keyAlias: Provider<String>,
    val keyPassword: Provider<String>,
    val isConfigured: Provider<Boolean>,
)

fun ProviderFactory.releaseSigning(
    keystorePropertiesFile: RegularFile,
): ReleaseSigning {
    val keystoreProperties = fileContents(keystorePropertiesFile).asText.map { text ->
        Properties().apply {
            if (text.isNotBlank()) load(text.byteInputStream())
        }
    }

    fun signingSecret(property: String, env: String): Provider<String> {
        val fromFile = keystoreProperties
            .map { props -> props.getProperty(property) }
            .filter { value -> !value.isNullOrBlank() }
        val fromEnv = environmentVariable(env)
            .filter { value -> !value.isNullOrBlank() }
        return fromFile.orElse(fromEnv)
    }

    val storeFile = signingSecret("storeFile", "TG_ANDROID_STORE_FILE")
    val storePassword = signingSecret("storePassword", "TG_ANDROID_STORE_PASSWORD")
    val keyAlias = signingSecret("keyAlias", "TG_ANDROID_KEY_ALIAS")
    val keyPassword = signingSecret("keyPassword", "TG_ANDROID_KEY_PASSWORD")
    val isConfigured = provider {
        listOf(storeFile, storePassword, keyAlias, keyPassword).all(Provider<*>::isPresent)
    }
    return ReleaseSigning(storeFile, storePassword, keyAlias, keyPassword, isConfigured)
}

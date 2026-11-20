package io.github.valnesfjord.tgwsproxyrs

import android.app.Application
import android.system.Os
import androidx.core.content.edit
import java.security.SecureRandom

class TgWsProxyApp : Application() {
    override fun onCreate() {
        super.onCreate()
        val prefs = getSharedPreferences(ProxyService.PREFS, MODE_PRIVATE)
        val secret = prefs.getString(PREF_DEFAULT_SECRET, null) ?: run {
            val key = ByteArray(16).also { SecureRandom().nextBytes(it) }
            val generated = "dd" + key.toHexString()
            prefs.edit { putString(PREF_DEFAULT_SECRET, generated) }
            generated
        }
        // Set the CLI's fallback before loading JNI. Explicit --secret values
        // still take precedence for starts from the activity, tile and boot.
        Os.setenv("TG_SECRET", secret, false)
        NativeProxy.load()
        ProxyBridge.syncFromNative()
    }

    companion object {
        internal const val PREF_DEFAULT_SECRET = "default_secret"
    }
}

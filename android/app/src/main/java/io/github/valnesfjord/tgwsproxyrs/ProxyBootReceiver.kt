package io.github.valnesfjord.tgwsproxyrs

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log

class ProxyBootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED) return
        val prefs = context.getSharedPreferences(ProxyService.PREFS, Context.MODE_PRIVATE)
        if (!prefs.getBoolean(ProxyService.PREF_START_ON_BOOT, false)) return
        val args = prefs.getString(ProxyService.PREF_ARGS, null) ?: ProxyService.DEFAULT_ARGS
        try {
            ProxyService.start(context, args)
        } catch (error: IllegalStateException) {
            Log.w("tg-ws-proxy", "Android rejected foreground service start after boot", error)
        } catch (error: SecurityException) {
            Log.w("tg-ws-proxy", "Android denied foreground service start after boot", error)
        }
    }
}

package io.github.valnesfjord.tgwsproxyrs

import android.app.PendingIntent
import android.content.Intent
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch

/**
 * Quick Settings toggle for the proxy (#158).
 *
 * The tile owns no state of its own: it mirrors [ProxyBridge.running], the
 * same flow the app's Start/Stop button reads, and taps go through
 * [ProxyService] exactly as the button's do.  A start uses the arguments last
 * saved by the app, so the tile runs whatever the user configured there.
 *
 * Reading [ProxyBridge.running] rather than asking the shim matters for the
 * same reason it does in the UI: it only drops once a stopping worker is
 * startable again, so the tile never offers a start the shim would refuse.
 */
class ProxyTileService : TileService() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    private var listening: Job? = null

    override fun onStartListening() {
        super.onStartListening()
        // A process the system started just to draw this tile has not seen a
        // worker the shim may still be running.
        ProxyBridge.syncFromNative()
        listening?.cancel()
        listening = scope.launch {
            ProxyBridge.running.collect(::render)
        }
    }

    override fun onStopListening() {
        listening?.cancel()
        listening = null
        super.onStopListening()
    }

    override fun onDestroy() {
        scope.cancel()
        super.onDestroy()
    }

    override fun onClick() {
        super.onClick()
        if (ProxyBridge.running.value) {
            ProxyService.stop(this)
            return
        }

        ProxyBridge.clearError()
        val args = getSharedPreferences(ProxyService.PREFS, MODE_PRIVATE)
            .getString(ProxyService.PREF_ARGS, null) ?: ProxyService.DEFAULT_ARGS
        try {
            ProxyService.start(this, args)
        } catch (e: IllegalStateException) {
            // `ForegroundServiceStartNotAllowedException` is one: a vendor
            // build that does not extend the tile-click exemption to us.  The
            // app's own button is always allowed, so hand the user to it
            // rather than doing nothing.
            ProxyBridge.reportMessage(e.message ?: e.toString())
            openApp()
        }
    }

    private fun render(running: Boolean) {
        val tile = qsTile ?: return
        tile.state = if (running) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            tile.subtitle = getString(if (running) R.string.status_running else R.string.status_stopped)
        }
        tile.updateTile()
    }

    private fun openApp() {
        val intent = Intent(this, MainActivity::class.java)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startActivityAndCollapse(
                PendingIntent.getActivity(this, 0, intent, PendingIntent.FLAG_IMMUTABLE),
            )
        } else {
            @Suppress("DEPRECATION")
            startActivityAndCollapse(intent)
        }
    }
}

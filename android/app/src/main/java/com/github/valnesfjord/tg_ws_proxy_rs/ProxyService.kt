package com.github.valnesfjord.tg_ws_proxy_rs

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import androidx.core.content.ContextCompat
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import androidx.core.content.edit

class ProxyService : Service() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)

    /**
     * True while this service is the one that started the proxy.  The native
     * worker reports startup failures asynchronously via [NativeProxy.onNativeError];
     * when `running` flips to false underneath us, tear down the foreground
     * notification and stop instead of leaving "Running" up with no listener.
     */
    private var proxyStarted = false

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        ensureChannel()
        scope.launch {
            ProxyBridge.running.collect { isRunning ->
                if (proxyStarted && !isRunning) {
                    proxyStarted = false
                    stopForeground(STOP_FOREGROUND_REMOVE)
                    stopSelf()
                }
            }
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START -> {
                if (NativeProxy.nativeIsRunning()) {
                    ProxyBridge.setRunning(true)
                    goForeground(getString(R.string.status_running))
                } else {
                    startProxy(intent.getStringExtra(EXTRA_ARGS) ?: DEFAULT_ARGS)
                }
            }
            ACTION_STOP -> stopProxy()
            else -> {
                if (NativeProxy.nativeIsRunning()) {
                    ProxyBridge.setRunning(true)
                    goForeground(getString(R.string.status_running))
                } else {
                    val args = prefs().getString(PREF_ARGS, null)
                    if (args != null) {
                        startProxy(args)
                    } else {
                        stopSelf()
                    }
                }
            }
        }
        return START_STICKY
    }

    override fun onDestroy() {
        scope.cancel()
        if (NativeProxy.nativeIsRunning()) {
            NativeProxy.nativeStop()
        }
        ProxyBridge.setRunning(false)
        super.onDestroy()
    }

    private fun startProxy(args: String) {
        prefs().edit { putString(PREF_ARGS, args) }
        ProxyBridge.clearError()
        goForeground(getString(R.string.status_starting))
        proxyStarted = true
        val error = NativeProxy.nativeStart(args)
        if (error != null) {
            proxyStarted = false
            ProxyBridge.reportError(error)
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
        } else if (ProxyBridge.error.value != null) {
            // NativeStart is async: the worker may have already failed and
            // reported the error before we optimistically flipped to running.
            proxyStarted = false
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
        } else {
            ProxyBridge.setRunning(true)
            if (NativeProxy.nativeIsRunning()) {
                goForeground(getString(R.string.status_running))
            } else {
                // The worker may already have exited (e.g. a --check run that
                // finished during nativeStart) before the optimistic flip, in
                // which case nothing will ever flip running back to false.
                proxyStarted = false
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
            }
        }
    }

    private fun goForeground(text: String) {
        val type = if (Build.VERSION.SDK_INT >= 34) {
            ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
        } else {
            0
        }
        ServiceCompat.startForeground(this, NOTIFICATION_ID, notification(text), type)
    }

    private fun stopProxy() {
        proxyStarted = false
        NativeProxy.nativeStop()
        ProxyBridge.setRunning(false)
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun ensureChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val channel = NotificationChannel(
            CHANNEL_ID,
            getString(R.string.notification_channel),
            NotificationManager.IMPORTANCE_LOW,
        )
        getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
    }

    private fun notification(text: String): Notification {
        val open = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val stop = PendingIntent.getService(
            this,
            1,
            Intent(this, ProxyService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle(getString(R.string.app_name))
            .setContentText(text)
            .setContentIntent(open)
            .setOngoing(true)
            .addAction(0, getString(R.string.stop), stop)
            .build()
    }

    private fun prefs() = getSharedPreferences(PREFS, MODE_PRIVATE)

    companion object {
        const val ACTION_START = "com.github.valnesfjord.tg_ws_proxy_rs.START"
        const val ACTION_STOP = "com.github.valnesfjord.tg_ws_proxy_rs.STOP"
        const val EXTRA_ARGS = "args"
        const val DEFAULT_ARGS =
            "--default-domains --cf-balance --quiet --host 127.0.0.1 --link-ip 127.0.0.1"
        const val PREFS = "tg_ws_proxy"
        const val PREF_ARGS = "args"

        private const val CHANNEL_ID = "proxy"
        private const val NOTIFICATION_ID = 1

        fun start(context: Context, args: String) {
            val intent = Intent(context, ProxyService::class.java)
                .setAction(ACTION_START)
                .putExtra(EXTRA_ARGS, args)
            ContextCompat.startForegroundService(context, intent)
        }

        fun stop(context: Context) {
            val intent = Intent(context, ProxyService::class.java).setAction(ACTION_STOP)
            context.startService(intent)
        }
    }
}

package io.github.valnesfjord.tgwsproxyrs

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
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeoutOrNull
import androidx.core.content.edit
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

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
        stopNative()
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
            // reported the error while we were inside it, and the optimistic
            // flip below would paint "Running" over that error.
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
        // Deliberately no `ProxyBridge.setRunning(false)` here.  The shim
        // refuses to start while the previous run is winding down, and the
        // worker only reports the stop once it is startable again, so
        // answering for it would put a Start button in front of the user
        // before a start could be accepted: tap Stop, tap Start, and the
        // shim's internal "proxy is still stopping" lands in the error line.
        // Leaving the running state is [stopNative]'s call instead: it waits
        // for the worker's report and answers for it only when none is coming
        // or none arrives.
        stopNative()
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
        const val ACTION_START = "io.github.valnesfjord.tgwsproxyrs.START"
        const val ACTION_STOP = "io.github.valnesfjord.tgwsproxyrs.STOP"
        const val EXTRA_ARGS = "args"
        const val DEFAULT_ARGS =
            "--default-domains --cf-balance --quiet --host 127.0.0.1 --link-ip 127.0.0.1"
        const val PREFS = "tg_ws_proxy"
        const val PREF_ARGS = "args"
        const val PREF_START_ON_BOOT = "start_on_boot"

        private const val CHANNEL_ID = "proxy"
        private const val NOTIFICATION_ID = 1

        /**
         * Runs the native shutdown off the main thread.  It has to outlive the
         * service: [onDestroy] cancels [scope] before it stops the proxy, so a
         * coroutine launched there would never run.  A single thread also keeps
         * a Stop button press and the [stopSelf] that follows it from entering
         * the JNI shim at the same time — and, now that the first of those two
         * waits for the worker's report, keeps the second from concluding
         * "nothing is running" about a worker the first is still winding down.
         */
        private val stopExecutor: ExecutorService = Executors.newSingleThreadExecutor { runnable ->
            Thread(runnable, "proxy-stop").apply { isDaemon = true }
        }

        /**
         * How long the worker is given to report its stop.
         *
         * Its tail is a bounded `rt.shutdown_timeout(2s)` followed by the
         * callback, so this is that bound plus room for a loaded emulator, not
         * a guess at how long a shutdown takes.
         */
        private const val STOP_REPORT_TIMEOUT_MS = 3_000L

        private fun stopNative() {
            stopExecutor.execute {
                if (NativeProxy.nativeIsRunning()) {
                    NativeProxy.nativeStop()
                    awaitStopReport()
                } else {
                    // Nothing for the shim to stop.  Either nothing ever ran,
                    // and this write is the only one there will be, or an
                    // earlier stop task has already returned — in which case
                    // the running state was left back then, by the worker's
                    // report or by that task giving up on one.  What this
                    // cannot be is a stop still awaiting its report: the
                    // executor is single-threaded, so that task would not have
                    // let this one start.
                    ProxyBridge.setRunning(false)
                }
            }
        }

        /**
         * Block until `onNativeStopped` (or `onNativeError`) has flipped
         * [ProxyBridge.running] false.
         *
         * On [stopExecutor], never on the main thread — that is the whole point
         * of the executor, and the report comes from a native worker thread, so
         * nothing here waits on the main looper.
         */
        private fun awaitStopReport() {
            val timedOut = runBlocking {
                withTimeoutOrNull(STOP_REPORT_TIMEOUT_MS) {
                    ProxyBridge.running.first { !it }
                } == null
            }
            if (timedOut) {
                // Should be unreachable given the shim's bounded tail.  If a
                // report really is lost, a UI stuck on "Running" with no way
                // back is worse than a Start the shim might still refuse.
                ProxyBridge.setRunning(false)
            }
        }

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

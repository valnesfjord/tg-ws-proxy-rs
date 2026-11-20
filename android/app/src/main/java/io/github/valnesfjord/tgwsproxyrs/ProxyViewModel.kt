package io.github.valnesfjord.tgwsproxyrs

import android.app.Application
import android.content.ActivityNotFoundException
import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Intent
import android.os.Build
import android.os.PersistableBundle
import android.widget.Toast
import androidx.compose.runtime.mutableStateListOf
import androidx.core.content.edit
import androidx.core.net.toUri
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

class ProxyViewModel(application: Application) : AndroidViewModel(application) {
    private val prefs = application.getSharedPreferences(ProxyService.PREFS, 0)

    private val _args = MutableStateFlow(
        prefs.getString(ProxyService.PREF_ARGS, null) ?: ProxyService.DEFAULT_ARGS,
    )
    val args: StateFlow<String> = _args.asStateFlow()

    private val _startOnBoot = MutableStateFlow(
        prefs.getBoolean(ProxyService.PREF_START_ON_BOOT, false),
    )
    val startOnBoot: StateFlow<Boolean> = _startOnBoot.asStateFlow()

    val running = ProxyBridge.running
    val tgLink = ProxyBridge.tgLink
    val error = ProxyBridge.error

    /**
     * Bounded log buffer the UI observes directly.  A `StateFlow<List<String>>`
     * copied the whole list to append and copied it again to trim, i.e. up to
     * a thousand element copies per line on a chatty proxy; a snapshot list
     * shares its backing structure between versions and lets Compose observe
     * the single append, so only the rows on screen recompose.
     */
    private val _logs = mutableStateListOf<LogLine>()
    val logs: List<LogLine> = _logs

    /** Never reused, never reordered — see [LogLine]. */
    private var nextLogId = 0L

    private var autoOpenPending = false

    init {
        ProxyBridge.syncFromNative()
        viewModelScope.launch {
            ProxyBridge.logs.collect { line ->
                _logs.add(LogLine(nextLogId++, line))
                if (_logs.size > MAX_LOG_LINES) {
                    _logs.removeAt(0)
                }
            }
        }
        viewModelScope.launch {
            ProxyBridge.tgLink.collect { link ->
                if (link != null && autoOpenPending) {
                    autoOpenPending = false
                    openLink()
                }
            }
        }
    }

    fun updateArgs(value: String) {
        _args.value = value
        prefs.edit { putString(ProxyService.PREF_ARGS, value) }
    }

    fun updateStartOnBoot(enabled: Boolean) {
        prefs.edit { putBoolean(ProxyService.PREF_START_ON_BOOT, enabled) }
        _startOnBoot.value = enabled
    }

    fun start() {
        ProxyBridge.clearError()
        autoOpenPending = true
        ProxyService.start(getApplication(), _args.value)
    }

    fun stop() {
        ProxyService.stop(getApplication())
    }

    fun openLink() {
        val link = tgLink.value ?: return
        val intent = Intent(Intent.ACTION_VIEW, link.toUri()).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        try {
            getApplication<Application>().startActivity(intent)
        } catch (_: ActivityNotFoundException) {
            ProxyBridge.reportMessage(getApplication<Application>().getString(R.string.telegram_missing))
        }
    }

    fun copyLink() {
        val link = tgLink.value ?: return
        val app = getApplication<Application>()
        val clip = ClipData.newPlainText(app.getString(R.string.proxy_link), link)
        val systemShowsPreview = Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU
        if (systemShowsPreview) {
            clip.description.extras = PersistableBundle().apply {
                putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true)
            }
        }
        app.getSystemService(ClipboardManager::class.java).setPrimaryClip(clip)
        if (!systemShowsPreview) {
            Toast.makeText(app, R.string.proxy_link_copied, Toast.LENGTH_SHORT).show()
        }
    }

    fun openRepo() {
        val uri = "https://github.com/valnesfjord/tg-ws-proxy-rs".toUri()
        val intent = Intent(Intent.ACTION_VIEW, uri).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        try {
            getApplication<Application>().startActivity(intent)
        } catch (_: ActivityNotFoundException) {
            ProxyBridge.reportMessage(getApplication<Application>().getString(R.string.browser_missing))
        }
    }

    companion object {
        private const val MAX_LOG_LINES = 500
    }
}

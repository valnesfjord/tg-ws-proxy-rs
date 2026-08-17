package com.github.valnesfjord.tg_ws_proxy_rs

import android.app.Application
import android.content.ActivityNotFoundException
import android.content.Intent
import androidx.core.content.edit
import androidx.core.net.toUri
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

class ProxyViewModel(application: Application) : AndroidViewModel(application) {
    private val prefs = application.getSharedPreferences(ProxyService.PREFS, 0)

    private val _args = MutableStateFlow(
        prefs.getString(ProxyService.PREF_ARGS, null) ?: ProxyService.DEFAULT_ARGS,
    )
    val args: StateFlow<String> = _args.asStateFlow()

    val running = ProxyBridge.running
    val tgLink = ProxyBridge.tgLink
    val error = ProxyBridge.error

    private val _logs = MutableStateFlow<List<String>>(emptyList())
    val logs: StateFlow<List<String>> = _logs.asStateFlow()

    private var autoOpenPending = false

    init {
        ProxyBridge.syncFromNative()
        viewModelScope.launch {
            ProxyBridge.logs.collect { line ->
                _logs.update { current ->
                    val next = current + line
                    if (next.size > MAX_LOG_LINES) next.takeLast(MAX_LOG_LINES) else next
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

    fun openRepo() {
        val uri = "https://github.com/valnesfjord/tg-ws-proxy-rs".toUri()
        val intent = Intent(Intent.ACTION_VIEW, uri).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        getApplication<Application>().startActivity(intent)
    }

    companion object {
        private const val MAX_LOG_LINES = 500
    }
}

package com.github.valnesfjord.tg_ws_proxy_rs

import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Process-wide state the service and the UI both read.
 *
 * Native callbacks land here so a configuration change cannot drop the
 * listener that `src/android.rs` calls by class name.
 */
object ProxyBridge {
    private val tgLinkRegex = Regex("""tg://proxy\?[^\s]+""")

    private val _logs = MutableSharedFlow<String>(extraBufferCapacity = 256)
    val logs: SharedFlow<String> = _logs.asSharedFlow()

    private val _running = MutableStateFlow(false)
    val running: StateFlow<Boolean> = _running.asStateFlow()

    private val _tgLink = MutableStateFlow<String?>(null)
    val tgLink: StateFlow<String?> = _tgLink.asStateFlow()

    private val _error = MutableStateFlow<String?>(null)
    val error: StateFlow<String?> = _error.asStateFlow()

    fun setRunning(value: Boolean) {
        _running.value = value
        if (!value) {
            _tgLink.value = null
        }
    }

    fun reportError(message: String) {
        _error.value = message
        _logs.tryEmit(message)
        setRunning(false)
    }

    fun reportMessage(message: String) {
        _error.value = message
        _logs.tryEmit(message)
    }

    fun clearError() {
        _error.value = null
    }

    fun onLog(line: String) {
        _logs.tryEmit(line)
        tgLinkRegex.find(line)?.let { _tgLink.value = it.value }
    }

    fun onListening(link: String) {
        _tgLink.value = link
        _running.value = true
    }

    fun syncFromNative() {
        _running.value = NativeProxy.nativeIsRunning()
    }
}

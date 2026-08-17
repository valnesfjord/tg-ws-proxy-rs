package com.github.valnesfjord.tg_ws_proxy_rs

/**
 * JNI boundary for `src/android.rs`.
 *
 * The native side calls [onNativeLog], [onNativeListening], [onNativeError]
 * and [onNativeStopped] on whichever thread the Tokio runtime happens to be
 * on; [ProxyBridge] hops to the main thread for UI observers.
 */
object NativeProxy {
    init {
        System.loadLibrary("tg_ws_proxy_rs")
    }

    fun load() {
        // Touch the object so `init` runs from Application.onCreate.
    }

    @JvmStatic
    external fun nativeStart(args: String): String?

    @JvmStatic
    external fun nativeStop()

    @JvmStatic
    external fun nativeIsRunning(): Boolean

    @JvmStatic
    fun onNativeLog(line: String) {
        ProxyBridge.onLog(line)
    }

    @JvmStatic
    fun onNativeListening(link: String) {
        ProxyBridge.onListening(link)
    }

    @JvmStatic
    fun onNativeError(message: String) {
        ProxyBridge.reportError(message)
    }

    @JvmStatic
    fun onNativeStopped() {
        ProxyBridge.setRunning(false)
    }
}

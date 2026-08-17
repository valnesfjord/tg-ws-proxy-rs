package com.github.valnesfjord.tg_ws_proxy_rs

import android.app.Application

class TgWsProxyApp : Application() {
    override fun onCreate() {
        super.onCreate()
        NativeProxy.load()
        ProxyBridge.syncFromNative()
    }
}

package com.github.valnesfjord.tg_ws_proxy_rs

import android.Manifest
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.compose.runtime.LaunchedEffect
import androidx.core.content.ContextCompat
import com.github.valnesfjord.tg_ws_proxy_rs.ui.ProxyScreen
import com.github.valnesfjord.tg_ws_proxy_rs.ui.TgWsTheme

class MainActivity : ComponentActivity() {
    private val viewModel: ProxyViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            val permissionLauncher = rememberLauncherForActivityResult(
                ActivityResultContracts.RequestPermission(),
            ) { }

            LaunchedEffect(Unit) {
                if (Build.VERSION.SDK_INT >= 33 &&
                    ContextCompat.checkSelfPermission(
                        this@MainActivity,
                        Manifest.permission.POST_NOTIFICATIONS,
                    ) != PackageManager.PERMISSION_GRANTED
                ) {
                    permissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
                }
            }

            TgWsTheme {
                ProxyScreen(viewModel)
            }
        }
    }

    override fun onResume() {
        super.onResume()
        ProxyBridge.syncFromNative()
    }
}

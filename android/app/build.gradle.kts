plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.compose)
    id("tgwsproxy.android")
}

android {
    namespace = "com.github.valnesfjord.tg_ws_proxy_rs"

    defaultConfig {
        applicationId = "com.github.valnesfjord.tg_ws_proxy_rs"
    }
}

dependencies {
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.ui.tooling.preview)
    implementation(libs.androidx.compose.material3)
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.androidx.lifecycle.viewmodel.compose)
    implementation(libs.androidx.lifecycle.runtime.compose)
    implementation(libs.androidx.core.ktx)
    debugImplementation(libs.androidx.compose.ui.tooling)
}

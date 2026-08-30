plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.compose)
    id("tgwsproxy.android")
}

android {
    namespace = "io.github.valnesfjord.tgwsproxyrs"

    defaultConfig {
        applicationId = "io.github.valnesfjord.tgwsproxyrs"
    }

    dependenciesInfo {
        // Disables dependency metadata when building APKs.
        includeInApk = false
        // Disables dependency metadata when building Android App Bundles.
        includeInBundle = false
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

    // Instrumentation tests only; nothing here touches Compose, so no Compose
    // test artifacts are needed.
    //
    // Do NOT add androidx.test:orchestrator (or clearPackageData): it runs each
    // test method in a fresh process, which would hand every test a fresh
    // global tracing subscriber and mask the exact bug
    // NativeProxyContractTest.logLevelIsReloadedOnEveryStart exists to catch.
    androidTestImplementation(libs.junit)
    androidTestImplementation(libs.androidx.test.runner)
    androidTestImplementation(libs.androidx.test.ext.junit)
    // The tests observe ProxyBridge's flows; declare coroutines rather than
    // inherit it, so the test source set does not depend on which app
    // dependency happens to expose it.
    androidTestImplementation(libs.kotlinx.coroutines.android)
}

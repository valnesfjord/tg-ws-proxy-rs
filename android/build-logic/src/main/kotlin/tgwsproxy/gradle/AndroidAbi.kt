package tgwsproxy.gradle

internal object AndroidAbi {
    val triples = mapOf(
        "arm64-v8a" to "aarch64-linux-android",
        "armeabi-v7a" to "armv7-linux-androideabi",
        "x86_64" to "x86_64-linux-android",
        "x86" to "i686-linux-android",
    )

    val clangPrefixes = mapOf(
        "arm64-v8a" to "aarch64-linux-android",
        "armeabi-v7a" to "armv7a-linux-androideabi",
        "x86_64" to "x86_64-linux-android",
        "x86" to "i686-linux-android",
    )

    val defaultAbis = listOf("arm64-v8a", "armeabi-v7a", "x86_64")
}

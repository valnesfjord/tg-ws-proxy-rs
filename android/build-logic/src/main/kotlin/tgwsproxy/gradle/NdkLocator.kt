package tgwsproxy.gradle

import org.gradle.api.GradleException
import java.io.File
import java.util.Locale

internal object NdkLocator {
    fun resolveNdkRoot(explicitNdkRoot: String, androidSdkRoot: String): File {
        val explicit = explicitNdkRoot.trim()
        if (explicit.isNotEmpty()) {
            return File(explicit)
        }

        val ndkDir = File(androidSdkRoot).resolve("ndk")
        if (!ndkDir.isDirectory) {
            throw GradleException("no NDK found under ${ndkDir.absolutePath}; set ANDROID_NDK_HOME")
        }

        return ndkDir.listFiles { file -> file.isDirectory }
            ?.maxWithOrNull { left, right -> compareVersions(left.name, right.name) }
            ?: throw GradleException("no NDK versions found under ${ndkDir.absolutePath}; set ANDROID_NDK_HOME")
    }

    fun hostTag(ndkRoot: File): String {
        val os = System.getProperty("os.name").lowercase(Locale.US)
        val arch = System.getProperty("os.arch").lowercase(Locale.US)
        return when {
            os.contains("windows") -> "windows-x86_64"
            os.contains("mac") || os.contains("darwin") -> {
                if ((arch == "aarch64" || arch == "arm64") &&
                    ndkRoot.resolve("toolchains/llvm/prebuilt/darwin-arm64").isDirectory
                ) {
                    "darwin-arm64"
                } else {
                    "darwin-x86_64"
                }
            }
            else -> "linux-x86_64"
        }
    }

    fun ndkExecutable(path: File): File {
        if (path.exists()) {
            return path
        }
        if (isWindows()) {
            val cmd = File("${path.absolutePath}.cmd")
            if (cmd.exists()) {
                return cmd
            }
            val exe = File("${path.absolutePath}.exe")
            if (exe.exists()) {
                return exe
            }
        }
        return path
    }

    fun hostExecutable(name: String): String =
        if (isWindows()) "$name.cmd" else name

    private fun isWindows(): Boolean =
        System.getProperty("os.name").lowercase(Locale.US).contains("windows")

    private fun compareVersions(left: String, right: String): Int {
        val leftParts = left.split(Regex("[^0-9]+")).filter(String::isNotEmpty).map(String::toLong)
        val rightParts = right.split(Regex("[^0-9]+")).filter(String::isNotEmpty).map(String::toLong)
        val max = maxOf(leftParts.size, rightParts.size)
        for (index in 0 until max) {
            val diff = (leftParts.getOrElse(index) { 0L } - rightParts.getOrElse(index) { 0L }).sign
            if (diff != 0) {
                return diff
            }
        }
        return left.compareTo(right)
    }

    private val Long.sign: Int
        get() = when {
            this < 0 -> -1
            this > 0 -> 1
            else -> 0
        }
}

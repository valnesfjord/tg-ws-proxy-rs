package tgwsproxy.gradle

import org.gradle.api.DefaultTask
import org.gradle.api.GradleException
import org.gradle.api.file.DirectoryProperty
import org.gradle.api.file.RegularFileProperty
import org.gradle.api.provider.ListProperty
import org.gradle.api.provider.Property
import org.gradle.api.tasks.CacheableTask
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.InputDirectory
import org.gradle.api.tasks.InputFile
import org.gradle.api.tasks.Internal
import org.gradle.api.tasks.Optional
import org.gradle.api.tasks.OutputDirectory
import org.gradle.api.tasks.PathSensitive
import org.gradle.api.tasks.PathSensitivity
import org.gradle.api.tasks.TaskAction
import org.gradle.process.ExecOperations
import java.io.File
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.util.Locale
import javax.inject.Inject

@CacheableTask
abstract class CargoNdkBuildTask @Inject constructor(
    private val execOperations: ExecOperations,
) : DefaultTask() {
    @get:Internal
    abstract val repoRoot: DirectoryProperty

    @get:InputDirectory
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val rustSources: DirectoryProperty

    @get:InputFile
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val cargoToml: RegularFileProperty

    @get:InputFile
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val cargoLock: RegularFileProperty

    @get:Optional
    @get:InputFile
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val cargoConfig: RegularFileProperty

    @get:OutputDirectory
    abstract val jniLibsDir: DirectoryProperty

    @get:Input
    abstract val abis: ListProperty<String>

    @get:Input
    abstract val profile: Property<String>

    @get:Input
    abstract val apiLevel: Property<Int>

    @get:Input
    abstract val androidSdkRoot: Property<String>

    @get:Input
    abstract val androidNdkRoot: Property<String>

    @TaskAction
    fun build() {
        val selectedAbis = abis.get().map(String::trim).filter(String::isNotEmpty)
        if (selectedAbis.isEmpty()) {
            throw GradleException("TG_ANDROID_ABIS resolved to an empty ABI list")
        }

        val rustProfile = profile.get().lowercase(Locale.US)
        val artifactDir = when (rustProfile) {
            "release" -> "release"
            "debug" -> "debug"
            else -> throw GradleException("TG_ANDROID_RUST_PROFILE must be 'release' or 'debug', got '$rustProfile'")
        }

        val ndkRoot = NdkLocator.resolveNdkRoot(androidNdkRoot.get(), androidSdkRoot.get())
        val toolchain = ndkRoot.resolve("toolchains/llvm/prebuilt/${NdkLocator.hostTag(ndkRoot)}")
        if (!toolchain.isDirectory) {
            throw GradleException("NDK toolchain missing: ${toolchain.absolutePath}")
        }

        val toolchainBin = toolchain.resolve("bin")
        val root = repoRoot.asFile.get()
        val outputRoot = jniLibsDir.asFile.get()
        val supportedAbis = AndroidAbi.triples.keys
        outputRoot.listFiles()
            ?.filter { it.isDirectory && it.name in supportedAbis && it.name !in selectedAbis }
            ?.forEach { it.deleteRecursively() }

        selectedAbis.forEach { abi ->
            val triple = AndroidAbi.triples[abi] ?: throw GradleException("Unsupported Android ABI: $abi")
            val clangPrefix = AndroidAbi.clangPrefixes[abi] ?: error("missing clang prefix for $abi")
            val clang = NdkLocator.ndkExecutable(toolchainBin.resolve("${clangPrefix}${apiLevel.get()}-clang"))
            val clangxx = NdkLocator.ndkExecutable(toolchainBin.resolve("${clangPrefix}${apiLevel.get()}-clang++"))
            val llvmAr = NdkLocator.ndkExecutable(toolchainBin.resolve("llvm-ar"))

            if (!clang.exists()) {
                throw GradleException("missing NDK clang: ${clang.absolutePath}")
            }
            if (!clangxx.exists()) {
                throw GradleException("missing NDK clang++: ${clangxx.absolutePath}")
            }
            if (!llvmAr.exists()) {
                throw GradleException("missing NDK llvm-ar: ${llvmAr.absolutePath}")
            }

            logger.lifecycle("building $triple ($abi, $rustProfile)")
            execOperations.exec {
                workingDir(root)
                commandLine(NdkLocator.hostExecutable("rustup"), "target", "add", triple)
            }

            val targetEnv = triple.uppercase(Locale.US).replace("-", "_")
            val ccEnv = triple.replace("-", "_")
            val cargoArgs = mutableListOf("build", "--lib", "--target", triple, "--locked")
            if (rustProfile == "release") {
                cargoArgs += "--release"
            }

            execOperations.exec {
                workingDir(root)
                environment("ANDROID_HOME", androidSdkRoot.get())
                environment("ANDROID_NDK_HOME", ndkRoot.absolutePath)
                environment("PATH", "${toolchainBin.absolutePath}${File.pathSeparator}${System.getenv("PATH").orEmpty()}")
                environment("CC_$ccEnv", clang.absolutePath)
                environment("CXX_$ccEnv", clangxx.absolutePath)
                environment("AR_$ccEnv", llvmAr.absolutePath)
                environment("CARGO_TARGET_${targetEnv}_LINKER", clang.absolutePath)
                environment("CARGO_TARGET_${targetEnv}_AR", llvmAr.absolutePath)
                commandLine(NdkLocator.hostExecutable("cargo"), *cargoArgs.toTypedArray())
            }

            val artifact = root.resolve("target/$triple/$artifactDir/libtg_ws_proxy_rs.so")
            if (!artifact.isFile) {
                throw GradleException("Cargo did not produce ${artifact.absolutePath}")
            }

            val destination = outputRoot.resolve("$abi/libtg_ws_proxy_rs.so")
            destination.parentFile.mkdirs()
            Files.copy(artifact.toPath(), destination.toPath(), StandardCopyOption.REPLACE_EXISTING)
            logger.lifecycle("  -> ${destination.absolutePath}")
        }
    }
}

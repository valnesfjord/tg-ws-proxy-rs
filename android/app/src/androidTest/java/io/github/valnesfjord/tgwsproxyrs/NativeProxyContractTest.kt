package io.github.valnesfjord.tgwsproxyrs

import android.content.ComponentName
import android.content.Context
import android.content.ContextWrapper
import android.content.Intent
import android.net.Uri
import androidx.core.content.edit
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.net.InetSocketAddress
import java.net.Socket

/**
 * What the JNI shim in `crates/android-jni/src/android.rs` promises Kotlin,
 * checked on a real device image.
 *
 * Everything here runs offline; see [OFFLINE_ARGS].
 */
@RunWith(AndroidJUnit4::class)
class NativeProxyContractTest {
    @Before
    fun startFromIdle() {
        stopAndWait()
        resetBridge()
    }

    @After
    fun leaveIdle() {
        stopAndWait()
        resetBridge()
    }

    /**
     * Calls all three externals, because calling them is the only thing that
     * proves they resolve: `System.loadLibrary` succeeds even when every
     * `Java_…` symbol is missing, and `UnsatisfiedLinkError` is not raised
     * until the first call.
     *
     * That gap is what makes a package rename dangerous — the symbol names are
     * spelled out by hand in `android.rs`, so a rename that reaches only the
     * Kotlin side still builds, still installs, and dies on the user's first
     * Start. This is the only check anywhere that catches it.
     */
    @Test
    fun nativeEntryPointsResolve() {
        assertFalse("nothing should be running yet", NativeProxy.nativeIsRunning())

        // Rejected by clap before anything is started, which exercises
        // nativeStart end to end with no side effect to clean up. The shim
        // returns the message rather than throwing — ProxyService.startProxy
        // reads it the same way — so a String is the success case, and
        // asserting *which* String is what keeps the check below honest: see
        // awaitRejection for why the other refusal `start_proxy` can produce
        // would quietly disarm it.
        val error = awaitRejection("--definitely-not-a-flag")
        assertTrue("unexpected rejection: $error", error.contains("--definitely-not-a-flag"))

        // Having reached clap, `start_proxy` was past its guard: it had already
        // reaped any finished worker, and reaping is also what clears the
        // `stopping` flag. That is what gives this line something to say — with
        // the flag set, `nativeIsRunning()` answers false whatever the worker
        // is doing, so a rejected start that spawned one anyway would read
        // exactly like a rejected start that did not.
        assertFalse("a rejected start must not leave a worker behind", NativeProxy.nativeIsRunning())

        // Has to come last, and is not free to call even from idle:
        // `stop_proxy` sets `stopping` unconditionally, whether or not it found
        // a worker to signal, and nothing short of the next accepted start
        // clears it. Any earlier and every `nativeIsRunning()` above would be
        // pinned to false and prove nothing.
        NativeProxy.nativeStop()
    }

    /**
     * The `on_listen` callback reaches Kotlin, carrying a usable link.
     *
     * This is the app's whole startup contract: the UI has no other way to
     * learn the port when `--port 0` is in use.
     */
    @Test
    fun startPublishesTheTelegramLink() {
        startProxy(OFFLINE_ARGS)
        val link = awaitLink()

        assertTrue("unexpected link: $link", link.startsWith("tg://proxy?server=127.0.0.1&port="))
        // `dd` is the padded-intermediate mode prefix Config::link_secret_for
        // adds to a bare 32-character secret. Asserting the whole field is
        // what makes passing an explicit --secret worth the trouble.
        assertTrue("unexpected link: $link", link.endsWith("&secret=dd$TEST_SECRET"))

        val port = portOf(link)
        assertTrue("port out of range: $port", port in 1..65535)

        // The banner is written before the callback fires, so the link on its
        // own would also be published by a run whose listener had already
        // died. Connecting is what proves the socket is really there.
        Socket().use { it.connect(InetSocketAddress("127.0.0.1", port), 5_000) }

        assertTrue("nativeIsRunning should be true once listening", NativeProxy.nativeIsRunning())
    }

    @Test
    fun bootUsesTheSameGeneratedSecretAsAManualStart() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val prefs = context.getSharedPreferences(ProxyService.PREFS, Context.MODE_PRIVATE)
        val saved = prefs.getString(TgWsProxyApp.PREF_DEFAULT_SECRET, null)
        assertTrue(saved?.matches(Regex("dd[0-9a-f]{32}")) == true)
        val args = OFFLINE_ARGS.removeSuffix(" --secret $TEST_SECRET")
        startProxy(args)
        assertEquals(saved, Uri.parse(awaitLink()).getQueryParameter("secret"))
        stopAndWait()
        resetBridge()

        // Capture the service intent so background-start restrictions on the
        // instrumentation process do not stand in for Android's boot exemption.
        val bootPrefs = context.getSharedPreferences("test_boot", Context.MODE_PRIVATE)
        var request: Intent? = null
        val bootContext = object : ContextWrapper(context) {
            override fun getSharedPreferences(name: String, mode: Int) = bootPrefs
            override fun startForegroundService(service: Intent): ComponentName? {
                request = service
                return service.component
            }
        }
        val boot = Intent(Intent.ACTION_BOOT_COMPLETED)
        val receiver = ProxyBootReceiver()
        try {
            bootPrefs.edit {
                clear()
                putString(ProxyService.PREF_ARGS, args)
            }
            receiver.onReceive(bootContext, boot)
            assertNull(request)
            bootPrefs.edit { putBoolean(ProxyService.PREF_START_ON_BOOT, true) }
            receiver.onReceive(bootContext, boot)
            val intent = requireNotNull(request)
            assertEquals(ProxyService::class.java.name, intent.component?.className)
            assertEquals(ProxyService.ACTION_START, intent.action)
            val bootArgs = requireNotNull(intent.getStringExtra(ProxyService.EXTRA_ARGS))
            assertEquals(args, bootArgs)
            startProxy(bootArgs)
            assertEquals(saved, Uri.parse(awaitLink()).getQueryParameter("secret"))
        } finally {
            bootPrefs.edit { clear() }
        }
    }

    /**
     * Verbose, then quiet, then verbose again.
     *
     * A global `tracing` subscriber can only be installed once per process, so
     * every Start after the first has to reload the filter through
     * `LOG_FILTER` instead. Before that the shim just dropped the second
     * `try_init()`'s error, and because `--quiet` is in the app's default
     * arguments the Log panel stayed empty for the whole life of the process —
     * clearing `--quiet` from the arguments field did nothing until the app was
     * force-stopped.
     *
     * The third phase is not redundant. With the old code the *first* Start
     * wins, so a verbose-then-quiet pair would pass whenever JUnit happened to
     * schedule this test first; only going back to verbose proves the filter
     * moves in both directions.
     */
    @Test
    fun logLevelIsReloadedOnEveryStart() {
        assertLogging(verbose = true)
        assertLogging(verbose = false)
        assertLogging(verbose = true)
    }

    private fun assertLogging(verbose: Boolean) {
        val flag = if (verbose) "--verbose" else "--quiet"
        LogCapture().use { capture ->
            startProxy("$OFFLINE_ARGS $flag")
            // The link is what keeps the quiet phase from being satisfied by a
            // proxy that never came up: `onNativeListening` does not travel
            // through the tracing writer — the callback is invoked straight
            // from `on_listen` — so it arrives even at `--quiet`, and it
            // arrives only once there is a listener to describe.
            awaitLink()
            stopAndWait()

            if (verbose) {
                assertNotNull("expected log lines with $flag", capture.awaitLine())
            } else {
                // There is nothing to wait *for* in this phase, so wait for a
                // line of this test's own, pushed through the same callback the
                // shim calls. Two facts make its arrival a complete answer
                // rather than a sample: the stop above returned only after the
                // runtime was torn down, so every line the run was ever going
                // to emit has been emitted, and a SharedFlow hands a collector
                // its lines in emission order, so all of them are already here
                // if any are. A barrier beats a sleep on both counts — it
                // cannot be outrun by a slow emulator, and it does not cost two
                // seconds when it passes.
                NativeProxy.onNativeLog(QUIET_BARRIER)
                assertEquals("expected no log lines with $flag", QUIET_BARRIER, capture.awaitLine())
            }
        }
        resetBridge()
    }

    private companion object {
        /**
         * The barrier line. Deliberately unlike anything the proxy logs, and in
         * particular free of a `tg://proxy?` link, which `ProxyBridge.onLog`
         * would pick up as a listening address.
         */
        const val QUIET_BARRIER = "androidTest quiet-phase barrier"
    }
}

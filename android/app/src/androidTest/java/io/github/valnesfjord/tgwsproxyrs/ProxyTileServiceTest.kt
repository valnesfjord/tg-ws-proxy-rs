package io.github.valnesfjord.tgwsproxyrs

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.service.quicksettings.TileService
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The Quick Settings tile is only offered if the system can find it, and a
 * manifest slip there fails silently: the tile is simply absent from the
 * editor, with nothing in the log.  So check what the system resolves.
 */
@RunWith(AndroidJUnit4::class)
class ProxyTileServiceTest {
    @Test
    fun theSystemCanFindTheTile() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val tiles = context.packageManager.queryIntentServices(
            Intent(TileService.ACTION_QS_TILE).setPackage(context.packageName),
            PackageManager.GET_META_DATA,
        )
        val tile = tiles.singleOrNull()?.serviceInfo
        assertNotNull("expected exactly one QS tile, found $tiles", tile)
        tile!!

        assertEquals(ProxyTileService::class.java.name, tile.name)
        assertTrue("SystemUI binds tiles from outside the app", tile.exported)
        // Without it any app could bind the tile and drive Start/Stop.
        assertEquals(Manifest.permission.BIND_QUICK_SETTINGS_TILE, tile.permission)
        assertTrue(
            "a toggle should be announced as one",
            tile.metaData?.getBoolean(TileService.META_DATA_TOGGLEABLE_TILE) == true,
        )
    }
}

package com.syncterm.android

import android.content.Context
import android.util.Log
import java.io.File
import java.io.FileOutputStream

/**
 * Utility to copy bundled default snapshot images from assets to filesDir
 * so the phonebook shows preview images on first launch.
 * Also handles migrating default BBS entries for existing users on app updates.
 */
object DefaultSnapshotHelper {

    private const val TAG = "DefaultSnapshotHelper"
    private const val CURRENT_DEFAULTS_VERSION = 3

    private val defaultSnapshots = mapOf(
        Pair("absinthebbs.net", 1940) to "default_snapshots/snapshot_0.png",
        Pair("telnet.deadmodemsociety.com", 1337) to "default_snapshots/snapshot_1.png",
        Pair("20forbeers.com", 1337) to "default_snapshots/snapshot_2.png",
        Pair("bbs.bottomlessabyss.net", 2023) to "default_snapshots/snapshot_3.png",
        Pair("sbbs.dmine.net", 24) to "default_snapshots/snapshot_4.png",
        Pair("bbs.erb.pw", 23) to "default_snapshots/snapshot_5.png",
        Pair("dura-bbs.net", 6359) to "default_snapshots/snapshot_6.png",
        Pair("wizardsrainbow.com", 23) to "default_snapshots/snapshot_7.png",
        Pair("xibalba.l33t.codes", 44510) to "default_snapshots/snapshot_8.png",
        Pair("d1st.org", 23) to "default_snapshots/snapshot_9.png"
    )

    /** All default BBSes in display order. */
    data class DefaultBbs(
        val name: String,
        val host: String,
        val port: Int,
        val screenMode: Int,
        val font: Int,
        val protocol: Int = MainActivity.SavedConnection.PROTOCOL_TELNET
    )

    private val allDefaults = listOf(
        DefaultBbs("aBSiNTHE BBS", "absinthebbs.net", 1940,
            MainActivity.SavedConnection.SCREEN_MODE_80X40,
            MainActivity.SavedConnection.FONT_TOPAZ_PLUS),
        DefaultBbs("Dead Modem Society", "telnet.deadmodemsociety.com", 1337,
            MainActivity.SavedConnection.SCREEN_MODE_80X25,
            MainActivity.SavedConnection.FONT_CP437),
        DefaultBbs("20 For Beers", "20forbeers.com", 1337,
            MainActivity.SavedConnection.SCREEN_MODE_80X25,
            MainActivity.SavedConnection.FONT_CP437),
        DefaultBbs("The Bottomless Abyss", "bbs.bottomlessabyss.net", 2023,
            MainActivity.SavedConnection.SCREEN_MODE_80X25,
            MainActivity.SavedConnection.FONT_CP437),
        DefaultBbs("Diamond Mine Online", "sbbs.dmine.net", 24,
            MainActivity.SavedConnection.SCREEN_MODE_80X25,
            MainActivity.SavedConnection.FONT_CP437),
        DefaultBbs("The Quantum Wormhole", "bbs.erb.pw", 23,
            MainActivity.SavedConnection.SCREEN_MODE_80X25,
            MainActivity.SavedConnection.FONT_CP437),
        DefaultBbs("Dura-Europos", "dura-bbs.net", 6359,
            MainActivity.SavedConnection.SCREEN_MODE_80X25,
            MainActivity.SavedConnection.FONT_CP437),
        DefaultBbs("Wizard's Rainbow", "wizardsrainbow.com", 23,
            MainActivity.SavedConnection.SCREEN_MODE_80X25,
            MainActivity.SavedConnection.FONT_CP437),
        DefaultBbs("Xibalba", "xibalba.l33t.codes", 44510,
            MainActivity.SavedConnection.SCREEN_MODE_80X25,
            MainActivity.SavedConnection.FONT_CP437),
        DefaultBbs("Distortion", "d1st.org", 23,
            MainActivity.SavedConnection.SCREEN_MODE_80X25,
            MainActivity.SavedConnection.FONT_CP437)
    )

    /**
     * Ensure all default BBSes exist in the phonebook.
     * - Fresh install (count == 0): adds all defaults.
     * - Existing user with outdated defaults_version: appends any missing defaults,
     *   skipping entries that already match by host+port.
     * - Already up to date: returns immediately.
     */
    fun migrateDefaultConnections(context: Context) {
        val prefs = context.getSharedPreferences("connections", Context.MODE_PRIVATE)
        val version = prefs.getInt("defaults_version", 0)

        if (version >= CURRENT_DEFAULTS_VERSION) return

        val count = prefs.getInt("count", 0)

        // Build set of existing host:port pairs for duplicate checking
        val existing = mutableSetOf<Pair<String, Int>>()
        for (i in 0 until count) {
            val host = prefs.getString("host_$i", "") ?: ""
            val port = prefs.getInt("port_$i", 23)
            if (host.isNotEmpty()) {
                existing.add(Pair(host, port))
            }
        }

        val editor = prefs.edit()
        var nextIndex = count

        for (bbs in allDefaults) {
            if (Pair(bbs.host, bbs.port) in existing) continue

            editor.putString("name_$nextIndex", bbs.name)
            editor.putString("host_$nextIndex", bbs.host)
            editor.putInt("port_$nextIndex", bbs.port)
            editor.putInt("screenMode_$nextIndex", bbs.screenMode)
            editor.putInt("font_$nextIndex", bbs.font)
            editor.putBoolean("hideStatusLine_$nextIndex", false)
            editor.putInt("protocol_$nextIndex", bbs.protocol)

            val snapshot = copyDefaultSnapshot(context, bbs.host, bbs.port)
            if (snapshot != null) {
                editor.putString("thumbnailPath_$nextIndex", snapshot.first)
                editor.putString("snapshotPath_$nextIndex", snapshot.second)
            }

            nextIndex++
        }

        editor.putInt("count", nextIndex)
        editor.putInt("defaults_version", CURRENT_DEFAULTS_VERSION)
        editor.commit()

        Log.d(TAG, "Migrated defaults: version $version -> $CURRENT_DEFAULTS_VERSION, added ${nextIndex - count} entries")
    }

    /**
     * Copy the default snapshot asset for a known BBS to filesDir.
     * The bundled assets are already thumbnail-sized so we just copy them
     * as both the thumbnail and snapshot file.
     * Returns Pair(thumbnailPath, snapshotPath) or null if no default exists.
     */
    fun copyDefaultSnapshot(context: Context, host: String, port: Int): Pair<String, String>? {
        val assetName = defaultSnapshots[Pair(host, port)] ?: return null

        val snapshotFileName = "snapshot_${host}_${port}.png"
        val thumbnailFileName = "thumbnail_${host}_${port}.png"

        val snapshotFile = File(context.filesDir, snapshotFileName)
        val thumbnailFile = File(context.filesDir, thumbnailFileName)

        // Skip if files already exist (don't overwrite user snapshots)
        if (snapshotFile.exists() && thumbnailFile.exists()) {
            Log.d(TAG, "Files already exist for $host:$port")
            return Pair(thumbnailFile.absolutePath, snapshotFile.absolutePath)
        }

        try {
            // Copy asset as snapshot
            context.assets.open(assetName).use { input ->
                FileOutputStream(snapshotFile).use { output ->
                    input.copyTo(output)
                }
            }
            Log.d(TAG, "Copied snapshot for $host:$port -> ${snapshotFile.absolutePath} (${snapshotFile.length()} bytes)")

            // Copy asset again as thumbnail (already correct size)
            context.assets.open(assetName).use { input ->
                FileOutputStream(thumbnailFile).use { output ->
                    input.copyTo(output)
                }
            }
            Log.d(TAG, "Copied thumbnail for $host:$port -> ${thumbnailFile.absolutePath} (${thumbnailFile.length()} bytes)")

            return Pair(thumbnailFile.absolutePath, snapshotFile.absolutePath)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to copy default snapshot for $host:$port", e)
            return null
        }
    }
}

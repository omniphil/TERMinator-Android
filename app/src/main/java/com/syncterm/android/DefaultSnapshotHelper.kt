package com.syncterm.android

import android.content.Context
import android.util.Log
import java.io.File
import java.io.FileOutputStream

/**
 * Utility to copy bundled default snapshot images from assets to filesDir
 * so the phonebook shows preview images on first launch.
 */
object DefaultSnapshotHelper {

    private const val TAG = "DefaultSnapshotHelper"

    private val defaultSnapshots = mapOf(
        Pair("absinthebbs.net", 1940) to "default_snapshots/snapshot_0.png",
        Pair("telnet.deadmodemsociety.com", 1337) to "default_snapshots/snapshot_1.png"
    )

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

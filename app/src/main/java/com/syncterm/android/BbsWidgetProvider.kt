package com.syncterm.android

import android.app.PendingIntent
import android.appwidget.AppWidgetManager
import android.appwidget.AppWidgetProvider
import android.content.Context
import android.content.Intent
import android.graphics.BitmapFactory
import android.util.Log
import android.widget.RemoteViews
import java.io.File

/**
 * Widget provider for quick BBS access from home screen.
 */
class BbsWidgetProvider : AppWidgetProvider() {

    override fun onUpdate(
        context: Context,
        appWidgetManager: AppWidgetManager,
        appWidgetIds: IntArray
    ) {
        // Update each widget instance
        for (appWidgetId in appWidgetIds) {
            try {
                updateWidget(context, appWidgetManager, appWidgetId)
            } catch (e: Exception) {
                Log.e(TAG, "Error updating widget $appWidgetId", e)
            }
        }
    }

    override fun onEnabled(context: Context) {
        super.onEnabled(context)
        Log.d(TAG, "Widget enabled")
    }

    override fun onDeleted(context: Context, appWidgetIds: IntArray) {
        // Clean up preferences for deleted widgets
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val editor = prefs.edit()
        for (appWidgetId in appWidgetIds) {
            editor.remove(PREF_PREFIX_KEY + appWidgetId)
        }
        editor.apply()
    }

    companion object {
        private const val TAG = "BbsWidgetProvider"
        const val PREFS_NAME = "widget_prefs"
        const val PREF_PREFIX_KEY = "widget_bbs_"

        /**
         * Update a single widget instance.
         */
        fun updateWidget(
            context: Context,
            appWidgetManager: AppWidgetManager,
            appWidgetId: Int
        ) {
            try {
                // Get the saved BBS config for this widget
                val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                val bbsData = prefs.getString(PREF_PREFIX_KEY + appWidgetId, null)

                val views = RemoteViews(context.packageName, R.layout.widget_bbs)

            if (bbsData != null) {
                // Parse stored data: "name|host|port|screenMode|font|reserved|hideStatusLine|thumbnailPath|protocol|username|encryptedPassword"
                val parts = bbsData.split("|")
                if (parts.size >= 3) {
                    val name = parts[0]
                    val host = parts[1]
                    val port = (parts[2].toIntOrNull() ?: 23).coerceIn(1, 65535)
                    val screenMode = (parts.getOrNull(3)?.toIntOrNull() ?: 0).coerceIn(0, 5)
                    val font = (parts.getOrNull(4)?.toIntOrNull() ?: 0).coerceAtLeast(0)
                    // Default to false (show status bar) - only hide if explicitly "true"
                    val hideStatusLine = parts.getOrNull(6)?.lowercase() == "true"
                    val thumbnailPath = parts.getOrNull(7)
                    val protocol = parts.getOrNull(8)?.toIntOrNull() ?: 0
                    val username = parts.getOrNull(9)?.takeIf { it.isNotEmpty() }
                    val encryptedPassword = parts.getOrNull(10)?.takeIf { it.isNotEmpty() }

                    views.setTextViewText(R.id.widgetBbsName, name)

                    // Load thumbnail if available, otherwise use default icon
                    if (thumbnailPath != null && thumbnailPath.isNotEmpty()) {
                        val file = File(thumbnailPath)
                        if (file.exists()) {
                            val bitmap = BitmapFactory.decodeFile(thumbnailPath)
                            if (bitmap != null) {
                                views.setImageViewBitmap(R.id.widgetIcon, bitmap)
                            } else {
                                views.setImageViewResource(R.id.widgetIcon, R.drawable.crt_screen_text)
                            }
                        } else {
                            views.setImageViewResource(R.id.widgetIcon, R.drawable.crt_screen_text)
                        }
                    } else {
                        views.setImageViewResource(R.id.widgetIcon, R.drawable.crt_screen_text)
                    }

                    // Create intent to launch terminal directly
                    val intent = Intent(context, TerminalActivity::class.java).apply {
                        putExtra(TerminalActivity.EXTRA_HOST, host)
                        putExtra(TerminalActivity.EXTRA_PORT, port)
                        putExtra(TerminalActivity.EXTRA_NAME, name)
                        putExtra(TerminalActivity.EXTRA_SCREEN_MODE, screenMode)
                        putExtra(TerminalActivity.EXTRA_FONT, font)
                        putExtra(TerminalActivity.EXTRA_HIDE_STATUS_LINE, hideStatusLine)
                        putExtra(TerminalActivity.EXTRA_PROTOCOL, protocol)
                        if (username != null) putExtra(TerminalActivity.EXTRA_USERNAME, username)
                        if (encryptedPassword != null) putExtra(TerminalActivity.EXTRA_PASSWORD, encryptedPassword)
                        flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
                    }

                    val pendingIntent = PendingIntent.getActivity(
                        context,
                        appWidgetId,  // Use widget ID as request code for uniqueness
                        intent,
                        PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
                    )

                    // Set click on entire widget root
                    views.setOnClickPendingIntent(R.id.widgetRoot, pendingIntent)
                }
            } else {
                views.setTextViewText(R.id.widgetBbsName, context.getString(R.string.widget_tap_to_setup))
                views.setImageViewResource(R.id.widgetIcon, R.drawable.crt_screen_text)

                // Set click to open config activity when unconfigured
                val configIntent = Intent(context, WidgetConfigActivity::class.java).apply {
                    putExtra(AppWidgetManager.EXTRA_APPWIDGET_ID, appWidgetId)
                    flags = Intent.FLAG_ACTIVITY_NEW_TASK
                }
                val configPendingIntent = PendingIntent.getActivity(
                    context,
                    appWidgetId + 10000,  // Different request code to avoid collision with connect intent
                    configIntent,
                    PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
                )
                views.setOnClickPendingIntent(R.id.widgetRoot, configPendingIntent)
            }

                appWidgetManager.updateAppWidget(appWidgetId, views)
            } catch (e: Exception) {
                Log.e(TAG, "Error in updateWidget for $appWidgetId", e)
            }
        }

        /**
         * Save widget configuration.
         */
        fun saveWidgetConfig(
            context: Context,
            appWidgetId: Int,
            name: String,
            host: String,
            port: Int,
            screenMode: Int,
            font: Int,
            hideStatusLine: Boolean,
            thumbnailPath: String? = null,
            protocol: Int = 0,
            username: String? = null,
            encryptedPassword: String? = null
        ) {
            val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            // Sanitize pipe characters to prevent delimiter injection
            val safeName = name.replace("|", "_")
            val safeHost = host.replace("|", "_")
            val safeThumbnail = thumbnailPath?.replace("|", "_") ?: ""
            val safeUsername = username?.replace("|", "_") ?: ""
            // encryptedPassword is Base64 (no pipes), but sanitize defensively
            val safePassword = encryptedPassword?.replace("|", "_") ?: ""
            // Position 5 kept as "100" for backward compatibility with existing widget configs
            val data = "$safeName|$safeHost|$port|$screenMode|$font|100|$hideStatusLine|$safeThumbnail|$protocol|$safeUsername|$safePassword"
            prefs.edit().putString(PREF_PREFIX_KEY + appWidgetId, data).apply()
        }
    }
}

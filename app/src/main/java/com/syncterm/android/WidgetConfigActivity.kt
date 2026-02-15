package com.syncterm.android

import android.appwidget.AppWidgetManager
import android.content.Intent
import android.content.pm.ActivityInfo
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.syncterm.android.databinding.ActivityWidgetConfigBinding

/**
 * Configuration activity for BBS widget.
 * Allows user to select which BBS connection the widget should launch.
 */
class WidgetConfigActivity : AppCompatActivity() {

    private lateinit var binding: ActivityWidgetConfigBinding
    private var appWidgetId = AppWidgetManager.INVALID_APPWIDGET_ID
    private val connections = mutableListOf<SavedConnection>()

    // Reuse SavedConnection from MainActivity
    data class SavedConnection(
        val name: String,
        val host: String,
        val port: Int,
        val screenMode: Int = 0,
        val font: Int = 0,
        val hideStatusLine: Boolean = false,
        val thumbnailPath: String? = null,
        val protocol: Int = 0,
        val username: String? = null,
        val encryptedPassword: String? = null
    )

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Set result to CANCELED in case user backs out
        setResult(RESULT_CANCELED)

        binding = ActivityWidgetConfigBinding.inflate(layoutInflater)
        setContentView(binding.root)

        applyOrientationSetting()

        // Get the widget ID from the intent
        appWidgetId = intent?.extras?.getInt(
            AppWidgetManager.EXTRA_APPWIDGET_ID,
            AppWidgetManager.INVALID_APPWIDGET_ID
        ) ?: AppWidgetManager.INVALID_APPWIDGET_ID

        if (appWidgetId == AppWidgetManager.INVALID_APPWIDGET_ID) {
            finish()
            return
        }

        // Load saved connections
        loadConnections()

        if (connections.isEmpty()) {
            Toast.makeText(this, R.string.widget_no_connections, Toast.LENGTH_LONG).show()
            finish()
            return
        }

        // Setup RecyclerView
        binding.connectionList.layoutManager = LinearLayoutManager(this)
        binding.connectionList.adapter = ConnectionAdapter(connections) { connection ->
            selectConnection(connection)
        }

        binding.btnCancel.setOnClickListener {
            finish()
        }
    }

    private fun loadConnections() {
        val prefs = getSharedPreferences("connections", MODE_PRIVATE)
        var count = prefs.getInt("count", 0)

        // Add default BBSs on first run
        if (count == 0) {
            addDefaultConnections()
            count = prefs.getInt("count", 0)
        }

        connections.clear()
        for (i in 0 until count) {
            val name = prefs.getString("name_$i", "") ?: ""
            val host = prefs.getString("host_$i", "") ?: ""
            val port = prefs.getInt("port_$i", 23).coerceIn(1, 65535)
            val screenMode = prefs.getInt("screenMode_$i", 0).coerceIn(0, 5)
            val font = prefs.getInt("font_$i", 0)
            val hideStatusLine = prefs.getBoolean("hideStatusLine_$i", false)
            val thumbnailPath = prefs.getString("thumbnailPath_$i", null)
            val protocol = prefs.getInt("protocol_$i", 0)
            val username = prefs.getString("username_$i", null)
            val encryptedPassword = prefs.getString("encryptedPassword_$i", null)

            if (name.isNotEmpty() && host.isNotEmpty()) {
                connections.add(SavedConnection(name, host, port, screenMode, font, hideStatusLine, thumbnailPath, protocol, username, encryptedPassword))
            }
        }
    }

    private fun addDefaultConnections() {
        val prefs = getSharedPreferences("connections", MODE_PRIVATE)
        val editor = prefs.edit()

        // aBSiNTHE BBS
        editor.putString("name_0", "aBSiNTHE BBS")
        editor.putString("host_0", "absinthebbs.net")
        editor.putInt("port_0", 1940)
        editor.putInt("screenMode_0", MainActivity.SavedConnection.SCREEN_MODE_80X40)
        editor.putInt("font_0", MainActivity.SavedConnection.FONT_TOPAZ_PLUS)
        editor.putBoolean("hideStatusLine_0", false)
        editor.putInt("protocol_0", 0)

        val snapshot0 = DefaultSnapshotHelper.copyDefaultSnapshot(this, "absinthebbs.net", 1940)
        if (snapshot0 != null) {
            editor.putString("thumbnailPath_0", snapshot0.first)
            editor.putString("snapshotPath_0", snapshot0.second)
        }

        // Dead Modem Society
        editor.putString("name_1", "Dead Modem Society")
        editor.putString("host_1", "telnet.deadmodemsociety.com")
        editor.putInt("port_1", 1337)
        editor.putInt("screenMode_1", 0)
        editor.putInt("font_1", MainActivity.SavedConnection.FONT_CP437)
        editor.putBoolean("hideStatusLine_1", false)
        editor.putInt("protocol_1", 0)

        val snapshot1 = DefaultSnapshotHelper.copyDefaultSnapshot(this, "telnet.deadmodemsociety.com", 1337)
        if (snapshot1 != null) {
            editor.putString("thumbnailPath_1", snapshot1.first)
            editor.putString("snapshotPath_1", snapshot1.second)
        }

        editor.putInt("count", 2)
        editor.apply()
    }

    private fun selectConnection(connection: SavedConnection) {
        // Save widget configuration
        BbsWidgetProvider.saveWidgetConfig(
            this,
            appWidgetId,
            connection.name,
            connection.host,
            connection.port,
            connection.screenMode,
            connection.font,
            connection.hideStatusLine,
            connection.thumbnailPath,
            connection.protocol,
            connection.username,
            connection.encryptedPassword
        )

        // Update the widget
        val appWidgetManager = AppWidgetManager.getInstance(this)
        BbsWidgetProvider.updateWidget(this, appWidgetManager, appWidgetId)

        // Return success
        val resultIntent = Intent().apply {
            putExtra(AppWidgetManager.EXTRA_APPWIDGET_ID, appWidgetId)
        }
        setResult(RESULT_OK, resultIntent)
        finish()
    }

    private fun applyOrientationSetting() {
        val prefs = getSharedPreferences(SettingsActivity.PREFS_NAME, MODE_PRIVATE)
        val orientationSetting = prefs.getInt(SettingsActivity.KEY_ORIENTATION, 0)
        requestedOrientation = when (orientationSetting) {
            1 -> ActivityInfo.SCREEN_ORIENTATION_LANDSCAPE
            else -> ActivityInfo.SCREEN_ORIENTATION_PORTRAIT
        }
    }

    /**
     * Simple adapter for connection list.
     */
    private class ConnectionAdapter(
        private val connections: List<SavedConnection>,
        private val onItemClick: (SavedConnection) -> Unit
    ) : RecyclerView.Adapter<ConnectionAdapter.ViewHolder>() {

        class ViewHolder(view: View) : RecyclerView.ViewHolder(view) {
            val nameText: TextView = view.findViewById(android.R.id.text1)
            val hostText: TextView = view.findViewById(android.R.id.text2)
        }

        override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
            val view = LayoutInflater.from(parent.context).inflate(
                android.R.layout.simple_list_item_2,
                parent,
                false
            )
            // Style for dark theme
            view.setBackgroundColor(0xFF2A2A3E.toInt())
            view.findViewById<TextView>(android.R.id.text1).setTextColor(0xFF00FF00.toInt())
            view.findViewById<TextView>(android.R.id.text2).setTextColor(0xFFAAAAAA.toInt())
            return ViewHolder(view)
        }

        override fun onBindViewHolder(holder: ViewHolder, position: Int) {
            val connection = connections[position]
            holder.nameText.text = connection.name
            holder.hostText.text = "${connection.host}:${connection.port}"
            holder.itemView.setOnClickListener { onItemClick(connection) }
        }

        override fun getItemCount() = connections.size
    }
}

package com.syncterm.android

import android.app.Dialog
import android.content.Intent
import android.content.pm.ActivityInfo
import android.graphics.BitmapFactory
import android.graphics.Color
import android.graphics.drawable.ColorDrawable
import android.os.Bundle
import android.view.LayoutInflater
import android.view.Menu
import android.view.MenuItem
import android.view.View
import android.view.ViewGroup
import android.view.Window
import android.widget.Button
import android.widget.TextView
import android.widget.Toast
import android.text.method.LinkMovementMethod
import android.text.util.Linkify
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.syncterm.android.databinding.ActivityHomeBinding
import java.io.File

/**
 * Home screen activity with splash background and navigation buttons.
 */
class HomeActivity : AppCompatActivity() {

    private lateinit var binding: ActivityHomeBinding

    companion object {
        const val PREFS_QUICK_CONNECT = "quick_connect"
        const val KEY_QUICK_CONNECT_1_NAME = "quick_connect_1_name"
        const val KEY_QUICK_CONNECT_1_HOST = "quick_connect_1_host"
        const val KEY_QUICK_CONNECT_1_PORT = "quick_connect_1_port"
        const val KEY_QUICK_CONNECT_1_SCREEN_MODE = "quick_connect_1_screen_mode"
        const val KEY_QUICK_CONNECT_1_FONT = "quick_connect_1_font"
        const val KEY_QUICK_CONNECT_1_PROTOCOL = "quick_connect_1_protocol"
        const val KEY_QUICK_CONNECT_1_USERNAME = "quick_connect_1_username"
        const val KEY_QUICK_CONNECT_1_PASSWORD = "quick_connect_1_password"
        const val KEY_QUICK_CONNECT_1_THUMBNAIL = "quick_connect_1_thumbnail"

        const val KEY_QUICK_CONNECT_2_NAME = "quick_connect_2_name"
        const val KEY_QUICK_CONNECT_2_HOST = "quick_connect_2_host"
        const val KEY_QUICK_CONNECT_2_PORT = "quick_connect_2_port"
        const val KEY_QUICK_CONNECT_2_SCREEN_MODE = "quick_connect_2_screen_mode"
        const val KEY_QUICK_CONNECT_2_FONT = "quick_connect_2_font"
        const val KEY_QUICK_CONNECT_2_PROTOCOL = "quick_connect_2_protocol"
        const val KEY_QUICK_CONNECT_2_USERNAME = "quick_connect_2_username"
        const val KEY_QUICK_CONNECT_2_PASSWORD = "quick_connect_2_password"
        const val KEY_QUICK_CONNECT_2_THUMBNAIL = "quick_connect_2_thumbnail"
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        binding = ActivityHomeBinding.inflate(layoutInflater)
        setContentView(binding.root)

        // Setup toolbar for menu
        setSupportActionBar(binding.toolbar)
        supportActionBar?.setDisplayShowTitleEnabled(false)

        // Set version number
        val versionName = packageManager.getPackageInfo(packageName, 0).versionName
        binding.textVersion.text = "v$versionName"

        // Start the CRT marquee scrolling text
        binding.marqueeText?.setText(getString(R.string.marquee_text))
        binding.marqueeText?.startScrolling()

        // Apply orientation from settings
        applyOrientationSetting()

        // Ensure default phonebook connections exist before any Quick Connect interaction
        ensureDefaultConnections()

        // Handle telnet:// URLs - forward to terminal
        handleIntent(intent)

        // Setup button click listeners
        setupButtons()

        // Update quick connect button labels
        updateQuickConnectButtons()

        // Start glitch effect after layout
        binding.splashBackgroundContainer.post {
            binding.splashBackground.enableGlitch()
        }
    }

    override fun onResume() {
        super.onResume()
        applyOrientationSetting()
        updateQuickConnectButtons()

        // Restart glitch effect
        binding.splashBackground.enableGlitch()
    }

    override fun onPause() {
        super.onPause()
        binding.splashBackground.disableGlitch()
    }

    override fun onDestroy() {
        super.onDestroy()
        binding.splashBackground.disableGlitch()
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        handleIntent(intent)
    }

    private fun handleIntent(intent: Intent) {
        val data = intent.data
        if (data != null && data.scheme == "telnet") {
            val host = data.host ?: return
            val port = if (data.port > 0) data.port else 23
            launchTerminal("Quick Connect", host, port)
        }
    }

    private fun setupButtons() {
        // Quick Connect 1 - click to connect (or assign if empty), long-press to clear
        binding.quickConnect1Container.setOnClickListener {
            launchQuickConnect(1)
        }
        binding.quickConnect1Container.setOnLongClickListener {
            handleQuickConnectLongPress(1)
            true
        }

        // Quick Connect 2 - click to connect (or assign if empty), long-press to clear
        binding.quickConnect2Container.setOnClickListener {
            launchQuickConnect(2)
        }
        binding.quickConnect2Container.setOnLongClickListener {
            handleQuickConnectLongPress(2)
            true
        }

        binding.buttonPhonebook.setOnClickListener {
            startActivity(Intent(this, MainActivity::class.java))
        }

        binding.buttonSettings.setOnClickListener {
            startActivity(Intent(this, SettingsActivity::class.java))
        }
    }

    /**
     * Handle long press on Quick Connect button.
     * Only used when assigned - shows clear dialog.
     */
    private fun handleQuickConnectLongPress(slot: Int) {
        val prefs = getSharedPreferences(PREFS_QUICK_CONNECT, MODE_PRIVATE)
        val nameKey = if (slot == 1) KEY_QUICK_CONNECT_1_NAME else KEY_QUICK_CONNECT_2_NAME
        val name = prefs.getString(nameKey, null)

        if (name != null) {
            // Assigned - show clear dialog
            showClearQuickConnectDialog(slot, name)
        }
        // If empty, do nothing - single click handles showing the picker
    }

    /**
     * Show BBS picker dialog to select a BBS for Quick Connect.
     */
    private fun showBbsPickerDialog(slot: Int) {
        val connections = loadConnections()

        val dialog = Dialog(this)
        dialog.requestWindowFeature(Window.FEATURE_NO_TITLE)
        dialog.setContentView(R.layout.dialog_bbs_picker)
        dialog.window?.setBackgroundDrawable(ColorDrawable(Color.TRANSPARENT))

        val dialogTitle = dialog.findViewById<TextView>(R.id.dialogTitle)
        val recyclerView = dialog.findViewById<RecyclerView>(R.id.recyclerBbsList)
        val textEmpty = dialog.findViewById<TextView>(R.id.textEmpty)
        val buttonCancel = dialog.findViewById<Button>(R.id.buttonCancel)

        dialogTitle.text = getString(R.string.quick_connect_slot_1).let {
            if (slot == 1) getString(R.string.quick_connect_slot_1) else getString(R.string.quick_connect_slot_2)
        }

        if (connections.isEmpty()) {
            recyclerView.visibility = View.GONE
            textEmpty.visibility = View.VISIBLE
        } else {
            recyclerView.visibility = View.VISIBLE
            textEmpty.visibility = View.GONE

            recyclerView.layoutManager = LinearLayoutManager(this)
            recyclerView.adapter = BbsPickerAdapter(connections) { connection ->
                dialog.dismiss()
                assignQuickConnect(connection, slot)
            }
        }

        buttonCancel.setOnClickListener {
            dialog.dismiss()
        }

        dialog.show()

        // Set dialog width to 85% of screen width
        dialog.window?.setLayout(
            (resources.displayMetrics.widthPixels * 0.85).toInt(),
            android.view.WindowManager.LayoutParams.WRAP_CONTENT
        )
    }

    /**
     * Ensure default phonebook connections exist on first run.
     * Called early in onCreate so connections are ready before Quick Connect.
     */
    private fun ensureDefaultConnections() {
        val prefs = getSharedPreferences("connections", MODE_PRIVATE)
        if (prefs.getInt("count", 0) == 0) {
            addDefaultConnections()
        }
    }

    /**
     * Load saved connections from SharedPreferences.
     */
    private fun loadConnections(): List<MainActivity.SavedConnection> {
        val prefs = getSharedPreferences("connections", MODE_PRIVATE)
        val count = prefs.getInt("count", 0)
        val connections = mutableListOf<MainActivity.SavedConnection>()

        for (i in 0 until count) {
            val name = prefs.getString("name_$i", null) ?: continue
            val host = prefs.getString("host_$i", null) ?: continue
            val port = prefs.getInt("port_$i", 23)
            val screenMode = prefs.getInt("screenMode_$i", MainActivity.SavedConnection.SCREEN_MODE_80X25)
            val font = prefs.getInt("font_$i", MainActivity.SavedConnection.FONT_CP437)
            val hideStatusLine = prefs.getBoolean("hideStatusLine_$i", false)
            val thumbnailPath = prefs.getString("thumbnailPath_$i", null)
            val snapshotPath = prefs.getString("snapshotPath_$i", null)
            val protocol = prefs.getInt("protocol_$i", MainActivity.SavedConnection.PROTOCOL_TELNET)
            val username = prefs.getString("username_$i", null)
            val encryptedPassword = prefs.getString("encryptedPassword_$i", null)

            connections.add(MainActivity.SavedConnection(
                name = name,
                host = host,
                port = port,
                screenMode = screenMode,
                font = font,
                hideStatusLine = hideStatusLine,
                thumbnailPath = thumbnailPath,
                snapshotPath = snapshotPath,
                protocol = protocol,
                username = username,
                encryptedPassword = encryptedPassword
            ))
        }

        return connections
    }

    /**
     * Add default BBS connections on first run.
     */
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
        editor.putInt("protocol_0", MainActivity.SavedConnection.PROTOCOL_TELNET)

        // Copy default snapshot for aBSiNTHE
        val snapshot0 = DefaultSnapshotHelper.copyDefaultSnapshot(this, "absinthebbs.net", 1940)
        if (snapshot0 != null) {
            editor.putString("thumbnailPath_0", snapshot0.first)
            editor.putString("snapshotPath_0", snapshot0.second)
        }

        // Dead Modem Society
        editor.putString("name_1", "Dead Modem Society")
        editor.putString("host_1", "telnet.deadmodemsociety.com")
        editor.putInt("port_1", 1337)
        editor.putInt("screenMode_1", MainActivity.SavedConnection.SCREEN_MODE_80X25)
        editor.putInt("font_1", MainActivity.SavedConnection.FONT_CP437)
        editor.putBoolean("hideStatusLine_1", false)
        editor.putInt("protocol_1", MainActivity.SavedConnection.PROTOCOL_TELNET)

        // Copy default snapshot for Dead Modem Society
        val snapshot1 = DefaultSnapshotHelper.copyDefaultSnapshot(this, "telnet.deadmodemsociety.com", 1337)
        if (snapshot1 != null) {
            editor.putString("thumbnailPath_1", snapshot1.first)
            editor.putString("snapshotPath_1", snapshot1.second)
        }

        editor.putInt("count", 2)
        editor.commit()
    }

    /**
     * Assign a connection to a Quick Connect slot.
     */
    private fun assignQuickConnect(connection: MainActivity.SavedConnection, slot: Int) {
        val prefs = getSharedPreferences(PREFS_QUICK_CONNECT, MODE_PRIVATE)
        val editor = prefs.edit()

        val prefix = if (slot == 1) "quick_connect_1_" else "quick_connect_2_"

        editor.putString("${prefix}name", connection.name)
        editor.putString("${prefix}host", connection.host)
        editor.putInt("${prefix}port", connection.port)
        editor.putInt("${prefix}screen_mode", connection.screenMode)
        editor.putInt("${prefix}font", connection.font)
        editor.putBoolean("${prefix}hide_status_line", connection.hideStatusLine)
        editor.putInt("${prefix}protocol", connection.protocol)
        if (connection.username != null) {
            editor.putString("${prefix}username", connection.username)
        } else {
            editor.remove("${prefix}username")
        }
        if (connection.encryptedPassword != null) {
            editor.putString("${prefix}password", connection.encryptedPassword)
        } else {
            editor.remove("${prefix}password")
        }
        if (connection.thumbnailPath != null) {
            editor.putString("${prefix}thumbnail", connection.thumbnailPath)
        } else {
            editor.remove("${prefix}thumbnail")
        }

        editor.apply()

        Toast.makeText(
            this,
            getString(R.string.quick_connect_assigned, connection.name, slot),
            Toast.LENGTH_SHORT
        ).show()

        updateQuickConnectButtons()
    }

    /**
     * Show dialog to confirm clearing a Quick Connect slot.
     */
    private fun showClearQuickConnectDialog(slot: Int, name: String) {
        val dialog = Dialog(this)
        dialog.requestWindowFeature(Window.FEATURE_NO_TITLE)
        dialog.setContentView(R.layout.dialog_quick_connect)
        dialog.window?.setBackgroundDrawable(ColorDrawable(Color.TRANSPARENT))

        val dialogTitle = dialog.findViewById<TextView>(R.id.dialogTitle)
        val textBbsName = dialog.findViewById<TextView>(R.id.textBbsName)
        val buttonSlot1 = dialog.findViewById<Button>(R.id.buttonSlot1)
        val buttonSlot2 = dialog.findViewById<Button>(R.id.buttonSlot2)
        val buttonCancel = dialog.findViewById<Button>(R.id.buttonCancel)

        dialogTitle.text = getString(R.string.quick_connect_clear, slot)
        textBbsName.text = getString(R.string.quick_connect_clear_confirm, name, slot)

        // Hide the slot buttons and repurpose for Clear/Cancel
        buttonSlot1.text = getString(R.string.delete)
        buttonSlot1.setBackgroundResource(R.drawable.retro_button_danger)
        buttonSlot1.setTextColor(resources.getColor(R.color.term_light_red, null))
        buttonSlot2.visibility = View.GONE

        buttonSlot1.setOnClickListener {
            dialog.dismiss()
            clearQuickConnect(slot)
        }

        buttonCancel.setOnClickListener {
            dialog.dismiss()
        }

        dialog.show()

        dialog.window?.setLayout(
            (resources.displayMetrics.widthPixels * 0.85).toInt(),
            android.view.WindowManager.LayoutParams.WRAP_CONTENT
        )
    }

    /**
     * Simple RecyclerView adapter for the BBS picker.
     */
    private inner class BbsPickerAdapter(
        private val connections: List<MainActivity.SavedConnection>,
        private val onItemClick: (MainActivity.SavedConnection) -> Unit
    ) : RecyclerView.Adapter<BbsPickerAdapter.ViewHolder>() {

        inner class ViewHolder(itemView: View) : RecyclerView.ViewHolder(itemView) {
            val textName: TextView = itemView.findViewById(R.id.textBbsName)
            val textHost: TextView = itemView.findViewById(R.id.textBbsHost)
        }

        override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
            val view = LayoutInflater.from(parent.context)
                .inflate(R.layout.item_bbs_picker, parent, false)
            return ViewHolder(view)
        }

        override fun onBindViewHolder(holder: ViewHolder, position: Int) {
            val connection = connections[position]
            holder.textName.text = connection.name
            holder.textHost.text = "${connection.host}:${connection.port}"
            holder.itemView.setOnClickListener {
                onItemClick(connection)
            }
        }

        override fun getItemCount() = connections.size
    }

    /**
     * Clear a Quick Connect slot.
     */
    private fun clearQuickConnect(slot: Int) {
        val prefs = getSharedPreferences(PREFS_QUICK_CONNECT, MODE_PRIVATE)
        val editor = prefs.edit()

        val prefix = if (slot == 1) "quick_connect_1_" else "quick_connect_2_"

        editor.remove("${prefix}name")
        editor.remove("${prefix}host")
        editor.remove("${prefix}port")
        editor.remove("${prefix}screen_mode")
        editor.remove("${prefix}font")
        editor.remove("${prefix}hide_status_line")
        editor.remove("${prefix}protocol")
        editor.remove("${prefix}username")
        editor.remove("${prefix}password")
        editor.remove("${prefix}thumbnail")

        editor.apply()

        Toast.makeText(this, getString(R.string.quick_connect_cleared, slot), Toast.LENGTH_SHORT).show()
        updateQuickConnectButtons()
    }

    private fun updateQuickConnectButtons() {
        val prefs = getSharedPreferences(PREFS_QUICK_CONNECT, MODE_PRIVATE)

        // Quick Connect 1
        val name1 = prefs.getString(KEY_QUICK_CONNECT_1_NAME, null)
        val thumbnail1 = prefs.getString(KEY_QUICK_CONNECT_1_THUMBNAIL, null)
        updateQuickConnectSlot(
            name1,
            thumbnail1,
            binding.quickConnect1Container,
            binding.imageQuickConnect1,
            binding.layoutQuickConnect1,
            binding.textQuickConnect1Name,
            binding.textQuickConnect1,
            getString(R.string.quick_connect_1_default)
        )

        // Quick Connect 2
        val name2 = prefs.getString(KEY_QUICK_CONNECT_2_NAME, null)
        val thumbnail2 = prefs.getString(KEY_QUICK_CONNECT_2_THUMBNAIL, null)
        updateQuickConnectSlot(
            name2,
            thumbnail2,
            binding.quickConnect2Container,
            binding.imageQuickConnect2,
            binding.layoutQuickConnect2,
            binding.textQuickConnect2Name,
            binding.textQuickConnect2,
            getString(R.string.quick_connect_2_default)
        )
    }

    /**
     * Update a Quick Connect slot's display:
     * - No BBS assigned: Show default text with border
     * - BBS assigned with snapshot: Show snapshot image without border
     * - BBS assigned without snapshot: Show icon + name with border
     */
    private fun updateQuickConnectSlot(
        name: String?,
        thumbnailPath: String?,
        container: View,
        imageView: android.widget.ImageView,
        iconLayout: android.widget.LinearLayout,
        nameTextView: android.widget.TextView,
        defaultTextView: android.widget.TextView,
        defaultText: String
    ) {
        // Hide all by default
        imageView.visibility = View.GONE
        iconLayout.visibility = View.GONE
        defaultTextView.visibility = View.GONE

        if (name == null) {
            // No BBS assigned - show default text with border
            container.setBackgroundResource(R.drawable.retro_button_primary)
            defaultTextView.visibility = View.VISIBLE
            defaultTextView.text = defaultText
        } else {
            // BBS assigned - try to load thumbnail
            var showImage = false
            if (thumbnailPath != null) {
                val file = File(thumbnailPath)
                if (file.exists()) {
                    val bitmap = BitmapFactory.decodeFile(thumbnailPath)
                    if (bitmap != null) {
                        imageView.setImageBitmap(bitmap)
                        showImage = true
                    }
                }
            }

            if (showImage) {
                // Show snapshot image - hide border for clean look
                container.setBackgroundColor(android.graphics.Color.BLACK)
                imageView.visibility = View.VISIBLE
            } else {
                // Show icon + name with border
                container.setBackgroundResource(R.drawable.retro_button_primary)
                iconLayout.visibility = View.VISIBLE
                nameTextView.text = name
            }
        }
    }

    private fun launchQuickConnect(slot: Int) {
        val prefs = getSharedPreferences(PREFS_QUICK_CONNECT, MODE_PRIVATE)

        val nameKey = if (slot == 1) KEY_QUICK_CONNECT_1_NAME else KEY_QUICK_CONNECT_2_NAME
        val hostKey = if (slot == 1) KEY_QUICK_CONNECT_1_HOST else KEY_QUICK_CONNECT_2_HOST
        val portKey = if (slot == 1) KEY_QUICK_CONNECT_1_PORT else KEY_QUICK_CONNECT_2_PORT
        val screenModeKey = if (slot == 1) KEY_QUICK_CONNECT_1_SCREEN_MODE else KEY_QUICK_CONNECT_2_SCREEN_MODE
        val fontKey = if (slot == 1) KEY_QUICK_CONNECT_1_FONT else KEY_QUICK_CONNECT_2_FONT
        val protocolKey = if (slot == 1) KEY_QUICK_CONNECT_1_PROTOCOL else KEY_QUICK_CONNECT_2_PROTOCOL
        val usernameKey = if (slot == 1) KEY_QUICK_CONNECT_1_USERNAME else KEY_QUICK_CONNECT_2_USERNAME
        val passwordKey = if (slot == 1) KEY_QUICK_CONNECT_1_PASSWORD else KEY_QUICK_CONNECT_2_PASSWORD

        val name = prefs.getString(nameKey, null)
        val host = prefs.getString(hostKey, null)

        if (name == null || host == null) {
            // No BBS assigned - show picker to assign one
            showBbsPickerDialog(slot)
            return
        }

        val port = prefs.getInt(portKey, 23).coerceIn(1, 65535)
        val screenMode = prefs.getInt(screenModeKey, MainActivity.SavedConnection.SCREEN_MODE_80X25).coerceIn(0, 5)
        val font = prefs.getInt(fontKey, MainActivity.SavedConnection.FONT_CP437)
        val prefix = if (slot == 1) "quick_connect_1_" else "quick_connect_2_"
        val hideStatusLine = prefs.getBoolean("${prefix}hide_status_line", false)
        val protocol = prefs.getInt(protocolKey, MainActivity.SavedConnection.PROTOCOL_TELNET)
        val username = prefs.getString(usernameKey, null)
        val encryptedPassword = prefs.getString(passwordKey, null)

        launchTerminal(name, host, port, screenMode, font, hideStatusLine, protocol = protocol, username = username, encryptedPassword = encryptedPassword)
    }

    private fun launchTerminal(
        name: String,
        host: String,
        port: Int,
        screenMode: Int = MainActivity.SavedConnection.SCREEN_MODE_80X25,
        font: Int = MainActivity.SavedConnection.FONT_CP437,
        hideStatusLine: Boolean = false,
        protocol: Int = MainActivity.SavedConnection.PROTOCOL_TELNET,
        username: String? = null,
        encryptedPassword: String? = null
    ) {
        val intent = Intent(this, TerminalActivity::class.java).apply {
            putExtra(TerminalActivity.EXTRA_NAME, name)
            putExtra(TerminalActivity.EXTRA_HOST, host)
            putExtra(TerminalActivity.EXTRA_PORT, port)
            putExtra(TerminalActivity.EXTRA_SCREEN_MODE, screenMode)
            putExtra(TerminalActivity.EXTRA_FONT, font)
            putExtra(TerminalActivity.EXTRA_HIDE_STATUS_LINE, hideStatusLine)
            putExtra(TerminalActivity.EXTRA_PROTOCOL, protocol)
            if (username != null) putExtra(TerminalActivity.EXTRA_USERNAME, username)
            if (encryptedPassword != null) putExtra(TerminalActivity.EXTRA_PASSWORD, encryptedPassword)
        }
        startActivity(intent)
    }

    private fun applyOrientationSetting() {
        val prefs = getSharedPreferences(SettingsActivity.PREFS_NAME, MODE_PRIVATE)
        val orientationSetting = prefs.getInt(SettingsActivity.KEY_ORIENTATION, 0)
        requestedOrientation = when (orientationSetting) {
            1 -> ActivityInfo.SCREEN_ORIENTATION_LANDSCAPE
            else -> ActivityInfo.SCREEN_ORIENTATION_PORTRAIT
        }
    }

    override fun onCreateOptionsMenu(menu: Menu): Boolean {
        menuInflater.inflate(R.menu.menu_main, menu)
        return true
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        return when (item.itemId) {
            R.id.action_settings -> {
                startActivity(Intent(this, SettingsActivity::class.java))
                true
            }
            R.id.action_help -> {
                showHelpDialog()
                true
            }
            R.id.action_changelog -> {
                showChangelogDialog()
                true
            }
            R.id.action_about -> {
                showAboutDialog()
                true
            }
            else -> super.onOptionsItemSelected(item)
        }
    }

    /**
     * Show the Help dialog with usage instructions.
     */
    private fun showHelpDialog() {
        AlertDialog.Builder(this)
            .setTitle(R.string.help_title)
            .setMessage(android.text.Html.fromHtml(getString(R.string.help_content), android.text.Html.FROM_HTML_MODE_COMPACT))
            .setPositiveButton(android.R.string.ok, null)
            .show()
    }

    /**
     * Show the Changelog dialog.
     */
    private fun showChangelogDialog() {
        AlertDialog.Builder(this)
            .setTitle(R.string.changelog_title)
            .setMessage(android.text.Html.fromHtml(getString(R.string.changelog_content), android.text.Html.FROM_HTML_MODE_COMPACT))
            .setPositiveButton(android.R.string.ok, null)
            .show()
    }

    /**
     * Show the About dialog with app information.
     */
    private fun showAboutDialog() {
        val dialog = AlertDialog.Builder(this)
            .setTitle(R.string.about_title)
            .setMessage(R.string.about_description)
            .setPositiveButton(android.R.string.ok, null)
            .show()

        // Make URLs clickable
        dialog.findViewById<TextView>(android.R.id.message)?.apply {
            Linkify.addLinks(this, Linkify.WEB_URLS)
            movementMethod = LinkMovementMethod.getInstance()
        }
    }
}

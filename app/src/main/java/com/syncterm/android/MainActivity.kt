package com.syncterm.android

import android.app.Activity
import android.app.Dialog
import android.content.Intent
import android.content.pm.ActivityInfo
import android.graphics.BitmapFactory
import android.graphics.Color
import android.graphics.drawable.ColorDrawable
import java.io.File
import android.net.Uri
import android.os.Bundle
import android.view.LayoutInflater
import android.view.Menu
import android.view.MenuItem
import android.view.View
import android.view.Window
import android.widget.ArrayAdapter
import android.widget.Button
import android.widget.EditText
import android.widget.Spinner
import android.widget.TextView
import android.widget.Toast
import android.text.method.LinkMovementMethod
import android.text.util.Linkify
import androidx.activity.result.ActivityResultLauncher
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.ItemTouchHelper
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.syncterm.android.databinding.ActivityMainBinding
import org.xmlpull.v1.XmlPullParser
import org.xmlpull.v1.XmlPullParserFactory
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.StringWriter
import java.util.Collections
import java.util.zip.ZipEntry
import java.util.zip.ZipInputStream
import java.util.zip.ZipOutputStream

/**
 * Phonebook activity showing the list of saved BBS connections.
 * Long-press a connection to assign it to Quick Connect 1 or 2.
 */
class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    private lateinit var connectionAdapter: ConnectionAdapter
    private lateinit var fileAccessManager: FileAccessManager
    private val connectionList = mutableListOf<SavedConnection>()

    // Placeholder shown when an encrypted password exists (8 dots)
    private val PASSWORD_PLACEHOLDER = "••••••••"

    // Activity result launcher for settings
    private lateinit var settingsLauncher: ActivityResultLauncher<Intent>

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Initialize file access manager for download folder selection
        // Must be done before setContentView for activity result launchers
        fileAccessManager = FileAccessManager(this)
        fileAccessManager.registerLaunchers()

        // Register settings launcher
        registerSettingsLauncher()

        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        setSupportActionBar(binding.toolbar)
        supportActionBar?.setDisplayShowTitleEnabled(false)  // Using image header instead

        setupRecyclerView()
        setupFab()
        loadConnections()

        // Apply orientation from settings
        applyOrientationSetting()

        // Prompt for download folder if not set (first run)
        checkDownloadFolderOnFirstRun()
    }

    /**
     * Check if download folder is configured, prompt user if not.
     */
    private fun checkDownloadFolderOnFirstRun() {
        if (!fileAccessManager.hasUserSelectedDownloadDirectory()) {
            // Show dialog explaining why we need a download folder
            AlertDialog.Builder(this)
                .setTitle(R.string.download_folder_title)
                .setMessage(R.string.download_folder_prompt)
                .setPositiveButton(R.string.select_folder) { _, _ ->
                    selectDownloadFolder()
                }
                .setNegativeButton(R.string.later, null)
                .show()
        }
    }

    override fun onResume() {
        super.onResume()
        // Apply orientation setting in case it was changed in settings
        applyOrientationSetting()
        // Reload connections to pick up any thumbnail changes from terminal snapshots
        loadConnections()
    }

    private fun setupRecyclerView() {
        connectionAdapter = ConnectionAdapter(
            onItemClick = { connection ->
                showConnectionDetailsDialog(connection)
            },
            onItemLongClick = { connection ->
                // Long press also opens details dialog (same as tap)
                showConnectionDetailsDialog(connection)
            }
        )

        binding.recyclerView.apply {
            layoutManager = LinearLayoutManager(this@MainActivity)
            adapter = connectionAdapter
        }

        // Add drag-to-reorder only (no swipe)
        val itemTouchHelper = ItemTouchHelper(object : ItemTouchHelper.SimpleCallback(
            ItemTouchHelper.UP or ItemTouchHelper.DOWN,  // Drag directions
            0  // No swipe
        ) {
            override fun onMove(
                recyclerView: RecyclerView,
                viewHolder: RecyclerView.ViewHolder,
                target: RecyclerView.ViewHolder
            ): Boolean {
                val fromPos = viewHolder.bindingAdapterPosition
                val toPos = target.bindingAdapterPosition

                if (fromPos == RecyclerView.NO_POSITION || toPos == RecyclerView.NO_POSITION) {
                    return false
                }

                // Swap items in the list
                Collections.swap(connectionList, fromPos, toPos)
                connectionAdapter.notifyItemMoved(fromPos, toPos)
                saveConnections()
                return true
            }

            override fun onSwiped(viewHolder: RecyclerView.ViewHolder, direction: Int) {
                // Not used - swipe disabled
            }
        })

        itemTouchHelper.attachToRecyclerView(binding.recyclerView)
    }

    private fun setupFab() {
        binding.fab.setOnClickListener {
            showNewConnectionDialog()
        }
        binding.fabHome.setOnClickListener {
            // Go back to Home screen
            finish()
        }
    }

    private fun loadConnections() {
        // Load saved connections from SharedPreferences
        val prefs = getSharedPreferences("connections", MODE_PRIVATE)
        val count = prefs.getInt("count", 0)

        connectionList.clear()

        // Add some default BBSes if first run
        if (count == 0) {
            addDefaultConnections()
        } else {
            for (i in 0 until count) {
                val name = prefs.getString("name_$i", "") ?: ""
                val host = prefs.getString("host_$i", "") ?: ""
                val port = prefs.getInt("port_$i", 23).coerceIn(1, 65535)  // Validate port range
                val screenMode = prefs.getInt("screenMode_$i", SavedConnection.SCREEN_MODE_80X25)
                val font = prefs.getInt("font_$i", SavedConnection.FONT_CP437)
                val hideStatusLine = prefs.getBoolean("hideStatusLine_$i", false)
                val thumbnailPath = prefs.getString("thumbnailPath_$i", null)
                val snapshotPath = prefs.getString("snapshotPath_$i", null)
                val protocol = prefs.getInt("protocol_$i", SavedConnection.PROTOCOL_TELNET)
                val username = prefs.getString("username_$i", null)
                val encryptedPassword = prefs.getString("encryptedPassword_$i", null)
                if (name.isNotEmpty() && host.isNotEmpty()) {
                    connectionList.add(SavedConnection(name, host, port, screenMode, font, hideStatusLine, thumbnailPath, snapshotPath, protocol, username, encryptedPassword))
                }
            }
        }

        connectionAdapter.submitList(connectionList.toList())
        updateEmptyState()
    }

    private fun addDefaultConnections() {
        // Add some well-known BBSes
        val snapshot0 = DefaultSnapshotHelper.copyDefaultSnapshot(this, "absinthebbs.net", 1940)
        connectionList.add(SavedConnection(
            name = "aBSiNTHE BBS",
            host = "absinthebbs.net",
            port = 1940,
            screenMode = SavedConnection.SCREEN_MODE_80X40,
            font = SavedConnection.FONT_TOPAZ_PLUS,  // Topaz Plus (Amiga) for aBSiNTHE
            thumbnailPath = snapshot0?.first,
            snapshotPath = snapshot0?.second
        ))
        val snapshot1 = DefaultSnapshotHelper.copyDefaultSnapshot(this, "telnet.deadmodemsociety.com", 1337)
        connectionList.add(SavedConnection(
            name = "Dead Modem Society",
            host = "telnet.deadmodemsociety.com",
            port = 1337,
            screenMode = SavedConnection.SCREEN_MODE_80X25,
            font = SavedConnection.FONT_CP437,
            thumbnailPath = snapshot1?.first,
            snapshotPath = snapshot1?.second
        ))
        saveConnections()
        connectionAdapter.submitList(connectionList.toList())
    }

    private fun saveConnections() {
        val prefs = getSharedPreferences("connections", MODE_PRIVATE)
        val editor = prefs.edit()

        editor.putInt("count", connectionList.size)
        connectionList.forEachIndexed { index, connection ->
            editor.putString("name_$index", connection.name)
            editor.putString("host_$index", connection.host)
            editor.putInt("port_$index", connection.port)
            editor.putInt("screenMode_$index", connection.screenMode)
            editor.putInt("font_$index", connection.font)
            editor.putBoolean("hideStatusLine_$index", connection.hideStatusLine)
            if (connection.thumbnailPath != null) {
                editor.putString("thumbnailPath_$index", connection.thumbnailPath)
            } else {
                editor.remove("thumbnailPath_$index")
            }
            if (connection.snapshotPath != null) {
                editor.putString("snapshotPath_$index", connection.snapshotPath)
            } else {
                editor.remove("snapshotPath_$index")
            }
            editor.putInt("protocol_$index", connection.protocol)
            if (connection.username != null) {
                editor.putString("username_$index", connection.username)
            } else {
                editor.remove("username_$index")
            }
            if (connection.encryptedPassword != null) {
                editor.putString("encryptedPassword_$index", connection.encryptedPassword)
            } else {
                editor.remove("encryptedPassword_$index")
            }
        }

        editor.apply()
    }

    private fun updateEmptyState() {
        if (connectionList.isEmpty()) {
            binding.emptyView.visibility = View.VISIBLE
            binding.recyclerView.visibility = View.GONE
        } else {
            binding.emptyView.visibility = View.GONE
            binding.recyclerView.visibility = View.VISIBLE
        }
    }

    // Lazy-initialized credential manager for SSH password encryption
    private val credentialManager by lazy { CredentialManager(this) }

    private fun showNewConnectionDialog() {
        val dialog = Dialog(this)
        dialog.requestWindowFeature(Window.FEATURE_NO_TITLE)
        dialog.setContentView(R.layout.dialog_connection)
        dialog.window?.setBackgroundDrawable(ColorDrawable(Color.TRANSPARENT))

        val dialogTitle = dialog.findViewById<TextView>(R.id.dialogTitle)
        val nameEdit = dialog.findViewById<EditText>(R.id.editName)
        val hostEdit = dialog.findViewById<EditText>(R.id.editHost)
        val portEdit = dialog.findViewById<EditText>(R.id.editPort)
        val spinnerProtocol = dialog.findViewById<Spinner>(R.id.spinnerProtocol)
        val sshCredentialsSection = dialog.findViewById<View>(R.id.sshCredentialsSection)
        val editUsername = dialog.findViewById<EditText>(R.id.editUsername)
        val editPassword = dialog.findViewById<EditText>(R.id.editPassword)
        val optionsSection = dialog.findViewById<View>(R.id.optionsSection)
        val checkShowStatusBar = dialog.findViewById<android.widget.CheckBox>(R.id.checkShowStatusBar)
        val buttonConnect = dialog.findViewById<Button>(R.id.buttonConnect)
        val buttonSave = dialog.findViewById<Button>(R.id.buttonSave)
        val cancelLink = dialog.findViewById<Button>(R.id.cancelLink)

        // Set dialog title for new connection
        dialogTitle.text = getString(R.string.menu_new_connection)

        portEdit.setText("23")

        // Show options section so user can configure screen mode, font, and status bar
        optionsSection.visibility = View.VISIBLE
        // Default: show status bar (checked = true, hideStatusLine = false)
        checkShowStatusBar.isChecked = true

        // Setup screen mode spinner for new connections
        val spinnerScreenMode = dialog.findViewById<Spinner>(R.id.spinnerScreenMode)
        val screenModes = arrayOf("80x25", "80x30", "80x40", "80x50", "132x25", "132x50")
        val screenModeAdapter = ArrayAdapter(this, R.layout.spinner_item_retro, screenModes)
        screenModeAdapter.setDropDownViewResource(R.layout.spinner_dropdown_item_retro)
        spinnerScreenMode.adapter = screenModeAdapter

        // Setup font spinner for new connections
        val spinnerFont = dialog.findViewById<Spinner>(R.id.spinnerFont)
        val fontAdapter = ArrayAdapter(this, R.layout.spinner_item_retro, fontDisplayNames)
        fontAdapter.setDropDownViewResource(R.layout.spinner_dropdown_item_retro)
        spinnerFont.adapter = fontAdapter

        // Setup protocol spinner
        val protocols = arrayOf("Telnet", "SSH")
        val protocolAdapter = ArrayAdapter(this, R.layout.spinner_item_retro, protocols)
        protocolAdapter.setDropDownViewResource(R.layout.spinner_dropdown_item_retro)
        spinnerProtocol.adapter = protocolAdapter

        // Protocol selection listener - toggle SSH credentials and auto-change port
        spinnerProtocol.onItemSelectedListener = object : android.widget.AdapterView.OnItemSelectedListener {
            override fun onItemSelected(parent: android.widget.AdapterView<*>?, view: View?, position: Int, id: Long) {
                val isSsh = position == SavedConnection.PROTOCOL_SSH
                sshCredentialsSection.visibility = if (isSsh) View.VISIBLE else View.GONE

                // Auto-switch port when protocol changes (only if port is default)
                val currentPort = portEdit.text.toString().toIntOrNull() ?: 0
                if (isSsh && currentPort == 23) {
                    portEdit.setText("22")
                } else if (!isSsh && currentPort == 22) {
                    portEdit.setText("23")
                }
            }

            override fun onNothingSelected(parent: android.widget.AdapterView<*>?) {}
        }

        // For new connections, hide Connect button and make Save full-width primary
        buttonConnect.visibility = View.GONE
        buttonSave.background = getDrawable(R.drawable.retro_button_primary)
        buttonSave.setTextColor(getColor(R.color.term_light_green))
        // Remove end margin so Save stretches to match Cancel width
        (buttonSave.layoutParams as android.widget.LinearLayout.LayoutParams).marginEnd = 0

        // Save button
        buttonSave.setOnClickListener {
            val name = nameEdit.text.toString().trim()
            val host = hostEdit.text.toString().trim()
            val portStr = portEdit.text.toString().trim()
            val protocol = spinnerProtocol.selectedItemPosition
            val username = editUsername.text.toString().trim().ifEmpty { null }
            val plainPassword = editPassword.text.toString()

            if (host.isEmpty()) {
                Toast.makeText(this, R.string.error_invalid_host, Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }

            val port = portStr.toIntOrNull() ?: 23
            if (port !in 1..65535) {
                Toast.makeText(this, R.string.error_invalid_port, Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }

            val connectionName = name.ifEmpty { host }

            // Encrypt password if SSH and password provided
            val encryptedPassword = if (protocol == SavedConnection.PROTOCOL_SSH && plainPassword.isNotEmpty()) {
                credentialManager.encryptPassword(plainPassword)
            } else {
                null
            }

            // Save connection with all options
            val hideStatusLine = !checkShowStatusBar.isChecked
            val screenMode = spinnerScreenMode.selectedItemPosition
            val font = spinnerFont.selectedItemPosition
            connectionList.add(SavedConnection(
                name = connectionName,
                host = host,
                port = port,
                screenMode = screenMode,
                font = font,
                hideStatusLine = hideStatusLine,
                protocol = protocol,
                username = username,
                encryptedPassword = encryptedPassword
            ))
            saveConnections()
            connectionAdapter.submitList(connectionList.toList())
            updateEmptyState()

            Toast.makeText(this, getString(R.string.connection_saved, connectionName), Toast.LENGTH_SHORT).show()
            dialog.dismiss()
        }

        // Cancel link
        cancelLink.setOnClickListener {
            dialog.dismiss()
        }

        dialog.show()

        // Set dialog width to 90% of screen width
        dialog.window?.setLayout(
            (resources.displayMetrics.widthPixels * 0.9).toInt(),
            android.view.WindowManager.LayoutParams.WRAP_CONTENT
        )
    }

    private fun showConnectionDetailsDialog(connection: SavedConnection) {
        val dialog = Dialog(this)
        dialog.requestWindowFeature(Window.FEATURE_NO_TITLE)
        dialog.setContentView(R.layout.dialog_connection)
        dialog.window?.setBackgroundDrawable(ColorDrawable(Color.TRANSPARENT))

        val dialogTitle = dialog.findViewById<TextView>(R.id.dialogTitle)
        val nameEdit = dialog.findViewById<EditText>(R.id.editName)
        val hostEdit = dialog.findViewById<EditText>(R.id.editHost)
        val portEdit = dialog.findViewById<EditText>(R.id.editPort)
        val spinnerProtocol = dialog.findViewById<Spinner>(R.id.spinnerProtocol)
        val sshCredentialsSection = dialog.findViewById<View>(R.id.sshCredentialsSection)
        val editUsername = dialog.findViewById<EditText>(R.id.editUsername)
        val editPassword = dialog.findViewById<EditText>(R.id.editPassword)
        val optionsSection = dialog.findViewById<View>(R.id.optionsSection)
        val spinnerScreenMode = dialog.findViewById<Spinner>(R.id.spinnerScreenMode)
        val spinnerFont = dialog.findViewById<Spinner>(R.id.spinnerFont)
        val checkShowStatusBar = dialog.findViewById<android.widget.CheckBox>(R.id.checkShowStatusBar)
        val buttonConnect = dialog.findViewById<Button>(R.id.buttonConnect)
        val buttonSave = dialog.findViewById<Button>(R.id.buttonSave)
        val deleteRow = dialog.findViewById<View>(R.id.deleteRow)
        val deleteButton = dialog.findViewById<Button>(R.id.deleteButton)
        val buttonCancel = dialog.findViewById<Button>(R.id.buttonCancel)
        val cancelLink = dialog.findViewById<Button>(R.id.cancelLink)

        // Set dialog title
        dialogTitle.text = connection.name

        // Populate with existing data
        nameEdit.setText(connection.name)
        hostEdit.setText(connection.host)
        portEdit.setText(connection.port.toString())

        // Setup protocol spinner
        val protocols = arrayOf("Telnet", "SSH")
        val protocolAdapter = ArrayAdapter(this, R.layout.spinner_item_retro, protocols)
        protocolAdapter.setDropDownViewResource(R.layout.spinner_dropdown_item_retro)
        spinnerProtocol.adapter = protocolAdapter
        spinnerProtocol.setSelection(connection.protocol.coerceIn(0, protocols.lastIndex))

        // Show SSH credentials section if SSH is selected
        val isSsh = connection.protocol == SavedConnection.PROTOCOL_SSH
        sshCredentialsSection.visibility = if (isSsh) View.VISIBLE else View.GONE

        // Populate SSH credentials if available
        if (isSsh) {
            editUsername.setText(connection.username ?: "")
            // Show placeholder dots if password exists (don't decrypt)
            if (!connection.encryptedPassword.isNullOrEmpty()) {
                editPassword.setText(PASSWORD_PLACEHOLDER)
            }
        }

        // Protocol selection listener - toggle SSH credentials and auto-change port
        spinnerProtocol.onItemSelectedListener = object : android.widget.AdapterView.OnItemSelectedListener {
            override fun onItemSelected(parent: android.widget.AdapterView<*>?, view: View?, position: Int, id: Long) {
                val selectedSsh = position == SavedConnection.PROTOCOL_SSH
                sshCredentialsSection.visibility = if (selectedSsh) View.VISIBLE else View.GONE

                // Auto-switch port when protocol changes (only if port is default)
                val currentPort = portEdit.text.toString().toIntOrNull() ?: 0
                if (selectedSsh && currentPort == 23) {
                    portEdit.setText("22")
                } else if (!selectedSsh && currentPort == 22) {
                    portEdit.setText("23")
                }
            }

            override fun onNothingSelected(parent: android.widget.AdapterView<*>?) {}
        }

        // Show options section for existing connections
        optionsSection.visibility = View.VISIBLE

        // Set status bar checkbox from connection setting (inverted: hideStatusLine=false means show)
        checkShowStatusBar.isChecked = !connection.hideStatusLine

        // Setup screen mode spinner
        val screenModes = arrayOf("80x25", "80x30", "80x40", "80x50", "132x25", "132x50")
        val screenModeAdapter = ArrayAdapter(this, R.layout.spinner_item_retro, screenModes)
        screenModeAdapter.setDropDownViewResource(R.layout.spinner_dropdown_item_retro)
        spinnerScreenMode.adapter = screenModeAdapter
        spinnerScreenMode.setSelection(connection.screenMode.coerceIn(0, screenModes.lastIndex))

        // Setup font spinner (use display names for UI)
        val fontAdapter = ArrayAdapter(this, R.layout.spinner_item_retro, fontDisplayNames)
        fontAdapter.setDropDownViewResource(R.layout.spinner_dropdown_item_retro)
        spinnerFont.adapter = fontAdapter
        spinnerFont.setSelection(connection.font.coerceIn(0, fontDisplayNames.lastIndex))

        // Show delete row (with Delete and Cancel buttons) for existing connections
        deleteRow.visibility = View.VISIBLE
        // Hide the standalone cancel link since we have Cancel in the delete row
        cancelLink.visibility = View.GONE

        // Connect button
        buttonConnect.setOnClickListener {
            val name = nameEdit.text.toString().trim()
            val host = hostEdit.text.toString().trim()
            val portStr = portEdit.text.toString().trim()
            val protocol = spinnerProtocol.selectedItemPosition
            val username = editUsername.text.toString().trim().ifEmpty { null }
            val plainPassword = editPassword.text.toString()
            val screenMode = spinnerScreenMode.selectedItemPosition
            val font = spinnerFont.selectedItemPosition
            val hideStatusLine = !checkShowStatusBar.isChecked

            if (host.isEmpty()) {
                Toast.makeText(this, R.string.error_invalid_host, Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }

            val port = portStr.toIntOrNull() ?: 23
            if (port !in 1..65535) {
                Toast.makeText(this, R.string.error_invalid_port, Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }

            val connectionName = name.ifEmpty { host }

            // Encrypt password if SSH and password provided, otherwise keep existing
            val encryptedPassword = if (protocol == SavedConnection.PROTOCOL_SSH) {
                if (plainPassword.isNotEmpty() && plainPassword != PASSWORD_PLACEHOLDER) {
                    credentialManager.encryptPassword(plainPassword)
                } else {
                    connection.encryptedPassword  // Keep existing encrypted password
                }
            } else {
                null
            }

            // Update connection if changed
            val index = connectionList.indexOf(connection)
            if (index >= 0) {
                connectionList[index] = SavedConnection(
                    name = connectionName,
                    host = host,
                    port = port,
                    screenMode = screenMode,
                    font = font,
                    hideStatusLine = hideStatusLine,
                    thumbnailPath = connection.thumbnailPath,
                    snapshotPath = connection.snapshotPath,
                    protocol = protocol,
                    username = if (protocol == SavedConnection.PROTOCOL_SSH) username else null,
                    encryptedPassword = encryptedPassword
                )
                saveConnections()
                connectionAdapter.submitList(connectionList.toList())
            }

            dialog.dismiss()
            launchTerminal(connectionName, host, port, screenMode, font, hideStatusLine, protocol = protocol, username = username, encryptedPassword = encryptedPassword)
        }

        // Save button
        buttonSave.setOnClickListener {
            val name = nameEdit.text.toString().trim()
            val host = hostEdit.text.toString().trim()
            val portStr = portEdit.text.toString().trim()
            val protocol = spinnerProtocol.selectedItemPosition
            val username = editUsername.text.toString().trim().ifEmpty { null }
            val plainPassword = editPassword.text.toString()
            val screenMode = spinnerScreenMode.selectedItemPosition
            val font = spinnerFont.selectedItemPosition
            val hideStatusLine = !checkShowStatusBar.isChecked

            if (host.isEmpty()) {
                Toast.makeText(this, R.string.error_invalid_host, Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }

            val port = portStr.toIntOrNull() ?: 23
            if (port !in 1..65535) {
                Toast.makeText(this, R.string.error_invalid_port, Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }

            val connectionName = name.ifEmpty { host }

            // Encrypt password if SSH and password provided, otherwise keep existing
            val encryptedPassword = if (protocol == SavedConnection.PROTOCOL_SSH) {
                if (plainPassword.isNotEmpty() && plainPassword != PASSWORD_PLACEHOLDER) {
                    credentialManager.encryptPassword(plainPassword)
                } else {
                    connection.encryptedPassword  // Keep existing encrypted password
                }
            } else {
                null
            }

            // Update connection with options
            val index = connectionList.indexOf(connection)
            if (index >= 0) {
                connectionList[index] = SavedConnection(
                    name = connectionName,
                    host = host,
                    port = port,
                    screenMode = screenMode,
                    font = font,
                    hideStatusLine = hideStatusLine,
                    thumbnailPath = connection.thumbnailPath,
                    snapshotPath = connection.snapshotPath,
                    protocol = protocol,
                    username = if (protocol == SavedConnection.PROTOCOL_SSH) username else null,
                    encryptedPassword = encryptedPassword
                )
                saveConnections()
                connectionAdapter.submitList(connectionList.toList())
                Toast.makeText(this, getString(R.string.connection_saved, connectionName), Toast.LENGTH_SHORT).show()
            }

            dialog.dismiss()
        }

        // Delete button
        deleteButton.setOnClickListener {
            dialog.dismiss()
            confirmDeleteConnection(connection)
        }

        // Cancel button
        buttonCancel.setOnClickListener {
            dialog.dismiss()
        }

        dialog.show()

        // Set dialog width to 90% of screen width
        dialog.window?.setLayout(
            (resources.displayMetrics.widthPixels * 0.9).toInt(),
            android.view.WindowManager.LayoutParams.WRAP_CONTENT
        )
    }

    private fun confirmDeleteConnection(connection: SavedConnection) {
        AlertDialog.Builder(this)
            .setTitle(R.string.delete)
            .setMessage(getString(R.string.delete_confirm, connection.name))
            .setPositiveButton(R.string.delete) { _, _ ->
                connectionList.remove(connection)
                saveConnections()
                connectionAdapter.submitList(connectionList.toList())
                updateEmptyState()
                Toast.makeText(this, getString(R.string.connection_deleted, connection.name), Toast.LENGTH_SHORT).show()
            }
            .setNegativeButton(R.string.cancel, null)
            .show()
    }

    private fun launchTerminal(
        name: String,
        host: String,
        port: Int,
        screenMode: Int = SavedConnection.SCREEN_MODE_80X25,
        font: Int = SavedConnection.FONT_CP437,
        hideStatusLine: Boolean = false,
        protocol: Int = SavedConnection.PROTOCOL_TELNET,
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

    override fun onCreateOptionsMenu(menu: Menu): Boolean {
        menuInflater.inflate(R.menu.menu_main, menu)
        return true
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        return when (item.itemId) {
            R.id.action_settings -> {
                settingsLauncher.launch(Intent(this, SettingsActivity::class.java))
                true
            }
            R.id.action_help -> {
                showHelpDialog()
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

    /**
     * Let user select download folder for received files.
     * This persists across app sessions.
     */
    private fun selectDownloadFolder() {
        fileAccessManager.pickDownloadFolder { uri ->
            if (uri != null) {
                val folderName = fileAccessManager.getDownloadLocationDescription()
                Toast.makeText(this, getString(R.string.transfer_folder_selected) + ": $folderName", Toast.LENGTH_SHORT).show()
            }
        }
    }

    /**
     * Show a dialog with the full-size snapshot image.
     */
    private fun showSnapshotDialog(bbsName: String, snapshotPath: String) {
        val bitmap = BitmapFactory.decodeFile(snapshotPath) ?: return

        val dialog = Dialog(this)
        dialog.requestWindowFeature(Window.FEATURE_NO_TITLE)
        dialog.window?.setBackgroundDrawable(ColorDrawable(Color.BLACK))

        val imageView = android.widget.ImageView(this).apply {
            setImageBitmap(bitmap)
            scaleType = android.widget.ImageView.ScaleType.FIT_CENTER
            adjustViewBounds = true
            setOnClickListener { dialog.dismiss() }
        }

        dialog.setContentView(imageView)
        dialog.setCanceledOnTouchOutside(true)

        // Make dialog nearly full screen
        dialog.window?.setLayout(
            (resources.displayMetrics.widthPixels * 0.95).toInt(),
            android.view.WindowManager.LayoutParams.WRAP_CONTENT
        )

        dialog.show()
    }

    /**
     * Register activity result launchers.
     * Must be called before activity is started.
     */
    private fun registerSettingsLauncher() {
        // Settings launcher - handle export/import actions from SettingsActivity
        settingsLauncher = registerForActivityResult(
            ActivityResultContracts.StartActivityForResult()
        ) { result ->
            if (result.resultCode == Activity.RESULT_OK) {
                val action = result.data?.getStringExtra("action")
                val uriString = result.data?.getStringExtra("uri")
                if (action != null && uriString != null) {
                    val uri = Uri.parse(uriString)
                    when (action) {
                        "export" -> writeExportFile(uri)
                        "import" -> readImportFile(uri)
                    }
                }
            }
        }
    }

    /**
     * Write connections to a ZIP file with snapshots.
     */
    private fun writeExportFile(uri: Uri) {
        try {
            contentResolver.openOutputStream(uri)?.use { outputStream ->
                ZipOutputStream(BufferedOutputStream(outputStream)).use { zipOut ->
                    // Write connections.xml
                    val xml = connectionsToXml(includeSnapshots = true)
                    zipOut.putNextEntry(ZipEntry("connections.xml"))
                    zipOut.write(xml.toByteArray(Charsets.UTF_8))
                    zipOut.closeEntry()

                    // Write snapshot images
                    for ((index, conn) in connectionList.withIndex()) {
                        if (!conn.thumbnailPath.isNullOrEmpty()) {
                            val file = File(conn.thumbnailPath)
                            if (file.exists()) {
                                zipOut.putNextEntry(ZipEntry("snapshots/snapshot_${index}.png"))
                                FileInputStream(file).use { fileIn ->
                                    fileIn.copyTo(zipOut)
                                }
                                zipOut.closeEntry()
                            }
                        }
                    }
                }
            }
            Toast.makeText(
                this,
                getString(R.string.export_success, connectionList.size),
                Toast.LENGTH_SHORT
            ).show()
        } catch (e: Exception) {
            android.util.Log.e("MainActivity", "Export failed", e)
            Toast.makeText(this, R.string.export_failed, Toast.LENGTH_SHORT).show()
        }
    }

    /**
     * Read and import connections from a ZIP or XML file.
     */
    private fun readImportFile(uri: Uri) {
        try {
            val inputStream = contentResolver.openInputStream(uri)
            if (inputStream == null) {
                Toast.makeText(this, getString(R.string.import_failed, "Cannot open file"), Toast.LENGTH_SHORT).show()
                return
            }

            // Check if it's a ZIP file by reading magic bytes
            val bufferedStream = BufferedInputStream(inputStream)
            bufferedStream.mark(4)
            val header = ByteArray(4)
            bufferedStream.read(header)
            bufferedStream.reset()

            val isZip = header[0] == 0x50.toByte() && header[1] == 0x4B.toByte() // "PK" magic

            if (isZip) {
                importFromZip(bufferedStream)
            } else {
                // Legacy XML import
                val xml = bufferedStream.bufferedReader().use { it.readText() }
                val (imported, _) = xmlToConnections(xml)
                showImportConfirmation(imported, emptyMap())
            }
        } catch (e: Exception) {
            android.util.Log.e("MainActivity", "Import failed", e)
            Toast.makeText(
                this,
                getString(R.string.import_failed, e.message ?: "Unknown error"),
                Toast.LENGTH_SHORT
            ).show()
        }
    }

    /**
     * Import connections from a ZIP file with snapshots.
     */
    private fun importFromZip(inputStream: BufferedInputStream) {
        val tempDir = File(cacheDir, "import_temp")
        tempDir.deleteRecursively()
        tempDir.mkdirs()

        try {
            // Extract ZIP contents (with path traversal protection)
            ZipInputStream(inputStream).use { zipIn ->
                var entry = zipIn.nextEntry
                while (entry != null) {
                    val file = File(tempDir, entry.name).canonicalFile
                    // Prevent ZipSlip: ensure extracted file stays within tempDir
                    if (!file.path.startsWith(tempDir.canonicalPath + File.separator) && file != tempDir.canonicalFile) {
                        throw SecurityException("ZIP entry '${entry.name}' would escape target directory")
                    }
                    if (entry.isDirectory) {
                        file.mkdirs()
                    } else {
                        file.parentFile?.mkdirs()
                        FileOutputStream(file).use { fileOut ->
                            zipIn.copyTo(fileOut)
                        }
                    }
                    zipIn.closeEntry()
                    entry = zipIn.nextEntry
                }
            }

            // Read connections.xml
            val xmlFile = File(tempDir, "connections.xml")
            if (!xmlFile.exists()) {
                Toast.makeText(this, getString(R.string.import_failed, "No connections.xml found"), Toast.LENGTH_SHORT).show()
                return
            }

            val xml = xmlFile.readText()
            val (imported, snapshotPaths) = xmlToConnections(xml)

            if (imported.isEmpty()) {
                Toast.makeText(this, R.string.import_no_connections, Toast.LENGTH_SHORT).show()
                return
            }

            // Map temp snapshot files
            val tempSnapshots = mutableMapOf<Int, File>()
            for ((index, relativePath) in snapshotPaths) {
                val snapshotFile = File(tempDir, relativePath)
                if (snapshotFile.exists()) {
                    tempSnapshots[index] = snapshotFile
                }
            }

            showImportConfirmation(imported, tempSnapshots)
        } catch (e: Exception) {
            tempDir.deleteRecursively()
            throw e
        }
    }

    /**
     * Show confirmation dialog and perform import.
     */
    private fun showImportConfirmation(imported: List<SavedConnection>, tempSnapshots: Map<Int, File>) {
        AlertDialog.Builder(this)
            .setTitle(R.string.import_confirm_title)
            .setMessage(getString(R.string.import_confirm_message, connectionList.size, imported.size))
            .setPositiveButton(R.string.import_action) { _, _ ->
                performImport(imported, tempSnapshots)
            }
            .setNegativeButton(R.string.cancel) { _, _ ->
                // Clean up temp files
                File(cacheDir, "import_temp").deleteRecursively()
            }
            .setOnCancelListener {
                File(cacheDir, "import_temp").deleteRecursively()
            }
            .show()
    }

    /**
     * Perform the actual import, copying snapshots to app storage.
     */
    private fun performImport(imported: List<SavedConnection>, tempSnapshots: Map<Int, File>) {
        val snapshotsDir = File(filesDir, "snapshots")
        snapshotsDir.mkdirs()

        // Create new list with updated snapshot paths
        val importedWithSnapshots = imported.mapIndexed { index, conn ->
            val tempSnapshot = tempSnapshots[index]
            if (tempSnapshot != null && tempSnapshot.exists()) {
                // Copy snapshot to app storage
                val destFile = File(snapshotsDir, "imported_${System.currentTimeMillis()}_${index}.png")
                tempSnapshot.copyTo(destFile, overwrite = true)
                conn.copy(thumbnailPath = destFile.absolutePath, snapshotPath = destFile.absolutePath)
            } else {
                conn
            }
        }

        // Replace existing connections
        connectionList.clear()
        connectionList.addAll(importedWithSnapshots)
        saveConnections()
        connectionAdapter.submitList(connectionList.toList())
        updateEmptyState()

        // Clean up temp files
        File(cacheDir, "import_temp").deleteRecursively()

        Toast.makeText(
            this,
            getString(R.string.import_success, imported.size),
            Toast.LENGTH_SHORT
        ).show()
    }

    /**
     * Convert current connection list to XML string.
     * @param includeSnapshots If true, includes relative snapshot paths for ZIP export
     */
    private fun connectionsToXml(includeSnapshots: Boolean = false): String {
        val writer = StringWriter()
        writer.append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")
        writer.append("<connections>\n")

        for ((index, conn) in connectionList.withIndex()) {
            writer.append("  <connection>\n")
            writer.append("    <name>${escapeXml(conn.name)}</name>\n")
            writer.append("    <host>${escapeXml(conn.host)}</host>\n")
            writer.append("    <port>${conn.port}</port>\n")
            writer.append("    <screenMode>${conn.screenMode}</screenMode>\n")
            writer.append("    <font>${conn.font}</font>\n")
            writer.append("    <hideStatusLine>${conn.hideStatusLine}</hideStatusLine>\n")
            writer.append("    <protocol>${conn.protocol}</protocol>\n")
            // Export username for SSH connections, but NOT password (security)
            if (conn.protocol == SavedConnection.PROTOCOL_SSH && !conn.username.isNullOrEmpty()) {
                writer.append("    <username>${escapeXml(conn.username)}</username>\n")
            }
            // Include snapshot path reference for ZIP export
            if (includeSnapshots && !conn.thumbnailPath.isNullOrEmpty()) {
                val file = File(conn.thumbnailPath)
                if (file.exists()) {
                    writer.append("    <snapshot>snapshots/snapshot_${index}.png</snapshot>\n")
                }
            }
            writer.append("  </connection>\n")
        }

        writer.append("</connections>\n")
        return writer.toString()
    }

    /**
     * Parse XML string into list of connections.
     * Returns a Pair of (connections list, map of index to snapshot relative path)
     */
    private fun xmlToConnections(xml: String): Pair<List<SavedConnection>, Map<Int, String>> {
        val connections = mutableListOf<SavedConnection>()
        val snapshotPaths = mutableMapOf<Int, String>()

        try {
            val factory = XmlPullParserFactory.newInstance()
            // Disable external entities to prevent XXE attacks
            factory.setFeature("http://xml.org/sax/features/external-general-entities", false)
            factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false)
            val parser = factory.newPullParser()
            parser.setInput(xml.reader())

            var eventType = parser.eventType
            var currentTag = ""
            var name = ""
            var host = ""
            var port = 23
            var screenMode = SavedConnection.SCREEN_MODE_80X25
            var font = SavedConnection.FONT_CP437
            var hideStatusLine = false
            var protocol = SavedConnection.PROTOCOL_TELNET
            var username: String? = null
            var snapshotPath: String? = null
            var inConnection = false

            while (eventType != XmlPullParser.END_DOCUMENT) {
                try {
                    when (eventType) {
                        XmlPullParser.START_TAG -> {
                            currentTag = parser.name ?: ""
                            if (currentTag == "connection") {
                                inConnection = true
                                // Reset to defaults
                                name = ""
                                host = ""
                                port = 23
                                screenMode = SavedConnection.SCREEN_MODE_80X25
                                font = SavedConnection.FONT_CP437
                                hideStatusLine = false
                                protocol = SavedConnection.PROTOCOL_TELNET
                                username = null
                                snapshotPath = null
                            }
                        }
                        XmlPullParser.TEXT -> {
                            if (inConnection) {
                                val text = parser.text?.trim() ?: ""
                                when (currentTag) {
                                    "name" -> name = text
                                    "host" -> host = text
                                    "port" -> port = (text.toIntOrNull() ?: 23).coerceIn(1, 65535)
                                    "screenMode" -> screenMode = (text.toIntOrNull() ?: SavedConnection.SCREEN_MODE_80X25).coerceIn(0, 5)
                                    "font" -> font = (text.toIntOrNull() ?: SavedConnection.FONT_CP437).coerceIn(0, fontDisplayNames.lastIndex)
                                    "hideStatusLine" -> hideStatusLine = text.toBoolean()
                                    "protocol" -> protocol = (text.toIntOrNull() ?: SavedConnection.PROTOCOL_TELNET).coerceIn(0, 1)
                                    "username" -> username = text.ifEmpty { null }
                                    "snapshot" -> snapshotPath = text.ifEmpty { null }
                                }
                            }
                        }
                        XmlPullParser.END_TAG -> {
                            val endTagName = parser.name ?: ""
                            if (endTagName == "connection" && inConnection) {
                                if (name.isNotEmpty() && host.isNotEmpty()) {
                                    val index = connections.size
                                    connections.add(SavedConnection(
                                        name = name,
                                        host = host,
                                        port = port,
                                        screenMode = screenMode,
                                        font = font,
                                        hideStatusLine = hideStatusLine,
                                        protocol = protocol,
                                        username = username
                                        // Note: password is NOT imported for security
                                        // thumbnailPath will be set after extracting from ZIP
                                    ))
                                    if (!snapshotPath.isNullOrEmpty()) {
                                        snapshotPaths[index] = snapshotPath
                                    }
                                }
                                inConnection = false
                            }
                            currentTag = ""
                        }
                    }
                } catch (e: Exception) {
                    android.util.Log.w("MainActivity", "Error parsing XML element: ${e.message}")
                    // Continue parsing despite element errors
                }
                eventType = parser.next()
            }
        } catch (e: Exception) {
            android.util.Log.e("MainActivity", "Error parsing XML: ${e.message}")
        }

        return Pair(connections, snapshotPaths)
    }

    /**
     * Escape special XML characters in a string.
     * IMPORTANT: & must be escaped FIRST, otherwise &lt; becomes &amp;lt;
     */
    private fun escapeXml(text: String): String {
        // Use StringBuilder for efficient character-by-character replacement
        // This avoids the issue of double-escaping when using chained replace()
        val sb = StringBuilder()
        for (char in text) {
            when (char) {
                '&' -> sb.append("&amp;")
                '<' -> sb.append("&lt;")
                '>' -> sb.append("&gt;")
                '"' -> sb.append("&quot;")
                '\'' -> sb.append("&apos;")
                else -> sb.append(char)
            }
        }
        return sb.toString()
    }

    /**
     * Apply orientation from settings preference.
     * 0 = Portrait, 1 = Landscape (no Auto option)
     */
    private fun applyOrientationSetting() {
        val prefs = getSharedPreferences(SettingsActivity.PREFS_NAME, MODE_PRIVATE)
        val orientationSetting = prefs.getInt(SettingsActivity.KEY_ORIENTATION, 0)
        requestedOrientation = when (orientationSetting) {
            1 -> ActivityInfo.SCREEN_ORIENTATION_LANDSCAPE
            else -> ActivityInfo.SCREEN_ORIENTATION_PORTRAIT  // 0 = Portrait (default)
        }
    }

    /**
     * Data class for saved connections.
     */
    data class SavedConnection(
        val name: String,
        val host: String,
        val port: Int,
        val screenMode: Int = SCREEN_MODE_80X25,
        val font: Int = FONT_CP437,
        val hideStatusLine: Boolean = false,
        val thumbnailPath: String? = null,  // Path to snapshot thumbnail image
        val snapshotPath: String? = null,   // Path to full-resolution snapshot
        val protocol: Int = PROTOCOL_TELNET,  // 0=Telnet, 1=SSH
        val username: String? = null,
        val encryptedPassword: String? = null
    ) {
        companion object {
            const val SCREEN_MODE_80X25 = 0
            const val SCREEN_MODE_80X30 = 1
            const val SCREEN_MODE_80X40 = 2
            const val SCREEN_MODE_80X50 = 3
            const val SCREEN_MODE_132X25 = 4
            const val SCREEN_MODE_132X50 = 5

            // Font constants - indexes into font list
            const val FONT_CP437 = 0
            const val FONT_TOPAZ_PLUS = 1

            // Protocol constants
            const val PROTOCOL_TELNET = 0
            const val PROTOCOL_SSH = 1
        }
    }

    // Reference font names from TerminalActivity to avoid duplication
    private val fontNames get() = TerminalActivity.fontNames
    private val fontDisplayNames get() = TerminalActivity.fontDisplayNames

    /**
     * RecyclerView adapter for connections using DiffUtil for efficient updates.
     */
    inner class ConnectionAdapter(
        private val onItemClick: (SavedConnection) -> Unit,
        private val onItemLongClick: (SavedConnection) -> Unit
    ) : RecyclerView.Adapter<ConnectionAdapter.ViewHolder>() {

        private var items = listOf<SavedConnection>()

        fun submitList(newList: List<SavedConnection>) {
            val diffCallback = ConnectionDiffCallback(items, newList)
            val diffResult = DiffUtil.calculateDiff(diffCallback)
            items = newList
            diffResult.dispatchUpdatesTo(this)
        }

        override fun onCreateViewHolder(parent: android.view.ViewGroup, viewType: Int): ViewHolder {
            val view = LayoutInflater.from(parent.context)
                .inflate(R.layout.item_connection, parent, false)
            return ViewHolder(view)
        }

        override fun onBindViewHolder(holder: ViewHolder, position: Int) {
            holder.bind(items[position])
        }

        override fun getItemCount() = items.size

        inner class ViewHolder(view: View) : RecyclerView.ViewHolder(view) {
            private val nameText: android.widget.TextView = view.findViewById(R.id.textName)
            private val hostText: android.widget.TextView = view.findViewById(R.id.textHost)
            private val iconView: android.widget.ImageView = view.findViewById(R.id.iconTerminal)

            fun bind(connection: SavedConnection) {
                nameText.text = connection.name
                hostText.text = "${connection.host}:${connection.port}"

                // Load thumbnail if available, otherwise show default icon
                val thumbnailPath = connection.thumbnailPath
                if (thumbnailPath != null) {
                    val file = File(thumbnailPath)
                    if (file.exists()) {
                        val bitmap = BitmapFactory.decodeFile(thumbnailPath)
                        if (bitmap != null) {
                            iconView.setImageBitmap(bitmap)
                        } else {
                            iconView.setImageResource(R.drawable.ic_terminal)
                        }
                    } else {
                        iconView.setImageResource(R.drawable.ic_terminal)
                    }
                } else {
                    iconView.setImageResource(R.drawable.ic_terminal)
                }

                // Make thumbnail clickable to show full snapshot
                iconView.setOnClickListener {
                    val snapshotPath = connection.snapshotPath
                    if (snapshotPath != null && File(snapshotPath).exists()) {
                        showSnapshotDialog(connection.name, snapshotPath)
                    } else {
                        // No snapshot, treat as regular item click
                        onItemClick(connection)
                    }
                }

                itemView.setOnClickListener { onItemClick(connection) }
                itemView.setOnLongClickListener {
                    onItemLongClick(connection)
                    true
                }
            }
        }
    }

    /**
     * DiffUtil callback for efficient RecyclerView updates.
     */
    private class ConnectionDiffCallback(
        private val oldList: List<SavedConnection>,
        private val newList: List<SavedConnection>
    ) : DiffUtil.Callback() {
        override fun getOldListSize() = oldList.size
        override fun getNewListSize() = newList.size

        override fun areItemsTheSame(oldPos: Int, newPos: Int): Boolean {
            // Items are the same if host, port, and protocol match (unique identifier)
            // Two connections to same host:port with different protocols are distinct
            return oldList[oldPos].host == newList[newPos].host &&
                   oldList[oldPos].port == newList[newPos].port &&
                   oldList[oldPos].protocol == newList[newPos].protocol
        }

        override fun areContentsTheSame(oldPos: Int, newPos: Int): Boolean {
            return oldList[oldPos] == newList[newPos]
        }
    }
}

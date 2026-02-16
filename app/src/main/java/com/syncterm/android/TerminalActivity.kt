package com.syncterm.android

import android.Manifest
import android.appwidget.AppWidgetManager
import android.content.ClipboardManager
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.ActivityInfo
import android.content.pm.PackageManager
import android.os.Build
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.content.ContextCompat
import android.content.res.Configuration
import android.graphics.Bitmap
import android.graphics.Canvas
import android.net.Uri
import android.os.Bundle
import android.view.KeyEvent
import android.view.Menu
import android.view.MenuItem
import android.widget.Toast
import androidx.activity.OnBackPressedCallback
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.syncterm.android.databinding.ActivityTerminalBinding
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import android.os.Handler
import android.os.Looper
import java.io.File
import java.io.FileOutputStream
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Terminal session activity.
 */
class TerminalActivity : AppCompatActivity() {

    companion object {
        const val EXTRA_NAME = "name"
        const val EXTRA_HOST = "host"
        const val EXTRA_PORT = "port"
        const val EXTRA_SCREEN_MODE = "screen_mode"
        const val EXTRA_FONT = "font"
        const val EXTRA_HIDE_STATUS_LINE = "hide_status_line"
        const val EXTRA_PROTOCOL = "protocol"
        const val EXTRA_USERNAME = "username"
        const val EXTRA_PASSWORD = "encrypted_password"  // Encrypted password

        // Screen mode constants matching MainActivity.SavedConnection
        const val SCREEN_MODE_80X25 = 0
        const val SCREEN_MODE_80X30 = 1
        const val SCREEN_MODE_80X40 = 2
        const val SCREEN_MODE_80X50 = 3
        const val SCREEN_MODE_132X25 = 4
        const val SCREEN_MODE_132X50 = 5

        // Font constants matching MainActivity.SavedConnection
        const val FONT_CP437 = 0

        // ZMODEM transfer cooldown to prevent re-triggering (milliseconds)
        private const val ZMODEM_RETRIGGER_COOLDOWN_MS = 3000L

        // Thumbnail dimensions for snapshot capture
        private const val SNAPSHOT_THUMBNAIL_WIDTH = 400

        // Font names must match the native SyncTERM font descriptions EXACTLY
        // These come from src/conio/allfonts.c
        val fontNames = arrayOf(
            "Codepage 437 English",           // Index 0 - Standard DOS font
            "Topaz Plus (Amiga)"              // Index 1 - Amiga font for Amiga BBSes
        )

        // Display names shown in the UI (can differ from internal names)
        val fontDisplayNames = arrayOf(
            "Codepage 437 English",           // Index 0
            "Topaz 1200 Plus"                 // Index 1
        )
    }

    private lateinit var binding: ActivityTerminalBinding
    private lateinit var bellManager: BellManager
    private val connectionManager = ConnectionManager()

    // File transfer managers
    private lateinit var fileAccessManager: FileAccessManager
    private lateinit var transferManager: TransferManager

    // Session logging
    private lateinit var sessionLogger: SessionLogger

    private var connectionName = ""
    private var host = ""
    private var port = 23
    private var screenMode = SCREEN_MODE_80X25
    private var font = FONT_CP437
    private var hideStatusLine = false
    private var protocol = MainActivity.SavedConnection.PROTOCOL_TELNET
    private var username: String? = null
    private var encryptedPassword: String? = null

    // Lazy-initialized credential manager for SSH password decryption
    private val credentialManager by lazy { CredentialManager(this) }
    private val isDestroying = AtomicBoolean(false)  // Thread-safe destruction flag
    private var ctrlPressed = false  // CTRL modifier state
    private var isPaused = false  // Track pause state for polling control
    @Volatile private var lastTransferEndTime = 0L  // Cooldown to prevent ZMODEM re-triggering
    private var lastStatusBarUpdate = 0L  // Throttle status bar updates
    private var pendingZrinitUpload = false  // ZRINIT detected, waiting for user to pick a file

    // Configuration change debouncing for foldable devices
    private val configChangeHandler = Handler(Looper.getMainLooper())
    private var pendingConfigChangeRunnable: Runnable? = null
    private val pendingRefreshRunnables = mutableListOf<Runnable>()
    private var isResizing = AtomicBoolean(false)  // Prevent concurrent resize operations

    // Notification permission request launcher (Android 13+)
    private val notificationPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { isGranted ->
        // Start service regardless - it will work, just without a visible notification on Android 13+
        // if permission was denied
        if (connectionManager.isConnected()) {
            startConnectionService()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Lock orientation to current to prevent screen clearing on rotation
        // User can change via menu
        lockCurrentOrientation()

        // Initialize file transfer managers - must register launchers before activity is started
        fileAccessManager = FileAccessManager(this)
        fileAccessManager.registerLaunchers()
        transferManager = TransferManager(fileAccessManager)

        // Initialize bell manager for BEL character handling
        bellManager = BellManager(this)

        // Initialize session logger
        sessionLogger = SessionLogger(this)

        binding = ActivityTerminalBinding.inflate(layoutInflater)
        setContentView(binding.root)

        // Get connection parameters
        connectionName = intent.getStringExtra(EXTRA_NAME) ?: "Terminal"
        host = intent.getStringExtra(EXTRA_HOST) ?: ""
        port = intent.getIntExtra(EXTRA_PORT, 23)
        screenMode = intent.getIntExtra(EXTRA_SCREEN_MODE, SCREEN_MODE_80X25)
        font = intent.getIntExtra(EXTRA_FONT, FONT_CP437)
        hideStatusLine = intent.getBooleanExtra(EXTRA_HIDE_STATUS_LINE, false)
        protocol = intent.getIntExtra(EXTRA_PROTOCOL, MainActivity.SavedConnection.PROTOCOL_TELNET)
        username = intent.getStringExtra(EXTRA_USERNAME)
        encryptedPassword = intent.getStringExtra(EXTRA_PASSWORD)

        // Validate port range
        if (port !in 1..65535) {
            port = 23
        }

        // Validate screen mode (0-5)
        if (screenMode !in 0..5) {
            screenMode = SCREEN_MODE_80X25
        }

        // Validate font index
        if (font !in 0 until fontNames.size) {
            font = FONT_CP437
        }

        // Validate protocol
        if (protocol !in 0..1) {
            protocol = MainActivity.SavedConnection.PROTOCOL_TELNET
        }

        if (host.isEmpty()) {
            Toast.makeText(this, R.string.error_invalid_host, Toast.LENGTH_SHORT).show()
            finish()
            return
        }

        // Set connection status bar visibility from per-connection setting
        binding.connectionStatusBar.visibility = if (hideStatusLine) android.view.View.GONE else android.view.View.VISIBLE

        // Set BBS name and protocol in status bar
        val protocolStr = if (protocol == MainActivity.SavedConnection.PROTOCOL_SSH) "SSH" else "Telnet"
        binding.statusName.text = "$connectionName ($protocolStr)"

        setupTerminalView()
        setupKeyboardInput()
        setupSpecialKeys()
        setupConnectionManager()
        setupBackPressHandler()

        // Initialize and connect
        initializeAndConnect()
    }

    /**
     * Setup back button handling using OnBackPressedDispatcher (replaces deprecated onBackPressed).
     */
    private fun setupBackPressHandler() {
        onBackPressedDispatcher.addCallback(this, object : OnBackPressedCallback(true) {
            override fun handleOnBackPressed() {
                // Capture connection state atomically to avoid race conditions
                val isConnecting = connectionManager.isConnecting()
                val isConnected = connectionManager.isConnected()

                when {
                    isConnecting -> {
                        // Connecting - just cancel without prompt
                        disconnectAndFinish()
                    }
                    isConnected -> {
                        // Connected - confirm before closing
                        androidx.appcompat.app.AlertDialog.Builder(this@TerminalActivity)
                            .setTitle(R.string.disconnect)
                            .setMessage(getString(R.string.disconnect_confirm, connectionName))
                            .setPositiveButton(R.string.disconnect) { _, _ ->
                                disconnectAndFinish()
                            }
                            .setNegativeButton(R.string.cancel, null)
                            .show()
                    }
                    else -> {
                        // Not connected, just finish
                        isEnabled = false
                        onBackPressedDispatcher.onBackPressed()
                    }
                }
            }
        })
    }

    private fun setupTerminalView() {
        // Apply screen mode
        val (cols, rows) = when (screenMode) {
            SCREEN_MODE_80X30 -> Pair(80, 30)
            SCREEN_MODE_80X40 -> Pair(80, 40)
            SCREEN_MODE_80X50 -> Pair(80, 50)
            SCREEN_MODE_132X25 -> Pair(132, 25)
            SCREEN_MODE_132X50 -> Pair(132, 50)
            else -> Pair(80, 25) // SCREEN_MODE_80X25 is default
        }

        binding.terminalView.setTerminalSize(cols, rows)

        // Apply font selection - will be called after native init in initializeAndConnect
        // Font is applied there since native code must be initialized first

        binding.terminalView.onTerminalSizeChanged = { width, height ->
            connectionManager.setTerminalSize(width, height)
        }

        // Handle URL taps - open in browser
        binding.terminalView.onUrlTapped = { url ->
            openUrlInBrowser(url)
        }

        // Make terminal view focusable for keyboard input
        binding.terminalView.isFocusable = true
        binding.terminalView.isFocusableInTouchMode = true
        binding.terminalView.requestFocus()
    }

    private fun setupKeyboardInput() {
        // Custom input connection to capture keyboard
        binding.terminalView.setOnKeyListener { _, keyCode, event ->
            if (event.action == KeyEvent.ACTION_DOWN) {
                handleKeyDown(keyCode, event)
            } else {
                false
            }
        }

        // Handle soft keyboard input via the hidden EditText
        binding.hiddenInput.setOnKeyListener { _, keyCode, event ->
            if (event.action == KeyEvent.ACTION_DOWN) {
                handleKeyDown(keyCode, event)
            } else {
                false
            }
        }

        // Use TerminalView's InputConnection directly - bypasses hidden EditText issues
        binding.terminalView.onCharacterInput = { c ->
            binding.terminalView.onUserInput()  // Return to live view if scrolled back
            sendCharacter(c)
        }

        binding.terminalView.onKeyInput = { keyCode ->
            binding.terminalView.onUserInput()  // Return to live view if scrolled back
            connectionManager.sendKey(keyCode)
        }

        // Touch to show keyboard - focus the TerminalView directly
        binding.terminalView.setOnClickListener {
            binding.terminalView.requestFocus()
            val imm = getSystemService(INPUT_METHOD_SERVICE) as? android.view.inputmethod.InputMethodManager
            imm?.showSoftInput(binding.terminalView, android.view.inputmethod.InputMethodManager.SHOW_IMPLICIT)
        }
    }

    private fun setupSpecialKeys() {
        // CTRL toggle key
        binding.btnCtrl.setOnClickListener {
            ctrlPressed = !ctrlPressed
            updateCtrlButton()
        }

        // ESC key
        binding.btnEsc.setOnClickListener {
            connectionManager.sendKey(27)  // ESC
            clearCtrl()
        }

        // Backspace key
        binding.btnBackspace.setOnClickListener {
            connectionManager.sendKey(8)  // Backspace
            clearCtrl()
        }

        // Tab key
        binding.btnTab.setOnClickListener {
            connectionManager.sendKey(9)  // TAB
            clearCtrl()
        }

        // Enter key
        binding.btnEnter.setOnClickListener {
            connectionManager.sendKey(13)  // CR
            clearCtrl()
        }

        // Arrow keys (ANSI escape sequences)
        binding.btnUp.setOnClickListener {
            connectionManager.sendData(byteArrayOf(27, 91, 65))  // ESC[A
        }

        binding.btnDown.setOnClickListener {
            connectionManager.sendData(byteArrayOf(27, 91, 66))  // ESC[B
        }

        binding.btnRight.setOnClickListener {
            connectionManager.sendData(byteArrayOf(27, 91, 67))  // ESC[C
        }

        binding.btnLeft.setOnClickListener {
            connectionManager.sendData(byteArrayOf(27, 91, 68))  // ESC[D
        }

        // Menu button - shows popup menu for file transfers and disconnect
        binding.btnMenu.setOnClickListener { view ->
            showPopupMenu(view)
        }
    }

    /**
     * Show popup menu for file transfers and other options.
     */
    private fun showPopupMenu(anchor: android.view.View) {
        val popup = android.widget.PopupMenu(this, anchor)
        popup.menuInflater.inflate(R.menu.menu_terminal, popup.menu)

        // Set the current cursor visibility state
        popup.menu.findItem(R.id.action_toggle_cursor)?.isChecked = binding.terminalView.isCursorEnabled()

        // Set the current status bar visibility state
        popup.menu.findItem(R.id.action_toggle_status_bar)?.isChecked =
            binding.connectionStatusBar.visibility == android.view.View.VISIBLE

        // Set the logging menu item title based on current state
        popup.menu.findItem(R.id.action_toggle_logging)?.title =
            if (sessionLogger.isLogging()) getString(R.string.logging_stop) else getString(R.string.logging_start)

        popup.setOnMenuItemClickListener { item ->
            when (item.itemId) {
                R.id.action_paste_text -> {
                    pasteFromClipboard()
                    true
                }
                R.id.action_snapshot -> {
                    captureTerminalSnapshot()
                    true
                }
                R.id.action_toggle_logging -> {
                    toggleSessionLogging()
                    true
                }
                R.id.action_send_file -> {
                    startFileSend()
                    true
                }
                R.id.action_receive_file -> {
                    startFileReceive()
                    true
                }
                R.id.action_toggle_cursor -> {
                    val isEnabled = binding.terminalView.toggleCursor()
                    item.isChecked = isEnabled
                    true
                }
                R.id.action_toggle_status_bar -> {
                    val nowVisible = binding.connectionStatusBar.visibility != android.view.View.VISIBLE
                    binding.connectionStatusBar.visibility =
                        if (nowVisible) android.view.View.VISIBLE else android.view.View.GONE
                    item.isChecked = nowVisible
                    true
                }
                R.id.action_disconnect -> {
                    disconnectAndFinish()
                    true
                }
                else -> false
            }
        }

        popup.show()
    }

    private fun handleKeyDown(keyCode: Int, event: KeyEvent): Boolean {
        // Map Android key codes to terminal sequences
        val bytes = when (keyCode) {
            KeyEvent.KEYCODE_ENTER -> byteArrayOf(13)  // CR
            KeyEvent.KEYCODE_DEL -> byteArrayOf(8)     // Backspace
            KeyEvent.KEYCODE_FORWARD_DEL -> byteArrayOf(127) // Delete
            KeyEvent.KEYCODE_TAB -> byteArrayOf(9)     // Tab
            KeyEvent.KEYCODE_ESCAPE -> byteArrayOf(27) // Escape

            // Arrow keys (ANSI sequences)
            KeyEvent.KEYCODE_DPAD_UP -> byteArrayOf(27, 91, 65)    // ESC[A
            KeyEvent.KEYCODE_DPAD_DOWN -> byteArrayOf(27, 91, 66)  // ESC[B
            KeyEvent.KEYCODE_DPAD_RIGHT -> byteArrayOf(27, 91, 67) // ESC[C
            KeyEvent.KEYCODE_DPAD_LEFT -> byteArrayOf(27, 91, 68)  // ESC[D

            // Home/End/Page keys
            KeyEvent.KEYCODE_MOVE_HOME -> byteArrayOf(27, 91, 72)      // ESC[H
            KeyEvent.KEYCODE_MOVE_END -> byteArrayOf(27, 91, 70)       // ESC[F
            KeyEvent.KEYCODE_PAGE_UP -> byteArrayOf(27, 91, 53, 126)   // ESC[5~
            KeyEvent.KEYCODE_PAGE_DOWN -> byteArrayOf(27, 91, 54, 126) // ESC[6~
            KeyEvent.KEYCODE_INSERT -> byteArrayOf(27, 91, 50, 126)    // ESC[2~

            // Function keys
            KeyEvent.KEYCODE_F1 -> byteArrayOf(27, 79, 80)   // ESC OP
            KeyEvent.KEYCODE_F2 -> byteArrayOf(27, 79, 81)   // ESC OQ
            KeyEvent.KEYCODE_F3 -> byteArrayOf(27, 79, 82)   // ESC OR
            KeyEvent.KEYCODE_F4 -> byteArrayOf(27, 79, 83)   // ESC OS
            KeyEvent.KEYCODE_F5 -> byteArrayOf(27, 91, 49, 53, 126)  // ESC[15~
            KeyEvent.KEYCODE_F6 -> byteArrayOf(27, 91, 49, 55, 126)  // ESC[17~
            KeyEvent.KEYCODE_F7 -> byteArrayOf(27, 91, 49, 56, 126)  // ESC[18~
            KeyEvent.KEYCODE_F8 -> byteArrayOf(27, 91, 49, 57, 126)  // ESC[19~
            KeyEvent.KEYCODE_F9 -> byteArrayOf(27, 91, 50, 48, 126)  // ESC[20~
            KeyEvent.KEYCODE_F10 -> byteArrayOf(27, 91, 50, 49, 126) // ESC[21~
            KeyEvent.KEYCODE_F11 -> byteArrayOf(27, 91, 50, 51, 126) // ESC[23~
            KeyEvent.KEYCODE_F12 -> byteArrayOf(27, 91, 50, 52, 126) // ESC[24~

            else -> {
                // Handle printable characters
                val char = event.unicodeChar
                if (char in 32..126) {
                    // Handle Ctrl+key combinations
                    if (event.isCtrlPressed && char in 64..127) {
                        // Ctrl+key: convert to control code (0-31 range)
                        val ctrlCode = (char - 64) and 0x7F  // Mask to 7-bit ASCII
                        byteArrayOf(ctrlCode.toByte())
                    } else {
                        // Normal printable ASCII - mask to ensure valid byte range
                        byteArrayOf((char and 0x7F).toByte())
                    }
                } else {
                    null
                }
            }
        }

        if (bytes != null) {
            connectionManager.sendData(bytes)
            return true
        }
        return false
    }

    private fun sendCharacter(c: Char) {
        val code = c.code

        // Check if activity is still valid before posting
        if (isDestroying.get() || isFinishing) return

        // Post to main thread to decouple from InputConnection callback
        binding.root.post {
            // Double-check after post in case activity was destroyed while queued
            if (isDestroying.get() || isFinishing) return@post

            when {
                code == 10 -> {
                    connectionManager.sendData(byteArrayOf(13))
                }
                code in 0..127 -> {
                    if (ctrlPressed) {
                        val ctrlCode = when {
                            code in 65..90 -> code - 64   // A-Z -> 1-26
                            code in 97..122 -> code - 96  // a-z -> 1-26
                            else -> code
                        }
                        // Mask to 7-bit to ensure valid byte range
                        connectionManager.sendData(byteArrayOf((ctrlCode and 0x7F).toByte()))
                        clearCtrl()
                    } else {
                        // Mask to 7-bit to ensure valid byte range
                        connectionManager.sendData(byteArrayOf((code and 0x7F).toByte()))
                    }
                }
            }
        }
    }

    /**
     * Update the CTRL button appearance based on state.
     */
    private fun updateCtrlButton() {
        if (ctrlPressed) {
            binding.btnCtrl.backgroundTintList = android.content.res.ColorStateList.valueOf(getColor(R.color.accent))
            binding.btnCtrl.setTextColor(getColor(R.color.black))
        } else {
            binding.btnCtrl.backgroundTintList = android.content.res.ColorStateList.valueOf(getColor(R.color.ctrl_button_inactive))
            binding.btnCtrl.setTextColor(getColor(R.color.white))
        }
    }

    /**
     * Clear CTRL modifier state.
     */
    private fun clearCtrl() {
        if (ctrlPressed) {
            ctrlPressed = false
            updateCtrlButton()
        }
    }

    private fun setupConnectionManager() {
        // Use AtomicBoolean check to safely handle lifecycle
        connectionManager.onScreenUpdate = {
            if (!isDestroying.get() && !isPaused) {
                binding.terminalView.refreshBuffer()

                // Check for bell (BEL character) and play sound/vibrate
                if (NativeBridge.nativeCheckBell()) {
                    bellManager.playBell()
                }

                // Flush logged data if logging is active
                if (sessionLogger.isLogging()) {
                    val logData = NativeBridge.nativeGetLoggedData()
                    if (logData != null && logData.isNotEmpty()) {
                        sessionLogger.logData(logData)
                    }
                }

                // Update status bar (throttled to once per second)
                val now = System.currentTimeMillis()
                if (!hideStatusLine && now - lastStatusBarUpdate >= 1000) {
                    lastStatusBarUpdate = now
                    if (!isDestroying.get() && !isFinishing) {
                        runOnUiThread {
                            if (!isDestroying.get() && !isFinishing) {
                                updateConnectionStatusBar()
                            }
                        }
                    }
                }
            }
        }

        // ZMODEM auto-detection callback - auto-start receive when BBS sends ZMODEM
        connectionManager.onZmodemDetected = {
            // Quick check on IO thread - skip if obviously not ready
            if (!isDestroying.get() && !transferManager.isTransferring.value && !pendingZrinitUpload) {
                // Do all timing and UI checks on main thread for thread safety
                runOnUiThread {
                    val now = System.currentTimeMillis()
                    val cooldownOk = (now - lastTransferEndTime) > ZMODEM_RETRIGGER_COOLDOWN_MS

                    // Final checks on main thread
                    if (!isDestroying.get() && !transferManager.isTransferring.value &&
                        !pendingZrinitUpload && cooldownOk && !isTransferDialogShowing()) {
                        // Pause data polling to prevent consuming more ZMODEM data
                        connectionManager.pauseForTransfer()
                        // Auto-start receive when ZMODEM is detected
                        startFileReceiveAutoDetected()
                    }
                }
            }
        }

        // ZMODEM upload ready callback - BBS is ready to receive a file (ZRINIT detected)
        connectionManager.onZmodemUploadReady = {
            if (!isDestroying.get() && !transferManager.isTransferring.value) {
                runOnUiThread {
                    if (NativeBridge.nativeIsUploadQueued()) {
                        // File already queued, proceed with upload
                        onUploadReady()
                    } else {
                        // No file queued - prompt user to pick a file (auto-detection)
                        // Pause terminal and prompt for file selection
                        connectionManager.pauseForTransfer()
                        pendingZrinitUpload = true
                        Toast.makeText(this, R.string.upload_request_detected, Toast.LENGTH_LONG).show()
                        promptForUploadFile()
                    }
                }
            } else {
                // Transfer in progress or destroying, clear the state
                NativeBridge.nativeClearUploadQueue()
            }
        }

        connectionManager.onStateChanged = { state ->
            if (!isDestroying.get()) {
                runOnUiThread {
                    when (state) {
                        ConnectionManager.State.DISCONNECTED -> {
                            showDisconnectedDialog()
                        }
                        ConnectionManager.State.ERROR -> {
                            val error = connectionManager.errorMessage.value
                            Toast.makeText(this, getString(R.string.error_connection_failed, error),
                                Toast.LENGTH_LONG).show()
                        }
                        else -> {}
                    }
                }
            }
        }

        // Observe state changes (lifecycleScope is already lifecycle-aware)
        lifecycleScope.launch {
            connectionManager.state.collectLatest { state ->
                if (!isDestroying.get()) {
                    updateTitle(state)
                }
            }
        }
    }

    private fun updateTitle(state: ConnectionManager.State) {
        title = when (state) {
            ConnectionManager.State.CONNECTING -> "$connectionName (${getString(R.string.connecting)})"
            ConnectionManager.State.CONNECTED -> connectionName
            ConnectionManager.State.DISCONNECTING -> "$connectionName (${getString(R.string.disconnected)})"
            else -> connectionName
        }
    }

    /**
     * Update the connection status bar with current stats.
     */
    private fun updateConnectionStatusBar() {
        val stats = NativeBridge.nativeGetConnectionStats()
        if (stats == null || stats.size < 4) return

        val bytesSent = stats.getOrNull(0) ?: return
        val bytesReceived = stats.getOrNull(1) ?: return
        val connectTimeMs = stats.getOrNull(2) ?: return
        val currentTimeMs = stats.getOrNull(3) ?: return

        // Calculate connection duration (guard against clock skew)
        val durationMs = (currentTimeMs - connectTimeMs).coerceAtLeast(0)
        val hours = (durationMs / 3600000).toInt()
        val minutes = ((durationMs % 3600000) / 60000).toInt()
        val seconds = ((durationMs % 60000) / 1000).toInt()
        val timeStr = String.format("%02d:%02d:%02d", hours, minutes, seconds)

        // Format bytes with units
        val sentStr = formatBytes(bytesSent)
        val recvStr = formatBytes(bytesReceived)

        // Get screen mode string
        val modeStr = when (screenMode) {
            SCREEN_MODE_80X30 -> "80x30"
            SCREEN_MODE_80X40 -> "80x40"
            SCREEN_MODE_80X50 -> "80x50"
            SCREEN_MODE_132X25 -> "132x25"
            SCREEN_MODE_132X50 -> "132x50"
            else -> "80x25"
        }

        // Update UI
        binding.statusTime.text = timeStr
        binding.statusMode.text = modeStr
        binding.statusBytes.text = "↑$sentStr ↓$recvStr"
    }

    /**
     * Format bytes into human-readable string.
     */
    private fun formatBytes(bytes: Long): String {
        return when {
            bytes >= 1024 * 1024 -> String.format("%.1fM", bytes / (1024.0 * 1024.0))
            bytes >= 1024 -> String.format("%.1fK", bytes / 1024.0)
            else -> "${bytes}B"
        }
    }

    /**
     * Toggle session logging on/off.
     */
    private fun toggleSessionLogging() {
        if (!connectionManager.isConnected()) {
            Toast.makeText(this, R.string.logging_not_connected, Toast.LENGTH_SHORT).show()
            return
        }

        if (sessionLogger.isLogging()) {
            // Stop logging
            NativeBridge.nativeSetLoggingEnabled(false)
            val logPath = sessionLogger.stopLogging()
            binding.statusLogging.visibility = android.view.View.GONE

            if (logPath != null) {
                // Show file name only (not full path)
                val fileName = logPath.substringAfterLast("/")
                Toast.makeText(this, getString(R.string.logging_stopped, fileName), Toast.LENGTH_LONG).show()
            }
        } else {
            // Start logging
            NativeBridge.nativeSetLoggingEnabled(true)
            if (sessionLogger.startLogging(connectionName)) {
                binding.statusLogging.visibility = android.view.View.VISIBLE
                Toast.makeText(this, R.string.logging_started, Toast.LENGTH_SHORT).show()
            } else {
                NativeBridge.nativeSetLoggingEnabled(false)
                Toast.makeText(this, R.string.logging_failed, Toast.LENGTH_SHORT).show()
            }
        }
    }

    private fun initializeAndConnect() {
        lifecycleScope.launch {
            // Show connecting status
            binding.statusText.text = getString(R.string.connecting)
            binding.statusText.visibility = android.view.View.VISIBLE

            // Initialize native code (pass filesDir for SSH key storage)
            val initialized = withContext(Dispatchers.IO) {
                connectionManager.initialize(filesDir.absolutePath)
            }

            if (!initialized) {
                Toast.makeText(this@TerminalActivity,
                    R.string.error_terminal_init, Toast.LENGTH_LONG).show()
                finish()
                return@launch
            }

            // Reset terminal view state for clean connection
            binding.terminalView.resetState()

            // Update palette from native code after reset
            binding.terminalView.updatePalette()

            // Load default font bitmap immediately after init
            binding.terminalView.loadFontBitmap()

            // Set initial terminal size
            binding.terminalView.post {
                val (cols, rows) = binding.terminalView.getTerminalSize()
                connectionManager.setTerminalSize(cols, rows)
            }

            // Apply font selection
            if (font in fontNames.indices) {
                val fontName = fontNames[font]

                // First set the native font (this updates g_current_font_id)
                withContext(Dispatchers.IO) {
                    connectionManager.setFont(fontName)
                }

                // Then load the bitmap font data and set character mapping
                binding.terminalView.setFontByName(fontName)
            }

            // Set connection options before connecting
            withContext(Dispatchers.IO) {
                connectionManager.setScreenMode(screenMode)
                connectionManager.setHideStatusLine(hideStatusLine)
            }

            // Decrypt password for SSH connection
            val decryptedPassword = if (protocol == MainActivity.SavedConnection.PROTOCOL_SSH && encryptedPassword != null) {
                credentialManager.decryptPassword(encryptedPassword)
            } else {
                null
            }

            // Convert protocol from SavedConnection format to native format
            val nativeProtocol = if (protocol == MainActivity.SavedConnection.PROTOCOL_SSH) {
                NativeBridge.CONN_TYPE_SSH
            } else {
                NativeBridge.CONN_TYPE_TELNET
            }

            // Connect with timeout
            val connected = connectionManager.connect(connectionName, host, port, nativeProtocol, username, decryptedPassword)

            binding.statusText.visibility = android.view.View.GONE

            if (!connected) {
                // Check if it was a timeout
                val errorMsg = connectionManager.errorMessage.value
                val message = if (errorMsg?.contains("timed out", ignoreCase = true) == true) {
                    getString(R.string.error_connection_timeout)
                } else {
                    getString(R.string.error_connection_failed, host)
                }
                Toast.makeText(this@TerminalActivity, message, Toast.LENGTH_LONG).show()
                finish()
            } else {
                // Connection successful - start foreground service to keep connection alive
                // Check if activity is still valid before starting service
                if (!isDestroying.get() && !isFinishing) {
                    requestNotificationPermissionAndStartService()
                }
            }
        }
    }

    override fun onResume() {
        super.onResume()
        isPaused = false
        if (!isDestroying.get()) {
            // Resume cursor animation
            binding.terminalView.resumeAnimation()
        }
    }

    override fun onWindowFocusChanged(hasFocus: Boolean) {
        super.onWindowFocusChanged(hasFocus)
        if (hasFocus && !isDestroying.get() && !isPaused) {
            // Window is now visible and focused - this is the best time to redraw
            // Reset saved dimensions in case screen size changed (foldable)
            binding.terminalView.resetSavedDimensions()

            // Use postDelayed with tracked runnables so they can be cancelled
            val firstRunnable = Runnable {
                if (!isDestroying.get() && !isPaused) {
                    binding.terminalView.forceRedraw()
                }
            }
            pendingRefreshRunnables.add(firstRunnable)
            binding.terminalView.postDelayed(firstRunnable, 100)

            // Second attempt after layout should definitely be complete
            val secondRunnable = Runnable {
                if (!isDestroying.get() && !isPaused) {
                    binding.terminalView.forceRedraw()
                }
            }
            pendingRefreshRunnables.add(secondRunnable)
            binding.terminalView.postDelayed(secondRunnable, 300)
        }
    }

    override fun onPause() {
        super.onPause()
        isPaused = true
        // Pause cursor animation to save CPU when backgrounded
        binding.terminalView.pauseAnimation()
    }

    override fun onConfigurationChanged(newConfig: android.content.res.Configuration) {
        super.onConfigurationChanged(newConfig)

        // Cancel any pending configuration change handling to debounce rapid changes (foldables)
        cancelPendingConfigChange()

        // Debounce: Wait for configuration changes to settle before processing
        // This prevents multiple rapid redraws during fold/unfold transitions
        val configRunnable = Runnable {
            if (!isDestroying.get() && !isPaused) {
                processConfigurationChange()
            }
        }
        pendingConfigChangeRunnable = configRunnable
        configChangeHandler.postDelayed(configRunnable, 150)  // 150ms debounce
    }

    /**
     * Cancel any pending configuration change processing.
     * Called when a new config change occurs to prevent stale processing.
     */
    private fun cancelPendingConfigChange() {
        // Cancel pending config change runnable
        pendingConfigChangeRunnable?.let { configChangeHandler.removeCallbacks(it) }
        pendingConfigChangeRunnable = null

        // Cancel all pending refresh runnables
        pendingRefreshRunnables.forEach { runnable ->
            binding.terminalView.removeCallbacks(runnable)
        }
        pendingRefreshRunnables.clear()
    }

    /**
     * Process a configuration change after debouncing.
     * This ensures we only process once when changes have settled.
     */
    private fun processConfigurationChange() {
        if (isDestroying.get() || isPaused) return

        // Prevent concurrent resize operations
        if (!isResizing.compareAndSet(false, true)) {
            // Another resize is in progress, schedule a retry
            val retryRunnable = Runnable {
                processConfigurationChange()
            }
            pendingRefreshRunnables.add(retryRunnable)
            binding.terminalView.postDelayed(retryRunnable, 100)
            return
        }

        try {
            // Reset saved dimensions so view recalculates with new screen size
            binding.terminalView.resetSavedDimensions()

            // Request a new layout pass
            binding.terminalView.requestLayout()

            // Use ViewTreeObserver to wait for layout to actually complete
            binding.terminalView.viewTreeObserver.addOnGlobalLayoutListener(
                object : android.view.ViewTreeObserver.OnGlobalLayoutListener {
                    override fun onGlobalLayout() {
                        // Remove listener to avoid multiple calls
                        binding.terminalView.viewTreeObserver.removeOnGlobalLayoutListener(this)

                        if (!isDestroying.get() && !isPaused) {
                            // Now the view has its new dimensions - recalculate and redraw
                            binding.terminalView.forceRedraw()
                        }

                        // Schedule follow-up refresh attempts for foldable devices
                        scheduleBufferRefreshRetries()

                        // Mark resize as complete after the last retry
                        val completeRunnable = Runnable {
                            isResizing.set(false)
                        }
                        pendingRefreshRunnables.add(completeRunnable)
                        binding.terminalView.postDelayed(completeRunnable, 600)
                    }
                }
            )
        } catch (e: Exception) {
            isResizing.set(false)
        }
    }

    /**
     * Schedule multiple buffer refresh attempts for foldable device support.
     * Foldable transitions can cause timing issues where the initial refresh fails.
     * Uses tracked runnables so they can be cancelled if a new config change occurs.
     */
    private fun scheduleBufferRefreshRetries() {
        val retryDelays = listOf(100L, 250L, 500L)
        retryDelays.forEach { delay ->
            val runnable = Runnable {
                if (!isDestroying.get() && !isPaused) {
                    binding.terminalView.forceRedraw()
                }
            }
            pendingRefreshRunnables.add(runnable)
            binding.terminalView.postDelayed(runnable, delay)
        }
    }

    override fun onDestroy() {
        // Set flag first to prevent callbacks from firing
        isDestroying.set(true)

        // Cancel all pending configuration change and refresh callbacks
        cancelPendingConfigChange()
        configChangeHandler.removeCallbacksAndMessages(null)

        // Stop the foreground service
        stopConnectionService()

        // Stop logging if active
        if (sessionLogger.isLogging()) {
            NativeBridge.nativeSetLoggingEnabled(false)
            sessionLogger.stopLogging()
        }

        // Cleanup BEFORE calling super.onDestroy()
        connectionManager.clearCallbacks()
        connectionManager.cleanup()

        // Cleanup file transfer resources
        transferManager.cleanup()

        // Cleanup bell manager
        bellManager.release()

        super.onDestroy()
    }

    override fun dispatchKeyEvent(event: KeyEvent): Boolean {
        // Intercept volume buttons for scrollback navigation
        if (event.action == KeyEvent.ACTION_DOWN) {
            when (event.keyCode) {
                KeyEvent.KEYCODE_VOLUME_UP -> {
                    // Scroll back into history
                    binding.terminalView.scrollByLines(1)
                    return true
                }
                KeyEvent.KEYCODE_VOLUME_DOWN -> {
                    // Scroll toward live
                    binding.terminalView.scrollByLines(-1)
                    return true
                }
            }
        } else if (event.action == KeyEvent.ACTION_UP) {
            // Consume the UP event too so volume UI doesn't appear
            when (event.keyCode) {
                KeyEvent.KEYCODE_VOLUME_UP, KeyEvent.KEYCODE_VOLUME_DOWN -> return true
            }
        }
        return super.dispatchKeyEvent(event)
    }

    override fun onCreateOptionsMenu(menu: Menu): Boolean {
        menuInflater.inflate(R.menu.menu_terminal, menu)
        // Set cursor checkbox state
        menu.findItem(R.id.action_toggle_cursor)?.isChecked = binding.terminalView.isCursorEnabled()
        return true
    }

    override fun onPrepareOptionsMenu(menu: Menu): Boolean {
        // Update states each time menu is shown
        menu.findItem(R.id.action_toggle_cursor)?.isChecked = binding.terminalView.isCursorEnabled()
        return super.onPrepareOptionsMenu(menu)
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        return when (item.itemId) {
            R.id.action_snapshot -> {
                captureTerminalSnapshot()
                true
            }
            R.id.action_send_file -> {
                startFileSend()
                true
            }
            R.id.action_receive_file -> {
                startFileReceive()
                true
            }
            R.id.action_toggle_cursor -> {
                val isEnabled = binding.terminalView.toggleCursor()
                item.isChecked = isEnabled
                true
            }
            R.id.action_disconnect -> {
                disconnectAndFinish()
                true
            }
            else -> super.onOptionsItemSelected(item)
        }
    }

    // Queued upload URI (waiting for BBS to send ZRINIT)
    private var queuedUploadUri: android.net.Uri? = null

    /**
     * Paste text from clipboard into the terminal.
     */
    private fun pasteFromClipboard() {
        val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val clipData = clipboard.primaryClip
        if (clipData != null && clipData.itemCount > 0) {
            val text = clipData.getItemAt(0).coerceToText(this).toString()
            if (text.isNotEmpty()) {
                // Convert to bytes and send to terminal
                val bytes = text.toByteArray(Charsets.UTF_8)
                connectionManager.sendData(bytes)
            } else {
                Toast.makeText(this, R.string.paste_empty, Toast.LENGTH_SHORT).show()
            }
        } else {
            Toast.makeText(this, R.string.paste_empty, Toast.LENGTH_SHORT).show()
        }
    }

    /**
     * Capture a snapshot of the terminal view and save it as a thumbnail for this BBS.
     */
    private fun captureTerminalSnapshot() {
        lifecycleScope.launch {
            try {
                // Get the actual terminal content bounds (excludes black padding)
                val terminalView = binding.terminalView
                val (contentWidth, contentHeight) = terminalView.getContentBounds()

                // If content bounds are invalid, fall back to view size
                val captureWidth = if (contentWidth > 0) contentWidth else terminalView.width
                val captureHeight = if (contentHeight > 0) contentHeight else terminalView.height

                // Capture only the terminal content area
                val bitmap = Bitmap.createBitmap(
                    captureWidth,
                    captureHeight,
                    Bitmap.Config.ARGB_8888
                )
                val canvas = Canvas(bitmap)
                terminalView.draw(canvas)

                // Save full-resolution image for viewing
                val fullFileName = "snapshot_${host}_${port}.png"
                    .replace(":", "_")
                    .replace("/", "_")
                    .replace("\\", "_")
                val fullFile = File(filesDir, fullFileName)

                withContext(Dispatchers.IO) {
                    FileOutputStream(fullFile).use { out ->
                        bitmap.compress(Bitmap.CompressFormat.PNG, 100, out)
                    }
                }

                // Create thumbnail for list display
                if (bitmap.width <= 0 || bitmap.height <= 0) {
                    bitmap.recycle()
                    return@launch
                }
                val aspectRatio = bitmap.height.toFloat() / bitmap.width.toFloat()
                val thumbnailHeight = (SNAPSHOT_THUMBNAIL_WIDTH * aspectRatio).toInt().coerceAtLeast(1)
                val thumbnail = Bitmap.createScaledBitmap(bitmap, SNAPSHOT_THUMBNAIL_WIDTH, thumbnailHeight, true)

                bitmap.recycle()

                // Save thumbnail
                val thumbFileName = "thumbnail_${host}_${port}.png"
                    .replace(":", "_")
                    .replace("/", "_")
                    .replace("\\", "_")
                val thumbnailFile = File(filesDir, thumbFileName)

                withContext(Dispatchers.IO) {
                    FileOutputStream(thumbnailFile).use { out ->
                        thumbnail.compress(Bitmap.CompressFormat.PNG, 100, out)
                    }
                }

                thumbnail.recycle()

                // Update SharedPreferences with both paths
                updateConnectionThumbnail(thumbnailFile.absolutePath, fullFile.absolutePath)

                Toast.makeText(
                    this@TerminalActivity,
                    getString(R.string.snapshot_saved, connectionName),
                    Toast.LENGTH_SHORT
                ).show()
            } catch (e: Exception) {
                Toast.makeText(
                    this@TerminalActivity,
                    R.string.snapshot_failed,
                    Toast.LENGTH_SHORT
                ).show()
            }
        }
    }

    /**
     * Update the thumbnail and full snapshot paths for the current connection in SharedPreferences.
     * Also updates Quick Connect slots if this BBS is assigned to one.
     */
    private fun updateConnectionThumbnail(thumbnailPath: String, fullImagePath: String) {
        val prefs = getSharedPreferences("connections", MODE_PRIVATE)
        val count = prefs.getInt("count", 0)

        // Find the connection matching this host and port
        for (i in 0 until count) {
            val savedHost = prefs.getString("host_$i", "") ?: ""
            val savedPort = prefs.getInt("port_$i", 23)

            if (savedHost == host && savedPort == port) {
                // Found it - update both paths
                prefs.edit()
                    .putString("thumbnailPath_$i", thumbnailPath)
                    .putString("snapshotPath_$i", fullImagePath)
                    .apply()
                break
            }
        }

        // Also update Quick Connect slots if this BBS is assigned to one
        updateQuickConnectThumbnail(thumbnailPath)

        // Update home screen widgets that use this BBS
        updateWidgetThumbnails(thumbnailPath)
    }

    /**
     * Update Quick Connect thumbnail if this BBS is assigned to a slot.
     */
    private fun updateQuickConnectThumbnail(thumbnailPath: String) {
        val quickConnectPrefs = getSharedPreferences(HomeActivity.PREFS_QUICK_CONNECT, MODE_PRIVATE)
        val editor = quickConnectPrefs.edit()
        var updated = false

        // Check Quick Connect 1
        val host1 = quickConnectPrefs.getString(HomeActivity.KEY_QUICK_CONNECT_1_HOST, null)
        val port1 = quickConnectPrefs.getInt(HomeActivity.KEY_QUICK_CONNECT_1_PORT, 23)
        if (host1 == host && port1 == port) {
            editor.putString(HomeActivity.KEY_QUICK_CONNECT_1_THUMBNAIL, thumbnailPath)
            updated = true
        }

        // Check Quick Connect 2
        val host2 = quickConnectPrefs.getString(HomeActivity.KEY_QUICK_CONNECT_2_HOST, null)
        val port2 = quickConnectPrefs.getInt(HomeActivity.KEY_QUICK_CONNECT_2_PORT, 23)
        if (host2 == host && port2 == port) {
            editor.putString(HomeActivity.KEY_QUICK_CONNECT_2_THUMBNAIL, thumbnailPath)
            updated = true
        }

        if (updated) {
            editor.apply()
        }
    }

    /**
     * Update home screen widgets that contain this BBS.
     */
    private fun updateWidgetThumbnails(thumbnailPath: String) {
        val appWidgetManager = AppWidgetManager.getInstance(this)

        // Update single-slot widgets
        updateSingleSlotWidgets(appWidgetManager, thumbnailPath)
    }

    /**
     * Update single-slot widgets that match this BBS.
     */
    private fun updateSingleSlotWidgets(appWidgetManager: AppWidgetManager, thumbnailPath: String) {
        val componentName = ComponentName(this, BbsWidgetProvider::class.java)
        val widgetIds = appWidgetManager.getAppWidgetIds(componentName)
        val prefs = getSharedPreferences(BbsWidgetProvider.PREFS_NAME, MODE_PRIVATE)

        for (widgetId in widgetIds) {
            val bbsData = prefs.getString(BbsWidgetProvider.PREF_PREFIX_KEY + widgetId, null)
            if (bbsData != null) {
                val parts = bbsData.split("|")
                if (parts.size >= 3) {
                    val widgetHost = parts[1]
                    val widgetPort = parts[2].toIntOrNull() ?: 23
                    if (widgetHost == host && widgetPort == port) {
                        // Update the thumbnail in widget config
                        val updatedData = updateThumbnailInData(bbsData, thumbnailPath)
                        prefs.edit().putString(BbsWidgetProvider.PREF_PREFIX_KEY + widgetId, updatedData).apply()
                        // Refresh the widget
                        BbsWidgetProvider.updateWidget(this, appWidgetManager, widgetId)
                    }
                }
            }
        }
    }

    /**
     * Update the thumbnail path in the pipe-delimited BBS data string.
     * Format: "name|host|port|screenMode|font|100|hideStatusLine|thumbnailPath|..."
     */
    private fun updateThumbnailInData(bbsData: String, newThumbnailPath: String): String {
        val parts = bbsData.split("|").toMutableList()
        // Ensure we have at least 8 parts (thumbnail is at index 7)
        while (parts.size < 8) {
            parts.add("")
        }
        parts[7] = newThumbnailPath.replace("|", "_")
        return parts.joinToString("|")
    }

    /**
     * Start file send process - pick a file and queue it for upload.
     * The actual upload will start when the BBS sends ZRINIT.
     */
    private fun startFileSend() {
        if (!connectionManager.isConnected()) {
            Toast.makeText(this, R.string.transfer_not_connected, Toast.LENGTH_SHORT).show()
            return
        }

        if (transferManager.isTransferring.value) {
            Toast.makeText(this, R.string.transfer_in_progress, Toast.LENGTH_SHORT).show()
            return
        }

        if (NativeBridge.nativeIsUploadQueued()) {
            Toast.makeText(this, R.string.upload_already_queued, Toast.LENGTH_SHORT).show()
            return
        }

        fileAccessManager.pickFileToSend { uri, fileName ->
            if (uri != null) {
                // Copy file to temp location for native access
                val tempPath = fileAccessManager.copyToTempFile(uri)
                if (tempPath != null) {
                    // Queue the file for upload - will be sent when BBS sends ZRINIT
                    queuedUploadUri = uri
                    NativeBridge.nativeQueueUpload(tempPath)
                    Toast.makeText(this, getString(R.string.upload_queued, fileName), Toast.LENGTH_LONG).show()
                } else {
                    Toast.makeText(this, R.string.error_file_access, Toast.LENGTH_SHORT).show()
                }
            }
        }
    }

    /**
     * Called when BBS sends ZRINIT - ready to receive our upload.
     */
    private fun onUploadReady() {
        val queuedPath = NativeBridge.nativeGetQueuedUpload()
        val uploadUri = queuedUploadUri
        if (queuedPath == null || uploadUri == null) {
            // No file queued, clear the state
            NativeBridge.nativeClearUploadQueue()
            return
        }

        // Start the actual upload
        connectionManager.pauseForTransfer()
        showTransferDialog()

        lifecycleScope.launch(Dispatchers.IO) {
            try {
                // Push any buffered ZMODEM data back
                NativeBridge.nativePushZmodemBuffer()

                // Start the send
                transferManager.launchSend(uploadUri) { result ->
                    // Clear the queue
                    queuedUploadUri = null
                    NativeBridge.nativeClearUploadQueue()
                    // Don't resume here - dialog dismiss listener handles it
                    // This prevents new ZMODEM detection while dialog is still showing
                    handleTransferResult(result)
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    queuedUploadUri = null
                    NativeBridge.nativeClearUploadQueue()
                    // Resume here since dialog might not have shown due to error
                    connectionManager.resumeAfterTransfer()
                    Toast.makeText(this@TerminalActivity, "Upload failed: ${e.message}", Toast.LENGTH_SHORT).show()
                }
            }
        }
    }

    /**
     * Prompt user to pick a file for upload after ZRINIT was detected.
     * This is called when the BBS requests a file but none was pre-queued.
     */
    private fun promptForUploadFile() {
        fileAccessManager.pickFileToSend { uri, fileName ->
            if (uri != null && pendingZrinitUpload) {
                // File selected and ZRINIT was detected - start upload immediately
                // Keep pendingZrinitUpload true until transfer actually starts to block download detection

                // Copy file to temp location for native access
                val tempPath = fileAccessManager.copyToTempFile(uri)
                if (tempPath != null) {
                    // Clear any pending ZMODEM detection to prevent false download triggers
                    NativeBridge.nativeClearZmodemDetected()

                    queuedUploadUri = uri
                    NativeBridge.nativeQueueUpload(tempPath)

                    // Show transfer dialog and start immediately
                    showTransferDialog()

                    lifecycleScope.launch(Dispatchers.IO) {
                        try {
                            // Push any buffered ZMODEM data back
                            NativeBridge.nativePushZmodemBuffer()

                            // Now clear the pending flag - transfer is starting
                            pendingZrinitUpload = false

                            // Start the send
                            transferManager.launchSend(uri) { result ->
                                // Clear the queue
                                queuedUploadUri = null
                                NativeBridge.nativeClearUploadQueue()
                                // Don't resume here - dialog dismiss listener handles it
                                handleTransferResult(result)
                            }
                        } catch (e: Exception) {
                            pendingZrinitUpload = false
                            withContext(Dispatchers.Main) {
                                queuedUploadUri = null
                                NativeBridge.nativeClearUploadQueue()
                                // Resume here since dialog might not have shown due to error
                                connectionManager.resumeAfterTransfer()
                                Toast.makeText(this@TerminalActivity, "Upload failed: ${e.message}", Toast.LENGTH_SHORT).show()
                            }
                        }
                    }
                } else {
                    // File access failed, resume terminal
                    pendingZrinitUpload = false
                    connectionManager.resumeAfterTransfer()
                    NativeBridge.nativeClearZmodemDetected()
                    Toast.makeText(this, R.string.error_file_access, Toast.LENGTH_SHORT).show()
                }
            } else {
                // User cancelled file picker or pendingZrinitUpload was cleared
                pendingZrinitUpload = false
                connectionManager.resumeAfterTransfer()
                NativeBridge.nativeClearZmodemDetected()
                if (uri == null) {
                    Toast.makeText(this, R.string.upload_cancelled, Toast.LENGTH_SHORT).show()
                }
            }
        }
    }

    /**
     * Start file receive process - initiate ZMODEM receive.
     * Called when user manually initiates receive from menu.
     */
    private fun startFileReceive() {
        if (!connectionManager.isConnected()) {
            Toast.makeText(this, R.string.transfer_not_connected, Toast.LENGTH_SHORT).show()
            return
        }

        if (transferManager.isTransferring.value) {
            Toast.makeText(this, R.string.transfer_in_progress, Toast.LENGTH_SHORT).show()
            return
        }

        // Pause terminal data processing during transfer
        connectionManager.pauseForTransfer()
        doFileReceive()
    }

    /**
     * Start file receive process - called when ZMODEM is auto-detected.
     * Pausing is already done before this is called.
     */
    private fun startFileReceiveAutoDetected() {
        if (!connectionManager.isConnected()) {
            connectionManager.resumeAfterTransfer()
            Toast.makeText(this, R.string.transfer_not_connected, Toast.LENGTH_SHORT).show()
            return
        }

        if (transferManager.isTransferring.value) {
            connectionManager.resumeAfterTransfer()
            Toast.makeText(this, R.string.transfer_in_progress, Toast.LENGTH_SHORT).show()
            return
        }

        doFileReceive()
    }

    /**
     * Actually perform the file receive (shared by manual and auto-detected).
     */
    private fun doFileReceive() {
        // Don't start receive if transfer dialog is already showing
        if (isTransferDialogShowing()) {
            android.util.Log.w("TerminalActivity", "Transfer dialog already showing, ignoring receive request")
            return
        }

        showTransferDialog()
        transferManager.launchReceive { result ->
            // Clear ZMODEM detection state to prevent re-triggering
            NativeBridge.nativeClearZmodemDetected()
            // Don't resume here - dialog dismiss listener handles it
            handleTransferResult(result)
        }
    }

    /**
     * Check if transfer dialog is currently showing.
     */
    private fun isTransferDialogShowing(): Boolean {
        return supportFragmentManager.findFragmentByTag(TransferDialogFragment.TAG) != null
    }

    /**
     * Show the transfer progress dialog.
     * Only shows one dialog at a time - if already showing, does nothing.
     */
    private fun showTransferDialog() {
        // Check if dialog is already showing - only allow one transfer dialog
        if (isTransferDialogShowing()) {
            android.util.Log.w("TerminalActivity", "Transfer dialog already showing, ignoring duplicate")
            return
        }

        val dialog = TransferDialogFragment.newInstance()
        dialog.setTransferManager(transferManager)
        dialog.setOnDismissListener {
            // Clear ZMODEM detection state to prevent re-triggering
            NativeBridge.nativeClearZmodemDetected()
            // Record end time to prevent immediate re-triggering
            lastTransferEndTime = System.currentTimeMillis()
            // Clear pending upload flag
            pendingZrinitUpload = false
            // Ensure connection is resumed when dialog is dismissed (e.g., on cancel)
            connectionManager.resumeAfterTransfer()
            transferManager.reset()
        }
        dialog.show(supportFragmentManager, TransferDialogFragment.TAG)
    }

    /**
     * Handle transfer completion result.
     */
    private fun handleTransferResult(result: TransferResult) {
        when (result) {
            is TransferResult.Success -> {
                Toast.makeText(
                    this,
                    getString(R.string.transfer_complete, result.fileName),
                    Toast.LENGTH_SHORT
                ).show()
            }
            is TransferResult.Error -> {
                Toast.makeText(
                    this,
                    getString(R.string.transfer_failed, result.message),
                    Toast.LENGTH_LONG
                ).show()
            }
            is TransferResult.Cancelled -> {
                Toast.makeText(this, R.string.transfer_cancelled, Toast.LENGTH_SHORT).show()
            }
        }
    }

    /**
     * Disconnect asynchronously and finish activity (prevents ANR).
     */
    private fun disconnectAndFinish() {
        isDestroying.set(true)
        connectionManager.clearCallbacks()

        // Stop the foreground service
        stopConnectionService()

        // Disconnect asynchronously to avoid blocking UI thread
        lifecycleScope.launch {
            withContext(Dispatchers.IO) {
                connectionManager.disconnect()
            }
            finish()
        }
    }

    /**
     * Show a dialog when disconnected by the remote host.
     */
    private fun showDisconnectedDialog() {
        if (isDestroying.get() || isFinishing) return

        isDestroying.set(true)  // Prevent further callbacks
        connectionManager.clearCallbacks()

        // Stop the foreground service since we're disconnected
        stopConnectionService()

        androidx.appcompat.app.AlertDialog.Builder(this)
            .setTitle(R.string.disconnected)
            .setMessage(getString(R.string.disconnected_message, connectionName))
            .setPositiveButton(android.R.string.ok) { _, _ ->
                finish()
            }
            .setCancelable(false)
            .show()
    }

    /**
     * Lock orientation based on user's preference setting.
     * 0 = Portrait, 1 = Landscape
     */
    private fun lockCurrentOrientation() {
        val prefs = getSharedPreferences(SettingsActivity.PREFS_NAME, MODE_PRIVATE)
        val orientationSetting = prefs.getInt(SettingsActivity.KEY_ORIENTATION, 0)
        requestedOrientation = when (orientationSetting) {
            1 -> ActivityInfo.SCREEN_ORIENTATION_LANDSCAPE
            else -> ActivityInfo.SCREEN_ORIENTATION_PORTRAIT
        }
    }

    /**
     * Request notification permission and start the foreground service.
     * On Android 13+, we need POST_NOTIFICATIONS permission for the notification to appear.
     * The service will still work without the permission, just without a visible notification.
     */
    private fun requestNotificationPermissionAndStartService() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            when {
                ContextCompat.checkSelfPermission(
                    this,
                    Manifest.permission.POST_NOTIFICATIONS
                ) == PackageManager.PERMISSION_GRANTED -> {
                    // Permission already granted
                    startConnectionService()
                }
                shouldShowRequestPermissionRationale(Manifest.permission.POST_NOTIFICATIONS) -> {
                    // User previously denied - start service anyway (will work, just no notification)
                    startConnectionService()
                }
                else -> {
                    // Request permission
                    notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
                }
            }
        } else {
            // Pre-Android 13 - no runtime permission needed
            startConnectionService()
        }
    }

    /**
     * Start the foreground service to keep the connection alive in background.
     */
    private fun startConnectionService() {
        ConnectionService.start(this, connectionName, host, port)
    }

    /**
     * Stop the foreground service.
     */
    private fun stopConnectionService() {
        ConnectionService.stop(this)
    }

    /**
     * Open a URL in the default browser.
     * Connection stays alive in background.
     */
    private fun openUrlInBrowser(url: String) {
        try {
            val intent = Intent(Intent.ACTION_VIEW, Uri.parse(url))
            startActivity(intent)
        } catch (e: Exception) {
            Toast.makeText(this, getString(R.string.error_opening_url), Toast.LENGTH_SHORT).show()
        }
    }
}

package com.syncterm.android

import android.util.Log
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.io.IOException
import java.net.SocketException
import java.net.SocketTimeoutException
import java.net.UnknownHostException

/**
 * Manages the terminal connection lifecycle.
 */
class ConnectionManager {

    companion object {
        private const val TAG = "ConnectionManager"
        private const val POLL_INTERVAL_ACTIVE_MS = 16L   // ~60fps when receiving data
        private const val POLL_INTERVAL_IDLE_MS = 50L     // Slower polling when idle
        private const val CONNECTION_TIMEOUT_MS = 5000L   // 5 seconds

        // ZMODEM detection return codes from native layer
        // These MUST match values in native code (conn_api.c)
        private const val ZMODEM_DOWNLOAD_DETECTED = -100  // ZRQINIT received - BBS wants to send file
        private const val ZMODEM_UPLOAD_READY = -101       // ZRINIT received - BBS ready to receive file
    }

    /**
     * Connection state.
     */
    enum class State {
        DISCONNECTED,
        CONNECTING,
        CONNECTED,
        DISCONNECTING,
        ERROR
    }

    /**
     * Connection info.
     */
    data class ConnectionInfo(
        val name: String,
        val host: String,
        val port: Int,
        val protocol: Int = NativeBridge.CONN_TYPE_TELNET
    )

    private val _state = MutableStateFlow(State.DISCONNECTED)
    val state: StateFlow<State> = _state.asStateFlow()

    private val _errorMessage = MutableStateFlow<String?>(null)
    val errorMessage: StateFlow<String?> = _errorMessage.asStateFlow()

    private var connectionInfo: ConnectionInfo? = null

    @Volatile
    private var dataPollingJob: Job? = null

    @Volatile
    private var scope: CoroutineScope? = null

    // Mutex to protect state transitions
    private val stateMutex = Mutex()

    // Flag to prevent double handling of disconnection
    @Volatile
    private var isHandlingDisconnection = false

    // Flag to pause polling during file transfers
    @Volatile
    private var isTransferInProgress = false

    /**
     * Callback for when data is received and the screen needs refresh.
     */
    var onScreenUpdate: (() -> Unit)? = null

    /**
     * Callback for connection state changes.
     */
    var onStateChanged: ((State) -> Unit)? = null

    /**
     * Callback for ZMODEM download auto-detection (ZRQINIT received).
     */
    var onZmodemDetected: (() -> Unit)? = null

    /**
     * Callback for ZMODEM upload ready (ZRINIT received from BBS).
     */
    var onZmodemUploadReady: (() -> Unit)? = null

    /**
     * Initialize the native terminal system.
     * @param filesDir The app's internal files directory for storing SSH keys etc.
     */
    fun initialize(filesDir: String? = null): Boolean {
        return try {
            // Check if native library was loaded successfully
            if (!NativeBridge.isNativeLibraryLoaded()) {
                Log.e(TAG, "Native library not loaded")
                return false
            }

            // Set files directory for SSH key storage (must be before nativeInit)
            if (filesDir != null) {
                NativeBridge.nativeSetFilesDir(filesDir)
                Log.i(TAG, "Files directory set to: $filesDir")
            }

            val result = NativeBridge.nativeInit()
            if (result) {
                Log.i(TAG, "Native terminal initialized")
            } else {
                Log.e(TAG, "Failed to initialize native terminal")
            }
            result
        } catch (e: Exception) {
            Log.e(TAG, "Exception initializing: ${e.message}", e)
            false
        }
    }

    /**
     * Connect to a server (Telnet or SSH) with timeout.
     * @param name Connection display name
     * @param host Hostname or IP address
     * @param port Port number
     * @param protocol NativeBridge.CONN_TYPE_TELNET (3) or NativeBridge.CONN_TYPE_SSH (5)
     * @param username Username for SSH authentication (null for Telnet)
     * @param password Plaintext password for SSH authentication (null for Telnet)
     */
    suspend fun connect(
        name: String,
        host: String,
        port: Int,
        protocol: Int = NativeBridge.CONN_TYPE_TELNET,
        username: String? = null,
        password: String? = null
    ): Boolean = withContext(Dispatchers.IO) {
        stateMutex.withLock {
            if (_state.value == State.CONNECTED || _state.value == State.CONNECTING) {
                Log.w(TAG, "Already connected or connecting")
                return@withContext false
            }
            _state.value = State.CONNECTING
        }

        _errorMessage.value = null
        connectionInfo = ConnectionInfo(name, host, port, protocol)
        isHandlingDisconnection = false  // Reset flag for new connection

        try {
            Log.i(TAG, "Connecting to $host:$port")

            // Clear screen before connecting for a fresh start
            NativeBridge.nativeClearScreen()

            // Use withTimeout to prevent hanging on connection attempts
            // Wrap in try-catch to handle exceptions from native code
            val result = try {
                withTimeoutOrNull(CONNECTION_TIMEOUT_MS) {
                    NativeBridge.nativeConnect(host, port, protocol, username, password)
                }
            } catch (e: Exception) {
                Log.e(TAG, "Native connect threw exception: ${e.message}", e)
                null
            }

            if (result == null) {
                Log.e(TAG, "Connection timed out or failed")
                stateMutex.withLock {
                    _state.value = State.ERROR
                }
                _errorMessage.value = "Connection timed out"
                return@withContext false
            }

            if (result) {
                Log.i(TAG, "Connected successfully")
                stateMutex.withLock {
                    _state.value = State.CONNECTED
                }
                try {
                    startDataPolling()
                } catch (e: Exception) {
                    Log.e(TAG, "Failed to start data polling: ${e.message}", e)
                    // Connection succeeded but polling failed - disconnect cleanly
                    try {
                        NativeBridge.nativeDisconnect()
                    } catch (disconnectError: Exception) {
                        Log.e(TAG, "Disconnect after polling failure: ${disconnectError.message}")
                    }
                    stateMutex.withLock {
                        _state.value = State.ERROR
                    }
                    _errorMessage.value = "Connected but failed to start data polling"
                    return@withContext false
                }
                true
            } else {
                Log.e(TAG, "Connection failed")
                stateMutex.withLock {
                    _state.value = State.ERROR
                }
                _errorMessage.value = "Failed to connect to $host:$port"
                false
            }
        } catch (e: UnknownHostException) {
            Log.e(TAG, "Connection failed: Unknown host $host", e)
            stateMutex.withLock { _state.value = State.ERROR }
            _errorMessage.value = "Connection failed: Unknown host $host"
            false
        } catch (e: SocketTimeoutException) {
            Log.e(TAG, "Connection failed: Timed out", e)
            stateMutex.withLock { _state.value = State.ERROR }
            _errorMessage.value = "Connection failed: Timed out"
            false
        } catch (e: SocketException) {
            Log.e(TAG, "Connection failed: ${e.message}", e)
            stateMutex.withLock { _state.value = State.ERROR }
            _errorMessage.value = "Connection failed: ${e.message ?: "Network error"}"
            false
        } catch (e: IOException) {
            Log.e(TAG, "Connection failed: ${e.message}", e)
            stateMutex.withLock { _state.value = State.ERROR }
            _errorMessage.value = "Connection failed: ${e.message ?: "I/O error"}"
            false
        } catch (e: Exception) {
            Log.e(TAG, "Connection failed: ${e.message}", e)
            stateMutex.withLock { _state.value = State.ERROR }
            _errorMessage.value = "Connection failed: ${e.message ?: "Unknown error"}"
            false
        }
    }

    /**
     * Disconnect from the server.
     */
    suspend fun disconnect() = withContext(Dispatchers.IO) {
        stateMutex.withLock {
            if (_state.value != State.CONNECTED && _state.value != State.CONNECTING) {
                return@withContext
            }

            Log.i(TAG, "Disconnecting")
            _state.value = State.DISCONNECTING
        }

        // Stop polling first and wait for it to complete
        stopDataPolling()

        try {
            NativeBridge.nativeDisconnect()
        } catch (e: Exception) {
            Log.e(TAG, "Disconnect exception: ${e.message}", e)
        }

        stateMutex.withLock {
            _state.value = State.DISCONNECTED
        }
        connectionInfo = null
        isHandlingDisconnection = false  // Reset flag
        Log.i(TAG, "Disconnected")
    }

    /**
     * Stop polling immediately without blocking (for use in cleanup).
     * Does not wait for coroutines to complete.
     */
    fun stopPollingImmediate() {
        dataPollingJob?.cancel()
        dataPollingJob = null
        scope?.cancel()
        scope = null
    }

    /**
     * Send a key code to the remote server.
     */
    fun sendKey(keyCode: Int) {
        if (_state.value != State.CONNECTED) return

        // Capture scope reference to prevent race condition
        val currentScope = scope ?: return
        currentScope.launch(Dispatchers.IO) {
            try {
                NativeBridge.nativeSendKey(keyCode)
            } catch (e: Exception) {
                Log.e(TAG, "Send key error: ${e.message}")
            }
        }
    }

    /**
     * Send raw bytes to the remote server.
     */
    fun sendData(data: ByteArray) {
        if (_state.value != State.CONNECTED) return

        // Capture scope reference to prevent race condition
        val currentScope = scope ?: return
        currentScope.launch(Dispatchers.IO) {
            try {
                val sent = NativeBridge.nativeSendData(data)
                // Check if send failed or connection is lost
                if (sent < 0 || !NativeBridge.nativeIsConnected()) {
                    Log.w(TAG, "Send failed or connection lost, sent=$sent")
                    withContext(Dispatchers.Main) {
                        handleDisconnection()
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "Send data error: ${e.message}")
            }
        }
    }

    /**
     * Set terminal size.
     */
    fun setTerminalSize(width: Int, height: Int) {
        try {
            val safeWidth = width.coerceIn(40, 132)
            val safeHeight = height.coerceIn(24, 60)
            NativeBridge.nativeSetTerminalSize(safeWidth, safeHeight)
        } catch (e: Exception) {
            Log.e(TAG, "Set terminal size error: ${e.message}")
        }
    }

    /**
     * Set terminal font by name.
     */
    fun setFont(fontName: String): Boolean {
        return try {
            NativeBridge.nativeSetFont(fontName)
        } catch (e: Exception) {
            Log.e(TAG, "Set font error: ${e.message}")
            false
        }
    }

    /**
     * Set hide status line option (call before connect).
     */
    fun setHideStatusLine(hide: Boolean) {
        try {
            NativeBridge.nativeSetHideStatusLine(hide)
        } catch (e: Exception) {
            Log.e(TAG, "Set hide status line error: ${e.message}")
        }
    }

    /**
     * Set screen mode option (call before connect).
     * Mode values: 0=80x25, 1=80x30, 2=80x40, 3=80x50, 4=132x25, 5=132x50
     */
    fun setScreenMode(mode: Int) {
        try {
            NativeBridge.nativeSetScreenMode(mode)
        } catch (e: Exception) {
            Log.e(TAG, "Set screen mode error: ${e.message}")
        }
    }

    /**
     * Start the data polling loop with adaptive polling intervals.
     * Polls faster when data is being received, slower when idle.
     */
    private fun startDataPolling() {
        // Cancel any existing scope - don't block waiting for completion
        scope?.cancel()
        scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

        dataPollingJob = scope?.launch {
            var consecutiveIdlePolls = 0

            while (isActive && _state.value == State.CONNECTED) {
                try {
                    // Skip processing if file transfer is in progress
                    if (isTransferInProgress) {
                        delay(100)  // Check periodically if transfer is done
                        continue
                    }

                    // Check if still connected
                    if (!NativeBridge.nativeIsConnected()) {
                        Log.w(TAG, "Connection lost")
                        withContext(Dispatchers.Main) {
                            handleDisconnection()
                        }
                        break
                    }

                    // Process incoming data
                    val bytesProcessed = NativeBridge.nativeProcessData()

                    // Check for ZMODEM auto-detection
                    if (bytesProcessed == ZMODEM_DOWNLOAD_DETECTED) {
                        Log.i(TAG, "ZMODEM download auto-detected (ZRQINIT)!")
                        withContext(Dispatchers.Main) {
                            onZmodemDetected?.invoke()
                        }
                        // Skip normal processing, wait for transfer to start
                        delay(100)
                        continue
                    }

                    // Check for ZMODEM upload ready (BBS sent ZRINIT)
                    if (bytesProcessed == ZMODEM_UPLOAD_READY) {
                        Log.i(TAG, "ZMODEM upload ready (ZRINIT detected)!")
                        withContext(Dispatchers.Main) {
                            onZmodemUploadReady?.invoke()
                        }
                        // Skip normal processing, wait for upload to start
                        delay(100)
                        continue
                    }

                    val screenDirty = NativeBridge.nativeIsScreenDirty()

                    // If data was processed or screen is dirty, notify UI
                    if (bytesProcessed > 0 || screenDirty) {
                        consecutiveIdlePolls = 0  // Reset idle counter
                        withContext(Dispatchers.Main) {
                            onScreenUpdate?.invoke()
                        }
                    } else {
                        consecutiveIdlePolls++
                    }

                } catch (e: CancellationException) {
                    // Normal cancellation, just exit
                    break
                } catch (e: Exception) {
                    Log.e(TAG, "Polling error: ${e.message}")
                }

                // Adaptive polling: faster when active, slower when idle
                val pollInterval = if (consecutiveIdlePolls < 3) {
                    POLL_INTERVAL_ACTIVE_MS  // Fast polling when recently active
                } else {
                    POLL_INTERVAL_IDLE_MS    // Slower polling when idle
                }
                delay(pollInterval)
            }
        }
    }

    /**
     * Stop the data polling loop and wait for completion.
     */
    private suspend fun stopDataPolling() {
        dataPollingJob?.cancelAndJoin()
        dataPollingJob = null
        scope?.cancel()
        scope = null
    }

    /**
     * Pause data polling for file transfer.
     * Call this before starting a ZMODEM transfer to give it exclusive connection access.
     */
    fun pauseForTransfer() {
        Log.i(TAG, "Pausing data polling for file transfer")
        isTransferInProgress = true
    }

    /**
     * Resume data polling after file transfer.
     * Call this after ZMODEM transfer completes.
     */
    fun resumeAfterTransfer() {
        Log.i(TAG, "Resuming data polling after file transfer")
        isTransferInProgress = false
    }

    /**
     * Handle unexpected disconnection (remote closed connection).
     */
    private suspend fun handleDisconnection() {
        // Prevent double handling with mutex protection
        val shouldHandle = stateMutex.withLock {
            if (isHandlingDisconnection) {
                Log.w(TAG, "Already handling disconnection, skipping")
                false
            } else {
                isHandlingDisconnection = true
                true
            }
        }
        if (!shouldHandle) return

        Log.w(TAG, "Handling disconnection - start")

        // Process any remaining data before disconnecting
        // This ensures goodbye screens are fully rendered
        withContext(Dispatchers.IO) {
            for (i in 0 until 10) { // Try up to 10 times to drain buffer
                val processed = try {
                    NativeBridge.nativeProcessData()
                } catch (e: Exception) {
                    0
                }
                if (processed > 0) {
                    withContext(Dispatchers.Main) {
                        onScreenUpdate?.invoke()
                    }
                    delay(50) // Small delay to let more data arrive
                } else {
                    break // No more data
                }
            }

            // Clean up native connection
            try {
                NativeBridge.nativeDisconnect()
            } catch (e: Exception) {
                Log.e(TAG, "Native disconnect error: ${e.message}")
            }
        }

        // Brief delay to ensure final screen update is rendered
        delay(200)

        // Clean up polling job and scope
        dataPollingJob?.cancel()
        dataPollingJob = null
        scope?.cancel()
        scope = null

        // Update state and notify
        stateMutex.withLock {
            _state.value = State.DISCONNECTED
        }
        _errorMessage.value = "Connection closed by remote host"
        connectionInfo = null

        Log.w(TAG, "Handling disconnection - invoking callback")
        onStateChanged?.invoke(State.DISCONNECTED)
        Log.w(TAG, "Handling disconnection - done")
    }

    /**
     * Get current connection info.
     */
    fun getConnectionInfo(): ConnectionInfo? = connectionInfo

    /**
     * Check if connected.
     */
    fun isConnected(): Boolean = _state.value == State.CONNECTED

    fun isConnecting(): Boolean = _state.value == State.CONNECTING

    /**
     * Clear all callbacks to prevent memory leaks.
     */
    fun clearCallbacks() {
        onScreenUpdate = null
        onStateChanged = null
    }

    /**
     * Cleanup resources without blocking.
     * Note: We intentionally do NOT call nativeDestroy() here because the native
     * code is shared across all ConnectionManager instances. Calling nativeDestroy()
     * when one TerminalActivity closes would break any other activity trying to
     * connect. The native code stays initialized for the lifetime of the app.
     */
    fun cleanup() {
        // Cancel polling without blocking - coroutines will be cancelled
        stopPollingImmediate()
        clearCallbacks()
        // Reset internal state
        isHandlingDisconnection = false
        Log.i(TAG, "Cleanup complete (native code stays initialized)")
    }
}

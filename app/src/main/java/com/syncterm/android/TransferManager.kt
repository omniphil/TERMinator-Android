package com.syncterm.android

import android.net.Uri
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.*

/**
 * Manages ZMODEM file transfers using coroutines.
 * Provides progress updates and handles transfer lifecycle.
 */
class TransferManager(
    private val fileAccessManager: FileAccessManager
) {
    private val supervisorJob = SupervisorJob()
    private val scope = CoroutineScope(Dispatchers.Default + supervisorJob)
    private var transferJob: Job? = null
    private var progressJob: Job? = null

    // Transfer state
    private val _transferState = MutableStateFlow(TransferInfo())
    val transferState: StateFlow<TransferInfo> = _transferState.asStateFlow()

    private val _isTransferring = MutableStateFlow(false)
    val isTransferring: StateFlow<Boolean> = _isTransferring.asStateFlow()

    @Volatile
    private var initialized = false
    private val initLock = Any()

    /**
     * Initialize the transfer subsystem.
     */
    fun initialize(): Boolean {
        if (initialized) return true

        synchronized(initLock) {
            // Double-check after acquiring lock
            if (initialized) return true

            val success = NativeBridge.nativeTransferInit()
            if (success) {
                // Set download directory
                val downloadDir = fileAccessManager.getTransferCacheDir()
                NativeBridge.nativeSetDownloadDir(downloadDir)
                initialized = true
            }
            return success
        }
    }

    /**
     * Start a ZMODEM receive operation.
     * Call this when auto-download is triggered or user initiates receive.
     */
    suspend fun startReceive(): TransferResult = withContext(Dispatchers.IO) {
        if (_isTransferring.value) {
            return@withContext TransferResult.Error("Transfer already in progress")
        }

        if (!initialize()) {
            return@withContext TransferResult.Error("Failed to initialize transfer subsystem")
        }

        NativeBridge.nativeTransferReset()
        _isTransferring.value = true
        _transferState.value = TransferInfo(
            state = TransferState.RECEIVING,
            direction = TransferDirection.RECEIVE
        )

        // Push any buffered ZMODEM data back into the connection buffer
        // This is critical - during auto-detection, we saved the ZMODEM protocol
        // data and need to make it available to the ZMODEM receiver
        val pushedBytes = NativeBridge.nativePushZmodemBuffer()
        android.util.Log.i("TransferManager", "Pushed $pushedBytes bytes of buffered ZMODEM data")

        transferStartTime = 0L
        startProgressMonitor()

        try {
            val result = NativeBridge.nativeZmodemReceive()

            stopProgressMonitor()

            // zmodem_recv_files returns COUNT of files received
            // result > 0 means success, result == 0 means no files received (failure)
            if (result > 0) {
                val fileName = NativeBridge.nativeGetTransferFileName() ?: "unknown"
                val progress = NativeBridge.nativeGetTransferProgress()
                val bytesTransferred = progress?.getOrNull(0) ?: 0L

                // Move file to final location
                val tempPath = "${fileAccessManager.getTransferCacheDir()}/$fileName"
                fileAccessManager.moveDownloadToFinalLocation(tempPath, fileName)

                _transferState.value = TransferInfo(
                    state = TransferState.COMPLETE,
                    direction = TransferDirection.RECEIVE,
                    fileName = fileName,
                    bytesTransferred = bytesTransferred,
                    totalBytes = bytesTransferred
                )
                TransferResult.Success(fileName, bytesTransferred)
            } else {
                val error = NativeBridge.nativeGetTransferError() ?: "Transfer failed (code: $result)"
                _transferState.value = TransferInfo(
                    state = TransferState.ERROR,
                    direction = TransferDirection.RECEIVE,
                    errorMessage = error
                )
                TransferResult.Error(error)
            }
        } catch (e: CancellationException) {
            NativeBridge.nativeTransferCancel()
            _transferState.value = TransferInfo(
                state = TransferState.CANCELLED,
                direction = TransferDirection.RECEIVE
            )
            TransferResult.Cancelled
        } finally {
            _isTransferring.value = false
        }
    }

    /**
     * Start a ZMODEM send operation.
     * @param uri Content URI of the file to send
     */
    suspend fun startSend(uri: Uri): TransferResult = withContext(Dispatchers.IO) {
        if (_isTransferring.value) {
            return@withContext TransferResult.Error("Transfer already in progress")
        }

        if (!initialize()) {
            return@withContext TransferResult.Error("Failed to initialize transfer subsystem")
        }

        // Copy file to temp location for native access
        val tempPath = fileAccessManager.copyToTempFile(uri)
        if (tempPath == null) {
            return@withContext TransferResult.Error("Failed to access file")
        }

        val fileName = fileAccessManager.getFileName(uri)
        val fileSize = fileAccessManager.getFileSize(uri)

        NativeBridge.nativeTransferReset()
        _isTransferring.value = true
        _transferState.value = TransferInfo(
            state = TransferState.SENDING,
            direction = TransferDirection.SEND,
            fileName = fileName,
            totalBytes = fileSize
        )

        transferStartTime = 0L
        startProgressMonitor()

        try {
            val result = NativeBridge.nativeZmodemSend(tempPath)

            stopProgressMonitor()

            if (result == 0) {
                val progress = NativeBridge.nativeGetTransferProgress()
                val bytesTransferred = progress?.getOrNull(0) ?: fileSize

                _transferState.value = TransferInfo(
                    state = TransferState.COMPLETE,
                    direction = TransferDirection.SEND,
                    fileName = fileName,
                    bytesTransferred = bytesTransferred,
                    totalBytes = fileSize
                )
                TransferResult.Success(fileName, bytesTransferred)
            } else {
                val error = NativeBridge.nativeGetTransferError() ?: "Transfer failed (code: $result)"
                _transferState.value = TransferInfo(
                    state = TransferState.ERROR,
                    direction = TransferDirection.SEND,
                    fileName = fileName,
                    errorMessage = error
                )
                TransferResult.Error(error)
            }
        } catch (e: CancellationException) {
            NativeBridge.nativeTransferCancel()
            _transferState.value = TransferInfo(
                state = TransferState.CANCELLED,
                direction = TransferDirection.SEND,
                fileName = fileName
            )
            TransferResult.Cancelled
        } finally {
            _isTransferring.value = false
            // Always clean up temp file, regardless of success/failure/cancellation
            try {
                java.io.File(tempPath).delete()
            } catch (ex: Exception) {
                // Ignore cleanup errors
            }
        }
    }

    /**
     * Start a ZMODEM send using coroutine launcher.
     */
    fun launchSend(uri: Uri, onComplete: (TransferResult) -> Unit) {
        transferJob = scope.launch {
            val result = try {
                startSend(uri)
            } catch (e: CancellationException) {
                TransferResult.Cancelled
            } catch (e: Exception) {
                android.util.Log.e("TransferManager", "Send failed with exception: ${e.message}", e)
                TransferResult.Error(e.message ?: "Unknown error")
            }
            try {
                withContext(Dispatchers.Main) {
                    onComplete(result)
                }
            } catch (e: Exception) {
                android.util.Log.e("TransferManager", "Callback failed: ${e.message}")
            }
        }
    }

    /**
     * Start a ZMODEM receive using coroutine launcher.
     */
    fun launchReceive(onComplete: (TransferResult) -> Unit) {
        transferJob = scope.launch {
            val result = try {
                startReceive()
            } catch (e: CancellationException) {
                TransferResult.Cancelled
            } catch (e: Exception) {
                android.util.Log.e("TransferManager", "Receive failed with exception: ${e.message}", e)
                TransferResult.Error(e.message ?: "Unknown error")
            }
            try {
                withContext(Dispatchers.Main) {
                    onComplete(result)
                }
            } catch (e: Exception) {
                android.util.Log.e("TransferManager", "Callback failed: ${e.message}")
            }
        }
    }

    /**
     * Cancel the current transfer.
     */
    fun cancelTransfer() {
        NativeBridge.nativeTransferCancel()
        transferJob?.cancel()
        transferJob = null
    }

    /**
     * Start monitoring transfer progress.
     */
    private fun startProgressMonitor() {
        progressJob = scope.launch {
            while (isActive && _isTransferring.value) {
                updateProgress()
                delay(100) // Update every 100ms
            }
        }
    }

    /**
     * Stop progress monitoring.
     */
    private fun stopProgressMonitor() {
        progressJob?.cancel()
        progressJob = null
    }

    /**
     * Update progress from native code.
     */
    private var transferStartTime = 0L

    private fun updateProgress() {
        try {
            val progress = NativeBridge.nativeGetTransferProgress()
            val fileName = NativeBridge.nativeGetTransferFileName()

            // Check native state - this allows UI to update even if the native call
            // is blocked (e.g., in zmodem_send_zfin waiting for BBS acknowledgment)
            val nativeState = NativeBridge.nativeGetTransferState()
            val currentState = _transferState.value.state

            // If native reports completion/error/cancel but Kotlin still shows in-progress,
            // update Kotlin state immediately so the dialog shows correct buttons
            if (currentState == TransferState.SENDING || currentState == TransferState.RECEIVING) {
                when (nativeState) {
                    3 -> { // TRANSFER_COMPLETE
                        val error = NativeBridge.nativeGetTransferError()
                        _transferState.value = _transferState.value.copy(
                            state = TransferState.COMPLETE,
                            errorMessage = if (error.isNullOrEmpty()) null else error
                        )
                        return
                    }
                    4 -> { // TRANSFER_ERROR
                        val error = NativeBridge.nativeGetTransferError() ?: "Transfer failed"
                        _transferState.value = _transferState.value.copy(
                            state = TransferState.ERROR,
                            errorMessage = error
                        )
                        return
                    }
                    5 -> { // TRANSFER_CANCELLED
                        _transferState.value = _transferState.value.copy(
                            state = TransferState.CANCELLED
                        )
                        return
                    }
                }
            }

            // Skip progress updates if we're already in a terminal state
            // (the state was updated above or previously)
            val currentStateAfterCheck = _transferState.value.state
            if (currentStateAfterCheck == TransferState.COMPLETE ||
                currentStateAfterCheck == TransferState.ERROR ||
                currentStateAfterCheck == TransferState.CANCELLED) {
                return
            }

            // Native returns 2 values: [current_pos, total_size]
            if (progress != null && progress.size >= 2) {
                val bytesTransferred = progress.getOrNull(0) ?: 0L
                val totalBytes = progress.getOrNull(1) ?: 0L

                // Track start time for speed calculation
                if (transferStartTime == 0L && bytesTransferred > 0) {
                    transferStartTime = System.currentTimeMillis()
                }

                val elapsedMs = if (transferStartTime > 0) {
                    (System.currentTimeMillis() - transferStartTime).coerceAtLeast(0)
                } else 0L

                val bytesPerSec = if (elapsedMs > 0 && bytesTransferred >= 0) {
                    (bytesTransferred * 1000L) / elapsedMs
                } else 0L

                _transferState.value = _transferState.value.copy(
                    fileName = fileName ?: _transferState.value.fileName,
                    bytesTransferred = bytesTransferred,
                    totalBytes = totalBytes,
                    bytesPerSecond = bytesPerSec
                )
            }
        } catch (e: Exception) {
            android.util.Log.e("TransferManager", "Failed to update progress: ${e.message}")
        }
    }

    /**
     * Reset state after transfer completion.
     */
    fun reset() {
        NativeBridge.nativeTransferReset()
        _transferState.value = TransferInfo()
        _isTransferring.value = false
        transferStartTime = 0L
    }

    /**
     * Clean up resources.
     */
    fun cleanup() {
        cancelTransfer()
        // Cancel progress job first, then the main scope
        progressJob?.cancel()
        progressJob = null
        transferJob?.cancel()
        transferJob = null
        // Cancel the supervisor job to stop all coroutines in the scope
        supervisorJob.cancel()
        if (initialized) {
            NativeBridge.nativeTransferCleanup()
            initialized = false
        }
        fileAccessManager.cleanupTempFiles()
    }

    /**
     * Check if a ZMODEM auto-download sequence was detected.
     *
     * NOTE: This method is currently unused - ZMODEM detection is handled
     * in native code (conn_api.c) which returns special codes (-100, -101)
     * through nativeProcessData(). Kept for reference/debugging purposes.
     *
     * @param data Received data from terminal
     * @return true if ZMODEM init sequence detected
     */
    @Suppress("unused")
    fun checkForZmodemInit(data: ByteArray): Boolean {
        // ZMODEM starts with "rz\r" followed by ZRQINIT (ZDLE 'B' '0' '0')
        // or just the ZRQINIT header: 0x18 0x42 0x30 0x30
        if (data.size < 4) return false

        // Look for ZDLE (0x18) followed by 'B' (0x42)
        for (i in 0 until data.size - 3) {
            if (data[i] == 0x18.toByte() && data[i + 1] == 0x42.toByte()) {
                // Possible ZMODEM header
                return true
            }
        }

        // Also check for "rz\r" or "rz\n" which some BBS systems send
        val dataStr = String(data, Charsets.US_ASCII)
        if (dataStr.contains("rz\r") || dataStr.contains("rz\n")) {
            return true
        }

        return false
    }
}

/**
 * Transfer state information.
 */
data class TransferInfo(
    val state: TransferState = TransferState.IDLE,
    val direction: TransferDirection = TransferDirection.NONE,
    val fileName: String? = null,
    val bytesTransferred: Long = 0,
    val totalBytes: Long = 0,
    val bytesPerSecond: Long = 0,
    val errorMessage: String? = null
) {
    val progressPercent: Int
        get() = if (totalBytes > 0) {
            ((bytesTransferred * 100) / totalBytes).toInt().coerceIn(0, 100)
        } else 0

    val formattedProgress: String
        get() = "${formatBytes(bytesTransferred)} / ${formatBytes(totalBytes)}"

    val formattedSpeed: String
        get() = "${formatBytes(bytesPerSecond)}/s"

    private fun formatBytes(bytes: Long): String {
        return when {
            bytes >= 1024 * 1024 -> String.format("%.1f MB", bytes / (1024.0 * 1024.0))
            bytes >= 1024 -> String.format("%.1f KB", bytes / 1024.0)
            else -> "$bytes B"
        }
    }
}

/**
 * Transfer state enumeration.
 */
enum class TransferState {
    IDLE,
    RECEIVING,
    SENDING,
    COMPLETE,
    ERROR,
    CANCELLED
}

/**
 * Transfer direction.
 */
enum class TransferDirection {
    NONE,
    SEND,
    RECEIVE
}

/**
 * Transfer result.
 */
sealed class TransferResult {
    data class Success(val fileName: String, val bytesTransferred: Long) : TransferResult()
    data class Error(val message: String) : TransferResult()
    object Cancelled : TransferResult()
}

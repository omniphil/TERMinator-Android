package com.syncterm.android

/**
 * JNI bridge to the native SyncTERM terminal emulator and Telnet connection code.
 */
object NativeBridge {

    private var isLibraryLoaded = false

    init {
        try {
            System.loadLibrary("syncterm-native")
            isLibraryLoaded = true
        } catch (e: UnsatisfiedLinkError) {
            android.util.Log.e("NativeBridge", "Failed to load native library: ${e.message}")
            isLibraryLoaded = false
        }
    }

    /**
     * Check if the native library was loaded successfully.
     */
    fun isNativeLibraryLoaded(): Boolean = isLibraryLoaded

    // Initialization
    @JvmStatic
    external fun nativeSetFilesDir(path: String)

    @JvmStatic
    external fun nativeInit(): Boolean

    @JvmStatic
    external fun nativeDestroy()

    // Connection management
    // protocol: CONN_TYPE_TELNET (3) or CONN_TYPE_SSH (5)
    @JvmStatic
    external fun nativeConnect(
        host: String,
        port: Int,
        protocol: Int = CONN_TYPE_TELNET,
        username: String? = null,
        password: String? = null
    ): Boolean

    // Connection type constants (from conn.h)
    const val CONN_TYPE_TELNET = 3
    const val CONN_TYPE_SSH = 5

    @JvmStatic
    external fun nativeDisconnect()

    @JvmStatic
    external fun nativeIsConnected(): Boolean

    // Data transfer
    @JvmStatic
    external fun nativeSendData(data: ByteArray): Int

    @JvmStatic
    external fun nativeSendKey(keyCode: Int): Int

    @JvmStatic
    external fun nativeSendString(str: String): Int

    @JvmStatic
    external fun nativeProcessData(): Int

    @JvmStatic
    external fun nativeDataWaiting(): Int

    // Screen state
    /**
     * Gets the screen buffer as a packed int array.
     * Each int is: character | (attr << 8) | (fg << 16) | (bg << 24)
     */
    @JvmStatic
    external fun nativeGetScreenBuffer(): IntArray?

    @JvmStatic
    external fun nativeGetPalette(): IntArray?

    @JvmStatic
    external fun nativeGetScreenSize(): IntArray?

    @JvmStatic
    external fun nativeGetCursorPos(): IntArray?

    @JvmStatic
    external fun nativeIsCursorVisible(): Boolean

    @JvmStatic
    external fun nativeIsScreenDirty(): Boolean

    /**
     * Get dirty region bounds for partial redraw optimization.
     * @return IntArray of [minX, minY, maxX, maxY] or null if no dirty region
     */
    @JvmStatic
    external fun nativeGetDirtyRegion(): IntArray?

    // Terminal control
    @JvmStatic
    external fun nativeSetTerminalSize(width: Int, height: Int)

    @JvmStatic
    external fun nativeSetFont(fontName: String): Boolean

    @JvmStatic
    external fun nativeClearScreen()

    @JvmStatic
    external fun nativePushInput(data: ByteArray)

    // Status
    @JvmStatic
    external fun nativeGetStatusInfo(): String

    /**
     * Get connection statistics.
     * @return LongArray of [bytesSent, bytesReceived, connectTimeMs, currentTimeMs], or null if error
     */
    @JvmStatic
    external fun nativeGetConnectionStats(): LongArray?

    // Font bitmap data for rendering
    // Returns: first 2 bytes are width (8) and height (8/14/16), rest is bitmap data
    @JvmStatic
    external fun nativeGetFontBitmap(): ByteArray?

    @JvmStatic
    external fun nativeSetFontById(fontId: Int): Boolean

    @JvmStatic
    external fun nativeSetHideStatusLine(hide: Boolean)

    @JvmStatic
    external fun nativeSetScreenMode(mode: Int)

    // File transfer (ZMODEM/XMODEM)

    /**
     * Initialize the file transfer subsystem.
     * Must be called before any transfer operations.
     * @return true if initialization successful
     */
    @JvmStatic
    external fun nativeTransferInit(): Boolean

    /**
     * Set the download directory for received files.
     * @param dir Absolute path to download directory
     */
    @JvmStatic
    external fun nativeSetDownloadDir(dir: String)

    /**
     * Start a ZMODEM receive operation.
     * This will block until the transfer completes or fails.
     * @return 0 on success, negative error code on failure
     */
    @JvmStatic
    external fun nativeZmodemReceive(): Int

    /**
     * Start a ZMODEM send operation.
     * This will block until the transfer completes or fails.
     * @param filePath Absolute path to file to send
     * @return 0 on success, negative error code on failure
     */
    @JvmStatic
    external fun nativeZmodemSend(filePath: String): Int

    /**
     * Cancel the current transfer operation.
     */
    @JvmStatic
    external fun nativeTransferCancel()

    /**
     * Get the current transfer state.
     * @return State code: 0=IDLE, 1=RECEIVING, 2=SENDING, 3=COMPLETE, 4=ERROR, 5=CANCELLED
     */
    @JvmStatic
    external fun nativeGetTransferState(): Int

    /**
     * Get transfer progress information.
     * @return LongArray of [bytesTransferred, totalBytes, startTime, currentTime], or null if no transfer
     */
    @JvmStatic
    external fun nativeGetTransferProgress(): LongArray?

    /**
     * Get the name of the file being transferred.
     * @return File name, or null if no active transfer
     */
    @JvmStatic
    external fun nativeGetTransferFileName(): String?

    /**
     * Get the error message from the last failed transfer.
     * @return Error message, or null if no error
     */
    @JvmStatic
    external fun nativeGetTransferError(): String?

    /**
     * Reset transfer state after completion or error.
     * Call this before starting a new transfer.
     */
    @JvmStatic
    external fun nativeTransferReset()

    /**
     * Cleanup file transfer resources.
     * Call when done with transfers.
     */
    @JvmStatic
    external fun nativeTransferCleanup()

    // Transfer state constants
    object TransferState {
        const val IDLE = 0
        const val RECEIVING = 1
        const val SENDING = 2
        const val COMPLETE = 3
        const val ERROR = 4
        const val CANCELLED = 5
    }

    // ZMODEM auto-detection

    /**
     * Check if ZMODEM was auto-detected in incoming data.
     * @return true if ZMODEM init sequence was detected
     */
    @JvmStatic
    external fun nativeIsZmodemDetected(): Boolean

    /**
     * Get buffered ZMODEM data that was saved during detection.
     * @return Byte array of buffered data, or null if none
     */
    @JvmStatic
    external fun nativeGetZmodemBuffer(): ByteArray?

    /**
     * Clear ZMODEM detection state after transfer completes.
     */
    @JvmStatic
    external fun nativeClearZmodemDetected()

    /**
     * Push buffered ZMODEM data back into connection input buffer.
     * Must be called before ZMODEM receive starts so the protocol data
     * that was saved during detection is available to the ZMODEM receiver.
     * @return Number of bytes pushed
     */
    @JvmStatic
    external fun nativePushZmodemBuffer(): Int

    // Upload queue functions

    /**
     * Queue a file for upload. The upload will start when the BBS sends ZRINIT.
     * @param filePath Absolute path to the file to upload
     */
    @JvmStatic
    external fun nativeQueueUpload(filePath: String)

    /**
     * Check if a file is queued for upload.
     * @return true if a file is waiting to be uploaded
     */
    @JvmStatic
    external fun nativeIsUploadQueued(): Boolean

    /**
     * Check if the BBS is ready for upload (ZRINIT received).
     * @return true if ZRINIT was detected and BBS is ready to receive
     */
    @JvmStatic
    external fun nativeIsUploadReady(): Boolean

    /**
     * Get the path of the queued upload file.
     * @return File path, or null if no file is queued
     */
    @JvmStatic
    external fun nativeGetQueuedUpload(): String?

    /**
     * Clear the upload queue and reset upload ready state.
     */
    @JvmStatic
    external fun nativeClearUploadQueue()

    // Scrollback buffer access

    /**
     * Get scrollback buffer info.
     * @return IntArray of [filledLines, totalCapacity, columns], or null if unavailable
     */
    @JvmStatic
    external fun nativeGetScrollbackInfo(): IntArray?

    /**
     * Get scrollback buffer content.
     * @param offset Lines back from most recent (0 = most recent scrollback line)
     * @param count Number of lines to retrieve
     * @return Packed int array like nativeGetScreenBuffer, or null if invalid
     */
    @JvmStatic
    external fun nativeGetScrollbackBuffer(offset: Int, count: Int): IntArray?

    // Bell detection

    /**
     * Check if a bell (BEL character) was received and clear the flag.
     * @return true if bell was detected since last check
     */
    @JvmStatic
    external fun nativeCheckBell(): Boolean

    // Session logging

    /**
     * Enable or disable session logging.
     * When enabled, received data is buffered for retrieval.
     * @param enabled true to enable logging, false to disable
     */
    @JvmStatic
    external fun nativeSetLoggingEnabled(enabled: Boolean)

    /**
     * Get and clear logged data from the buffer.
     * @return Byte array of logged data, or null if no data available
     */
    @JvmStatic
    external fun nativeGetLoggedData(): ByteArray?

    // Helper functions

    /**
     * Unpack character from packed cell value.
     */
    fun unpackChar(cell: Int): Char = (cell and 0xFF).toChar()

    /**
     * Unpack legacy attribute from packed cell value.
     */
    fun unpackAttr(cell: Int): Int = (cell shr 8) and 0xFF

    /**
     * Get foreground color from attribute byte.
     */
    fun attrToFg(attr: Int): Int = attr and 0x0F

    /**
     * Get background color from attribute byte.
     */
    fun attrToBg(attr: Int): Int = (attr shr 4) and 0x07
}

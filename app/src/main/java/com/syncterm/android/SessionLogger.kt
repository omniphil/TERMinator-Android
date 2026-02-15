package com.syncterm.android

import android.content.Context
import android.net.Uri
import android.util.Log
import androidx.documentfile.provider.DocumentFile
import java.io.BufferedWriter
import java.io.File
import java.io.FileWriter
import java.io.OutputStreamWriter
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Manages session logging for terminal sessions.
 * Captures terminal output and saves to a text file.
 */
class SessionLogger(private val context: Context) {

    companion object {
        private const val TAG = "SessionLogger"
        private const val LOG_DIR = "session_logs"
        private const val FLUSH_INTERVAL_BYTES = 4096L
    }

    private var writer: BufferedWriter? = null
    private var logFile: File? = null
    private var logUri: Uri? = null
    private val isLogging = AtomicBoolean(false)
    private var sessionName: String = ""
    private var startTime: Long = 0
    private var bytesLogged: Long = 0
    private var lastFlushBytes: Long = 0  // Track bytes at last flush

    // Lock object for thread-safe writer access
    private val writerLock = Any()

    /**
     * Check if logging is currently active.
     */
    fun isLogging(): Boolean = isLogging.get()

    /**
     * Get the current log file name.
     */
    fun getLogFileName(): String? = logFile?.name

    /**
     * Get bytes logged in current session.
     */
    fun getBytesLogged(): Long = bytesLogged

    /**
     * Start logging a session.
     * @param bbsName Name of the BBS for the log filename
     * @param customUri Optional custom URI to save to (from SAF picker)
     * @return true if logging started successfully
     */
    fun startLogging(bbsName: String, customUri: Uri? = null): Boolean {
        if (isLogging.get()) {
            Log.w(TAG, "Already logging")
            return false
        }

        sessionName = bbsName.replace(Regex("[^a-zA-Z0-9._-]"), "_")
        startTime = System.currentTimeMillis()
        bytesLogged = 0

        try {
            if (customUri != null) {
                // Use SAF-provided URI
                logUri = customUri
                val outputStream = context.contentResolver.openOutputStream(customUri, "wa")
                if (outputStream != null) {
                    writer = BufferedWriter(OutputStreamWriter(outputStream, Charsets.UTF_8))
                } else {
                    Log.e(TAG, "Failed to open output stream for URI")
                    return false
                }
            } else {
                // Use internal app storage
                val logDir = File(context.filesDir, LOG_DIR)
                if (!logDir.exists()) {
                    logDir.mkdirs()
                }

                val timestamp = SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(Date())
                val fileName = "${sessionName}_$timestamp.log"
                logFile = File(logDir, fileName)
                writer = BufferedWriter(FileWriter(logFile, true))
            }

            // Write session header
            val header = buildString {
                append("=" .repeat(60))
                append("\n")
                append("TERMinator Session Log\n")
                append("BBS: $bbsName\n")
                append("Started: ${SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(Date())}\n")
                append("=".repeat(60))
                append("\n\n")
            }
            val currentWriter = writer
            if (currentWriter == null) {
                Log.e(TAG, "Writer is null after initialization")
                return false
            }
            currentWriter.write(header)
            currentWriter.flush()

            isLogging.set(true)
            Log.i(TAG, "Started logging to: ${logFile?.absolutePath ?: logUri}")
            return true

        } catch (e: Exception) {
            Log.e(TAG, "Failed to start logging", e)
            cleanup()
            return false
        }
    }

    /**
     * Log raw data received from the terminal.
     * Strips ANSI escape sequences for cleaner logs.
     * Thread-safe: uses synchronized access to writer.
     * @param data Raw bytes from terminal
     */
    fun logData(data: ByteArray) {
        // Early return without lock for performance
        if (!isLogging.get()) return

        try {
            // Convert to string and strip ANSI escape sequences
            val text = String(data, Charsets.ISO_8859_1)
            val cleanText = stripAnsiCodes(text)

            if (cleanText.isNotEmpty()) {
                synchronized(writerLock) {
                    // Re-check logging state inside synchronized block to prevent race condition
                    // where stopLogging() is called between the outer check and acquiring the lock
                    if (!isLogging.get()) return
                    val currentWriter = writer ?: return
                    currentWriter.write(cleanText)
                    bytesLogged += cleanText.length

                    // Flush periodically (every 4KB) to prevent data loss
                    if (bytesLogged - lastFlushBytes >= FLUSH_INTERVAL_BYTES) {
                        currentWriter.flush()
                        lastFlushBytes = bytesLogged
                    }
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error writing to log", e)
        }
    }

    /**
     * Log a string directly (for sent data or markers).
     * Thread-safe: uses synchronized access to writer.
     */
    fun logString(text: String) {
        if (!isLogging.get()) return

        try {
            synchronized(writerLock) {
                val currentWriter = writer ?: return
                currentWriter.write(text)
                bytesLogged += text.length
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error writing string to log", e)
        }
    }

    /**
     * Add a timestamp marker to the log.
     */
    fun addTimestamp() {
        if (!isLogging.get()) return

        val timestamp = SimpleDateFormat("HH:mm:ss", Locale.US).format(Date())
        logString("\n--- [$timestamp] ---\n")
    }

    /**
     * Stop logging and close the file.
     * Thread-safe: uses synchronized access to writer.
     * @return The path/URI of the saved log file, or null if not logging
     */
    fun stopLogging(): String? {
        if (!isLogging.get()) return null

        try {
            synchronized(writerLock) {
                val currentWriter = writer ?: return null

                // Write session footer
                val duration = (System.currentTimeMillis() - startTime) / 1000
                val hours = duration / 3600
                val minutes = (duration % 3600) / 60
                val seconds = duration % 60

                val footer = buildString {
                    append("\n\n")
                    append("=".repeat(60))
                    append("\n")
                    append("Session ended: ${SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(Date())}\n")
                    append("Duration: ${String.format("%02d:%02d:%02d", hours, minutes, seconds)}\n")
                    append("Bytes logged: ${formatBytes(bytesLogged)}\n")
                    append("=".repeat(60))
                    append("\n")
                }
                currentWriter.write(footer)
                currentWriter.flush()
                currentWriter.close()
            }

            val result = logFile?.absolutePath ?: logUri?.toString()
            Log.i(TAG, "Stopped logging. File: $result")

            return result

        } catch (e: Exception) {
            Log.e(TAG, "Error stopping log", e)
            return null
        } finally {
            cleanup()
        }
    }

    /**
     * Clean up resources.
     * Thread-safe: uses synchronized access to writer.
     */
    private fun cleanup() {
        synchronized(writerLock) {
            try {
                writer?.close()
            } catch (e: Exception) {
                // Ignore
            }
            writer = null
            logFile = null
            logUri = null
            lastFlushBytes = 0
        }
        isLogging.set(false)
    }

    /**
     * Strip ANSI escape sequences from text.
     */
    private fun stripAnsiCodes(text: String): String {
        // Match ANSI escape sequences:
        // ESC [ ... (letter) - CSI sequences
        // ESC ] ... (BEL or ESC \) - OSC sequences
        // ESC (other) - other escape sequences
        return text
            .replace(Regex("\u001B\\[[0-9;]*[A-Za-z]"), "")  // CSI sequences
            .replace(Regex("\u001B\\][^\u0007\u001B]*[\u0007]"), "")  // OSC sequences ending with BEL
            .replace(Regex("\u001B\\][^\u0007\u001B]*\u001B\\\\"), "")  // OSC sequences ending with ST
            .replace(Regex("\u001B[^\\[\\]][A-Za-z]"), "")  // Other escape sequences
            .replace("\u0007", "")  // BEL character
    }

    /**
     * Format bytes to human-readable string.
     */
    private fun formatBytes(bytes: Long): String {
        return when {
            bytes >= 1024 * 1024 -> String.format("%.1f MB", bytes / (1024.0 * 1024.0))
            bytes >= 1024 -> String.format("%.1f KB", bytes / 1024.0)
            else -> "$bytes bytes"
        }
    }

    /**
     * Get list of saved log files.
     */
    fun getLogFiles(): List<File> {
        val logDir = File(context.filesDir, LOG_DIR)
        return if (logDir.exists()) {
            logDir.listFiles()?.filter { it.extension == "log" }?.sortedByDescending { it.lastModified() } ?: emptyList()
        } else {
            emptyList()
        }
    }

    /**
     * Delete a log file.
     */
    fun deleteLogFile(file: File): Boolean {
        return try {
            file.delete()
        } catch (e: Exception) {
            Log.e(TAG, "Failed to delete log file", e)
            false
        }
    }
}

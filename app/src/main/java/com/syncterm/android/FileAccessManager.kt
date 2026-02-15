package com.syncterm.android

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Environment
import android.provider.DocumentsContract
import android.provider.OpenableColumns
import androidx.activity.result.ActivityResultLauncher
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.documentfile.provider.DocumentFile
import java.io.File
import java.io.FileOutputStream
import java.io.InputStream

/**
 * Manages file access for ZMODEM transfers using Android's Scoped Storage.
 * Handles file picking, folder selection, and URI-to-path conversions.
 */
class FileAccessManager(private val activity: AppCompatActivity) {

    companion object {
        private const val TAG = "FileAccessManager"
        private const val PREFS_NAME = "file_access_settings"
        private const val KEY_DOWNLOAD_DIR_URI = "download_dir_uri"
    }

    private var onFilePicked: ((Uri?, String?) -> Unit)? = null
    private var onFolderPicked: ((Uri?) -> Unit)? = null
    private var onFileCreated: ((Uri?) -> Unit)? = null

    // Launcher for picking files to send
    private lateinit var filePickerLauncher: ActivityResultLauncher<Array<String>>

    // Launcher for picking download folder
    private lateinit var folderPickerLauncher: ActivityResultLauncher<Uri?>

    // Launcher for creating files (for download)
    private lateinit var fileCreatorLauncher: ActivityResultLauncher<String>

    // Cached download directory URI - loaded from SharedPreferences
    private var downloadDirUri: Uri? = null

    init {
        // Load saved download directory URI on initialization
        loadDownloadDirUri()
    }

    /**
     * Load the saved download directory URI from SharedPreferences.
     */
    private fun loadDownloadDirUri() {
        val prefs = activity.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val uriString = prefs.getString(KEY_DOWNLOAD_DIR_URI, null)
        if (uriString != null) {
            try {
                downloadDirUri = Uri.parse(uriString)
                android.util.Log.i(TAG, "Loaded saved download dir: $downloadDirUri")
            } catch (e: Exception) {
                android.util.Log.e(TAG, "Failed to parse saved download URI: ${e.message}")
            }
        }
    }

    /**
     * Save the download directory URI to SharedPreferences.
     */
    private fun saveDownloadDirUri(uri: Uri?) {
        val prefs = activity.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val editor = prefs.edit()
        if (uri != null) {
            editor.putString(KEY_DOWNLOAD_DIR_URI, uri.toString())
            android.util.Log.i(TAG, "Saved download dir: $uri")
        } else {
            editor.remove(KEY_DOWNLOAD_DIR_URI)
        }
        editor.apply()
    }

    // Temporary directory for native access
    private val transferCacheDir: File by lazy {
        File(activity.cacheDir, "zmodem_transfer").apply { mkdirs() }
    }

    /**
     * Register activity result launchers. Must be called in onCreate before activity is started.
     */
    fun registerLaunchers() {
        filePickerLauncher = activity.registerForActivityResult(
            ActivityResultContracts.OpenDocument()
        ) { uri ->
            if (uri != null) {
                // Take persistent permission
                try {
                    activity.contentResolver.takePersistableUriPermission(
                        uri,
                        Intent.FLAG_GRANT_READ_URI_PERMISSION
                    )
                } catch (e: SecurityException) {
                    // Permission might not be persistable, continue anyway
                }
                val fileName = getFileName(uri)
                onFilePicked?.invoke(uri, fileName)
            } else {
                onFilePicked?.invoke(null, null)
            }
        }

        folderPickerLauncher = activity.registerForActivityResult(
            ActivityResultContracts.OpenDocumentTree()
        ) { uri ->
            if (uri != null) {
                // Take persistent permission
                try {
                    activity.contentResolver.takePersistableUriPermission(
                        uri,
                        Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION
                    )
                } catch (e: SecurityException) {
                    // Permission might not be persistable
                }
                downloadDirUri = uri
                // Save to SharedPreferences for persistence across sessions
                saveDownloadDirUri(uri)
            }
            onFolderPicked?.invoke(uri)
        }

        fileCreatorLauncher = activity.registerForActivityResult(
            ActivityResultContracts.CreateDocument("*/*")
        ) { uri ->
            onFileCreated?.invoke(uri)
        }
    }

    /**
     * Pick a file to send via ZMODEM.
     * @param callback Called with the file URI and name, or null if cancelled
     */
    fun pickFileToSend(callback: (Uri?, String?) -> Unit) {
        onFilePicked = callback
        filePickerLauncher.launch(arrayOf("*/*"))
    }

    /**
     * Pick a folder for downloads.
     * @param callback Called with the folder URI, or null if cancelled
     */
    fun pickDownloadFolder(callback: (Uri?) -> Unit) {
        onFolderPicked = callback
        folderPickerLauncher.launch(null)
    }

    /**
     * Get the currently selected download directory URI.
     */
    fun getDownloadDirUri(): Uri? = downloadDirUri

    /**
     * Get the file name from a content URI.
     * Always returns a non-null value, using "file" as ultimate fallback.
     */
    fun getFileName(uri: Uri): String {
        var name: String? = null
        try {
            activity.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { cursor ->
                if (cursor.moveToFirst()) {
                    val nameIndex = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                    if (nameIndex >= 0) {
                        // cursor.getString can return null
                        name = cursor.getString(nameIndex)
                    }
                }
            }
        } catch (e: Exception) {
            // Ignore query errors, fall through to other methods
        }
        // Try lastPathSegment if query didn't work
        if (name == null) {
            name = uri.lastPathSegment
        }
        // Ultimate fallback
        return name ?: "file"
    }

    /**
     * Get the file size from a content URI.
     * @return File size in bytes, or 0 if size cannot be determined (never returns -1)
     */
    fun getFileSize(uri: Uri): Long {
        var size: Long = 0  // Default to 0 instead of -1 for unknown size
        try {
            activity.contentResolver.query(uri, arrayOf(OpenableColumns.SIZE), null, null, null)?.use { cursor ->
                if (cursor.moveToFirst()) {
                    val sizeIndex = cursor.getColumnIndex(OpenableColumns.SIZE)
                    if (sizeIndex >= 0) {
                        val queriedSize = cursor.getLong(sizeIndex)
                        // Only use queried size if it's positive (valid)
                        if (queriedSize > 0) {
                            size = queriedSize
                        }
                    }
                }
            }
        } catch (e: Exception) {
            android.util.Log.e(TAG, "Failed to get file size: ${e.message}")
        }
        return size
    }

    /**
     * Copy a content URI to a temporary file for native access.
     * Native code requires file paths, not content URIs.
     * @param uri Source content URI
     * @return Path to temporary file, or null on failure
     */
    fun copyToTempFile(uri: Uri): String? {
        val fileName = getFileName(uri)
        val tempFile = File(transferCacheDir, fileName)

        return try {
            activity.contentResolver.openInputStream(uri)?.use { input ->
                FileOutputStream(tempFile).use { output ->
                    input.copyTo(output)
                }
            }
            tempFile.absolutePath
        } catch (e: Exception) {
            android.util.Log.e(TAG, "Failed to copy file to temp: ${e.message}")
            // Delete partial file on failure to avoid leaving corrupted files
            try {
                if (tempFile.exists()) {
                    tempFile.delete()
                }
            } catch (deleteError: Exception) {
                // Ignore cleanup errors
            }
            null
        }
    }

    /**
     * Create a file in the download directory for receiving.
     * @param fileName Name of the file to create
     * @return Path to the created file, or null on failure
     */
    fun createDownloadFile(fileName: String): String? {
        // If we have a SAF-selected directory, create file there
        val dirUri = downloadDirUri
        if (dirUri != null) {
            val docFile = DocumentFile.fromTreeUri(activity, dirUri)
            if (docFile != null && docFile.canWrite()) {
                val newFile = docFile.createFile("application/octet-stream", fileName)
                if (newFile != null) {
                    // We need a real path for native code - copy to cache and we'll move later
                    return createTempDownloadFile(fileName)
                }
            }
        }

        // Fall back to app-specific downloads directory
        return createTempDownloadFile(fileName)
    }

    /**
     * Create a temporary file for download that native code can write to.
     */
    private fun createTempDownloadFile(fileName: String): String? {
        val tempFile = File(transferCacheDir, fileName)
        return try {
            if (tempFile.exists()) {
                tempFile.delete()
            }
            tempFile.createNewFile()
            tempFile.absolutePath
        } catch (e: Exception) {
            android.util.Log.e(TAG, "Failed to create temp download file: ${e.message}")
            null
        }
    }

    /**
     * Move a completed download from temp to the selected download directory.
     * @param tempPath Path to the temporary file
     * @param fileName Desired file name in download directory
     * @return true if successful
     */
    fun moveDownloadToFinalLocation(tempPath: String, fileName: String): Boolean {
        val tempFile = File(tempPath)
        if (!tempFile.exists()) return false

        val dirUri = downloadDirUri
        if (dirUri != null) {
            val docFile = DocumentFile.fromTreeUri(activity, dirUri)
            if (docFile != null && docFile.canWrite()) {
                // Create the destination file
                val newFile = docFile.createFile("application/octet-stream", fileName)
                if (newFile != null) {
                    return try {
                        activity.contentResolver.openOutputStream(newFile.uri)?.use { output ->
                            tempFile.inputStream().use { input ->
                                input.copyTo(output)
                            }
                        }
                        tempFile.delete()
                        true
                    } catch (e: Exception) {
                        android.util.Log.e(TAG, "Failed to copy to SAF: ${e.message}")
                        false
                    }
                }
            }
        }

        // Try to move to public Downloads folder
        val downloadsDir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
        if (downloadsDir.canWrite()) {
            val destFile = File(downloadsDir, fileName)
            return try {
                tempFile.copyTo(destFile, overwrite = true)
                tempFile.delete()
                true
            } catch (e: Exception) {
                android.util.Log.e(TAG, "Failed to move to Downloads: ${e.message}")
                false
            }
        }

        // Leave in cache dir as fallback
        return true
    }

    /**
     * Get the path to the transfer cache directory.
     * Native code writes downloads here before final placement.
     */
    fun getTransferCacheDir(): String {
        return transferCacheDir.absolutePath
    }

    /**
     * Clean up temporary transfer files.
     */
    fun cleanupTempFiles() {
        val files = transferCacheDir.listFiles()
        if (files == null) {
            android.util.Log.w(TAG, "Could not list temp files for cleanup (permission denied or not a directory)")
            return
        }
        var cleanedCount = 0
        var failedCount = 0
        files.forEach { file ->
            try {
                if (file.delete()) {
                    cleanedCount++
                } else {
                    failedCount++
                }
            } catch (e: Exception) {
                android.util.Log.w(TAG, "Failed to delete temp file ${file.name}: ${e.message}")
                failedCount++
            }
        }
        if (cleanedCount > 0 || failedCount > 0) {
            android.util.Log.i(TAG, "Temp file cleanup: $cleanedCount deleted, $failedCount failed")
        }
    }

    /**
     * Open an input stream for reading a file.
     */
    fun openInputStream(uri: Uri): InputStream? {
        return try {
            activity.contentResolver.openInputStream(uri)
        } catch (e: Exception) {
            android.util.Log.e(TAG, "Failed to open input stream: ${e.message}")
            null
        }
    }

    /**
     * Check if we have a download directory configured.
     */
    fun hasDownloadDirectory(): Boolean {
        return downloadDirUri != null || transferCacheDir.canWrite()
    }

    /**
     * Check if user has selected a custom download directory (not just using cache).
     */
    fun hasUserSelectedDownloadDirectory(): Boolean {
        return downloadDirUri != null
    }

    /**
     * Get a human-readable description of the download location.
     */
    fun getDownloadLocationDescription(): String {
        val dirUri = downloadDirUri
        if (dirUri != null) {
            val docFile = DocumentFile.fromTreeUri(activity, dirUri)
            return docFile?.name ?: "Selected folder"
        }
        return "App cache (select folder for permanent storage)"
    }
}

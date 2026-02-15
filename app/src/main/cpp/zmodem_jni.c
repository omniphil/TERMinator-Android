/**
 * ZMODEM JNI Bridge
 *
 * Provides JNI functions to connect Android/Kotlin with the native
 * ZMODEM file transfer protocol implementation.
 */

#include <jni.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <android/log.h>
#include <errno.h>
#include <sys/stat.h>

#include "safe_math.h"

// xpdev headers - must come before zmodem.h for type definitions
#include "gen_defs.h"   // BOOL, BYTE, etc.
#include "genwrap.h"
#include "filewrap.h"
#include "dirwrap.h"    // MAX_PATH

// SBBS3 protocol headers
#include "zmodem.h"
#include "xmodem.h"
#include "conn.h"

#define LOG_TAG "SyncTERM-ZMODEM"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)

// Transfer states
typedef enum {
    TRANSFER_IDLE = 0,
    TRANSFER_RECEIVING = 1,
    TRANSFER_SENDING = 2,
    TRANSFER_COMPLETE = 3,
    TRANSFER_ERROR = 4,
    TRANSFER_CANCELLED = 5
} transfer_state_t;

// Transfer context
typedef struct {
    zmodem_t zm;
    xmodem_t xm;
    transfer_state_t state;
    int cancelled;
    int64_t current_pos;
    int64_t total_size;
    char current_file[MAX_PATH + 1];
    char download_dir[MAX_PATH + 1];
    char error_message[256];
    int log_level;
    pthread_mutex_t lock;
} transfer_context_t;

// Global transfer context
static transfer_context_t g_transfer = {
    .state = TRANSFER_IDLE,
    .cancelled = 0,
    .current_pos = 0,
    .total_size = 0,
    .current_file = "",
    .download_dir = "",
    .error_message = "",
    .log_level = LOG_INFO
};

static int g_transfer_initialized = 0;

// Forward declarations for callbacks
static int zmodem_lputs_cb(void* cbdata, int level, const char* str);
static int zmodem_send_byte_cb(void* cbdata, BYTE ch, unsigned timeout);
static int zmodem_recv_byte_cb(void* cbdata, unsigned timeout);
static void zmodem_progress_cb(void* cbdata, int64_t current_pos);
static BOOL zmodem_is_connected_cb(void* cbdata);
static BOOL zmodem_is_cancelled_cb(void* cbdata);
static BOOL zmodem_data_waiting_cb(void* cbdata, unsigned timeout);
static void zmodem_flush_cb(void* cbdata);

// External connection API - declared in conn.h, implemented in conn.c
// Note: conn_connected(), conn_send(), conn_recv_upto(), conn_data_waiting()
// are all declared in conn.h which is included via conn.h

/**
 * ZMODEM Callback: Log output
 */
static int zmodem_lputs_cb(void* cbdata, int level, const char* str) {
    (void)cbdata;

    int android_level;
    switch (level) {
        case LOG_EMERG:
        case LOG_ALERT:
        case LOG_CRIT:
        case LOG_ERR:
            android_level = ANDROID_LOG_ERROR;
            break;
        case LOG_WARNING:
            android_level = ANDROID_LOG_WARN;
            break;
        case LOG_NOTICE:
        case LOG_INFO:
            android_level = ANDROID_LOG_INFO;
            break;
        case LOG_DEBUG:
        default:
            android_level = ANDROID_LOG_DEBUG;
            break;
    }

    __android_log_print(android_level, LOG_TAG, "%s", str);
    return 0;
}

/**
 * ZMODEM Callback: Send a byte with timeout
 */
static int zmodem_send_byte_cb(void* cbdata, BYTE ch, unsigned timeout) {
    (void)cbdata;

    if (!conn_connected()) {
        return -1;
    }

    // Cap timeout to prevent overflow in multiplication (max ~4294 seconds)
    if (timeout > 4000000) timeout = 4000000;
    int sent = conn_send(&ch, 1, timeout * 1000);  // Convert to milliseconds
    return (sent == 1) ? 0 : -1;
}

/**
 * ZMODEM Callback: Receive a byte with timeout
 */
static int zmodem_recv_byte_cb(void* cbdata, unsigned timeout) {
    (void)cbdata;
    static unsigned recv_call_count = 0;

    recv_call_count++;

    if (!conn_connected()) {
        LOGE("recv_byte: conn_connected() returned false! (call #%u)", recv_call_count);
        return -1;
    }

    // Cap timeout to prevent overflow in multiplication (max ~4294 seconds)
    if (timeout > 4000000) timeout = 4000000;
    BYTE ch;
    int received = conn_recv_upto(&ch, 1, timeout * 1000);  // Convert to milliseconds

    if (received == 1) {
        return ch;
    }

    return -1;  // Timeout or error
}

/**
 * ZMODEM Callback: Progress update
 */
static void zmodem_progress_cb(void* cbdata, int64_t current_pos) {
    (void)cbdata;

    int64_t total_size;
    char current_file[MAX_PATH + 1];

    pthread_mutex_lock(&g_transfer.lock);
    g_transfer.current_pos = current_pos;

    // Also update from zmodem structure
    g_transfer.total_size = g_transfer.zm.current_file_size;
    if (g_transfer.zm.current_file_name[0] != '\0') {
        strncpy(g_transfer.current_file, g_transfer.zm.current_file_name, MAX_PATH);
        g_transfer.current_file[MAX_PATH] = '\0';
    }

    // Copy for logging outside mutex
    total_size = g_transfer.total_size;
    strncpy(current_file, g_transfer.current_file, MAX_PATH);
    current_file[MAX_PATH] = '\0';
    pthread_mutex_unlock(&g_transfer.lock);

    LOGD("Progress: %lld / %lld - %s",
         (long long)current_pos,
         (long long)total_size,
         current_file);
}

/**
 * ZMODEM Callback: Check if connected
 */
static BOOL zmodem_is_connected_cb(void* cbdata) {
    (void)cbdata;
    BOOL connected = conn_connected() ? TRUE : FALSE;
    if (!connected) {
        LOGE("is_connected_cb: returning FALSE!");
    }
    return connected;
}

/**
 * ZMODEM Callback: Check if cancelled
 */
static BOOL zmodem_is_cancelled_cb(void* cbdata) {
    (void)cbdata;

    pthread_mutex_lock(&g_transfer.lock);
    int cancelled = g_transfer.cancelled;
    pthread_mutex_unlock(&g_transfer.lock);

    return cancelled ? TRUE : FALSE;
}

/**
 * ZMODEM Callback: Check if data is waiting
 */
static BOOL zmodem_data_waiting_cb(void* cbdata, unsigned timeout) {
    (void)cbdata;

    if (!conn_connected()) {
        return FALSE;
    }

    // Cap timeout to prevent overflow in multiplication (max ~4294 seconds)
    if (timeout > 4000000) timeout = 4000000;
    // Poll for data with timeout
    unsigned elapsed = 0;
    while (elapsed < timeout * 1000) {
        size_t waiting = conn_data_waiting();
        if (waiting > 0) {
            return TRUE;
        }

        // Check for cancellation
        pthread_mutex_lock(&g_transfer.lock);
        int cancelled = g_transfer.cancelled;
        pthread_mutex_unlock(&g_transfer.lock);
        if (cancelled) {
            return FALSE;
        }

        usleep(10000);  // 10ms
        elapsed += 10;
    }

    return conn_data_waiting() > 0 ? TRUE : FALSE;
}

/**
 * ZMODEM Callback: Flush output
 */
static void zmodem_flush_cb(void* cbdata) {
    (void)cbdata;
    // Connection is already unbuffered, nothing to do
}

/**
 * Initialize the transfer system
 */
JNIEXPORT jboolean JNICALL
Java_com_syncterm_android_NativeBridge_nativeTransferInit(JNIEnv *env, jclass clazz) {
    (void)env;
    (void)clazz;

    LOGI("nativeTransferInit called");

    if (g_transfer_initialized) {
        LOGI("Transfer system already initialized");
        return JNI_TRUE;
    }

    // Initialize mutex
    if (pthread_mutex_init(&g_transfer.lock, NULL) != 0) {
        LOGE("Failed to initialize transfer mutex");
        return JNI_FALSE;
    }

    // Initialize ZMODEM structure
    zmodem_init(&g_transfer.zm,
                &g_transfer,           // cbdata
                zmodem_lputs_cb,       // lputs
                zmodem_progress_cb,    // progress
                zmodem_send_byte_cb,   // send_byte
                zmodem_recv_byte_cb,   // recv_byte
                zmodem_is_connected_cb,// is_connected
                zmodem_is_cancelled_cb,// is_cancelled
                zmodem_data_waiting_cb,// data_waiting
                zmodem_flush_cb);      // flush

    // Configure ZMODEM
    g_transfer.zm.log_level = &g_transfer.log_level;
    g_transfer.zm.max_errors = 10;
    g_transfer.zm.recv_timeout = 10;
    g_transfer.zm.send_timeout = 10;
    g_transfer.zm.escape_telnet_iac = TRUE;  // Important for Telnet connections

    g_transfer.state = TRANSFER_IDLE;
    g_transfer.cancelled = 0;
    g_transfer_initialized = 1;

    LOGI("Transfer system initialized successfully");
    return JNI_TRUE;
}

/**
 * Set download directory
 */
JNIEXPORT void JNICALL
Java_com_syncterm_android_NativeBridge_nativeSetDownloadDir(JNIEnv *env, jclass clazz, jstring dir) {
    (void)clazz;

    const char *dir_str = (*env)->GetStringUTFChars(env, dir, NULL);
    if (!dir_str) {
        if ((*env)->ExceptionOccurred(env)) {
            (*env)->ExceptionClear(env);
        }
        LOGE("Failed to get download directory string");
        return;
    }

    pthread_mutex_lock(&g_transfer.lock);
    strncpy(g_transfer.download_dir, dir_str, MAX_PATH - 1);
    g_transfer.download_dir[MAX_PATH - 1] = '\0';
    pthread_mutex_unlock(&g_transfer.lock);

    (*env)->ReleaseStringUTFChars(env, dir, dir_str);

    LOGI("Download directory set to: %s", g_transfer.download_dir);
}

/**
 * Receive files via ZMODEM
 * Returns: number of files received, or negative on error
 */
JNIEXPORT jint JNICALL
Java_com_syncterm_android_NativeBridge_nativeZmodemReceive(JNIEnv *env, jclass clazz) {
    (void)env;
    (void)clazz;

    LOGI("nativeZmodemReceive called");

    if (!g_transfer_initialized) {
        LOGE("Transfer system not initialized");
        return -1;
    }

    if (!conn_connected()) {
        LOGE("Not connected");
        return -2;
    }

    pthread_mutex_lock(&g_transfer.lock);
    if (g_transfer.state != TRANSFER_IDLE) {
        pthread_mutex_unlock(&g_transfer.lock);
        LOGE("Transfer already in progress");
        return -3;
    }

    g_transfer.state = TRANSFER_RECEIVING;
    g_transfer.cancelled = 0;
    g_transfer.current_pos = 0;
    g_transfer.total_size = 0;
    g_transfer.current_file[0] = '\0';
    g_transfer.error_message[0] = '\0';

    char download_dir[MAX_PATH + 1];
    strncpy(download_dir, g_transfer.download_dir, MAX_PATH);
    download_dir[MAX_PATH] = '\0';
    pthread_mutex_unlock(&g_transfer.lock);

    if (download_dir[0] == '\0') {
        LOGE("Download directory not set");
        pthread_mutex_lock(&g_transfer.lock);
        g_transfer.state = TRANSFER_ERROR;
        strncpy(g_transfer.error_message, "Download directory not set", sizeof(g_transfer.error_message) - 1);
        pthread_mutex_unlock(&g_transfer.lock);
        return -4;
    }

    // Create download directory if it doesn't exist
    // Use mkdir directly and check for EEXIST to avoid TOCTOU race condition
    // Save errno immediately after syscall for thread safety
    int mkdir_result = mkdir(download_dir, 0755);
    int saved_errno = errno;
    if (mkdir_result != 0 && saved_errno != EEXIST) {
        LOGE("Failed to create download directory: %s", strerror(saved_errno));
        pthread_mutex_lock(&g_transfer.lock);
        g_transfer.state = TRANSFER_ERROR;
        snprintf(g_transfer.error_message, sizeof(g_transfer.error_message),
                 "Failed to create directory: %s", strerror(saved_errno));
        pthread_mutex_unlock(&g_transfer.lock);
        return -5;
    }

    LOGI("Starting ZMODEM receive to: %s", download_dir);

    // Perform ZMODEM receive
    uint64_t bytes_received = 0;
    LOGI("Calling zmodem_recv_files...");
    int result = zmodem_recv_files(&g_transfer.zm, download_dir, &bytes_received);
    LOGI("zmodem_recv_files returned: %d, bytes_received: %llu", result, (unsigned long long)bytes_received);

    pthread_mutex_lock(&g_transfer.lock);
    if (g_transfer.cancelled) {
        g_transfer.state = TRANSFER_CANCELLED;
        LOGI("ZMODEM receive cancelled");
    } else if (result < 0) {
        g_transfer.state = TRANSFER_ERROR;
        snprintf(g_transfer.error_message, sizeof(g_transfer.error_message),
                 "ZMODEM receive failed (code %d)", result);
        LOGE("ZMODEM receive failed: %d, file: %s, pos: %lld/%lld",
             result, g_transfer.current_file,
             (long long)g_transfer.current_pos, (long long)g_transfer.total_size);
    } else if (result == 0 && bytes_received == 0) {
        g_transfer.state = TRANSFER_ERROR;
        snprintf(g_transfer.error_message, sizeof(g_transfer.error_message),
                 "No files received - check BBS is sending");
        LOGE("ZMODEM receive: no files received");
    } else {
        g_transfer.state = TRANSFER_COMPLETE;
        LOGI("ZMODEM receive complete: %d files, %llu bytes", result, (unsigned long long)bytes_received);
    }
    pthread_mutex_unlock(&g_transfer.lock);

    return result;
}

/**
 * Send a file via ZMODEM
 * Returns: 0 on success, negative on error
 */
JNIEXPORT jint JNICALL
Java_com_syncterm_android_NativeBridge_nativeZmodemSend(JNIEnv *env, jclass clazz, jstring filePath) {
    (void)clazz;

    LOGI("nativeZmodemSend called");

    if (!g_transfer_initialized) {
        LOGE("Transfer system not initialized");
        return -1;
    }

    if (!conn_connected()) {
        LOGE("Not connected");
        return -2;
    }

    const char *file_path = (*env)->GetStringUTFChars(env, filePath, NULL);
    if (!file_path) {
        if ((*env)->ExceptionOccurred(env)) {
            (*env)->ExceptionClear(env);
        }
        LOGE("Failed to get file path string");
        return -3;
    }

    pthread_mutex_lock(&g_transfer.lock);
    if (g_transfer.state != TRANSFER_IDLE) {
        pthread_mutex_unlock(&g_transfer.lock);
        (*env)->ReleaseStringUTFChars(env, filePath, file_path);
        LOGE("Transfer already in progress");
        return -4;
    }

    g_transfer.state = TRANSFER_SENDING;
    g_transfer.cancelled = 0;
    g_transfer.current_pos = 0;
    g_transfer.total_size = 0;
    strncpy(g_transfer.current_file, file_path, MAX_PATH);
    g_transfer.current_file[MAX_PATH] = '\0';
    g_transfer.error_message[0] = '\0';
    pthread_mutex_unlock(&g_transfer.lock);

    LOGI("Starting ZMODEM send: %s", file_path);

    // Open the file
    FILE *fp = fopen(file_path, "rb");
    if (!fp) {
        int saved_errno = errno;  // Save errno immediately for thread safety
        LOGE("Failed to open file: %s - %s", file_path, strerror(saved_errno));
        (*env)->ReleaseStringUTFChars(env, filePath, file_path);

        pthread_mutex_lock(&g_transfer.lock);
        g_transfer.state = TRANSFER_ERROR;
        snprintf(g_transfer.error_message, sizeof(g_transfer.error_message),
                 "Failed to open file: %s", strerror(saved_errno));
        pthread_mutex_unlock(&g_transfer.lock);
        return -5;
    }

    // Get file name from path
    const char *filename = strrchr(file_path, '/');
    if (filename) {
        filename++;  // Skip the slash
    } else {
        filename = file_path;
    }

    // Make a mutable copy of filename for zmodem_send_file
    char name_buf[MAX_PATH + 1];
    strncpy(name_buf, filename, MAX_PATH);
    name_buf[MAX_PATH] = '\0';

    // Perform ZMODEM send
    time_t start_time = 0;
    uint64_t bytes_sent = 0;
    BOOL success = zmodem_send_file(&g_transfer.zm, name_buf, fp, TRUE, &start_time, &bytes_sent);

    fclose(fp);
    (*env)->ReleaseStringUTFChars(env, filePath, file_path);

    pthread_mutex_lock(&g_transfer.lock);
    if (g_transfer.cancelled) {
        g_transfer.state = TRANSFER_CANCELLED;
        LOGI("ZMODEM send cancelled");
    } else if (!success) {
        g_transfer.state = TRANSFER_ERROR;
        strncpy(g_transfer.error_message, "ZMODEM send failed", sizeof(g_transfer.error_message) - 1);
        LOGE("ZMODEM send failed");
    } else {
        g_transfer.state = TRANSFER_COMPLETE;
        LOGI("ZMODEM send complete: %llu bytes", (unsigned long long)bytes_sent);
    }
    pthread_mutex_unlock(&g_transfer.lock);

    // Properly end the ZMODEM session - sends ZFIN, waits for response, sends OO
    zmodem_get_zfin(&g_transfer.zm);

    return success ? 0 : -6;
}

/**
 * Cancel current transfer
 */
JNIEXPORT void JNICALL
Java_com_syncterm_android_NativeBridge_nativeTransferCancel(JNIEnv *env, jclass clazz) {
    (void)env;
    (void)clazz;

    LOGI("nativeTransferCancel called");

    pthread_mutex_lock(&g_transfer.lock);
    g_transfer.cancelled = 1;
    pthread_mutex_unlock(&g_transfer.lock);

    // Send abort sequence
    if (g_transfer_initialized) {
        zmodem_send_zabort(&g_transfer.zm);
    }
}

/**
 * Get current transfer state
 * Returns: state enum value
 */
JNIEXPORT jint JNICALL
Java_com_syncterm_android_NativeBridge_nativeGetTransferState(JNIEnv *env, jclass clazz) {
    (void)env;
    (void)clazz;

    pthread_mutex_lock(&g_transfer.lock);
    int state = (int)g_transfer.state;
    pthread_mutex_unlock(&g_transfer.lock);

    return state;
}

/**
 * Get transfer progress
 * Returns: long array [current_pos, total_size]
 */
JNIEXPORT jlongArray JNICALL
Java_com_syncterm_android_NativeBridge_nativeGetTransferProgress(JNIEnv *env, jclass clazz) {
    (void)clazz;

    jlongArray result = (*env)->NewLongArray(env, 2);
    if (!result) {
        return NULL;
    }

    pthread_mutex_lock(&g_transfer.lock);
    jlong values[2] = {
        (jlong)g_transfer.current_pos,
        (jlong)g_transfer.total_size
    };
    pthread_mutex_unlock(&g_transfer.lock);

    (*env)->SetLongArrayRegion(env, result, 0, 2, values);

    return result;
}

/**
 * Get current file name being transferred
 */
JNIEXPORT jstring JNICALL
Java_com_syncterm_android_NativeBridge_nativeGetTransferFileName(JNIEnv *env, jclass clazz) {
    (void)clazz;

    pthread_mutex_lock(&g_transfer.lock);
    char filename[MAX_PATH + 1];
    strncpy(filename, g_transfer.current_file, MAX_PATH);
    filename[MAX_PATH] = '\0';
    pthread_mutex_unlock(&g_transfer.lock);

    return (*env)->NewStringUTF(env, filename);
}

/**
 * Get last error message
 */
JNIEXPORT jstring JNICALL
Java_com_syncterm_android_NativeBridge_nativeGetTransferError(JNIEnv *env, jclass clazz) {
    (void)clazz;

    pthread_mutex_lock(&g_transfer.lock);
    char error[256];
    strncpy(error, g_transfer.error_message, sizeof(error) - 1);
    error[sizeof(error) - 1] = '\0';
    pthread_mutex_unlock(&g_transfer.lock);

    return (*env)->NewStringUTF(env, error);
}

/**
 * Reset transfer state to idle
 */
JNIEXPORT void JNICALL
Java_com_syncterm_android_NativeBridge_nativeTransferReset(JNIEnv *env, jclass clazz) {
    (void)env;
    (void)clazz;

    LOGI("nativeTransferReset called");

    pthread_mutex_lock(&g_transfer.lock);
    g_transfer.state = TRANSFER_IDLE;
    g_transfer.cancelled = 0;
    g_transfer.current_pos = 0;
    g_transfer.total_size = 0;
    g_transfer.current_file[0] = '\0';
    g_transfer.error_message[0] = '\0';
    pthread_mutex_unlock(&g_transfer.lock);
}

/**
 * Cleanup transfer system
 */
JNIEXPORT void JNICALL
Java_com_syncterm_android_NativeBridge_nativeTransferCleanup(JNIEnv *env, jclass clazz) {
    (void)env;
    (void)clazz;

    LOGI("nativeTransferCleanup called");

    if (!g_transfer_initialized) {
        return;
    }

    pthread_mutex_destroy(&g_transfer.lock);
    g_transfer_initialized = 0;
}

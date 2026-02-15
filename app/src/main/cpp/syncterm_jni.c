/**
 * SyncTERM JNI Bridge
 *
 * Provides JNI functions to connect Android/Kotlin with the native
 * SyncTERM terminal emulator and Telnet connection code.
 */

#include <jni.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdatomic.h>
#include <pthread.h>
#include <sys/time.h>
#include <android/log.h>

#include "safe_math.h"
#include "android_ciolib.h"
#include "conn.h"
#include "conn_telnet.h"
#include "cterm.h"
#include "bbslist.h"
#include "ciolib.h"
#include "genwrap.h"
#include "sockwrap.h"

#ifndef WITHOUT_CRYPTLIB
#include "ssh.h"
#endif

#define LOG_TAG "SyncTERM-JNI"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// Maximum scrollback buffer size to prevent excessive memory usage (100 MB)
#define MAX_SCROLLBACK_BYTES (100 * 1024 * 1024)

// Maximum bytes to drain from connection buffer when clearing stale data
#define MAX_DRAIN_BYTES 4096

// Global state
static struct cterminal *g_cterm = NULL;
static struct vmem_cell *g_scrollback = NULL;
static int g_scrollback_lines = 1000;
static int g_connected = 0;
static int g_initialized = 0;
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

// JVM reference for callbacks
static JavaVM *g_jvm = NULL;
static jobject g_callback_obj = NULL;
static jmethodID g_on_data_callback = NULL;

// Terminal dimensions
static int g_term_width = 80;
static int g_term_height = 24;

// Current font ID for bitmap rendering
static int g_current_font_id = 0;

// Connection settings (set before connect, applied during connect)
static int g_hide_status_line = 1;  // Default to hiding status line
static int g_screen_mode = SCREEN_MODE_80X25;  // Default screen mode
static char g_font_name[256] = "Codepage 437 English";  // Default font

// Connection config
static struct bbslist g_bbs_config;

// ZMODEM auto-detection
static volatile int g_zmodem_detected = 0;      // Download init (ZRQINIT) detected
static volatile int g_zmodem_upload_ready = 0;  // Upload init (ZRINIT) detected
static unsigned char g_zmodem_buffer[4096];
static int g_zmodem_buffer_len = 0;
static pthread_mutex_t g_zmodem_lock = PTHREAD_MUTEX_INITIALIZER;

// Upload queue - file waiting to be sent when BBS is ready
static char g_upload_queued_file[512] = {0};
static volatile int g_upload_file_queued = 0;

// Bell detection - set when BEL character (0x07) is received
static volatile int g_bell_detected = 0;

// Connection statistics
static _Atomic uint64_t g_bytes_sent = 0;
static _Atomic uint64_t g_bytes_received = 0;
static _Atomic int64_t g_connect_time_ms = 0;  // Timestamp when connected

// Session logging
#define LOG_BUFFER_SIZE (64 * 1024)  // 64KB circular buffer for logging
static unsigned char g_log_buffer[LOG_BUFFER_SIZE];
static volatile int g_log_buffer_len = 0;
static volatile int g_logging_enabled = 0;
static pthread_mutex_t g_log_lock = PTHREAD_MUTEX_INITIALIZER;

// Helper function to get current time in milliseconds
static int64_t get_current_time_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (int64_t)tv.tv_sec * 1000 + (int64_t)tv.tv_usec / 1000;
}

// ZMODEM frame types
#define ZMODEM_FRAME_ZRQINIT  0x00  // Request receive init (sender -> receiver, download)
#define ZMODEM_FRAME_ZRINIT   0x01  // Receive init (receiver -> sender, upload ready)

// Structure to hold ZMODEM detection result
typedef struct {
    int position;    // Start position of header (-1 if not found)
    int frame_type;  // Frame type (ZRQINIT, ZRINIT, etc.) or -1
} zmodem_detect_result_t;

// Check if buffer contains ZMODEM init sequence and identify frame type
// ZMODEM headers start with: ZPAD ZPAD ZDLE <type>
// where ZPAD = '*' (0x2a), ZDLE = CAN (0x18)
// and <type> is 'A' (ZBIN), 'B' (ZHEX), or 'C' (ZBIN32)
// We detect ZDLE + type, then back up to include preceding ZPAD bytes
static zmodem_detect_result_t detect_zmodem_ex(const unsigned char *buf, int len) {
    zmodem_detect_result_t result = { -1, -1 };

    // Need at least 2 bytes for ZDLE + type detection (prevents len-1 underflow)
    if (len < 2) {
        return result;
    }

    for (int i = 0; i < len - 1; i++) {
        // Look for ZDLE (CAN/0x18) byte followed by header type
        if (buf[i] == 0x18 && (buf[i+1] == 'A' || buf[i+1] == 'B' || buf[i+1] == 'C')) {
            LOGI("ZMODEM header detected: ZDLE(0x18) + '%c'(0x%02x) at position %d, buflen=%d",
                 buf[i+1], buf[i+1], i, len);

            // Back up to include preceding ZPAD ('*' = 0x2a) bytes
            // ZMODEM headers start with one or two ZPAD bytes before ZDLE
            // This is CRITICAL - zmodem_recv_header_raw() expects ZPAD first!
            int start = i;
            while (start > 0 && buf[start - 1] == 0x2a) {  // 0x2a = '*' = ZPAD
                start--;
            }

            if (start < i) {
                LOGI("  Backed up to include %d ZPAD byte(s), new start position: %d", i - start, start);
            }

            // Extract frame type based on header encoding
            int frame_type = -1;
            if (buf[i+1] == 'B' && i + 3 < len) {
                // ZHEX: frame type is two hex digits after 'B'
                char hex[3] = { buf[i+2], buf[i+3], 0 };
                frame_type = (int)strtol(hex, NULL, 16);
                LOGI("  ZHEX frame type: 0x%02x (from '%s')", frame_type, hex);
            } else if ((buf[i+1] == 'A' || buf[i+1] == 'C') && i + 2 < len) {
                // ZBIN/ZBIN32: frame type is raw byte after 'A' or 'C'
                frame_type = buf[i+2];
                LOGI("  ZBIN frame type: 0x%02x", frame_type);
            }

            // Log a few more bytes for debugging
            if (i + 7 < len) {
                LOGI("  Following bytes: %02x %02x %02x %02x %02x %02x",
                     buf[i+2], buf[i+3], buf[i+4], buf[i+5], buf[i+6], buf[i+7]);
            }

            result.position = start;
            result.frame_type = frame_type;
            return result;
        }
    }
    return result;  // Not found
}

// Legacy function for backward compatibility
static int detect_zmodem(const unsigned char *buf, int len) {
    return detect_zmodem_ex(buf, len).position;
}

// Helper: Get JNI environment for current thread
static JNIEnv* get_jni_env(void) {
    JNIEnv *env = NULL;
    if (g_jvm) {
        int status = (*g_jvm)->GetEnv(g_jvm, (void**)&env, JNI_VERSION_1_6);
        if (status == JNI_EDETACHED) {
            (*g_jvm)->AttachCurrentThread(g_jvm, &env, NULL);
        }
    }
    return env;
}

// Called when library is loaded
JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void *reserved) {
    LOGI("JNI_OnLoad called");
    g_jvm = vm;
    return JNI_VERSION_1_6;
}

// External function from android_stubs.c
extern void android_set_files_dir(const char *path);

// Set the files directory for SSH keys and config files
JNIEXPORT void JNICALL
Java_com_syncterm_android_NativeBridge_nativeSetFilesDir(JNIEnv *env, jclass clazz, jstring path) {
    const char *path_str = (*env)->GetStringUTFChars(env, path, NULL);
    if (!path_str) {
        if ((*env)->ExceptionOccurred(env)) {
            (*env)->ExceptionClear(env);
        }
        LOGE("Failed to get files directory path string");
        return;
    }
    android_set_files_dir(path_str);
    (*env)->ReleaseStringUTFChars(env, path, path_str);
}

// Initialize the terminal system
JNIEXPORT jboolean JNICALL
Java_com_syncterm_android_NativeBridge_nativeInit(JNIEnv *env, jclass clazz) {
    LOGI("nativeInit called");

    pthread_mutex_lock(&g_lock);

    if (g_initialized) {
        LOGI("Already initialized");
        pthread_mutex_unlock(&g_lock);
        return JNI_TRUE;
    }

    // Socket library initialization not needed on Android (BSD sockets)

#ifndef WITHOUT_CRYPTLIB
    // Initialize cryptlib for SSH support - MUST be done before ciolib init
    LOGI("Initializing cryptlib for SSH support");
    init_crypt();
#endif

    // Initialize ciolib
    if (initciolib(CIOLIB_MODE_AUTO) != 0) {
        LOGE("Failed to initialize ciolib");
        pthread_mutex_unlock(&g_lock);
        return JNI_FALSE;
    }

    // Allocate scrollback buffer with overflow check
    int scrollback_cols = g_term_width > 132 ? g_term_width : 132;
    size_t scrollback_alloc_size;
    if (!validate_alloc_size(g_scrollback_lines, scrollback_cols,
                             sizeof(struct vmem_cell), &scrollback_alloc_size)) {
        LOGE("Scrollback buffer size overflow: %d x %d", g_scrollback_lines, scrollback_cols);
        pthread_mutex_unlock(&g_lock);
        return JNI_FALSE;
    }
    // Ensure allocation doesn't exceed maximum allowed size
    if (scrollback_alloc_size > MAX_SCROLLBACK_BYTES) {
        LOGE("Scrollback buffer too large: %zu bytes (max: %d)", scrollback_alloc_size, MAX_SCROLLBACK_BYTES);
        pthread_mutex_unlock(&g_lock);
        return JNI_FALSE;
    }
    g_scrollback = calloc(1, scrollback_alloc_size);
    if (!g_scrollback) {
        LOGE("Failed to allocate scrollback buffer");
        pthread_mutex_unlock(&g_lock);
        return JNI_FALSE;
    }

    // Initialize terminal emulator
    g_cterm = cterm_init(g_term_height, g_term_width, 1, 1,
                         g_scrollback_lines, scrollback_cols,
                         g_scrollback, CTERM_EMULATION_ANSI_BBS);
    if (!g_cterm) {
        LOGE("Failed to initialize cterm");
        free(g_scrollback);
        g_scrollback = NULL;
        pthread_mutex_unlock(&g_lock);
        return JNI_FALSE;
    }

    // Start terminal
    cterm_start(g_cterm);

    g_initialized = 1;
    LOGI("Terminal initialized: %dx%d", g_term_width, g_term_height);

    pthread_mutex_unlock(&g_lock);
    return JNI_TRUE;
}

// Set callback object for data notifications
JNIEXPORT void JNICALL
Java_com_syncterm_android_NativeBridge_nativeSetCallback(JNIEnv *env, jclass clazz, jobject callback) {
    pthread_mutex_lock(&g_lock);

    // Release old callback
    if (g_callback_obj) {
        (*env)->DeleteGlobalRef(env, g_callback_obj);
        g_callback_obj = NULL;
        g_on_data_callback = NULL;
    }

    if (callback) {
        g_callback_obj = (*env)->NewGlobalRef(env, callback);
        if (g_callback_obj) {
            jclass cls = (*env)->GetObjectClass(env, callback);
            if (cls) {
                g_on_data_callback = (*env)->GetMethodID(env, cls, "onDataReceived", "()V");
                if (!g_on_data_callback) {
                    LOGE("Failed to get onDataReceived method ID");
                    (*env)->ExceptionClear(env);
                    // Clean up global ref since we can't use this callback
                    (*env)->DeleteGlobalRef(env, g_callback_obj);
                    g_callback_obj = NULL;
                }
                // Delete local reference to prevent local reference table overflow
                (*env)->DeleteLocalRef(env, cls);
            } else {
                LOGE("Failed to get callback class");
                (*env)->DeleteGlobalRef(env, g_callback_obj);
                g_callback_obj = NULL;
            }
        } else {
            LOGE("Failed to create global reference for callback");
        }
    }

    pthread_mutex_unlock(&g_lock);
}

// Connect to a server (Telnet or SSH)
// protocol: CONN_TYPE_TELNET (3) or CONN_TYPE_SSH (5)
JNIEXPORT jboolean JNICALL
Java_com_syncterm_android_NativeBridge_nativeConnect(JNIEnv *env, jclass clazz,
                                                      jstring host, jint port, jint protocol,
                                                      jstring username, jstring password) {
    LOGI("nativeConnect called (protocol=%d)", protocol);

    if (!g_initialized) {
        LOGE("Not initialized");
        return JNI_FALSE;
    }

    if (g_connected) {
        LOGE("Already connected");
        return JNI_FALSE;
    }

    const char *host_str = (*env)->GetStringUTFChars(env, host, NULL);
    if (!host_str) {
        if ((*env)->ExceptionOccurred(env)) {
            (*env)->ExceptionClear(env);
        }
        LOGE("Failed to get host string");
        return JNI_FALSE;
    }

    // Get username if provided (for SSH)
    const char *user_str = NULL;
    if (username != NULL) {
        user_str = (*env)->GetStringUTFChars(env, username, NULL);
        if (!user_str && (*env)->ExceptionOccurred(env)) {
            (*env)->ExceptionClear(env);
            LOGW("Failed to get username string, continuing without it");
        }
    }

    // Get password if provided (for SSH)
    const char *pass_str = NULL;
    if (password != NULL) {
        pass_str = (*env)->GetStringUTFChars(env, password, NULL);
        if (!pass_str && (*env)->ExceptionOccurred(env)) {
            (*env)->ExceptionClear(env);
            LOGW("Failed to get password string, continuing without it");
        }
    }

    pthread_mutex_lock(&g_lock);

    // Set up connection config
    memset(&g_bbs_config, 0, sizeof(g_bbs_config));
    strncpy(g_bbs_config.name, "Android Connection", sizeof(g_bbs_config.name) - 1);
    g_bbs_config.name[sizeof(g_bbs_config.name) - 1] = '\0';
    strncpy(g_bbs_config.addr, host_str, sizeof(g_bbs_config.addr) - 1);
    g_bbs_config.addr[sizeof(g_bbs_config.addr) - 1] = '\0';

    // Validate port number to prevent truncation
    if (!validate_port(port, &g_bbs_config.port)) {
        LOGE("Invalid port number: %d (must be 1-65535)", port);
        (*env)->ReleaseStringUTFChars(env, host, host_str);
        if (user_str) (*env)->ReleaseStringUTFChars(env, username, user_str);
        if (pass_str) (*env)->ReleaseStringUTFChars(env, password, pass_str);
        pthread_mutex_unlock(&g_lock);
        return JNI_FALSE;
    }

    // Set connection type based on protocol parameter
    // CONN_TYPE_TELNET = 3, CONN_TYPE_SSH = 5 (from conn.h)
    if (protocol == 5) {  // SSH
#ifndef WITHOUT_CRYPTLIB
        g_bbs_config.type = CONN_TYPE_SSH;
        g_bbs_config.conn_type = CONN_TYPE_SSH;
        LOGI("SSH connection requested");

        // Copy username for SSH
        if (user_str && user_str[0] != '\0') {
            strncpy(g_bbs_config.user, user_str, sizeof(g_bbs_config.user) - 1);
            g_bbs_config.user[sizeof(g_bbs_config.user) - 1] = '\0';
            LOGI("SSH username set: %s", g_bbs_config.user);
        }

        // Copy password for SSH
        if (pass_str && pass_str[0] != '\0') {
            strncpy(g_bbs_config.password, pass_str, sizeof(g_bbs_config.password) - 1);
            g_bbs_config.password[sizeof(g_bbs_config.password) - 1] = '\0';
            LOGI("SSH password set (length=%zu)", strlen(pass_str));
        }
#else
        LOGE("SSH requested but cryptlib not available - falling back to Telnet");
        g_bbs_config.type = CONN_TYPE_TELNET;
        g_bbs_config.conn_type = CONN_TYPE_TELNET;
#endif
    } else {
        g_bbs_config.type = CONN_TYPE_TELNET;
        g_bbs_config.conn_type = CONN_TYPE_TELNET;
    }
    g_bbs_config.screen_mode = g_screen_mode;  // Apply screen mode setting
    g_bbs_config.hidepopups = 1;  // No UI popups on Android
    g_bbs_config.address_family = ADDRESS_FAMILY_UNSPEC;
    g_bbs_config.music = 0;
    g_bbs_config.nostatus = g_hide_status_line;  // Apply hide status line setting
    strncpy(g_bbs_config.font, g_font_name, sizeof(g_bbs_config.font) - 1);  // Apply font setting
    g_bbs_config.font[sizeof(g_bbs_config.font) - 1] = '\0';

    // Initialize palette with DOS colors
    g_bbs_config.palette[0]  = 0x000000;  // Black
    g_bbs_config.palette[1]  = 0x0000AA;  // Blue
    g_bbs_config.palette[2]  = 0x00AA00;  // Green
    g_bbs_config.palette[3]  = 0x00AAAA;  // Cyan
    g_bbs_config.palette[4]  = 0xAA0000;  // Red
    g_bbs_config.palette[5]  = 0xAA00AA;  // Magenta
    g_bbs_config.palette[6]  = 0xAA5500;  // Brown
    g_bbs_config.palette[7]  = 0xAAAAAA;  // Light Gray
    g_bbs_config.palette[8]  = 0x555555;  // Dark Gray
    g_bbs_config.palette[9]  = 0x5555FF;  // Light Blue
    g_bbs_config.palette[10] = 0x55FF55;  // Light Green
    g_bbs_config.palette[11] = 0x55FFFF;  // Light Cyan
    g_bbs_config.palette[12] = 0xFF5555;  // Light Red
    g_bbs_config.palette[13] = 0xFF55FF;  // Light Magenta
    g_bbs_config.palette[14] = 0xFFFF55;  // Yellow
    g_bbs_config.palette[15] = 0xFFFFFF;  // White

    LOGI("Connecting to %s:%d (type=%d)", host_str, port, g_bbs_config.conn_type);

    (*env)->ReleaseStringUTFChars(env, host, host_str);
    if (user_str) (*env)->ReleaseStringUTFChars(env, username, user_str);
    if (pass_str) (*env)->ReleaseStringUTFChars(env, password, pass_str);

    // Attempt connection
    // NOTE: conn_connect() returns conn_api.terminate which is:
    //   - true (non-zero) on FAILURE (connection was terminated)
    //   - false (0) on SUCCESS (connection is active)
    bool terminated = conn_connect(&g_bbs_config);

    if (!terminated) {
        g_connected = 1;
        // Reset connection stats
        g_bytes_sent = 0;
        g_bytes_received = 0;
        g_connect_time_ms = get_current_time_ms();
        LOGI("Connected successfully");
    } else {
        LOGE("Connection failed (terminated=%d)", terminated);
    }

    pthread_mutex_unlock(&g_lock);
    return !terminated ? JNI_TRUE : JNI_FALSE;
}

// Disconnect from server
JNIEXPORT void JNICALL
Java_com_syncterm_android_NativeBridge_nativeDisconnect(JNIEnv *env, jclass clazz) {
    LOGI("nativeDisconnect called");

    pthread_mutex_lock(&g_lock);

    if (g_connected) {
        conn_close();
        g_connected = 0;
        LOGI("Disconnected");
    }

    pthread_mutex_unlock(&g_lock);
}

// Check if connected
JNIEXPORT jboolean JNICALL
Java_com_syncterm_android_NativeBridge_nativeIsConnected(JNIEnv *env, jclass clazz) {
    pthread_mutex_lock(&g_lock);
    jboolean result = g_connected && conn_connected() ? JNI_TRUE : JNI_FALSE;
    pthread_mutex_unlock(&g_lock);
    return result;
}

// Send data to the remote server
JNIEXPORT jint JNICALL
Java_com_syncterm_android_NativeBridge_nativeSendData(JNIEnv *env, jclass clazz,
                                                       jbyteArray data) {
    if (!g_connected) {
        return -1;
    }

    jsize len = (*env)->GetArrayLength(env, data);
    if (len <= 0) {
        return 0;
    }

    // Validate len is within reasonable bounds for conn_send
    if (len > INT_MAX) {
        LOGE("Data length too large: %d", (int)len);
        return -1;
    }

    jbyte *bytes = (*env)->GetByteArrayElements(env, data, NULL);
    if (!bytes) {
        return -1;
    }

    int sent = conn_send(bytes, (size_t)len, 1000);

    // Track bytes sent
    if (sent > 0) {
        g_bytes_sent += sent;
    }

    (*env)->ReleaseByteArrayElements(env, data, bytes, JNI_ABORT);

    return sent;
}

// Send a single key code
JNIEXPORT jint JNICALL
Java_com_syncterm_android_NativeBridge_nativeSendKey(JNIEnv *env, jclass clazz, jint keyCode) {
    if (!g_connected) {
        return -1;
    }

    unsigned char c = (unsigned char)keyCode;
    return conn_send(&c, 1, 1000);
}

// Send a string
JNIEXPORT jint JNICALL
Java_com_syncterm_android_NativeBridge_nativeSendString(JNIEnv *env, jclass clazz, jstring str) {
    if (!g_connected) {
        return -1;
    }

    const char *chars = (*env)->GetStringUTFChars(env, str, NULL);
    if (!chars) {
        return -1;
    }

    // Validate string length to prevent size_t to int overflow
    size_t str_len = strlen(chars);
    if (str_len > INT_MAX) {
        LOGE("String too long: %zu", str_len);
        (*env)->ReleaseStringUTFChars(env, str, chars);
        return -1;
    }
    int len = (int)str_len;
    int sent = conn_send(chars, (size_t)len, 1000);

    (*env)->ReleaseStringUTFChars(env, str, chars);

    return sent;
}

// Process incoming data and update terminal
// Returns: bytes processed, or -100 if ZMODEM detected
JNIEXPORT jint JNICALL
Java_com_syncterm_android_NativeBridge_nativeProcessData(JNIEnv *env, jclass clazz) {
    pthread_mutex_lock(&g_lock);

    if (!g_connected || !g_cterm) {
        pthread_mutex_unlock(&g_lock);
        return 0;
    }

    // If ZMODEM already detected, don't consume more data
    pthread_mutex_lock(&g_zmodem_lock);
    if (g_zmodem_detected) {
        pthread_mutex_unlock(&g_zmodem_lock);
        pthread_mutex_unlock(&g_lock);
        return -100;  // Signal ZMODEM detected
    }
    pthread_mutex_unlock(&g_zmodem_lock);

    // Check for data waiting
    size_t waiting = conn_data_waiting();
    if (waiting == 0) {
        pthread_mutex_unlock(&g_lock);
        return 0;
    }

    // Read up to 4KB at a time
    unsigned char buffer[4096];
    int len = conn_recv_upto(buffer, sizeof(buffer), 0);

    if (len <= 0) {
        pthread_mutex_unlock(&g_lock);
        return len;
    }

    // Track bytes received
    g_bytes_received += len;

    // Buffer data for logging if enabled
    if (g_logging_enabled) {
        pthread_mutex_lock(&g_log_lock);
        if (g_logging_enabled) {  // Re-check under lock to avoid TOCTOU
            int space_available = LOG_BUFFER_SIZE - g_log_buffer_len;
            int to_copy = (len < space_available) ? len : space_available;
            if (to_copy > 0) {
                memcpy(g_log_buffer + g_log_buffer_len, buffer, to_copy);
                g_log_buffer_len += to_copy;
            }
        }
        pthread_mutex_unlock(&g_log_lock);
    }

    // Check for ZMODEM init sequence
    zmodem_detect_result_t zmodem_result = detect_zmodem_ex(buffer, len);
    // Use < len (not <=) to prevent off-by-one boundary access
    if (zmodem_result.position >= 0 && zmodem_result.position < len) {
        int zmodem_pos = zmodem_result.position;
        LOGI("ZMODEM detected at position %d, frame type 0x%02x", zmodem_pos, zmodem_result.frame_type);

        // Process any data before ZMODEM start through terminal
        if (zmodem_pos > 0) {
            char retbuf[256];
            memset(retbuf, 0, sizeof(retbuf));
            int speed = 0;
            cterm_write(g_cterm, buffer, zmodem_pos, retbuf, sizeof(retbuf), &speed);
            retbuf[sizeof(retbuf) - 1] = '\0';  // Ensure null termination
            if (retbuf[0] != '\0') {
                conn_send(retbuf, strlen(retbuf), 1000);
            }
        }

        // Save ZMODEM data for later
        pthread_mutex_lock(&g_zmodem_lock);
        g_zmodem_buffer_len = len - zmodem_pos;
        // Validate buffer length is positive and within bounds (prevents signed wrap)
        if (g_zmodem_buffer_len <= 0) {
            g_zmodem_buffer_len = 0;
            pthread_mutex_unlock(&g_zmodem_lock);
            pthread_mutex_unlock(&g_lock);
            return 0;  // Nothing to copy
        }
        if (g_zmodem_buffer_len > (int)sizeof(g_zmodem_buffer)) {
            g_zmodem_buffer_len = sizeof(g_zmodem_buffer);
        }
        memcpy(g_zmodem_buffer, buffer + zmodem_pos, g_zmodem_buffer_len);

        // Set appropriate flag based on frame type
        if (zmodem_result.frame_type == ZMODEM_FRAME_ZRINIT) {
            // BBS is ready to receive - this is for uploads
            LOGI("ZRINIT detected - BBS ready to receive upload");
            g_zmodem_upload_ready = 1;
            g_zmodem_detected = 0;
            pthread_mutex_unlock(&g_zmodem_lock);
            pthread_mutex_unlock(&g_lock);
            return -101;  // Signal ZMODEM upload ready
        } else {
            // ZRQINIT or other - this is for downloads
            LOGI("ZRQINIT detected - BBS wants to send download");
            g_zmodem_detected = 1;
            g_zmodem_upload_ready = 0;
            pthread_mutex_unlock(&g_zmodem_lock);
            pthread_mutex_unlock(&g_lock);
            return -100;  // Signal ZMODEM download detected
        }
    }

    // Check for BEL character (0x07) before processing
    for (int i = 0; i < len; i++) {
        if (buffer[i] == 0x07) {
            g_bell_detected = 1;
            break;
        }
    }

    // Normal processing through terminal emulator
    char retbuf[256];
    memset(retbuf, 0, sizeof(retbuf));
    int speed = 0;

    cterm_write(g_cterm, buffer, len, retbuf, sizeof(retbuf), &speed);
    retbuf[sizeof(retbuf) - 1] = '\0';  // Ensure null termination

    pthread_mutex_unlock(&g_lock);

    // Send any return data (e.g., terminal queries)
    if (retbuf[0] != '\0') {
        conn_send(retbuf, strlen(retbuf), 1000);
    }

    return len;
}

// Get screen buffer for rendering
// Returns packed int array: [char | (attr << 8) | (fg << 16) | (bg << 24)]
JNIEXPORT jintArray JNICALL
Java_com_syncterm_android_NativeBridge_nativeGetScreenBuffer(JNIEnv *env, jclass clazz) {
    pthread_mutex_lock(&g_lock);

    android_ciolib_lock();

    int width = android_ciolib_get_screen_width();
    int height = android_ciolib_get_screen_height();

    // Validate dimensions and calculate size with overflow protection
    int size;
    if (!validate_dimensions(width, height, &size)) {
        LOGE("Invalid screen dimensions: %dx%d", width, height);
        android_ciolib_unlock();
        pthread_mutex_unlock(&g_lock);
        return NULL;
    }

    struct vmem_cell *screen = android_ciolib_get_screen_buffer();
    if (!screen) {
        android_ciolib_unlock();
        pthread_mutex_unlock(&g_lock);
        return NULL;
    }

    jintArray result = (*env)->NewIntArray(env, size);
    if (!result) {
        android_ciolib_unlock();
        pthread_mutex_unlock(&g_lock);
        return NULL;
    }

    jint *arr = (*env)->GetIntArrayElements(env, result, NULL);
    if (!arr) {
        android_ciolib_unlock();
        pthread_mutex_unlock(&g_lock);
        return NULL;
    }

    // Pack cell data for Java
    // Values are already masked to 0xFF so bit shifts are safe
    for (int i = 0; i < size; i++) {
        unsigned int ch = screen[i].ch & 0xFFu;
        unsigned int attr = screen[i].legacy_attr & 0xFFu;
        unsigned int fg = screen[i].fg & 0xFFu;
        unsigned int bg = screen[i].bg & 0xFFu;
        arr[i] = (jint)(ch | (attr << 8) | (fg << 16) | (bg << 24));
    }

    (*env)->ReleaseIntArrayElements(env, result, arr, 0);

    android_ciolib_clear_dirty();
    android_ciolib_unlock();

    pthread_mutex_unlock(&g_lock);
    return result;
}

// Get color palette
JNIEXPORT jintArray JNICALL
Java_com_syncterm_android_NativeBridge_nativeGetPalette(JNIEnv *env, jclass clazz) {
    android_ciolib_lock();
    uint32_t *palette = android_ciolib_get_palette();

    if (!palette) {
        android_ciolib_unlock();
        return NULL;
    }

    jintArray result = (*env)->NewIntArray(env, 16);
    if (result) {
        (*env)->SetIntArrayRegion(env, result, 0, 16, (jint*)palette);
    }

    android_ciolib_unlock();
    return result;
}

// Set terminal size
JNIEXPORT void JNICALL
Java_com_syncterm_android_NativeBridge_nativeSetTerminalSize(JNIEnv *env, jclass clazz,
                                                              jint width, jint height) {
    LOGI("nativeSetTerminalSize: %dx%d", width, height);

    // Validate input dimensions
    if (width <= 0 || height <= 0 || width > 1000 || height > 1000) {
        LOGE("Invalid terminal dimensions: %dx%d", width, height);
        return;
    }

    pthread_mutex_lock(&g_lock);

    // Check if size is actually changing - skip if same to preserve screen content
    if (g_term_width == width && g_term_height == height) {
        LOGI("Terminal size unchanged (%dx%d), skipping resize", width, height);
        pthread_mutex_unlock(&g_lock);
        return;
    }

    g_term_width = width;
    g_term_height = height;

    // Resize the ciolib screen
    android_ciolib_resize(width, height);

    // Reinitialize cterm with new size if already initialized
    if (g_cterm && g_initialized) {
        struct cterminal *old_cterm = g_cterm;
        g_cterm = NULL;  // Set to NULL first to prevent race conditions
        cterm_end(old_cterm, 0);

        // Reallocate scrollback if needed with overflow protection
        int scrollback_cols = width > 132 ? width : 132;
        size_t scrollback_alloc_size;
        if (!validate_alloc_size(g_scrollback_lines, scrollback_cols,
                                 sizeof(struct vmem_cell), &scrollback_alloc_size) ||
            scrollback_alloc_size > MAX_SCROLLBACK_BYTES) {
            LOGE("Scrollback buffer size overflow during resize: %d x %d (max: %d bytes)",
                 g_scrollback_lines, scrollback_cols, MAX_SCROLLBACK_BYTES);
            // Keep old scrollback and try to reinitialize with it
            g_cterm = cterm_init(height, width, 1, 1,
                                 g_scrollback_lines, scrollback_cols,
                                 g_scrollback, CTERM_EMULATION_ANSI_BBS);
            if (g_cterm) {
                cterm_start(g_cterm);
            }
            pthread_mutex_unlock(&g_lock);
            return;
        }

        struct vmem_cell *old_scrollback = g_scrollback;
        g_scrollback = calloc(1, scrollback_alloc_size);

        if (g_scrollback) {
            free(old_scrollback);
            g_cterm = cterm_init(height, width, 1, 1,
                                 g_scrollback_lines, scrollback_cols,
                                 g_scrollback, CTERM_EMULATION_ANSI_BBS);
            if (g_cterm) {
                cterm_start(g_cterm);
            } else {
                LOGE("Failed to reinitialize cterm after resize");
            }
        } else {
            LOGE("Failed to allocate scrollback buffer during resize");
            g_scrollback = old_scrollback;  // Restore old buffer
        }
    }

    pthread_mutex_unlock(&g_lock);
}

// Set font by name
JNIEXPORT jboolean JNICALL
Java_com_syncterm_android_NativeBridge_nativeSetFont(JNIEnv *env, jclass clazz, jstring fontName) {
    LOGI("nativeSetFont called");

    if (!g_initialized) {
        LOGE("Not initialized");
        return JNI_FALSE;
    }

    const char *font_str = (*env)->GetStringUTFChars(env, fontName, NULL);
    if (!font_str) {
        if ((*env)->ExceptionOccurred(env)) {
            (*env)->ExceptionClear(env);
        }
        LOGE("Failed to get font string");
        return JNI_FALSE;
    }

    pthread_mutex_lock(&g_lock);

    // Search for the font in conio_fontdata array
    int font_id = -1;
    for (int i = 0; i < 256; i++) {
        if (conio_fontdata[i].desc != NULL &&
            strcmp(conio_fontdata[i].desc, font_str) == 0) {
            font_id = i;
            break;
        }
    }

    if (font_id >= 0) {
        // Save to global for use in nativeConnect
        strncpy(g_font_name, font_str, sizeof(g_font_name) - 1);
        g_font_name[sizeof(g_font_name) - 1] = '\0';

        // Also update current config (for active connections)
        strncpy(g_bbs_config.font, font_str, sizeof(g_bbs_config.font) - 1);
        g_bbs_config.font[sizeof(g_bbs_config.font) - 1] = '\0';

        // Track current font for bitmap rendering
        g_current_font_id = font_id;

        // Set the font in ciolib (font_id, force=1, font_num=0 for primary)
        int result = ciolib_setfont(font_id, 1, 0);
        LOGI("setfont: '%s' (id=%d) result=%d", font_str, font_id, result);

        pthread_mutex_unlock(&g_lock);
        (*env)->ReleaseStringUTFChars(env, fontName, font_str);
        return result == 0 ? JNI_TRUE : JNI_FALSE;
    }

    LOGE("Font not found: %s", font_str);
    pthread_mutex_unlock(&g_lock);
    (*env)->ReleaseStringUTFChars(env, fontName, font_str);
    return JNI_FALSE;
}

// Get screen dimensions
JNIEXPORT jintArray JNICALL
Java_com_syncterm_android_NativeBridge_nativeGetScreenSize(JNIEnv *env, jclass clazz) {
    jintArray result = (*env)->NewIntArray(env, 2);
    if (result) {
        jint size[2] = { android_ciolib_get_screen_width(), android_ciolib_get_screen_height() };
        (*env)->SetIntArrayRegion(env, result, 0, 2, size);
    }
    return result;
}

// Get cursor position
JNIEXPORT jintArray JNICALL
Java_com_syncterm_android_NativeBridge_nativeGetCursorPos(JNIEnv *env, jclass clazz) {
    jintArray result = (*env)->NewIntArray(env, 2);
    if (result) {
        jint pos[2] = { android_ciolib_get_cursor_x(), android_ciolib_get_cursor_y() };
        (*env)->SetIntArrayRegion(env, result, 0, 2, pos);
    }
    return result;
}

// Check if cursor is visible
JNIEXPORT jboolean JNICALL
Java_com_syncterm_android_NativeBridge_nativeIsCursorVisible(JNIEnv *env, jclass clazz) {
    return android_ciolib_is_cursor_visible() ? JNI_TRUE : JNI_FALSE;
}

// Check if screen is dirty (needs redraw)
JNIEXPORT jboolean JNICALL
Java_com_syncterm_android_NativeBridge_nativeIsScreenDirty(JNIEnv *env, jclass clazz) {
    return android_ciolib_is_dirty() ? JNI_TRUE : JNI_FALSE;
}

// Get dirty region bounds (for partial redraw optimization)
// Returns [minX, minY, maxX, maxY] or null if no dirty region
JNIEXPORT jintArray JNICALL
Java_com_syncterm_android_NativeBridge_nativeGetDirtyRegion(JNIEnv *env, jclass clazz) {
    android_ciolib_lock();

    int min_x, min_y, max_x, max_y;
    int has_dirty = android_ciolib_get_dirty_region(&min_x, &min_y, &max_x, &max_y);

    if (!has_dirty) {
        android_ciolib_unlock();
        return NULL;
    }

    jintArray result = (*env)->NewIntArray(env, 4);
    if (result) {
        jint values[4] = { min_x, min_y, max_x, max_y };
        (*env)->SetIntArrayRegion(env, result, 0, 4, values);
    }

    android_ciolib_unlock();
    return result;
}

// Push keyboard input
JNIEXPORT void JNICALL
Java_com_syncterm_android_NativeBridge_nativePushInput(JNIEnv *env, jclass clazz,
                                                        jbyteArray data) {
    jsize len = (*env)->GetArrayLength(env, data);
    if (len <= 0) return;

    jbyte *bytes = (*env)->GetByteArrayElements(env, data, NULL);
    if (!bytes) return;

    android_ciolib_push_input_buffer((unsigned char*)bytes, len);

    (*env)->ReleaseByteArrayElements(env, data, bytes, JNI_ABORT);
}

// Clear the screen
JNIEXPORT void JNICALL
Java_com_syncterm_android_NativeBridge_nativeClearScreen(JNIEnv *env, jclass clazz) {
    pthread_mutex_lock(&g_lock);
    if (g_cterm) {
        cterm_clearscreen(g_cterm, 7);  // Clear with light gray on black
    }
    pthread_mutex_unlock(&g_lock);
}

// Cleanup and destroy
JNIEXPORT void JNICALL
Java_com_syncterm_android_NativeBridge_nativeDestroy(JNIEnv *env, jclass clazz) {
    LOGI("nativeDestroy called");

    pthread_mutex_lock(&g_lock);

    // Disconnect if connected
    if (g_connected) {
        conn_close();
        g_connected = 0;
    }

    // Cleanup cterm
    if (g_cterm) {
        cterm_end(g_cterm, 0);
        g_cterm = NULL;
    }

    // Free scrollback
    if (g_scrollback) {
        free(g_scrollback);
        g_scrollback = NULL;
    }

    // Cleanup ciolib
    android_ciolib_cleanup();

    // Release callback
    if (g_callback_obj) {
        (*env)->DeleteGlobalRef(env, g_callback_obj);
        g_callback_obj = NULL;
    }

    g_initialized = 0;

    pthread_mutex_unlock(&g_lock);

    LOGI("Cleanup complete");
}

// Check how much data is waiting
JNIEXPORT jint JNICALL
Java_com_syncterm_android_NativeBridge_nativeDataWaiting(JNIEnv *env, jclass clazz) {
    if (!g_connected) {
        return 0;
    }
    return (jint)conn_data_waiting();
}

// Get connection status info
JNIEXPORT jstring JNICALL
Java_com_syncterm_android_NativeBridge_nativeGetStatusInfo(JNIEnv *env, jclass clazz) {
    char status[256];

    if (!g_initialized) {
        snprintf(status, sizeof(status), "Not initialized");
    } else if (!g_connected) {
        snprintf(status, sizeof(status), "Disconnected");
    } else {
        snprintf(status, sizeof(status), "Connected to %s:%d (%dx%d)",
                 g_bbs_config.addr, g_bbs_config.port,
                 g_term_width, g_term_height);
    }

    return (*env)->NewStringUTF(env, status);
}

// Get connection statistics
// Returns: [bytes_sent, bytes_received, connect_time_ms, current_time_ms]
JNIEXPORT jlongArray JNICALL
Java_com_syncterm_android_NativeBridge_nativeGetConnectionStats(JNIEnv *env, jclass clazz) {
    jlongArray result = (*env)->NewLongArray(env, 4);
    if (result) {
        int64_t current_time = get_current_time_ms();
        jlong stats[4] = {
            (jlong)g_bytes_sent,
            (jlong)g_bytes_received,
            (jlong)g_connect_time_ms,
            (jlong)current_time
        };
        (*env)->SetLongArrayRegion(env, result, 0, 4, stats);
    }
    return result;
}

// Get font bitmap data for rendering
// Returns the 8x16 bitmap data for all 256 characters (256 * 16 = 4096 bytes)
JNIEXPORT jbyteArray JNICALL
Java_com_syncterm_android_NativeBridge_nativeGetFontBitmap(JNIEnv *env, jclass clazz) {
    pthread_mutex_lock(&g_lock);

    LOGI("nativeGetFontBitmap: current_font_id=%d", g_current_font_id);

    // Find font with 8x16 data
    const char *bitmap_data = NULL;
    int font_height = 16;

    // First try current font
    if (g_current_font_id >= 0 && g_current_font_id < 256) {
        const char *desc = conio_fontdata[g_current_font_id].desc;
        LOGI("Font %d desc: %s", g_current_font_id, desc ? desc : "(null)");
        LOGI("Font %d 8x16: %p, 8x14: %p, 8x8: %p", g_current_font_id,
             conio_fontdata[g_current_font_id].eight_by_sixteen,
             conio_fontdata[g_current_font_id].eight_by_fourteen,
             conio_fontdata[g_current_font_id].eight_by_eight);

        if (conio_fontdata[g_current_font_id].eight_by_sixteen != NULL) {
            bitmap_data = conio_fontdata[g_current_font_id].eight_by_sixteen;
            font_height = 16;
            LOGI("Using 8x16 font from font %d", g_current_font_id);
        } else if (conio_fontdata[g_current_font_id].eight_by_fourteen != NULL) {
            bitmap_data = conio_fontdata[g_current_font_id].eight_by_fourteen;
            font_height = 14;
            LOGI("Using 8x14 font from font %d", g_current_font_id);
        } else if (conio_fontdata[g_current_font_id].eight_by_eight != NULL) {
            bitmap_data = conio_fontdata[g_current_font_id].eight_by_eight;
            font_height = 8;
            LOGI("Using 8x8 font from font %d", g_current_font_id);
        }
    }

    // Fallback to Codepage 437 English (font 0)
    // Font 0 is always valid since conio_fontdata array size is 257 (indices 0-256)
    #define CONIO_FONTDATA_SIZE 257
    if (bitmap_data == NULL && 0 < CONIO_FONTDATA_SIZE) {
        LOGI("Trying fallback to font 0");
        LOGI("Font 0 8x16: %p", conio_fontdata[0].eight_by_sixteen);
        if (conio_fontdata[0].eight_by_sixteen != NULL) {
            bitmap_data = conio_fontdata[0].eight_by_sixteen;
            font_height = 16;
            LOGI("Using fallback 8x16 font from font 0");
        }
    }
    #undef CONIO_FONTDATA_SIZE

    if (bitmap_data == NULL) {
        LOGE("No font bitmap data available!");
        pthread_mutex_unlock(&g_lock);
        return NULL;
    }

    LOGI("Got font bitmap data, height=%d", font_height);

    // Create byte array with font data
    // Format: first 2 bytes are width (8) and height, rest is bitmap data
    // font_height is 8, 14, or 16; max data_size = 256 * 16 = 4096
    int data_size = 256 * font_height;
    if (data_size <= 0 || data_size > 256 * 64) {
        pthread_mutex_unlock(&g_lock);
        return NULL;
    }
    jbyteArray result = (*env)->NewByteArray(env, data_size + 2);
    if (result) {
        jbyte header[2] = { 8, (jbyte)font_height };
        (*env)->SetByteArrayRegion(env, result, 0, 2, header);
        (*env)->SetByteArrayRegion(env, result, 2, data_size, (jbyte*)bitmap_data);
    }

    pthread_mutex_unlock(&g_lock);
    return result;
}

// Update current font ID when font is set
JNIEXPORT jboolean JNICALL
Java_com_syncterm_android_NativeBridge_nativeSetFontById(JNIEnv *env, jclass clazz, jint fontId) {
    if (fontId < 0 || fontId >= 256) {
        return JNI_FALSE;
    }

    pthread_mutex_lock(&g_lock);
    g_current_font_id = fontId;

    // Also set in ciolib
    int result = ciolib_setfont(fontId, 1, 0);
    LOGI("setfont by id: %d result=%d", fontId, result);

    pthread_mutex_unlock(&g_lock);
    return result == 0 ? JNI_TRUE : JNI_FALSE;
}

// Set hide status line option (call before connect)
JNIEXPORT void JNICALL
Java_com_syncterm_android_NativeBridge_nativeSetHideStatusLine(JNIEnv *env, jclass clazz, jboolean hide) {
    pthread_mutex_lock(&g_lock);
    g_hide_status_line = hide ? 1 : 0;
    LOGI("Hide status line set to: %d", g_hide_status_line);
    pthread_mutex_unlock(&g_lock);
}

// Set screen mode option (call before connect)
// Mode values: 0=80x25, 1=80x30, 2=80x40, 3=80x50, 4=132x25, 5=132x50
JNIEXPORT void JNICALL
Java_com_syncterm_android_NativeBridge_nativeSetScreenMode(JNIEnv *env, jclass clazz, jint mode) {
    pthread_mutex_lock(&g_lock);
    // Validate screen mode range (0-5 maps to known Android modes)
    if (mode < 0 || mode > SCREEN_MODE_132X60) {
        mode = SCREEN_MODE_80X25;
    }
    g_screen_mode = mode;
    LOGI("Screen mode set to: %d", g_screen_mode);
    pthread_mutex_unlock(&g_lock);
}

// Check if ZMODEM auto-download was detected
JNIEXPORT jboolean JNICALL
Java_com_syncterm_android_NativeBridge_nativeIsZmodemDetected(JNIEnv *env, jclass clazz) {
    pthread_mutex_lock(&g_zmodem_lock);
    jboolean result = g_zmodem_detected ? JNI_TRUE : JNI_FALSE;
    pthread_mutex_unlock(&g_zmodem_lock);
    return result;
}

// Get buffered ZMODEM data (call before starting ZMODEM receive)
JNIEXPORT jbyteArray JNICALL
Java_com_syncterm_android_NativeBridge_nativeGetZmodemBuffer(JNIEnv *env, jclass clazz) {
    pthread_mutex_lock(&g_zmodem_lock);

    if (g_zmodem_buffer_len <= 0) {
        pthread_mutex_unlock(&g_zmodem_lock);
        return NULL;
    }

    jbyteArray result = (*env)->NewByteArray(env, g_zmodem_buffer_len);
    if (result) {
        (*env)->SetByteArrayRegion(env, result, 0, g_zmodem_buffer_len, (jbyte*)g_zmodem_buffer);
    }

    pthread_mutex_unlock(&g_zmodem_lock);
    return result;
}

// Clear ZMODEM detection state (call after transfer completes or is cancelled)
JNIEXPORT void JNICALL
Java_com_syncterm_android_NativeBridge_nativeClearZmodemDetected(JNIEnv *env, jclass clazz) {
    pthread_mutex_lock(&g_zmodem_lock);
    g_zmodem_detected = 0;
    g_zmodem_upload_ready = 0;
    g_zmodem_buffer_len = 0;
    pthread_mutex_unlock(&g_zmodem_lock);
    LOGI("ZMODEM detection cleared");
}

// Queue a file for upload (will be sent when BBS sends ZRINIT)
JNIEXPORT void JNICALL
Java_com_syncterm_android_NativeBridge_nativeQueueUpload(JNIEnv *env, jclass clazz, jstring filePath) {
    const char *path = (*env)->GetStringUTFChars(env, filePath, NULL);
    if (!path) {
        if ((*env)->ExceptionOccurred(env)) {
            (*env)->ExceptionClear(env);
        }
        LOGE("Failed to get upload file path string");
        return;
    }

    pthread_mutex_lock(&g_zmodem_lock);
    strncpy(g_upload_queued_file, path, sizeof(g_upload_queued_file) - 1);
    g_upload_queued_file[sizeof(g_upload_queued_file) - 1] = '\0';
    g_upload_file_queued = 1;
    pthread_mutex_unlock(&g_zmodem_lock);

    (*env)->ReleaseStringUTFChars(env, filePath, path);
    LOGI("File queued for upload: %s", g_upload_queued_file);
}

// Check if a file is queued for upload
JNIEXPORT jboolean JNICALL
Java_com_syncterm_android_NativeBridge_nativeIsUploadQueued(JNIEnv *env, jclass clazz) {
    pthread_mutex_lock(&g_zmodem_lock);
    jboolean result = g_upload_file_queued ? JNI_TRUE : JNI_FALSE;
    pthread_mutex_unlock(&g_zmodem_lock);
    return result;
}

// Check if BBS is ready for upload (ZRINIT received)
JNIEXPORT jboolean JNICALL
Java_com_syncterm_android_NativeBridge_nativeIsUploadReady(JNIEnv *env, jclass clazz) {
    pthread_mutex_lock(&g_zmodem_lock);
    jboolean result = g_zmodem_upload_ready ? JNI_TRUE : JNI_FALSE;
    pthread_mutex_unlock(&g_zmodem_lock);
    return result;
}

// Get the queued upload file path
JNIEXPORT jstring JNICALL
Java_com_syncterm_android_NativeBridge_nativeGetQueuedUpload(JNIEnv *env, jclass clazz) {
    pthread_mutex_lock(&g_zmodem_lock);
    jstring result = NULL;
    if (g_upload_file_queued && g_upload_queued_file[0] != '\0') {
        result = (*env)->NewStringUTF(env, g_upload_queued_file);
    }
    pthread_mutex_unlock(&g_zmodem_lock);
    return result;
}

// Clear the upload queue
JNIEXPORT void JNICALL
Java_com_syncterm_android_NativeBridge_nativeClearUploadQueue(JNIEnv *env, jclass clazz) {
    pthread_mutex_lock(&g_zmodem_lock);
    g_upload_file_queued = 0;
    g_upload_queued_file[0] = '\0';
    g_zmodem_upload_ready = 0;
    pthread_mutex_unlock(&g_zmodem_lock);
    LOGI("Upload queue cleared");
}

// Clear buffered ZMODEM data, detection state, AND drain connection buffer
// The buffered data was ZRQINIT (BBS requesting to send) - we don't need to
// re-process it. zmodem_recv_init() will send ZRINIT and wait for ZFILE.
// We also drain any leftover data in the connection buffer that arrived
// between ZMODEM detection and starting the receive - this stale data
// would otherwise be read by zmodem_recv_header() causing failure.
JNIEXPORT jint JNICALL
Java_com_syncterm_android_NativeBridge_nativePushZmodemBuffer(JNIEnv *env, jclass clazz) {
    pthread_mutex_lock(&g_zmodem_lock);

    int len = g_zmodem_buffer_len;

    if (len > 0) {
        LOGI("Clearing %d bytes of ZMODEM buffer (ZRQINIT signal - not pushing back)", len);
        LOGI("  First bytes were: %02x %02x %02x %02x",
             g_zmodem_buffer[0], g_zmodem_buffer[1],
             len > 2 ? g_zmodem_buffer[2] : 0, len > 3 ? g_zmodem_buffer[3] : 0);
    }

    // Clear the buffer and detection state
    g_zmodem_buffer_len = 0;
    g_zmodem_detected = 0;

    pthread_mutex_unlock(&g_zmodem_lock);

    // CRITICAL: Drain any stale data from the connection buffer
    // Between ZMODEM detection and now, there may be leftover data from:
    // 1. Additional terminal output from the BBS (status messages, etc.)
    // 2. Data that arrived after the ZRQINIT but before we processed it
    // This stale data would confuse zmodem_recv_header() if not drained.
    // The BBS is waiting for our ZRINIT before sending ZFILE, so there
    // shouldn't be any important ZMODEM data to preserve here.
    size_t waiting = conn_data_waiting();
    if (waiting > 0) {
        LOGI("Draining %zu bytes of stale data from connection buffer", waiting);
        unsigned char drain_buf[256];
        size_t total_drained = 0;
        while (conn_data_waiting() > 0 && total_drained < MAX_DRAIN_BYTES) {
            int n = conn_recv_upto(drain_buf, sizeof(drain_buf), 10);  // 10ms timeout
            if (n <= 0) break;
            total_drained += (size_t)n;  // Explicit cast for type consistency
            // Log first few bytes for debugging
            if (total_drained == (size_t)n) {
                LOGI("  First drained bytes: %02x %02x %02x %02x",
                     drain_buf[0], n > 1 ? drain_buf[1] : 0,
                     n > 2 ? drain_buf[2] : 0, n > 3 ? drain_buf[3] : 0);
            }
        }
        LOGI("Drained %zu total bytes", total_drained);
    } else {
        LOGI("Connection buffer is empty - good");
    }

    return 0;
}

// Get scrollback buffer info
// Returns: [filled_lines, total_capacity, columns]
JNIEXPORT jintArray JNICALL
Java_com_syncterm_android_NativeBridge_nativeGetScrollbackInfo(JNIEnv *env, jclass clazz) {
    pthread_mutex_lock(&g_lock);

    jintArray result = (*env)->NewIntArray(env, 3);
    if (!result) {
        pthread_mutex_unlock(&g_lock);
        return NULL;
    }

    jint info[3] = {0, 0, 0};

    if (g_cterm && g_cterm->scrollback) {
        info[0] = g_cterm->backfilled;   // Lines actually filled
        info[1] = g_cterm->backlines;    // Total capacity
        info[2] = g_cterm->backwidth;    // Columns per line
    }

    (*env)->SetIntArrayRegion(env, result, 0, 3, info);

    pthread_mutex_unlock(&g_lock);
    return result;
}

// Get scrollback buffer content
// offset: lines back from most recent (0 = most recent scrollback line)
// count: number of lines to retrieve
// Returns packed int array like nativeGetScreenBuffer, or null if invalid
JNIEXPORT jintArray JNICALL
Java_com_syncterm_android_NativeBridge_nativeGetScrollbackBuffer(JNIEnv *env, jclass clazz,
                                                                  jint offset, jint count) {
    pthread_mutex_lock(&g_lock);

    if (!g_cterm || !g_cterm->scrollback || g_cterm->backfilled <= 0) {
        pthread_mutex_unlock(&g_lock);
        return NULL;
    }

    int filled = g_cterm->backfilled;
    int capacity = g_cterm->backlines;
    int cols = g_cterm->backwidth;
    int backpos = g_cterm->backpos;  // Next write position (one past most recent)

    // Validate parameters
    if (offset < 0 || count <= 0 || offset >= filled) {
        pthread_mutex_unlock(&g_lock);
        return NULL;
    }

    // Clamp count to available lines (use subtraction to avoid overflow)
    // Instead of: if (offset + count > filled) which can overflow
    // Use: if (count > filled - offset) which is safe since offset < filled
    if (count > filled - offset) {
        count = filled - offset;
    }

    // Calculate size with overflow check
    long long size_check = (long long)count * (long long)cols;
    if (size_check > INT_MAX || size_check <= 0) {
        pthread_mutex_unlock(&g_lock);
        return NULL;
    }
    int size = (int)size_check;

    jintArray result = (*env)->NewIntArray(env, size);
    if (!result) {
        pthread_mutex_unlock(&g_lock);
        return NULL;
    }

    jint *arr = (*env)->GetIntArrayElements(env, result, NULL);
    if (!arr) {
        pthread_mutex_unlock(&g_lock);
        return NULL;
    }

    // The scrollback is a ring buffer
    // backpos points to the NEXT write position (one past the most recent line)
    // Most recent line is at (backpos - 1 + capacity) % capacity
    // offset=0 means the most recent line, offset=1 means the one before that, etc.

    struct vmem_cell *scrollback = g_cterm->scrollback;
    int arr_idx = 0;

    // Pre-calculate maximum valid cell index to avoid repeated overflow checks
    int max_valid_cell_idx;
    if (!safe_mult_int(capacity, cols, &max_valid_cell_idx)) {
        // Overflow in capacity * cols - shouldn't happen with valid cterm
        (*env)->ReleaseIntArrayElements(env, result, arr, JNI_ABORT);
        pthread_mutex_unlock(&g_lock);
        return NULL;
    }

    for (int line = 0; line < count; line++) {
        // Calculate ring buffer index for this line
        // We're reading 'offset + line' lines back from the most recent
        int lines_back = offset + line;

        // Validate lines_back doesn't exceed filled (prevents reading uninitialized data)
        if (lines_back >= filled) {
            break;  // Stop if we've exceeded available data
        }

        // Safe modulo calculation for ring index
        // Use long long to prevent overflow in intermediate calculation
        long long ring_calc = (long long)backpos - 1 - lines_back + (long long)capacity * 2;
        int ring_idx = (int)(ring_calc % capacity);
        if (ring_idx < 0) ring_idx += capacity;  // Handle negative modulo

        // Validate ring_idx is within bounds
        if (ring_idx < 0 || ring_idx >= capacity) {
            continue;  // Skip invalid index
        }

        // Copy this line's cells
        for (int col = 0; col < cols; col++) {
            // Safe multiplication for cell index
            int line_offset;
            if (!safe_mult_int(ring_idx, cols, &line_offset)) {
                continue;  // Skip on overflow
            }
            int cell_idx;
            if (!safe_add_int(line_offset, col, &cell_idx)) {
                continue;  // Skip on overflow
            }

            // Validate cell_idx is within scrollback buffer bounds
            if (cell_idx < 0 || cell_idx >= max_valid_cell_idx) {
                continue;  // Skip invalid index
            }

            // Validate arr_idx is within output array bounds
            if (arr_idx >= size) {
                break;  // Stop if output array is full
            }

            struct vmem_cell *cell = &scrollback[cell_idx];

            unsigned int ch = cell->ch & 0xFFu;
            unsigned int attr = cell->legacy_attr & 0xFFu;
            unsigned int fg = cell->fg & 0xFFu;
            unsigned int bg = cell->bg & 0xFFu;
            arr[arr_idx++] = (jint)(ch | (attr << 8) | (fg << 16) | (bg << 24));
        }
        // Check if we filled the array (outer loop break)
        if (arr_idx >= size) {
            break;
        }
    }

    (*env)->ReleaseIntArrayElements(env, result, arr, 0);
    pthread_mutex_unlock(&g_lock);
    return result;
}

// Check if bell was detected and clear the flag (atomic read-and-clear)
// Returns: 1 if bell was detected, 0 otherwise
JNIEXPORT jboolean JNICALL
Java_com_syncterm_android_NativeBridge_nativeCheckBell(JNIEnv *env, jclass clazz) {
    pthread_mutex_lock(&g_lock);
    int detected = g_bell_detected;
    g_bell_detected = 0;  // Clear flag after reading
    pthread_mutex_unlock(&g_lock);
    return detected ? JNI_TRUE : JNI_FALSE;
}

// Session logging functions

// Enable or disable session logging
JNIEXPORT void JNICALL
Java_com_syncterm_android_NativeBridge_nativeSetLoggingEnabled(JNIEnv *env, jclass clazz, jboolean enabled) {
    pthread_mutex_lock(&g_log_lock);
    g_logging_enabled = enabled ? 1 : 0;
    if (!enabled) {
        // Clear buffer when logging is disabled
        g_log_buffer_len = 0;
    }
    pthread_mutex_unlock(&g_log_lock);
    LOGI("Session logging %s", enabled ? "enabled" : "disabled");
}

// Get and clear logged data
// Returns: byte array of logged data, or null if no data
JNIEXPORT jbyteArray JNICALL
Java_com_syncterm_android_NativeBridge_nativeGetLoggedData(JNIEnv *env, jclass clazz) {
    pthread_mutex_lock(&g_log_lock);

    if (g_log_buffer_len <= 0) {
        pthread_mutex_unlock(&g_log_lock);
        return NULL;
    }

    jbyteArray result = (*env)->NewByteArray(env, g_log_buffer_len);
    if (result) {
        (*env)->SetByteArrayRegion(env, result, 0, g_log_buffer_len, (jbyte*)g_log_buffer);
    }

    // Clear the buffer after reading
    g_log_buffer_len = 0;

    pthread_mutex_unlock(&g_log_lock);
    return result;
}

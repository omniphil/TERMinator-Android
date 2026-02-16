/**
 * Android stubs for SyncTERM dependencies that aren't needed on Android.
 *
 * This file provides stub implementations for UI-related functions
 * that are referenced by the connection code but not used when
 * hidepopups is set to true.
 */

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdbool.h>
#include <android/log.h>

// Include ciolib.h early to get struct definitions and correct function signatures
#include "ciolib.h"
#include "bbslist.h"
#include "cterm.h"

#define LOG_TAG "SyncTERM-Stubs"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)

// Android app files directory path (set from Java via JNI)
static char g_android_files_dir[512] = {0};

// Set the Android files directory (called from Java/Kotlin)
void android_set_files_dir(const char *path) {
    if (!path) {
        LOGW("android_set_files_dir: path is NULL");
        return;
    }
    size_t path_len = strlen(path);
    if (path_len >= sizeof(g_android_files_dir)) {
        LOGW("android_set_files_dir: path too long (%zu >= %zu)",
             path_len, sizeof(g_android_files_dir));
        return;
    }
    strncpy(g_android_files_dir, path, sizeof(g_android_files_dir) - 1);
    g_android_files_dir[sizeof(g_android_files_dir) - 1] = '\0';
    LOGI("Files directory set to: %s", g_android_files_dir);
}

// uifc stub structure and functions
typedef struct {
    int (*pop)(const char *);
    int scrn_len;
    int scrn_width;
} uifc_api_t;

static int stub_pop(const char *str) {
    if (str) {
        LOGI("uifc.pop: %s", str);
    }
    return 0;
}

uifc_api_t uifc = {
    .pop = stub_pop,
    .scrn_len = 25,
    .scrn_width = 80
};

// uifc message functions
void uifcmsg(const char *str, const char *help) {
    if (str) {
        LOGW("uifcmsg: %s", str);
    }
}

int uifcinput(const char *mode, int maxlen, char *str, int opts, const char *help) {
    return -1;  // Cancel
}

// uifc initialization
void init_uifc(int force_remote, int force_login) {
    LOGI("init_uifc called (stubbed)");
}

void uifc_bail(void) {
    LOGI("uifc_bail called (stubbed)");
}

// Window/popup functions
int popup_menu(int items, char **item_list, char *title, int top, int left) {
    return -1;  // Cancel
}

void load_font_files(void) {
    LOGI("load_font_files called (stubbed)");
}

// Settings functions
struct syncterm_settings {
    int confirm_close;
    int startup_mode;
    int output_types;
    // Add more as needed
};

struct syncterm_settings settings = {
    .confirm_close = 0,
    .startup_mode = 0,
    .output_types = 0
};

// Other stubs that might be needed
void get_cterm_size(int *cols, int *rows, int force_full) {
    if (cols) *cols = 80;
    if (rows) *rows = 25;
}

void term_title(const char *title) {
    LOGI("term_title: %s", title ? title : "(null)");
}

// Global variables that might be referenced
int quession = 0;
int *startup_mode = NULL;

// ANSI music stub
void play_music(const char *music_str) {
    LOGI("play_music called (not implemented on Android)");
}

// Font-related stubs
int setfont_from_bbs(int font_num, int force) {
    return 0;
}

// Status line stubs
void setup_status_line(void) {
    // No-op on Android
}

void update_status(int conn_status, int speed) {
    // No-op on Android
}

// Log stubs
void conn_log(int level, const char *fmt, ...) {
    // Could be implemented to use Android logging if needed
}

// =============================================================================
// ciolib pixel/graphics stubs
// =============================================================================

// Pixel manipulation - not supported on Android (sixel graphics)
// Signatures must match ciolib.h exactly
int ciolib_setpixels(uint32_t sx, uint32_t sy, uint32_t ex, uint32_t ey,
                     uint32_t x_off, uint32_t y_off, uint32_t mx_off, uint32_t my_off,
                     struct ciolib_pixels *pixels, struct ciolib_mask *mask) {
    (void)sx; (void)sy; (void)ex; (void)ey;
    (void)x_off; (void)y_off; (void)mx_off; (void)my_off;
    (void)pixels; (void)mask;
    return 0;  // Not supported
}

struct ciolib_pixels *ciolib_getpixels(uint32_t sx, uint32_t sy, uint32_t ex, uint32_t ey, int force) {
    (void)sx; (void)sy; (void)ex; (void)ey; (void)force;
    return NULL;  // Not supported
}

void ciolib_freepixels(struct ciolib_pixels *pixels) {
    (void)pixels;
    // No-op
}

// Custom cursor - not supported on Android
void ciolib_getcustomcursor(int *startline, int *endline, int *range, int *blink, int *visible) {
    if (startline) *startline = 0;
    if (endline) *endline = 0;
    if (range) *range = 0;
    if (blink) *blink = 1;
    if (visible) *visible = 1;
}

void ciolib_setcustomcursor(int startline, int endline, int range, int blink, int visible) {
    (void)startline; (void)endline; (void)range; (void)blink; (void)visible;
    // Not supported
}

// RGB color mapping
uint32_t ciolib_map_rgb(uint16_t r, uint16_t g, uint16_t b) {
    return ((r & 0xFF) << 16) | ((g & 0xFF) << 8) | (b & 0xFF);
}

// =============================================================================
// Audio stubs - beep and tone generation
// =============================================================================

// xptone - returns 0 on success, -1 on failure
int xptone(double freq, unsigned long duration, unsigned volume) {
    LOGI("xptone: freq=%.2f dur=%lu vol=%u (not implemented)", freq, duration, volume);
    return 0;  // Pretend success
}

int xptone_complete(void) {
    return 1;  // Tone completed
}

int xptone_open(void) {
    return 0;  // Success
}

int xptone_close(void) {
    return 0;  // Success
}

void xpbeep(void) {
    LOGI("xpbeep (not implemented)");
}

// =============================================================================
// Emulation mode
// =============================================================================

cterm_emulation_t get_emulation(struct bbslist *bbs) {
    // Return ANSI-BBS emulation by default for Android
    (void)bbs;  // Suppress unused warning
    return CTERM_EMULATION_ANSI_BBS;
}

const char* get_emulation_str(struct bbslist *bbs) {
    // Check if custom term name is set
    if (bbs && bbs->term_name[0])
        return bbs->term_name;

    // Return string based on emulation type
    switch (get_emulation(bbs)) {
        case CTERM_EMULATION_ANSI_BBS:
            return "syncterm";
        case CTERM_EMULATION_PETASCII:
            return "PETSCII";
        case CTERM_EMULATION_ATASCII:
            return "ATASCII";
        case CTERM_EMULATION_PRESTEL:
            return "Prestel";
        case CTERM_EMULATION_BEEB:
            return "Beeb7";
        case CTERM_EMULATION_ATARIST_VT52:
            return "AtariST+VT52";
        default:
            return "syncterm";
    }
}

// =============================================================================
// Serial/Modem stubs - not needed for Telnet-only
// =============================================================================

// Serial port functions
typedef void* COM_HANDLE;
#define COM_HANDLE_INVALID NULL

int modem_connect(void *bbs) {
    LOGW("modem_connect called - not supported on Android");
    return -1;  // Failure
}

void modem_close(void) {
    // No-op
}

void serial_close(COM_HANDLE h) {
    // No-op
}

COM_HANDLE serial_open(const char *port) {
    return COM_HANDLE_INVALID;
}

int serial_read(COM_HANDLE h, void *buf, size_t len) {
    return -1;
}

int serial_write(COM_HANDLE h, const void *buf, size_t len) {
    return -1;
}

// =============================================================================
// SSH/SFTP stubs - disabled via WITHOUT_CRYPTLIB
// =============================================================================

#ifdef WITHOUT_CRYPTLIB
int ssh_connect(void *bbs) {
    return -1;
}

void ssh_close(void) {
}
#endif

// =============================================================================
// RIP graphics stubs (if referenced)
// =============================================================================

void rip_reset(void) {
    // No-op
}

int rip_parse(unsigned char *buf, int len) {
    return 0;  // Not supported
}

// =============================================================================
// PTY stubs - not needed on Android
// =============================================================================

int pty_connect(void *bbs) {
    LOGW("pty_connect called - not supported on Android");
    return -1;
}

void pty_close(void) {
    // No-op
}

// =============================================================================
// ciolib cputs and font replacement
// =============================================================================

int ciolib_cputs(const char *str) {
    // Simple implementation - write string character by character
    extern int ciolib_putch(int);
    if (!str) return 0;
    int count = 0;
    while (*str) {
        ciolib_putch(*str++);
        count++;
    }
    return count;
}

void ciolib_replace_font(uint8_t id, char *name, void *data, size_t size) {
    (void)id; (void)name; (void)data; (void)size;
    LOGI("ciolib_replace_font called (not implemented)");
    // Not supported
}

// =============================================================================
// Logging variables
// =============================================================================

FILE *log_fp = NULL;
char *log_levels[] = {
    "EMERG",
    "ALERT",
    "CRIT",
    "ERR",
    "WARNING",
    "NOTICE",
    "INFO",
    "DEBUG"
};

// =============================================================================
// SSH-related stubs
// =============================================================================

// SYNCTERM_PATH types from syncterm.h
#define SYNCTERM_PATH_INI 0
#define SYNCTERM_PATH_LIST 1
#define SYNCTERM_PATH_CACHE 3
#define SYNCTERM_PATH_KEYS 4
#define SYNCTERM_PATH_SYSTEM_CACHE 5

// Get syncterm configuration file path
char *get_syncterm_filename(char *fn, int fnlen, int type, bool shared) {
    (void)shared;

    if (!fn || fnlen <= 0) {
        return fn;
    }

    fn[0] = '\0';

    // If files directory isn't set, return empty path
    if (g_android_files_dir[0] == '\0') {
        LOGW("get_syncterm_filename: files directory not set");
        return fn;
    }

    const char *filename;
    switch (type) {
        case SYNCTERM_PATH_KEYS:
            filename = "ssh_keys.p15";
            break;
        case SYNCTERM_PATH_INI:
            filename = "syncterm.ini";
            break;
        case SYNCTERM_PATH_LIST:
            filename = "syncterm.lst";
            break;
        case SYNCTERM_PATH_CACHE:
        case SYNCTERM_PATH_SYSTEM_CACHE:
            filename = "cache";
            break;
        default:
            filename = "syncterm.dat";
            break;
    }

    snprintf(fn, fnlen, "%s/%s", g_android_files_dir, filename);
    LOGI("get_syncterm_filename: type=%d -> %s", type, fn);
    return fn;
}

// Alias for uifc_bail (some code uses uifcbail)
void uifcbail(void) {
    uifc_bail();
}

// Get terminal window size
void get_term_win_size(int *width, int *height) {
    // Default Android terminal size
    if (width) *width = 80;
    if (height) *height = 25;
}

// BBS list INI reading - not needed for Android connection flow
str_list_t iniReadBBSList(FILE *fp, bool userList) {
    (void)fp; (void)userList;
    return NULL;
}

// INI file style - global variable
ini_style_t ini_style = {0};

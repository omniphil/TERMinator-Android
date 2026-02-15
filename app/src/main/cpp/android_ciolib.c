/**
 * Android ciolib implementation
 *
 * Provides stub implementations of ciolib functions for Android.
 * Instead of rendering directly, this stores terminal state in a buffer
 * that can be read via JNI for rendering in Java/Kotlin.
 */

#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <android/log.h>

#include "safe_math.h"
#include "android_ciolib.h"
#include "ciolib.h"
#include "vidmodes.h"

#define LOG_TAG "SyncTERM-CIO"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// Maximum terminal dimensions to prevent unreasonable allocations
#define MAX_TERMINAL_WIDTH  1000
#define MAX_TERMINAL_HEIGHT 1000

// Global ciolib variables that must be defined
struct text_info cio_textinfo;
cioapi_t cio_api;
int _wscroll = 1;
int directvideo = 0;
int hold_update = 0;
int puttext_can_move = 0;
int ciolib_reaper = 0;
const char *ciolib_appname = "SyncTERM";
double ciolib_initial_scaling = 1.0;
int ciolib_initial_mode = C80;
enum ciolib_scaling ciolib_initial_scaling_type = CIOLIB_SCALING_INTERNAL;
const void *ciolib_initial_icon = NULL;
size_t ciolib_initial_icon_width = 0;
const char *ciolib_initial_program_name = "SyncTERM";
const char *ciolib_initial_program_class = "SyncTERM";
bool ciolib_swap_mouse_butt45 = false;
uint32_t ciolib_fg = 7;  // Light gray
uint32_t ciolib_bg = 0;  // Black

// Font data from allfonts.c (extern - actual data is in allfonts.c)
extern struct conio_font_data_struct conio_fontdata[257];

// Android-specific screen state
static struct android_screen_state {
    struct vmem_cell *screen;
    int width;
    int height;
    int cursor_x;
    int cursor_y;
    int cursor_visible;
    int cursor_type;
    uint8_t current_attr;
    uint32_t fg_color;
    uint32_t bg_color;
    int dirty;
    // Dirty region tracking for partial redraws
    int dirty_min_x;
    int dirty_max_x;
    int dirty_min_y;
    int dirty_max_y;
    pthread_mutex_t mutex;
    uint32_t palette[16];
} android_state = {
    .screen = NULL,
    .width = 80,
    .height = 25,
    .cursor_x = 1,
    .cursor_y = 1,
    .cursor_visible = 1,
    .cursor_type = _NORMALCURSOR,
    .current_attr = 7,
    .fg_color = 7,
    .bg_color = 0,
    .dirty = 0,
    .dirty_min_x = 0,
    .dirty_max_x = 0,
    .dirty_min_y = 0,
    .dirty_max_y = 0,
    .palette = {
        0x000000, // Black
        0x0000AA, // Blue
        0x00AA00, // Green
        0x00AAAA, // Cyan
        0xAA0000, // Red
        0xAA00AA, // Magenta
        0xAA5500, // Brown
        0xAAAAAA, // Light Gray
        0x555555, // Dark Gray
        0x5555FF, // Light Blue
        0x55FF55, // Light Green
        0x55FFFF, // Light Cyan
        0xFF5555, // Light Red
        0xFF55FF, // Light Magenta
        0xFFFF55, // Yellow
        0xFFFFFF  // White
    }
};

// Forward declarations
static void android_clreol(void);
static int android_puttext(int sx, int sy, int ex, int ey, void *buf);
static int android_vmem_puttext(int sx, int sy, int ex, int ey, struct vmem_cell *buf);
static int android_gettext(int sx, int sy, int ex, int ey, void *buf);
static int android_vmem_gettext(int sx, int sy, int ex, int ey, struct vmem_cell *buf);
static void android_textattr(int attr);
static int android_kbhit(void);
static int android_kbwait(int timeout);
static void android_delay(long ms);
static int android_wherex(void);
static int android_wherey(void);
static int android_putch(int c);
static void android_gotoxy(int x, int y);
static void android_clrscr(void);
static void android_gettextinfo(struct text_info *info);
static void android_setcursortype(int type);
static int android_getch(void);
static int android_getche(void);
static void android_beep(void);
static void android_highvideo(void);
static void android_lowvideo(void);
static void android_normvideo(void);
static void android_textmode(int mode);
static int android_ungetch(int ch);
static int android_movetext(int sx, int sy, int ex, int ey, int dx, int dy);
static void android_wscroll(void);
static void android_window(int sx, int sy, int ex, int ey);
static void android_delline(void);
static void android_insline(void);
static void android_textbackground(int color);
static void android_textcolor(int color);
static void android_settitle(const char *title);
static void android_setname(const char *name);
static int android_setfont(int font, int force, int font_num);
static int android_getfont(int font_num);
static void android_setvideoflags(int flags);
static int android_getvideoflags(void);
static int android_setpalette(uint32_t entry, uint16_t r, uint16_t g, uint16_t b);
static int android_attr2palette(uint8_t attr, uint32_t *fg, uint32_t *bg);

// Input buffer for keyboard input from Java
#define INPUT_BUFFER_SIZE 256
static unsigned char input_buffer[INPUT_BUFFER_SIZE];
static int input_head = 0;
static int input_tail = 0;
static pthread_mutex_t input_mutex = PTHREAD_MUTEX_INITIALIZER;

// Public functions for JNI access
int android_ciolib_get_screen_width(void) {
    return android_state.width;
}

int android_ciolib_get_screen_height(void) {
    return android_state.height;
}

int android_ciolib_get_cursor_x(void) {
    return android_state.cursor_x;
}

int android_ciolib_get_cursor_y(void) {
    return android_state.cursor_y;
}

int android_ciolib_is_cursor_visible(void) {
    return android_state.cursor_visible && android_state.cursor_type != _NOCURSOR;
}

int android_ciolib_is_dirty(void) {
    return android_state.dirty;
}

void android_ciolib_clear_dirty(void) {
    android_state.dirty = 0;
    // Reset dirty region to invalid state
    android_state.dirty_min_x = android_state.width;
    android_state.dirty_max_x = 0;
    android_state.dirty_min_y = android_state.height;
    android_state.dirty_max_y = 0;
}

// Get dirty region bounds (returns 0 if no dirty region, 1 if valid)
int android_ciolib_get_dirty_region(int *min_x, int *min_y, int *max_x, int *max_y) {
    if (!android_state.dirty) {
        return 0;
    }
    *min_x = android_state.dirty_min_x;
    *min_y = android_state.dirty_min_y;
    *max_x = android_state.dirty_max_x;
    *max_y = android_state.dirty_max_y;
    return 1;
}

// Mark a cell as dirty and expand dirty region
static inline void mark_cell_dirty(int x, int y) {
    android_state.dirty = 1;
    if (x < android_state.dirty_min_x) android_state.dirty_min_x = x;
    if (x > android_state.dirty_max_x) android_state.dirty_max_x = x;
    if (y < android_state.dirty_min_y) android_state.dirty_min_y = y;
    if (y > android_state.dirty_max_y) android_state.dirty_max_y = y;
}

// Mark a rectangular region as dirty
static inline void mark_region_dirty(int x1, int y1, int x2, int y2) {
    android_state.dirty = 1;
    if (x1 < android_state.dirty_min_x) android_state.dirty_min_x = x1;
    if (x2 > android_state.dirty_max_x) android_state.dirty_max_x = x2;
    if (y1 < android_state.dirty_min_y) android_state.dirty_min_y = y1;
    if (y2 > android_state.dirty_max_y) android_state.dirty_max_y = y2;
}

// Mark entire screen as dirty
static inline void mark_screen_dirty(void) {
    android_state.dirty = 1;
    android_state.dirty_min_x = 0;
    android_state.dirty_max_x = android_state.width - 1;
    android_state.dirty_min_y = 0;
    android_state.dirty_max_y = android_state.height - 1;
}

struct vmem_cell* android_ciolib_get_screen_buffer(void) {
    return android_state.screen;
}

void android_ciolib_lock(void) {
    pthread_mutex_lock(&android_state.mutex);
}

void android_ciolib_unlock(void) {
    pthread_mutex_unlock(&android_state.mutex);
}

uint32_t* android_ciolib_get_palette(void) {
    return android_state.palette;
}

// Push keyboard input from Java/Kotlin
void android_ciolib_push_input(unsigned char c) {
    pthread_mutex_lock(&input_mutex);
    int next = (input_head + 1) % INPUT_BUFFER_SIZE;
    if (next != input_tail) {
        input_buffer[input_head] = c;
        input_head = next;
    }
    pthread_mutex_unlock(&input_mutex);
}

void android_ciolib_push_input_buffer(const unsigned char *buf, int len) {
    // Validate parameters - reject NULL buffer or negative/zero length
    if (buf == NULL || len <= 0) {
        return;
    }

    pthread_mutex_lock(&input_mutex);
    for (int i = 0; i < len; i++) {
        int next = (input_head + 1) % INPUT_BUFFER_SIZE;
        if (next == input_tail) break;
        input_buffer[input_head] = buf[i];
        input_head = next;
    }
    pthread_mutex_unlock(&input_mutex);
}

// Implementation functions
static void android_clreol(void) {
    pthread_mutex_lock(&android_state.mutex);
    int y = android_state.cursor_y - 1;
    int x = android_state.cursor_x - 1;
    if (y >= 0 && y < android_state.height && x >= 0 && android_state.screen) {
        for (int i = x; i < android_state.width; i++) {
            int idx;
            if (!validate_index(i, y, android_state.width, android_state.height, &idx)) {
                break;  // Index overflow, stop processing
            }
            android_state.screen[idx].ch = ' ';
            android_state.screen[idx].legacy_attr = android_state.current_attr;
            android_state.screen[idx].fg = android_state.fg_color;
            android_state.screen[idx].bg = android_state.bg_color;
            android_state.screen[idx].font = 0;
        }
        mark_region_dirty(x, y, android_state.width - 1, y);
    }
    pthread_mutex_unlock(&android_state.mutex);
}

static int android_puttext(int sx, int sy, int ex, int ey, void *buf) {
    // Convert legacy format to vmem and call vmem_puttext
    if (!buf) return 0;

    // Validate rectangle dimensions with overflow protection
    int width, height;
    if (!validate_rect_dims(sx, sy, ex, ey, &width, &height)) {
        return 0;  // Invalid rectangle
    }

    unsigned char *src = (unsigned char *)buf;

    pthread_mutex_lock(&android_state.mutex);
    if (android_state.screen) {
        for (int y = 0; y < height; y++) {
            for (int x = 0; x < width; x++) {
                int screen_x = sx - 1 + x;
                int screen_y = sy - 1 + y;

                // Validate screen index
                int idx;
                if (!validate_index(screen_x, screen_y, android_state.width,
                                   android_state.height, &idx)) {
                    continue;  // Skip out-of-bounds
                }

                // Validate source index
                int src_idx;
                if (!validate_index(x, y, width, height, &src_idx)) {
                    continue;
                }

                // Validate multiplication to prevent overflow
                int src_offset;
                if (!safe_mult_int(src_idx, 2, &src_offset)) {
                    continue;  // Skip if multiplication overflows
                }

                // Validate src_offset + 1 is within buffer bounds
                // Buffer size is width * height * 2 bytes
                // NOTE: Must compute width*height safely first to avoid overflow
                int area;
                if (!safe_mult_int(width, height, &area)) {
                    continue;
                }
                int buf_size;
                if (!safe_mult_int(area, 2, &buf_size)) {
                    continue;
                }
                if (src_offset < 0 || src_offset + 1 >= buf_size) {
                    continue;  // Skip if would read past buffer end
                }

                android_state.screen[idx].ch = src[src_offset];
                android_state.screen[idx].legacy_attr = src[src_offset + 1];
            }
        }
        mark_region_dirty(sx - 1, sy - 1, ex - 1, ey - 1);
    }
    pthread_mutex_unlock(&android_state.mutex);
    return 1;
}

static int android_vmem_puttext(int sx, int sy, int ex, int ey, struct vmem_cell *buf) {
    if (!buf) return 0;

    // Validate rectangle dimensions with overflow protection
    int width, height;
    if (!validate_rect_dims(sx, sy, ex, ey, &width, &height)) {
        return 0;  // Invalid rectangle
    }

    pthread_mutex_lock(&android_state.mutex);
    if (android_state.screen) {
        for (int y = 0; y < height; y++) {
            for (int x = 0; x < width; x++) {
                int screen_x = sx - 1 + x;
                int screen_y = sy - 1 + y;

                // Validate screen index
                int idx;
                if (!validate_index(screen_x, screen_y, android_state.width,
                                   android_state.height, &idx)) {
                    continue;
                }

                // Validate source index
                int src_idx;
                if (!validate_index(x, y, width, height, &src_idx)) {
                    continue;
                }

                android_state.screen[idx] = buf[src_idx];
            }
        }
        mark_region_dirty(sx - 1, sy - 1, ex - 1, ey - 1);
    }
    pthread_mutex_unlock(&android_state.mutex);
    return 1;
}

static int android_gettext(int sx, int sy, int ex, int ey, void *buf) {
    if (!buf) return 0;

    // Validate rectangle dimensions with overflow protection
    int width, height;
    if (!validate_rect_dims(sx, sy, ex, ey, &width, &height)) {
        return 0;  // Invalid rectangle
    }

    unsigned char *dst = (unsigned char *)buf;

    pthread_mutex_lock(&android_state.mutex);
    if (android_state.screen) {
        for (int y = 0; y < height; y++) {
            for (int x = 0; x < width; x++) {
                int screen_x = sx - 1 + x;
                int screen_y = sy - 1 + y;

                // Validate screen index
                int idx;
                if (!validate_index(screen_x, screen_y, android_state.width,
                                   android_state.height, &idx)) {
                    continue;
                }

                // Validate destination index
                int dst_idx;
                if (!validate_index(x, y, width, height, &dst_idx)) {
                    continue;
                }

                // Validate multiplication to prevent overflow
                int dst_offset;
                if (!safe_mult_int(dst_idx, 2, &dst_offset)) {
                    continue;  // Skip if multiplication overflows
                }

                // Validate dst_offset + 1 is within buffer bounds
                // Buffer size is width * height * 2 bytes
                // NOTE: Must compute width*height safely first to avoid overflow
                int area;
                if (!safe_mult_int(width, height, &area)) {
                    continue;
                }
                int buf_size;
                if (!safe_mult_int(area, 2, &buf_size)) {
                    continue;
                }
                if (dst_offset < 0 || dst_offset + 1 >= buf_size) {
                    continue;  // Skip if would write past buffer end
                }

                dst[dst_offset] = android_state.screen[idx].ch;
                dst[dst_offset + 1] = android_state.screen[idx].legacy_attr;
            }
        }
    }
    pthread_mutex_unlock(&android_state.mutex);
    return 1;
}

static int android_vmem_gettext(int sx, int sy, int ex, int ey, struct vmem_cell *buf) {
    if (!buf) return 0;

    // Validate rectangle dimensions with overflow protection
    int width, height;
    if (!validate_rect_dims(sx, sy, ex, ey, &width, &height)) {
        return 0;  // Invalid rectangle
    }

    pthread_mutex_lock(&android_state.mutex);
    if (android_state.screen) {
        for (int y = 0; y < height; y++) {
            for (int x = 0; x < width; x++) {
                int screen_x = sx - 1 + x;
                int screen_y = sy - 1 + y;

                // Validate screen index
                int idx;
                if (!validate_index(screen_x, screen_y, android_state.width,
                                   android_state.height, &idx)) {
                    continue;
                }

                // Validate destination index
                int dst_idx;
                if (!validate_index(x, y, width, height, &dst_idx)) {
                    continue;
                }

                buf[dst_idx] = android_state.screen[idx];
            }
        }
    }
    pthread_mutex_unlock(&android_state.mutex);
    return 1;
}

static void android_textattr(int attr) {
    pthread_mutex_lock(&android_state.mutex);
    android_state.current_attr = (uint8_t)attr;
    android_state.fg_color = attr & 0x0F;
    android_state.bg_color = (attr >> 4) & 0x07;
    pthread_mutex_unlock(&android_state.mutex);
}

static int android_kbhit(void) {
    pthread_mutex_lock(&input_mutex);
    int has_data = (input_head != input_tail);
    pthread_mutex_unlock(&input_mutex);
    return has_data;
}

static int android_kbwait(int timeout) {
    // Simple polling implementation
    long elapsed = 0;
    while (elapsed < timeout || timeout == 0) {
        if (android_kbhit()) return 1;
        usleep(10000); // 10ms
        elapsed += 10;
        if (timeout == 0) break;
    }
    return android_kbhit();
}

static void android_delay(long ms) {
    // Validate ms to prevent overflow and negative values
    // usleep takes useconds_t (typically unsigned int, max ~4.3 billion microseconds = ~4294 seconds)
    if (ms <= 0) {
        return;  // No delay for zero or negative
    }
    // Cap at a reasonable maximum (1 hour = 3600000ms) to prevent overflow
    if (ms > 3600000L) {
        ms = 3600000L;
    }
    usleep((useconds_t)(ms * 1000));
}

static int android_wherex(void) {
    return android_state.cursor_x;
}

static int android_wherey(void) {
    return android_state.cursor_y;
}

static int android_putch(int c) {
    pthread_mutex_lock(&android_state.mutex);
    if (android_state.screen) {
        int x = android_state.cursor_x - 1;
        int y = android_state.cursor_y - 1;

        // Validate index with overflow protection
        int idx;
        if (validate_index(x, y, android_state.width, android_state.height, &idx)) {
            android_state.screen[idx].ch = (uint8_t)c;
            android_state.screen[idx].legacy_attr = android_state.current_attr;
            android_state.screen[idx].fg = android_state.fg_color;
            android_state.screen[idx].bg = android_state.bg_color;
            android_state.screen[idx].font = 0;
            mark_cell_dirty(x, y);

            // Advance cursor
            android_state.cursor_x++;
            if (android_state.cursor_x > android_state.width) {
                android_state.cursor_x = 1;
                android_state.cursor_y++;
                if (android_state.cursor_y > android_state.height) {
                    android_state.cursor_y = android_state.height;
                    // Would need to scroll here
                }
            }
        }
    }
    pthread_mutex_unlock(&android_state.mutex);
    return c;
}

static void android_gotoxy(int x, int y) {
    pthread_mutex_lock(&android_state.mutex);
    if (x >= 1 && x <= android_state.width) {
        android_state.cursor_x = x;
    }
    if (y >= 1 && y <= android_state.height) {
        android_state.cursor_y = y;
    }
    pthread_mutex_unlock(&android_state.mutex);
}

static void android_clrscr(void) {
    pthread_mutex_lock(&android_state.mutex);
    if (android_state.screen) {
        // Calculate screen size with overflow protection
        int screen_size;
        if (validate_dimensions(android_state.width, android_state.height, &screen_size)) {
            for (int i = 0; i < screen_size; i++) {
                android_state.screen[i].ch = ' ';
                android_state.screen[i].legacy_attr = android_state.current_attr;
                android_state.screen[i].fg = android_state.fg_color;
                android_state.screen[i].bg = android_state.bg_color;
                android_state.screen[i].font = 0;
            }
        }
        android_state.cursor_x = 1;
        android_state.cursor_y = 1;
        mark_screen_dirty();
    }
    pthread_mutex_unlock(&android_state.mutex);
}

static void android_gettextinfo(struct text_info *info) {
    if (!info) return;
    pthread_mutex_lock(&android_state.mutex);
    info->winleft = 1;
    info->wintop = 1;
    info->winright = android_state.width;
    info->winbottom = android_state.height;
    info->attribute = android_state.current_attr;
    info->normattr = 7;
    info->currmode = C80;
    info->screenheight = android_state.height;
    info->screenwidth = android_state.width;
    info->curx = android_state.cursor_x;
    info->cury = android_state.cursor_y;
    pthread_mutex_unlock(&android_state.mutex);
}

static void android_setcursortype(int type) {
    pthread_mutex_lock(&android_state.mutex);
    android_state.cursor_type = type;
    android_state.cursor_visible = (type != _NOCURSOR);
    pthread_mutex_unlock(&android_state.mutex);
}

static int android_getch(void) {
    // Wait for input
    while (!android_kbhit()) {
        usleep(10000); // 10ms
    }

    pthread_mutex_lock(&input_mutex);
    int c = -1;
    if (input_head != input_tail) {
        c = input_buffer[input_tail];
        input_tail = (input_tail + 1) % INPUT_BUFFER_SIZE;
    }
    pthread_mutex_unlock(&input_mutex);
    return c;
}

static int android_getche(void) {
    int c = android_getch();
    if (c >= 0) {
        android_putch(c);
    }
    return c;
}

static void android_beep(void) {
    // Could trigger a vibration or sound callback to Java
    LOGI("Beep!");
}

static void android_highvideo(void) {
    pthread_mutex_lock(&android_state.mutex);
    android_state.current_attr |= 0x08;
    android_state.fg_color = android_state.current_attr & 0x0F;
    pthread_mutex_unlock(&android_state.mutex);
}

static void android_lowvideo(void) {
    pthread_mutex_lock(&android_state.mutex);
    android_state.current_attr &= ~0x08;
    android_state.fg_color = android_state.current_attr & 0x0F;
    pthread_mutex_unlock(&android_state.mutex);
}

static void android_normvideo(void) {
    android_textattr(7);
}

static void android_textmode(int mode) {
    int new_width = 80;
    int new_height = 25;

    // Map mode to dimensions
    switch (mode) {
        case C40:
        case BW40:
            new_width = 40;
            new_height = 25;
            break;
        case C80:
        case BW80:
        case MONO:
        default:
            new_width = 80;
            new_height = 25;
            break;
        case C80X28:
            new_width = 80;
            new_height = 28;
            break;
        case C80X30:
            new_width = 80;
            new_height = 30;
            break;
        case C80X43:
            new_width = 80;
            new_height = 43;
            break;
        case C80X50:
            new_width = 80;
            new_height = 50;
            break;
        case C80X60:
            new_width = 80;
            new_height = 60;
            break;
    }

    pthread_mutex_lock(&android_state.mutex);

    // Reallocate screen buffer if size changed
    if (new_width != android_state.width || new_height != android_state.height) {
        // Validate allocation size with overflow protection
        size_t alloc_size;
        if (!validate_alloc_size(new_width, new_height, sizeof(struct vmem_cell), &alloc_size)) {
            __android_log_print(ANDROID_LOG_ERROR, "AndroidCiolib",
                "Screen buffer size overflow for %dx%d", new_width, new_height);
            pthread_mutex_unlock(&android_state.mutex);
            return;
        }

        struct vmem_cell *new_screen = calloc(1, alloc_size);
        if (new_screen) {
            // Free old screen only after successful allocation
            free(android_state.screen);
            android_state.screen = new_screen;
            android_state.width = new_width;
            android_state.height = new_height;

            // Initialize screen with validated size
            int screen_size;
            if (validate_dimensions(new_width, new_height, &screen_size)) {
                for (int i = 0; i < screen_size; i++) {
                    android_state.screen[i].ch = ' ';
                    android_state.screen[i].legacy_attr = 7;
                    android_state.screen[i].fg = 7;
                    android_state.screen[i].bg = 0;
                    android_state.screen[i].font = 0;
                }
            }
        } else {
            // Allocation failed, keep old screen
            __android_log_print(ANDROID_LOG_ERROR, "AndroidCiolib",
                "Failed to allocate screen buffer for %dx%d", new_width, new_height);
        }
    }

    android_state.cursor_x = 1;
    android_state.cursor_y = 1;
    mark_screen_dirty();

    pthread_mutex_unlock(&android_state.mutex);

    // Update text_info
    cio_textinfo.screenwidth = new_width;
    cio_textinfo.screenheight = new_height;
}

static int android_ungetch(int ch) {
    pthread_mutex_lock(&input_mutex);
    // Push to front of buffer (actually just add to queue for simplicity)
    int next = (input_head + 1) % INPUT_BUFFER_SIZE;
    if (next != input_tail) {
        input_buffer[input_head] = (unsigned char)ch;
        input_head = next;
        pthread_mutex_unlock(&input_mutex);
        return ch;
    }
    pthread_mutex_unlock(&input_mutex);
    return -1;
}

static int android_movetext(int sx, int sy, int ex, int ey, int dx, int dy) {
    // Validate rectangle dimensions with overflow protection
    int width, height;
    if (!validate_rect_dims(sx, sy, ex, ey, &width, &height)) {
        return 0;  // Invalid rectangle
    }

    // Validate allocation size
    size_t alloc_size;
    if (!validate_alloc_size(width, height, sizeof(struct vmem_cell), &alloc_size)) {
        return 0;  // Size overflow
    }

    struct vmem_cell *temp = malloc(alloc_size);
    if (!temp) return 0;

    // Get source
    android_vmem_gettext(sx, sy, ex, ey, temp);
    // Put at destination
    android_vmem_puttext(dx, dy, dx + width - 1, dy + height - 1, temp);

    free(temp);
    return 1;
}

static void android_wscroll(void) {
    pthread_mutex_lock(&android_state.mutex);
    if (android_state.screen && android_state.height > 1) {
        // Calculate sizes with overflow protection
        int last_line_offset;
        if (!safe_mult_int(android_state.height - 1, android_state.width, &last_line_offset)) {
            pthread_mutex_unlock(&android_state.mutex);
            return;  // Overflow
        }

        size_t move_size;
        if (!safe_mult_size((size_t)last_line_offset, sizeof(struct vmem_cell), &move_size)) {
            pthread_mutex_unlock(&android_state.mutex);
            return;  // Overflow
        }

        // Move all lines up by one
        memmove(android_state.screen,
                android_state.screen + android_state.width,
                move_size);

        // Clear bottom line with validated index
        for (int i = 0; i < android_state.width; i++) {
            int idx;
            if (!safe_add_int(last_line_offset, i, &idx)) {
                break;  // Overflow
            }
            android_state.screen[idx].ch = ' ';
            android_state.screen[idx].legacy_attr = android_state.current_attr;
            android_state.screen[idx].fg = android_state.fg_color;
            android_state.screen[idx].bg = android_state.bg_color;
            android_state.screen[idx].font = 0;
        }
        mark_screen_dirty();  // Scroll affects entire screen
    }
    pthread_mutex_unlock(&android_state.mutex);
}

static void android_window(int sx, int sy, int ex, int ey) {
    // For now, just update text_info
    cio_textinfo.winleft = sx;
    cio_textinfo.wintop = sy;
    cio_textinfo.winright = ex;
    cio_textinfo.winbottom = ey;
}

static void android_delline(void) {
    pthread_mutex_lock(&android_state.mutex);
    if (android_state.screen) {
        int y = android_state.cursor_y - 1;
        if (y >= 0 && y < android_state.height - 1) {
            // Calculate offsets with overflow protection
            int src_offset, dst_offset, lines_to_move, cells_to_move;

            // Validate y + 1 won't overflow before multiplication
            int y_plus_1;
            if (!safe_add_int(y, 1, &y_plus_1)) {
                pthread_mutex_unlock(&android_state.mutex);
                return;
            }

            if (!safe_mult_int(y, android_state.width, &dst_offset) ||
                !safe_mult_int(y_plus_1, android_state.width, &src_offset)) {
                pthread_mutex_unlock(&android_state.mutex);
                return;
            }

            lines_to_move = android_state.height - y - 1;

            // Calculate cells_to_move safely before passing to safe_mult_size
            if (!safe_mult_int(lines_to_move, android_state.width, &cells_to_move)) {
                pthread_mutex_unlock(&android_state.mutex);
                return;
            }

            size_t move_size;
            if (!safe_mult_size((size_t)cells_to_move, sizeof(struct vmem_cell), &move_size)) {
                pthread_mutex_unlock(&android_state.mutex);
                return;
            }

            // Move lines up
            memmove(android_state.screen + dst_offset,
                    android_state.screen + src_offset,
                    move_size);
        }

        // Clear last line with validated index
        int last_line;
        if (safe_mult_int(android_state.height - 1, android_state.width, &last_line)) {
            for (int i = 0; i < android_state.width; i++) {
                int idx;
                if (!safe_add_int(last_line, i, &idx)) break;
                android_state.screen[idx].ch = ' ';
                android_state.screen[idx].legacy_attr = android_state.current_attr;
            }
        }
        // Mark from deleted line to bottom as dirty
        if (y >= 0 && y < android_state.height) {
            mark_region_dirty(0, y, android_state.width - 1, android_state.height - 1);
        }
    }
    pthread_mutex_unlock(&android_state.mutex);
}

static void android_insline(void) {
    pthread_mutex_lock(&android_state.mutex);
    if (android_state.screen) {
        int y = android_state.cursor_y - 1;
        if (y >= 0 && y < android_state.height - 1) {
            // Calculate offsets with overflow protection
            int src_offset, dst_offset, lines_to_move, cells_to_move;

            // Validate y + 1 won't overflow before multiplication
            int y_plus_1;
            if (!safe_add_int(y, 1, &y_plus_1)) {
                pthread_mutex_unlock(&android_state.mutex);
                return;
            }

            if (!safe_mult_int(y, android_state.width, &src_offset) ||
                !safe_mult_int(y_plus_1, android_state.width, &dst_offset)) {
                pthread_mutex_unlock(&android_state.mutex);
                return;
            }

            lines_to_move = android_state.height - y - 1;

            // Calculate cells_to_move safely before passing to safe_mult_size
            if (!safe_mult_int(lines_to_move, android_state.width, &cells_to_move)) {
                pthread_mutex_unlock(&android_state.mutex);
                return;
            }

            size_t move_size;
            if (!safe_mult_size((size_t)cells_to_move, sizeof(struct vmem_cell), &move_size)) {
                pthread_mutex_unlock(&android_state.mutex);
                return;
            }

            // Move lines down
            memmove(android_state.screen + dst_offset,
                    android_state.screen + src_offset,
                    move_size);
        }

        // Clear current line with validated index
        if (y >= 0) {
            int line_offset;
            if (safe_mult_int(y, android_state.width, &line_offset)) {
                for (int i = 0; i < android_state.width; i++) {
                    int idx;
                    if (!safe_add_int(line_offset, i, &idx)) break;
                    android_state.screen[idx].ch = ' ';
                    android_state.screen[idx].legacy_attr = android_state.current_attr;
                }
            }
        }
        // Mark from inserted line to bottom as dirty
        if (y >= 0 && y < android_state.height) {
            mark_region_dirty(0, y, android_state.width - 1, android_state.height - 1);
        }
    }
    pthread_mutex_unlock(&android_state.mutex);
}

static void android_textbackground(int color) {
    pthread_mutex_lock(&android_state.mutex);
    android_state.bg_color = color & 0x07;
    android_state.current_attr = (android_state.current_attr & 0x8F) | ((color & 0x07) << 4);
    pthread_mutex_unlock(&android_state.mutex);
}

static void android_textcolor(int color) {
    pthread_mutex_lock(&android_state.mutex);
    android_state.fg_color = color & 0x0F;
    android_state.current_attr = (android_state.current_attr & 0xF0) | (color & 0x0F);
    pthread_mutex_unlock(&android_state.mutex);
}

static void android_settitle(const char *title) {
    LOGI("Set title: %s", title ? title : "(null)");
    // Could callback to Java to set activity title
}

static void android_setname(const char *name) {
    LOGI("Set name: %s", name ? name : "(null)");
}

static int android_setfont(int font, int force, int font_num) {
    // Font loading not supported in basic implementation
    return 0;
}

static int android_getfont(int font_num) {
    return 0;
}

static void android_setvideoflags(int flags) {
    // Not implemented
}

static int android_getvideoflags(void) {
    return 0;
}

static int android_setpalette(uint32_t entry, uint16_t r, uint16_t g, uint16_t b) {
    if (entry >= 16) return 0;
    pthread_mutex_lock(&android_state.mutex);
    android_state.palette[entry] = ((r & 0xFF) << 16) | ((g & 0xFF) << 8) | (b & 0xFF);
    pthread_mutex_unlock(&android_state.mutex);
    return 1;
}

static int android_attr2palette(uint8_t attr, uint32_t *fg, uint32_t *bg) {
    if (fg) *fg = attr & 0x0F;
    if (bg) *bg = (attr >> 4) & 0x07;
    return 1;
}

// Initialize ciolib for Android
int initciolib(int mode) {
    LOGI("initciolib called with mode %d", mode);

    pthread_mutex_init(&android_state.mutex, NULL);

    // Allocate initial screen buffer with safe math validation
    const int init_width = 80;
    const int init_height = 25;
    size_t alloc_size;
    int screen_size;

    if (!validate_alloc_size(init_width, init_height, sizeof(struct vmem_cell), &alloc_size) ||
        !validate_dimensions(init_width, init_height, &screen_size)) {
        LOGE("Screen buffer size overflow for %dx%d", init_width, init_height);
        return -1;
    }

    android_state.width = init_width;
    android_state.height = init_height;
    android_state.screen = calloc(1, alloc_size);

    if (!android_state.screen) {
        LOGE("Failed to allocate screen buffer");
        return -1;
    }

    // Initialize screen with spaces
    for (int i = 0; i < screen_size; i++) {
        android_state.screen[i].ch = ' ';
        android_state.screen[i].legacy_attr = 7;
        android_state.screen[i].fg = 7;
        android_state.screen[i].bg = 0;
        android_state.screen[i].font = 0;
    }

    // Initialize text_info
    cio_textinfo.winleft = 1;
    cio_textinfo.wintop = 1;
    cio_textinfo.winright = 80;
    cio_textinfo.winbottom = 25;
    cio_textinfo.attribute = 7;
    cio_textinfo.normattr = 7;
    cio_textinfo.currmode = C80;
    cio_textinfo.screenheight = 25;
    cio_textinfo.screenwidth = 80;
    cio_textinfo.curx = 1;
    cio_textinfo.cury = 1;

    // Set up cio_api function pointers
    memset(&cio_api, 0, sizeof(cio_api));
    cio_api.mode = mode;
    cio_api.mouse = 0;
    cio_api.options = 0;
    cio_api.clreol = android_clreol;
    cio_api.puttext = android_puttext;
    cio_api.vmem_puttext = android_vmem_puttext;
    cio_api.gettext = android_gettext;
    cio_api.vmem_gettext = android_vmem_gettext;
    cio_api.textattr = android_textattr;
    cio_api.kbhit = android_kbhit;
    cio_api.kbwait = android_kbwait;
    cio_api.delay = android_delay;
    cio_api.wherex = android_wherex;
    cio_api.wherey = android_wherey;
    cio_api.putch = android_putch;
    cio_api.gotoxy = android_gotoxy;
    cio_api.clrscr = android_clrscr;
    cio_api.gettextinfo = android_gettextinfo;
    cio_api.setcursortype = android_setcursortype;
    cio_api.getch = android_getch;
    cio_api.getche = android_getche;
    cio_api.beep = android_beep;
    cio_api.highvideo = android_highvideo;
    cio_api.lowvideo = android_lowvideo;
    cio_api.normvideo = android_normvideo;
    cio_api.textmode = android_textmode;
    cio_api.ungetch = android_ungetch;
    cio_api.movetext = android_movetext;
    cio_api.wscroll = android_wscroll;
    cio_api.window = android_window;
    cio_api.delline = android_delline;
    cio_api.insline = android_insline;
    cio_api.textbackground = android_textbackground;
    cio_api.textcolor = android_textcolor;
    cio_api.settitle = android_settitle;
    cio_api.setname = android_setname;
    cio_api.setfont = android_setfont;
    cio_api.getfont = android_getfont;
    cio_api.setvideoflags = android_setvideoflags;
    cio_api.getvideoflags = android_getvideoflags;
    cio_api.setpalette = android_setpalette;
    cio_api.attr2palette = android_attr2palette;

    LOGI("ciolib initialized successfully");
    return 0;
}

void suspendciolib(void) {
    LOGI("suspendciolib called");
}

// Resize terminal for Android
int android_ciolib_resize(int width, int height) {
    LOGI("Resizing terminal to %dx%d", width, height);

    // Validate dimensions against defined maximums
    if (width <= 0 || height <= 0 ||
        width > MAX_TERMINAL_WIDTH || height > MAX_TERMINAL_HEIGHT) {
        LOGE("Invalid resize dimensions: %dx%d (max: %dx%d)",
             width, height, MAX_TERMINAL_WIDTH, MAX_TERMINAL_HEIGHT);
        return -1;
    }

    // Skip resize if dimensions haven't changed - preserves screen content
    pthread_mutex_lock(&android_state.mutex);
    if (android_state.screen != NULL &&
        android_state.width == width && android_state.height == height) {
        LOGI("Screen size unchanged (%dx%d), skipping resize", width, height);
        pthread_mutex_unlock(&android_state.mutex);
        return 0;
    }
    pthread_mutex_unlock(&android_state.mutex);

    // Validate allocation size with overflow protection
    size_t alloc_size;
    if (!validate_alloc_size(width, height, sizeof(struct vmem_cell), &alloc_size)) {
        LOGE("Screen buffer size overflow for resize: %dx%d", width, height);
        return -1;
    }

    pthread_mutex_lock(&android_state.mutex);

    struct vmem_cell *new_screen = calloc(1, alloc_size);
    if (!new_screen) {
        pthread_mutex_unlock(&android_state.mutex);
        return -1;
    }

    // Initialize new screen with validated size
    int screen_size;
    if (validate_dimensions(width, height, &screen_size)) {
        for (int i = 0; i < screen_size; i++) {
            new_screen[i].ch = ' ';
            new_screen[i].legacy_attr = android_state.current_attr;
            new_screen[i].fg = android_state.fg_color;
            new_screen[i].bg = android_state.bg_color;
            new_screen[i].font = 0;
        }
    }

    // Copy old content with validated indices
    if (android_state.screen) {
        int copy_width = (width < android_state.width) ? width : android_state.width;
        int copy_height = (height < android_state.height) ? height : android_state.height;

        for (int y = 0; y < copy_height; y++) {
            for (int x = 0; x < copy_width; x++) {
                int new_idx, old_idx;
                if (validate_index(x, y, width, height, &new_idx) &&
                    validate_index(x, y, android_state.width, android_state.height, &old_idx)) {
                    new_screen[new_idx] = android_state.screen[old_idx];
                }
            }
        }
        free(android_state.screen);
    }

    android_state.screen = new_screen;
    android_state.width = width;
    android_state.height = height;

    // Adjust cursor if needed
    if (android_state.cursor_x > width) android_state.cursor_x = width;
    if (android_state.cursor_y > height) android_state.cursor_y = height;

    mark_screen_dirty();

    pthread_mutex_unlock(&android_state.mutex);

    // Update text_info
    cio_textinfo.screenwidth = width;
    cio_textinfo.screenheight = height;
    cio_textinfo.winright = width;
    cio_textinfo.winbottom = height;

    return 0;
}

// Cleanup
void android_ciolib_cleanup(void) {
    pthread_mutex_lock(&android_state.mutex);
    if (android_state.screen) {
        free(android_state.screen);
        android_state.screen = NULL;
    }
    pthread_mutex_unlock(&android_state.mutex);
    pthread_mutex_destroy(&android_state.mutex);
}

// Undefine ciolib macros to avoid conflicts with our wrapper functions
#undef gotoxy
#undef wherex
#undef wherey
#undef clrscr
#undef gettextinfo
#undef textattr
#undef vmem_puttext
#undef vmem_gettext
#undef movetext
#undef window
#undef putch
#undef setcursortype
#undef clreol
#undef delline
#undef insline
#undef textbackground
#undef textcolor
#undef highvideo
#undef lowvideo
#undef normvideo
#undef setfont
#undef getfont
#undef settitle
#undef setname
#undef beep
#undef kbhit
#undef getch
#undef getche
#undef ungetch
#undef wscroll
#undef delay
#undef puttext
#undef gettext
#undef textmode
#undef setpalette
#undef attr2palette
#undef setvideoflags
#undef getvideoflags

// ciolib_* wrapper functions that cterm.c expects
// Call android_* functions directly to avoid macro issues

void ciolib_gotoxy(int x, int y) {
    android_gotoxy(x, y);
}

int ciolib_wherex(void) {
    return android_wherex();
}

int ciolib_wherey(void) {
    return android_wherey();
}

void ciolib_clrscr(void) {
    android_clrscr();
}

void ciolib_gettextinfo(struct text_info *info) {
    android_gettextinfo(info);
}

void ciolib_textattr(int attr) {
    android_textattr(attr);
}

int ciolib_vmem_puttext(int sx, int sy, int ex, int ey, struct vmem_cell *buf) {
    return android_vmem_puttext(sx, sy, ex, ey, buf);
}

int ciolib_vmem_gettext(int sx, int sy, int ex, int ey, struct vmem_cell *buf) {
    return android_vmem_gettext(sx, sy, ex, ey, buf);
}

int ciolib_movetext(int sx, int sy, int ex, int ey, int dx, int dy) {
    return android_movetext(sx, sy, ex, ey, dx, dy);
}

void ciolib_window(int sx, int sy, int ex, int ey) {
    android_window(sx, sy, ex, ey);
}

int ciolib_putch(int ch) {
    return android_putch(ch);
}

void ciolib_setcursortype(int type) {
    android_setcursortype(type);
}

void ciolib_clreol(void) {
    android_clreol();
}

void ciolib_delline(void) {
    android_delline();
}

void ciolib_insline(void) {
    android_insline();
}

void ciolib_textbackground(int color) {
    android_textbackground(color);
}

void ciolib_textcolor(int color) {
    android_textcolor(color);
}

void ciolib_highvideo(void) {
    android_highvideo();
}

void ciolib_lowvideo(void) {
    android_lowvideo();
}

void ciolib_normvideo(void) {
    android_normvideo();
}

int ciolib_setfont(int font, int force, int font_num) {
    return android_setfont(font, force, font_num);
}

int ciolib_getfont(int font_num) {
    return android_getfont(font_num);
}

void ciolib_settitle(const char *title) {
    android_settitle(title);
}

void ciolib_setname(const char *name) {
    android_setname(name);
}

void ciolib_beep(void) {
    android_beep();
}

int ciolib_kbhit(void) {
    return android_kbhit();
}

int ciolib_getch(void) {
    return android_getch();
}

int ciolib_getche(void) {
    return android_getche();
}

int ciolib_ungetch(int ch) {
    return android_ungetch(ch);
}

void ciolib_wscroll(void) {
    android_wscroll();
}

void ciolib_delay(long ms) {
    android_delay(ms);
}

int ciolib_puttext(int sx, int sy, int ex, int ey, void *buf) {
    return android_puttext(sx, sy, ex, ey, buf);
}

int ciolib_gettext(int sx, int sy, int ex, int ey, void *buf) {
    return android_gettext(sx, sy, ex, ey, buf);
}

void ciolib_textmode(int mode) {
    android_textmode(mode);
}

int ciolib_setpalette(uint32_t entry, uint16_t r, uint16_t g, uint16_t b) {
    return android_setpalette(entry, r, g, b);
}

int ciolib_attr2palette(uint8_t attr, uint32_t *fg, uint32_t *bg) {
    return android_attr2palette(attr, fg, bg);
}

void ciolib_setvideoflags(int flags) {
    android_setvideoflags(flags);
}

int ciolib_getvideoflags(void) {
    return android_getvideoflags();
}

// Additional ciolib functions expected by cterm.c
void ciolib_setcolour(uint32_t fg, uint32_t bg) {
    pthread_mutex_lock(&android_state.mutex);
    android_state.fg_color = fg;
    android_state.bg_color = bg;
    pthread_mutex_unlock(&android_state.mutex);
}

int ciolib_attrfont(uint8_t attr) {
    // Return font number for attribute - just return 0 for default
    return 0;
}

// Get/set modepalette functions
int ciolib_get_modepalette(uint32_t *palette) {
    if (palette) {
        pthread_mutex_lock(&android_state.mutex);
        memcpy(palette, android_state.palette, 16 * sizeof(uint32_t));
        pthread_mutex_unlock(&android_state.mutex);
    }
    return 0;
}

int ciolib_set_modepalette(uint32_t *palette) {
    if (palette) {
        pthread_mutex_lock(&android_state.mutex);
        memcpy(android_state.palette, palette, 16 * sizeof(uint32_t));
        pthread_mutex_unlock(&android_state.mutex);
    }
    return 0;
}

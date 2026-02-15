/**
 * Android ciolib header
 *
 * Declares functions for JNI access to the Android ciolib implementation.
 */

#ifndef _ANDROID_CIOLIB_H_
#define _ANDROID_CIOLIB_H_

#include <stdbool.h>
#include <stdint.h>

// Forward declaration
struct vmem_cell;

#ifdef __cplusplus
extern "C" {
#endif

// Screen state accessors
int android_ciolib_get_screen_width(void);
int android_ciolib_get_screen_height(void);
int android_ciolib_get_cursor_x(void);
int android_ciolib_get_cursor_y(void);
int android_ciolib_is_cursor_visible(void);
int android_ciolib_is_dirty(void);
void android_ciolib_clear_dirty(void);
int android_ciolib_get_dirty_region(int *min_x, int *min_y, int *max_x, int *max_y);
struct vmem_cell* android_ciolib_get_screen_buffer(void);
uint32_t* android_ciolib_get_palette(void);

// Thread safety
void android_ciolib_lock(void);
void android_ciolib_unlock(void);

// Input handling
void android_ciolib_push_input(unsigned char c);
void android_ciolib_push_input_buffer(const unsigned char *buf, int len);

// Terminal management
int android_ciolib_resize(int width, int height);
void android_ciolib_cleanup(void);

#ifdef __cplusplus
}
#endif

#endif // _ANDROID_CIOLIB_H_

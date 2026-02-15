#!/usr/bin/env python3
"""
Create a colorful BBS Terminal app icon with green terminal text.
"""

from PIL import Image, ImageDraw, ImageFont
import os

def create_bbs_icon(size=512):
    """Create a colorful BBS terminal icon with green text."""

    img = Image.new('RGBA', (size, size), (10, 25, 50, 255))
    draw = ImageDraw.Draw(img)
    s = size / 512

    # Colors
    green = (0, 255, 0)
    bright_green = (85, 255, 85)
    dim_green = (0, 180, 0)
    dark_green = (0, 100, 0)

    # Extra left offset to avoid Android clipping on left edge
    left_extra = int(5 * s)

    # Outer glow - pulled in to match new frame position
    glow_inset = int(12 * s)
    for i in range(int(8 * s), 0, -1):
        alpha = int(100 - i * 10)
        glow_color = (0, 150, 255, max(0, alpha))
        draw.rounded_rectangle([glow_inset + left_extra + i, glow_inset + i, size - glow_inset - i, size - glow_inset - i], radius=int(50 * s), outline=glow_color, width=2)

    # Monitor frame - pulled in 12 pixels to avoid Android clipping
    frame_margin = int(32 * s)
    draw.rounded_rectangle([frame_margin + left_extra, frame_margin, size - frame_margin, size - frame_margin],
        radius=int(42 * s), fill=(40, 60, 90), outline=(60, 90, 130), width=int(4 * s))

    # Screen bezel
    bezel_margin = int(52 * s)
    draw.rounded_rectangle([bezel_margin + left_extra, bezel_margin, size - bezel_margin, size - bezel_margin],
        radius=int(28 * s), fill=(20, 30, 50), outline=(30, 50, 80), width=int(3 * s))

    # Screen (dark with slight green tint for CRT effect)
    screen_margin = int(67 * s)
    screen_left = screen_margin + left_extra
    screen_top = screen_margin
    screen_right = size - screen_margin
    screen_bottom = size - screen_margin
    draw.rounded_rectangle([screen_left, screen_top, screen_right, screen_bottom],
        radius=int(20 * s), fill=(0, 10, 5))

    # Subtle screen glow
    for i in range(3):
        glow_margin = screen_margin + i * 2
        draw.rounded_rectangle([glow_margin + left_extra, glow_margin, size - glow_margin, size - glow_margin],
            radius=int(20 * s), outline=(0, 40, 20, 50))

    # Scan lines
    for y in range(int(screen_top), int(screen_bottom), int(3 * s)):
        draw.line([(screen_left, y), (screen_right, y)], fill=(0, 30, 15), width=1)

    # Draw green terminal text - pixel-art style characters
    char_w = int(28 * s)  # character width
    char_h = int(38 * s)  # character height
    line_spacing = int(43 * s)
    text_left = int(62 * s) + left_extra
    text_top = int(62 * s)

    # Simple pixel font patterns (5x7 grid scaled up)
    def draw_char(x, y, pattern, color):
        """Draw a character from a pixel pattern."""
        pixel_w = int(5.2 * s)
        pixel_h = int(5.2 * s)
        for row_idx, row in enumerate(pattern):
            for col_idx, pixel in enumerate(row):
                if pixel:
                    px = x + col_idx * pixel_w
                    py = y + row_idx * pixel_h
                    draw.rectangle([px, py, px + pixel_w - 1, py + pixel_h - 1], fill=color)

    # Character patterns (5 wide x 7 tall)
    chars = {
        'T': [[1,1,1,1,1], [0,0,1,0,0], [0,0,1,0,0], [0,0,1,0,0], [0,0,1,0,0], [0,0,1,0,0], [0,0,1,0,0]],
        'E': [[1,1,1,1,1], [1,0,0,0,0], [1,0,0,0,0], [1,1,1,1,0], [1,0,0,0,0], [1,0,0,0,0], [1,1,1,1,1]],
        'R': [[1,1,1,1,0], [1,0,0,0,1], [1,0,0,0,1], [1,1,1,1,0], [1,0,1,0,0], [1,0,0,1,0], [1,0,0,0,1]],
        'M': [[1,0,0,0,1], [1,1,0,1,1], [1,0,1,0,1], [1,0,0,0,1], [1,0,0,0,1], [1,0,0,0,1], [1,0,0,0,1]],
        'I': [[1,1,1,1,1], [0,0,1,0,0], [0,0,1,0,0], [0,0,1,0,0], [0,0,1,0,0], [0,0,1,0,0], [1,1,1,1,1]],
        'N': [[1,0,0,0,1], [1,1,0,0,1], [1,0,1,0,1], [1,0,0,1,1], [1,0,0,0,1], [1,0,0,0,1], [1,0,0,0,1]],
        'A': [[0,0,1,0,0], [0,1,0,1,0], [1,0,0,0,1], [1,1,1,1,1], [1,0,0,0,1], [1,0,0,0,1], [1,0,0,0,1]],
        'O': [[0,1,1,1,0], [1,0,0,0,1], [1,0,0,0,1], [1,0,0,0,1], [1,0,0,0,1], [1,0,0,0,1], [0,1,1,1,0]],
        'B': [[1,1,1,1,0], [1,0,0,0,1], [1,0,0,0,1], [1,1,1,1,0], [1,0,0,0,1], [1,0,0,0,1], [1,1,1,1,0]],
        'S': [[0,1,1,1,1], [1,0,0,0,0], [1,0,0,0,0], [0,1,1,1,0], [0,0,0,0,1], [0,0,0,0,1], [1,1,1,1,0]],
        'C': [[0,1,1,1,0], [1,0,0,0,1], [1,0,0,0,0], [1,0,0,0,0], [1,0,0,0,0], [1,0,0,0,1], [0,1,1,1,0]],
        'D': [[1,1,1,1,0], [1,0,0,0,1], [1,0,0,0,1], [1,0,0,0,1], [1,0,0,0,1], [1,0,0,0,1], [1,1,1,1,0]],
        'W': [[1,0,0,0,1], [1,0,0,0,1], [1,0,0,0,1], [1,0,1,0,1], [1,0,1,0,1], [1,1,0,1,1], [1,0,0,0,1]],
        'L': [[1,0,0,0,0], [1,0,0,0,0], [1,0,0,0,0], [1,0,0,0,0], [1,0,0,0,0], [1,0,0,0,0], [1,1,1,1,1]],
        'U': [[1,0,0,0,1], [1,0,0,0,1], [1,0,0,0,1], [1,0,0,0,1], [1,0,0,0,1], [1,0,0,0,1], [0,1,1,1,0]],
        'P': [[1,1,1,1,0], [1,0,0,0,1], [1,0,0,0,1], [1,1,1,1,0], [1,0,0,0,0], [1,0,0,0,0], [1,0,0,0,0]],
        '>': [[1,0,0,0,0], [0,1,0,0,0], [0,0,1,0,0], [0,0,0,1,0], [0,0,1,0,0], [0,1,0,0,0], [1,0,0,0,0]],
        '_': [[0,0,0,0,0], [0,0,0,0,0], [0,0,0,0,0], [0,0,0,0,0], [0,0,0,0,0], [0,0,0,0,0], [1,1,1,1,1]],
        '-': [[0,0,0,0,0], [0,0,0,0,0], [0,0,0,0,0], [1,1,1,1,1], [0,0,0,0,0], [0,0,0,0,0], [0,0,0,0,0]],
        '=': [[0,0,0,0,0], [0,0,0,0,0], [1,1,1,1,1], [0,0,0,0,0], [1,1,1,1,1], [0,0,0,0,0], [0,0,0,0,0]],
        ' ': [[0,0,0,0,0], [0,0,0,0,0], [0,0,0,0,0], [0,0,0,0,0], [0,0,0,0,0], [0,0,0,0,0], [0,0,0,0,0]],
        '.': [[0,0,0,0,0], [0,0,0,0,0], [0,0,0,0,0], [0,0,0,0,0], [0,0,0,0,0], [0,0,1,0,0], [0,0,1,0,0]],
        ':': [[0,0,0,0,0], [0,0,1,0,0], [0,0,1,0,0], [0,0,0,0,0], [0,0,1,0,0], [0,0,1,0,0], [0,0,0,0,0]],
        '/': [[0,0,0,0,1], [0,0,0,1,0], [0,0,0,1,0], [0,0,1,0,0], [0,1,0,0,0], [0,1,0,0,0], [1,0,0,0,0]],
        '1': [[0,0,1,0,0], [0,1,1,0,0], [0,0,1,0,0], [0,0,1,0,0], [0,0,1,0,0], [0,0,1,0,0], [0,1,1,1,0]],
        '2': [[0,1,1,1,0], [1,0,0,0,1], [0,0,0,0,1], [0,0,1,1,0], [0,1,0,0,0], [1,0,0,0,0], [1,1,1,1,1]],
        '4': [[0,0,0,1,0], [0,0,1,1,0], [0,1,0,1,0], [1,0,0,1,0], [1,1,1,1,1], [0,0,0,1,0], [0,0,0,1,0]],
        '0': [[0,1,1,1,0], [1,0,0,0,1], [1,0,0,1,1], [1,0,1,0,1], [1,1,0,0,1], [1,0,0,0,1], [0,1,1,1,0]],
        '3': [[1,1,1,1,0], [0,0,0,0,1], [0,0,0,0,1], [0,1,1,1,0], [0,0,0,0,1], [0,0,0,0,1], [1,1,1,1,0]],
        '5': [[1,1,1,1,1], [1,0,0,0,0], [1,1,1,1,0], [0,0,0,0,1], [0,0,0,0,1], [1,0,0,0,1], [0,1,1,1,0]],
        '6': [[0,1,1,1,0], [1,0,0,0,0], [1,0,0,0,0], [1,1,1,1,0], [1,0,0,0,1], [1,0,0,0,1], [0,1,1,1,0]],
        '7': [[1,1,1,1,1], [0,0,0,0,1], [0,0,0,1,0], [0,0,1,0,0], [0,0,1,0,0], [0,0,1,0,0], [0,0,1,0,0]],
        '8': [[0,1,1,1,0], [1,0,0,0,1], [1,0,0,0,1], [0,1,1,1,0], [1,0,0,0,1], [1,0,0,0,1], [0,1,1,1,0]],
        '9': [[0,1,1,1,0], [1,0,0,0,1], [1,0,0,0,1], [0,1,1,1,1], [0,0,0,0,1], [0,0,0,0,1], [0,1,1,1,0]],
        'K': [[1,0,0,0,1], [1,0,0,1,0], [1,0,1,0,0], [1,1,0,0,0], [1,0,1,0,0], [1,0,0,1,0], [1,0,0,0,1]],
        'Z': [[1,1,1,1,1], [0,0,0,0,1], [0,0,0,1,0], [0,0,1,0,0], [0,1,0,0,0], [1,0,0,0,0], [1,1,1,1,1]],
        'V': [[1,0,0,0,1], [1,0,0,0,1], [1,0,0,0,1], [1,0,0,0,1], [0,1,0,1,0], [0,1,0,1,0], [0,0,1,0,0]],
    }

    def draw_text(x, y, text, color):
        """Draw a string of text."""
        cursor_x = x
        for char in text.upper():
            if char in chars:
                draw_char(cursor_x, y, chars[char], color)
            cursor_x += char_w

    # Draw terminal content - modem init sequence
    y = text_top

    draw_text(text_left, y, "TERMINATOR", bright_green)
    y += line_spacing

    draw_text(text_left, y, "BBS TERMINAL", bright_green)
    y += line_spacing

    draw_text(text_left, y, "OK", bright_green)
    y += line_spacing

    draw_text(text_left, y, "ATDT", bright_green)
    y += line_spacing

    draw_text(text_left, y, "2125554240", bright_green)
    y += line_spacing

    draw_text(text_left, y, "CONNECTED", bright_green)
    y += line_spacing

    draw_text(text_left, y, "9600 BAUD", bright_green)
    y += line_spacing

    draw_text(text_left, y, "WELCOME TO", bright_green)
    y += line_spacing

    draw_text(text_left, y, "OTV STUDIOS", bright_green)

    # LEDs at bottom
    led_y = size - int(48 * s)
    led_colors = [(255, 85, 85), (255, 255, 85), (85, 255, 85)]
    for i, led_color in enumerate(led_colors):
        led_x = int(80 * s) + left_extra + i * int(25 * s)
        draw.ellipse([led_x - int(4*s), led_y - int(4*s), led_x + int(12*s), led_y + int(12*s)], fill=(*led_color[:3], 100))
        draw.ellipse([led_x, led_y, led_x + int(8*s), led_y + int(8*s)], fill=led_color)

    return img

def create_all_icons():
    """Generate icons for all platforms."""
    output_dir = "/mnt/c/Users/omniphil/Dropbox/Coding/TERMinator/icons"
    os.makedirs(output_dir, exist_ok=True)

    # Create the base icon at high resolution
    print("Creating BBS terminal icon...")
    base_icon = create_bbs_icon(1024)

    # Save main icon
    main_path = os.path.join(output_dir, "icon_main.png")
    base_icon.save(main_path, "PNG")
    print(f"Created: {main_path}")

    # Standard sizes
    sizes = [16, 24, 32, 48, 64, 128, 256, 512, 1024]

    for size in sizes:
        icon = base_icon.resize((size, size), Image.Resampling.LANCZOS)
        path = os.path.join(output_dir, f"icon_{size}x{size}.png")
        icon.save(path, "PNG")
        print(f"Created: {path}")

    # Create ICO file for Windows
    ico_sizes = [16, 24, 32, 48, 64, 128, 256]
    ico_images = [base_icon.resize((s, s), Image.Resampling.LANCZOS) for s in ico_sizes]
    ico_path = os.path.join(output_dir, "icon.ico")
    ico_images[0].save(ico_path, format='ICO', sizes=[(s, s) for s in ico_sizes])
    print(f"Created: {ico_path}")

    print("\nAll icons created!")
    return output_dir

if __name__ == "__main__":
    create_all_icons()

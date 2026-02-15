#!/usr/bin/env python3
"""
Create Android app launcher icons from the Terminator icon.
Generates icons for all Android density buckets.
"""

from PIL import Image, ImageDraw
import os

def create_round_icon(img, size):
    """Create a circular version of the icon."""
    # Create a circular mask
    mask = Image.new('L', (size, size), 0)
    draw = ImageDraw.Draw(mask)
    draw.ellipse((0, 0, size, size), fill=255)

    # Resize the image
    resized = img.resize((size, size), Image.Resampling.LANCZOS)

    # Apply circular mask
    output = Image.new('RGBA', (size, size), (0, 0, 0, 0))
    output.paste(resized, (0, 0))
    output.putalpha(mask)

    return output

def create_android_icons(source_path, res_dir):
    """Create Android launcher icons in all density buckets."""

    # Open the source image (already cropped square from previous script)
    img = Image.open(source_path)

    # Ensure it's in RGBA mode
    if img.mode != 'RGBA':
        img = img.convert('RGBA')

    print(f"Source image size: {img.size[0]}x{img.size[1]}")

    # Android density buckets and their icon sizes
    # Standard launcher icon sizes
    densities = {
        'mipmap-mdpi': 48,
        'mipmap-hdpi': 72,
        'mipmap-xhdpi': 96,
        'mipmap-xxhdpi': 144,
        'mipmap-xxxhdpi': 192,
    }

    for density_folder, size in densities.items():
        folder_path = os.path.join(res_dir, density_folder)
        os.makedirs(folder_path, exist_ok=True)

        # Create standard square icon
        icon = img.resize((size, size), Image.Resampling.LANCZOS)
        icon_path = os.path.join(folder_path, 'ic_launcher.png')
        icon.save(icon_path, 'PNG')
        print(f"Created: {icon_path} ({size}x{size})")

        # Create round icon
        round_icon = create_round_icon(img, size)
        round_path = os.path.join(folder_path, 'ic_launcher_round.png')
        round_icon.save(round_path, 'PNG')
        print(f"Created: {round_path} ({size}x{size})")

    # Also create a foreground layer for adaptive icons (larger with padding)
    # Adaptive icon foreground should be 108dp with content in inner 72dp
    adaptive_densities = {
        'mipmap-mdpi': 108,
        'mipmap-hdpi': 162,
        'mipmap-xhdpi': 216,
        'mipmap-xxhdpi': 324,
        'mipmap-xxxhdpi': 432,
    }

    print("\nCreating adaptive icon foregrounds...")
    for density_folder, size in adaptive_densities.items():
        folder_path = os.path.join(res_dir, density_folder)

        # Calculate the inner content area (72dp of 108dp total = 66.67%)
        content_size = int(size * 72 / 108)
        padding = (size - content_size) // 2

        # Create transparent canvas
        foreground = Image.new('RGBA', (size, size), (0, 0, 0, 0))

        # Resize icon to fit in the content area
        icon_resized = img.resize((content_size, content_size), Image.Resampling.LANCZOS)

        # Paste centered on the canvas
        foreground.paste(icon_resized, (padding, padding))

        fg_path = os.path.join(folder_path, 'ic_launcher_foreground.png')
        foreground.save(fg_path, 'PNG')
        print(f"Created: {fg_path} ({size}x{size})")

    print("\nAndroid icons created successfully!")
    print("\nNote: You may also want to create an adaptive icon XML in drawable-v26/")

if __name__ == "__main__":
    # Use the main icon we created earlier
    source = "/mnt/c/Users/omniphil/Dropbox/Coding/TERMinator/icons/icon_main.png"
    res_dir = "/mnt/c/Users/omniphil/Dropbox/Coding/TERMinator/app/src/main/res"
    create_android_icons(source, res_dir)

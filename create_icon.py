#!/usr/bin/env python3
"""
Create app icons from the Terminator splash image.
Generates multiple sizes for different platforms.
"""

from PIL import Image
import os

def create_icons(source_path, output_dir):
    """Create app icons in various sizes from the source image."""

    # Open the source image
    img = Image.open(source_path)
    width, height = img.size
    print(f"Source image size: {width}x{height}")

    # Calculate crop box to make it square, centered on the skull
    # The skull is roughly centered, so we'll crop from the center
    if width > height:
        # Wider than tall - crop sides
        left = (width - height) // 2
        crop_box = (left, 0, left + height, height)
    else:
        # Taller than wide - crop top and bottom
        # Offset slightly upward to focus on the skull face
        crop_size = width
        # Center vertically but shift up a bit to focus on the skull
        top = (height - crop_size) // 2 - 20  # shift up 20 pixels
        top = max(0, top)  # ensure we don't go negative
        crop_box = (0, top, crop_size, top + crop_size)

    # Crop to square
    img_square = img.crop(crop_box)
    print(f"Cropped to square: {img_square.size[0]}x{img_square.size[1]}")

    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)

    # Standard icon sizes for various platforms
    icon_sizes = [
        16,    # Small icon (Windows, macOS menu bar)
        24,    # Windows toolbar
        32,    # Windows standard
        48,    # Windows large
        64,    # Linux
        128,   # macOS
        256,   # macOS, Windows Vista+
        512,   # macOS Retina
        1024,  # macOS Retina 2x
    ]

    png_icons = []

    for size in icon_sizes:
        # Resize using high-quality resampling
        icon = img_square.resize((size, size), Image.Resampling.LANCZOS)

        # Save as PNG
        png_path = os.path.join(output_dir, f"icon_{size}x{size}.png")
        icon.save(png_path, "PNG")
        print(f"Created: {png_path}")

        # Keep track for ICO creation
        if size <= 256:
            png_icons.append(icon)

    # Create Windows ICO file (supports sizes up to 256x256)
    ico_path = os.path.join(output_dir, "icon.ico")
    # ICO format works best with specific sizes
    ico_sizes = [16, 24, 32, 48, 64, 128, 256]
    ico_images = []
    for size in ico_sizes:
        ico_img = img_square.resize((size, size), Image.Resampling.LANCZOS)
        ico_images.append(ico_img)

    # Save ICO with multiple sizes embedded
    ico_images[0].save(ico_path, format='ICO', sizes=[(s, s) for s in ico_sizes])
    print(f"Created: {ico_path}")

    # Save the main square image at original cropped resolution
    main_icon_path = os.path.join(output_dir, "icon_main.png")
    img_square.save(main_icon_path, "PNG")
    print(f"Created: {main_icon_path}")

    print(f"\nAll icons created in: {output_dir}")
    return output_dir

if __name__ == "__main__":
    source = "/mnt/c/Users/omniphil/Dropbox/Coding/TERMinator/Terminator_splash_pic2.png"
    output = "/mnt/c/Users/omniphil/Dropbox/Coding/TERMinator/icons"
    create_icons(source, output)

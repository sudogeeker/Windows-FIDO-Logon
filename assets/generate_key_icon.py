"""Render the checked-in SVG into Windows icon and credential-provider BMP assets."""
from __future__ import annotations

import io
import struct
from pathlib import Path

import cairosvg
from PIL import Image


ROOT = Path(__file__).resolve().parent
SVG = ROOT / "key.svg"


def render(size: int) -> Image.Image:
    png = cairosvg.svg2png(
        url=str(SVG),
        output_width=size * 4,
        output_height=size * 4,
        background_color="#ffffff",
    )
    return Image.open(io.BytesIO(png)).convert("RGB").resize(
        (size, size), Image.Resampling.LANCZOS
    )


def ico_entry(image: Image.Image) -> bytes:
    size = image.width
    rgba = image.convert("RGBA")
    pixels = bytearray()
    for y in range(size - 1, -1, -1):
        for x in range(size):
            r, g, b, a = rgba.getpixel((x, y))
            pixels += bytes((b, g, r, a))
    mask_row = (size + 31) // 32 * 4
    mask = b"\x00" * (mask_row * size)
    header = struct.pack(
        "<IIIHHIIIIII", 40, size, size * 2, 1, 32, 0,
        len(pixels) + len(mask), 0, 0, 0, 0,
    )
    return header + pixels + mask


def write_ico() -> None:
    sizes = [16, 24, 32, 48, 64, 128, 256]
    images = [ico_entry(render(size)) for size in sizes]
    output = bytearray(struct.pack("<HHH", 0, 1, len(images)))
    offset = 6 + len(images) * 16
    for size, image in zip(sizes, images):
        output += struct.pack(
            "<BBBBHHII", 0 if size == 256 else size,
            0 if size == 256 else size, 0, 0, 1, 32,
            len(image), offset,
        )
        offset += len(image)
    for image in images:
        output += image
    (ROOT / "key.ico").write_bytes(output)


def write_bmp(path: Path) -> None:
    render(256).save(path, format="BMP")


def main() -> None:
    write_ico()
    write_bmp(ROOT.parent / "CredentialProvider" / "tileimage.bmp")
    write_bmp(ROOT.parent / "CredentialProviderFilter" / "tileimage.bmp")


if __name__ == "__main__":
    main()

"""Generate the Windows FIDO Logon key icon without third-party image libraries."""
from __future__ import annotations

import math
import struct
import zlib
from pathlib import Path


NAVY = (11, 31, 58, 255)
BLUE = (120, 174, 245, 255)
WHITE = (220, 233, 250, 255)
YELLOW = (255, 209, 102, 255)


def blend(dst: bytearray, index: int, color: tuple[int, int, int, int]) -> None:
    sr, sg, sb, sa = color
    if sa == 255:
        dst[index:index + 4] = bytes(color)
        return
    dr, dg, db, da = dst[index:index + 4]
    out_a = sa + (da * (255 - sa) + 127) // 255
    if out_a == 0:
        return
    dst[index:index + 4] = bytes((
        (sr * sa + dr * da * (255 - sa) // 255) // out_a,
        (sg * sa + dg * da * (255 - sa) // 255) // out_a,
        (sb * sa + db * da * (255 - sa) // 255) // out_a,
        out_a,
    ))


def canvas(size: int) -> bytearray:
    return bytearray(size * size * 4)


def paint_circle(buf: bytearray, size: int, cx: float, cy: float, radius: float, color: tuple[int, int, int, int], scale: int) -> None:
    cx *= scale
    cy *= scale
    radius *= scale
    left = max(0, int(cx - radius - 1))
    right = min(size, int(cx + radius + 2))
    top = max(0, int(cy - radius - 1))
    bottom = min(size, int(cy + radius + 2))
    r2 = radius * radius
    for y in range(top, bottom):
        for x in range(left, right):
            if (x + 0.5 - cx) ** 2 + (y + 0.5 - cy) ** 2 <= r2:
                blend(buf, (y * size + x) * 4, color)


def paint_ring(buf: bytearray, size: int, cx: float, cy: float, radius: float, width: float, fill: tuple[int, int, int, int], outline: tuple[int, int, int, int], scale: int) -> None:
    cx *= scale
    cy *= scale
    radius *= scale
    width *= scale
    left = max(0, int(cx - radius - 1))
    right = min(size, int(cx + radius + 2))
    top = max(0, int(cy - radius - 1))
    bottom = min(size, int(cy + radius + 2))
    outer = radius * radius
    inner = max(0, radius - width) ** 2
    for y in range(top, bottom):
        for x in range(left, right):
            distance = (x + 0.5 - cx) ** 2 + (y + 0.5 - cy) ** 2
            if distance <= inner:
                blend(buf, (y * size + x) * 4, fill)
            elif distance <= outer:
                blend(buf, (y * size + x) * 4, outline)


def distance_to_segment(px: float, py: float, ax: float, ay: float, bx: float, by: float) -> float:
    dx, dy = bx - ax, by - ay
    if dx == 0 and dy == 0:
        return math.hypot(px - ax, py - ay)
    t = max(0.0, min(1.0, ((px - ax) * dx + (py - ay) * dy) / (dx * dx + dy * dy)))
    return math.hypot(px - (ax + t * dx), py - (ay + t * dy))


def paint_line(buf: bytearray, size: int, a: tuple[float, float], b: tuple[float, float], width: float, color: tuple[int, int, int, int], scale: int) -> None:
    ax, ay = a[0] * scale, a[1] * scale
    bx, by = b[0] * scale, b[1] * scale
    radius = width * scale / 2
    left = max(0, int(min(ax, bx) - radius - 1))
    right = min(size, int(max(ax, bx) + radius + 2))
    top = max(0, int(min(ay, by) - radius - 1))
    bottom = min(size, int(max(ay, by) + radius + 2))
    for y in range(top, bottom):
        for x in range(left, right):
            if distance_to_segment(x + 0.5, y + 0.5, ax, ay, bx, by) <= radius:
                blend(buf, (y * size + x) * 4, color)


def paint_polygon(buf: bytearray, size: int, points: list[tuple[float, float]], fill: tuple[int, int, int, int], outline: tuple[int, int, int, int], width: float, scale: int) -> None:
    scaled = [(x * scale, y * scale) for x, y in points]
    left = max(0, int(min(x for x, _ in scaled) - 1))
    right = min(size, int(max(x for x, _ in scaled) + 2))
    top = max(0, int(min(y for _, y in scaled) - 1))
    bottom = min(size, int(max(y for _, y in scaled) + 2))
    for y in range(top, bottom):
        for x in range(left, right):
            inside = False
            j = len(scaled) - 1
            for i, (xi, yi) in enumerate(scaled):
                xj, yj = scaled[j]
                if ((yi > y) != (yj > y)) and x < (xj - xi) * (y - yi) / ((yj - yi) or 1e-9) + xi:
                    inside = not inside
                j = i
            if inside:
                blend(buf, (y * size + x) * 4, fill)
    for i, point in enumerate(scaled):
        paint_line(buf, size, point, scaled[(i + 1) % len(scaled)], width, outline, 1)


def render(target: int) -> bytes:
    scale = 4
    size = target * scale
    buf = canvas(size)
    paint_ring(buf, size, 174, 184, 105, 24, BLUE, NAVY, scale)
    paint_ring(buf, size, 174, 184, 42, 20, WHITE, NAVY, scale)
    paint_line(buf, size, (248, 258), (430, 440), 48, NAVY, scale)
    paint_line(buf, size, (302, 312), (350, 264), 26, BLUE, scale)
    paint_line(buf, size, (348, 358), (396, 310), 26, BLUE, scale)
    paint_polygon(buf, size, [(390, 106), (401, 131), (426, 142), (401, 153), (390, 178), (379, 153), (354, 142), (379, 131)], YELLOW, NAVY, 10, scale)

    # Box-filter the supersampled canvas down to the requested icon size.
    output = bytearray(target * target * 4)
    for y in range(target):
        for x in range(target):
            sums = [0, 0, 0, 0]
            for sy in range(y * scale, (y + 1) * scale):
                for sx in range(x * scale, (x + 1) * scale):
                    index = (sy * size + sx) * 4
                    for channel in range(4):
                        sums[channel] += buf[index + channel]
            index = (y * target + x) * 4
            output[index:index + 4] = bytes(value // (scale * scale) for value in sums)
    return bytes(output)


def dib_icon(rgba: bytes, size: int) -> bytes:
    """Build a conventional uncompressed 32-bit ICO image with alpha."""
    pixels = bytearray()
    for y in range(size - 1, -1, -1):
        for x in range(size):
            r, g, b, a = rgba[(y * size + x) * 4:(y * size + x + 1) * 4]
            pixels += bytes((b, g, r, a))
    mask_row = (size + 31) // 32 * 4
    mask = b"\x00" * (mask_row * size)
    header = struct.pack("<IIIHHIIIIII", 40, size, size * 2, 1, 32, 0,
        len(pixels) + len(mask), 0, 0, 0, 0)
    return header + pixels + mask


def main() -> None:
    sizes = [16, 24, 32, 48, 64, 128, 256]
    images = [dib_icon(render(size), size) for size in sizes]
    output = bytearray(struct.pack("<HHH", 0, 1, len(sizes)))
    offset = 6 + len(sizes) * 16
    for size, image in zip(sizes, images):
        output += struct.pack("<BBBBHHII", 0 if size == 256 else size, 0 if size == 256 else size, 0, 0, 1, 32, len(image), offset)
        offset += len(image)
    for image in images:
        output += image
    Path(__file__).with_name("key.ico").write_bytes(output)


if __name__ == "__main__":
    main()

"""Small, deterministic cv2 artwork for command embeds.

OpenCV is imported lazily so the bot still starts if the wheel is unavailable;
the first command that needs an icon pays the import cost. Icons are generated
from the command name and category, so every command gets a stable, unique
badge without shipping a folder of image assets.
"""

from __future__ import annotations

import functools
import hashlib
import re
from typing import Any

_SIZE = 128
_ACCENT = 0x3B82F6


def _bgr(colour: int) -> tuple[int, int, int]:
    return (colour & 0xFF, (colour >> 8) & 0xFF, (colour >> 16) & 0xFF)


def _scale(colour: int, factor: float) -> tuple[int, int, int]:
    red, green, blue = _bgr(colour)
    return (
        max(0, min(255, int(blue * factor))),
        max(0, min(255, int(green * factor))),
        max(0, min(255, int(red * factor))),
    )


def _lighten(colour: int, amount: float = 0.2) -> tuple[int, int, int]:
    blue, green, red = _bgr(colour)
    return (
        max(0, min(255, int(blue * (1.0 - amount) + 255 * amount))),
        max(0, min(255, int(green * (1.0 - amount) + 255 * amount))),
        max(0, min(255, int(red * (1.0 - amount) + 255 * amount))),
    )


def _code(command: str) -> str:
    letters = ''.join(character for character in str(command).upper() if character.isalnum())
    if len(letters) <= 3:
        return letters or '?'
    consonants = ''.join(character for character in letters if character not in 'AEIOU')
    if len(consonants) >= 3:
        return consonants[:3]
    candidate = (letters[0] + consonants[:2])[:3]
    return (candidate + ''.join(character for character in letters if character not in candidate))[:3]


def _mask(size: int, radius: int) -> Any:
    import cv2
    import numpy as np

    mask = np.zeros((size, size), dtype=np.uint8)
    inset = 2
    left, top, right, bottom = inset, inset, size - inset, size - inset
    cv2.rectangle(mask, (left + radius, top), (right - radius, bottom), 255, -1)
    cv2.rectangle(mask, (left, top + radius), (right, bottom - radius), 255, -1)
    for cx, cy in (
        (left + radius, top + radius),
        (right - radius, top + radius),
        (left + radius, bottom - radius),
        (right - radius, bottom - radius),
    ):
        cv2.circle(mask, (cx, cy), radius, 255, -1)
    return mask


def _gradient(size: int, top: tuple[int, int, int], bottom: tuple[int, int, int]) -> Any:
    import numpy as np

    rows = np.linspace(0.0, 1.0, size, dtype=np.float32)[:, None]
    top_row = np.array(top, dtype=np.float32)[None, :]
    bottom_row = np.array(bottom, dtype=np.float32)[None, :]
    strip = top_row * (1.0 - rows) + bottom_row * rows
    return np.repeat(strip[:, None, :], size, axis=1).astype(np.uint8)


def _glyph(cv2: Any, canvas: Any, category: str, colour: tuple[int, int, int]) -> None:
    """Draw one plain line symbol in the upper half of the tile."""
    cx, cy = 64, 45
    thick = 3
    if category == "network":
        points = ((40, 36), (88, 36), (64, 68))
        for start, end in ((points[0], points[1]), (points[0], points[2]), (points[1], points[2])):
            cv2.line(canvas, start, end, colour, thick, cv2.LINE_AA)
        for point in points:
            cv2.circle(canvas, point, 5, colour, -1, cv2.LINE_AA)
    elif category == "domain":
        cv2.circle(canvas, (cx, cy), 23, colour, thick, cv2.LINE_AA)
        cv2.ellipse(canvas, (cx, cy), (10, 23), 0, 0, 360, colour, thick, cv2.LINE_AA)
        cv2.line(canvas, (cx - 23, cy), (cx + 23, cy), colour, thick, cv2.LINE_AA)
    elif category == "web":
        cv2.rectangle(canvas, (36, 25), (92, 68), colour, thick, cv2.LINE_AA)
        cv2.line(canvas, (36, 37), (92, 37), colour, thick, cv2.LINE_AA)
        cv2.circle(canvas, (45, 31), 2, colour, -1, cv2.LINE_AA)
        cv2.circle(canvas, (53, 31), 2, colour, -1, cv2.LINE_AA)
        cv2.line(canvas, (48, 48), (42, 56), colour, thick, cv2.LINE_AA)
        cv2.line(canvas, (48, 64), (42, 56), colour, thick, cv2.LINE_AA)
        cv2.line(canvas, (56, 48), (62, 56), colour, thick, cv2.LINE_AA)
        cv2.line(canvas, (56, 64), (62, 56), colour, thick, cv2.LINE_AA)
    elif category == "identity":
        cv2.circle(canvas, (cx, 35), 12, colour, thick, cv2.LINE_AA)
        cv2.ellipse(canvas, (cx, 72), (26, 20), 0, 200, 340, colour, thick, cv2.LINE_AA)
    elif category == "social":
        cv2.rectangle(canvas, (34, 24), (94, 62), colour, thick, cv2.LINE_AA)
        cv2.fillPoly(canvas, [__import__('numpy').array(((50, 62), (44, 73), (62, 62)), dtype='int32')], colour, cv2.LINE_AA)
        for dot in ((48, 43), (64, 43), (80, 43)):
            cv2.circle(canvas, dot, 3, colour, -1, cv2.LINE_AA)
    elif category == "discord":
        cv2.rectangle(canvas, (34, 32), (94, 68), colour, thick, cv2.LINE_AA)
        cv2.circle(canvas, (50, 50), 4, colour, -1, cv2.LINE_AA)
        cv2.circle(canvas, (78, 50), 4, colour, -1, cv2.LINE_AA)
        cv2.line(canvas, (46, 78), (54, 68), colour, thick, cv2.LINE_AA)
        cv2.line(canvas, (82, 78), (74, 68), colour, thick, cv2.LINE_AA)
    elif category == "vuln":
        shield = ((64, 21), (91, 31), (86, 63), (64, 80), (42, 63), (37, 31))
        cv2.polylines(canvas, [__import__("numpy").array(shield, dtype="int32")], True, colour, thick, cv2.LINE_AA)
        cv2.line(canvas, (64, 34), (64, 50), colour, thick, cv2.LINE_AA)
        cv2.circle(canvas, (64, 60), 2, colour, -1, cv2.LINE_AA)
    elif category == "crypto":
        points = ((64, 20), (89, 34), (89, 60), (64, 74), (39, 60), (39, 34))
        cv2.polylines(canvas, [__import__("numpy").array(points, dtype="int32")], True, colour, thick, cv2.LINE_AA)
        cv2.line(canvas, (50, 47), (78, 47), colour, thick, cv2.LINE_AA)
        cv2.line(canvas, (64, 33), (64, 61), colour, thick, cv2.LINE_AA)
    elif category == "error":
        cv2.line(canvas, (43, 25), (85, 67), colour, thick, cv2.LINE_AA)
        cv2.line(canvas, (85, 25), (43, 67), colour, thick, cv2.LINE_AA)
    else:
        for y, knob in ((31, 48), (45, 78), (59, 56)):
            cv2.line(canvas, (38, y), (90, y), colour, thick, cv2.LINE_AA)
            cv2.circle(canvas, (knob, y), 4, colour, -1, cv2.LINE_AA)


@functools.lru_cache(maxsize=512)
def icon_png(command: str, category: str = "admin", accent: int = _ACCENT) -> bytes:
    """Return a 128x128 RGBA PNG for a command badge."""
    import cv2
    import numpy as np

    digest = hashlib.sha1(str(command).encode('utf-8')).hexdigest()
    shift = int(digest[:2], 16) % 13 - 6
    top = tuple(max(0, min(255, value + shift)) for value in (52, 38, 28))
    bottom = tuple(max(0, min(255, value + shift)) for value in (24, 18, 14))
    canvas = _gradient(_SIZE, top, bottom)
    mask = _mask(_SIZE, 26)

    accent_bgr = _bgr(accent)
    glyph_colour = _lighten(accent, 0.24)
    border = _lighten(accent, 0.1)
    _glyph(cv2, canvas, category, glyph_colour)

    # A readable consonant code under the category mark.
    letters = _code(command)
    scale = 0.46 if len(letters) >= 3 else 0.58
    thickness = 1
    (text_width, text_height), _ = cv2.getTextSize(letters, cv2.FONT_HERSHEY_DUPLEX, scale, thickness)
    cv2.putText(
        canvas,
        letters,
        (max(10, 64 - text_width // 2), 108),
        cv2.FONT_HERSHEY_DUPLEX,
        scale,
        (238, 242, 247),
        thickness,
        cv2.LINE_AA,
    )
    cv2.line(canvas, (44, 82), (84, 82), border, 2, cv2.LINE_AA)

    image = np.zeros((_SIZE, _SIZE, 4), dtype=np.uint8)
    image[:, :, :3] = canvas
    image[:, :, 3] = mask
    okay, buffer = cv2.imencode(".png", image, [cv2.IMWRITE_PNG_COMPRESSION, 9])
    if not okay:
        raise RuntimeError("could not encode command icon")
    return buffer.tobytes()


def filename(command: str) -> str:
    safe = re.sub(r"[^a-z0-9_-]+", "_", str(command).lower()).strip("_") or "command"
    return f"{safe[:32]}.png"


def icon_size(png: bytes) -> tuple[int, int]:
    import cv2
    import numpy as np

    image = cv2.imdecode(np.frombuffer(png, dtype=np.uint8), cv2.IMREAD_UNCHANGED)
    if image is None:
        raise ValueError("invalid icon image")
    return image.shape[1], image.shape[0]

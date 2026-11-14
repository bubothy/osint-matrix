"""Operator-controlled visual style for every embed.

The defaults are deliberately restrained: plain field labels, no numbered
sections, no analysis-pipeline blocks and a compact footer. Operators can
switch themes or tune individual options with the ``appearance`` command; the
result is persisted in the bot's SQLite key/value store.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any

LOG = logging.getLogger("osint.appearance")

CATEGORIES = (
    "network",
    "domain",
    "web",
    "identity",
    "social",
    "discord",
    "vuln",
    "crypto",
    "admin",
    "error",
    "ok",
)

THEMES: dict[str, dict[str, Any]] = {
    "clean": {
        "numbers": False,
        "icons": False,
        "pipeline": False,
        "checks": "text",
        "author": True,
        "compact": True,
        "accent": None,
        "colors": {},
    },
    "classic": {
        "numbers": True,
        "icons": True,
        "pipeline": True,
        "checks": "emoji",
        "author": True,
        "compact": False,
        "accent": None,
        "colors": {},
    },
    "mono": {
        "numbers": False,
        "icons": False,
        "pipeline": False,
        "checks": "text",
        "author": False,
        "compact": True,
        "accent": 0x64748B,
        "colors": {},
    },
    "neon": {
        "numbers": True,
        "icons": True,
        "pipeline": True,
        "checks": "emoji",
        "author": True,
        "compact": False,
        "accent": None,
        "colors": {
            "network": 0x38BDF8,
            "domain": 0xA78BFA,
            "web": 0x22D3EE,
            "identity": 0xFBBF24,
            "social": 0xF472B6,
            "discord": 0x818CF8,
            "vuln": 0xF87171,
            "crypto": 0x34D399,
            "admin": 0x94A3B8,
            "error": 0xDC2626,
            "ok": 0x4ADE80,
        },
    },
}


@dataclass
class Appearance:
    theme: str = "clean"
    brand: str = "OSINT Matrix"
    footer: str = ""
    accent: int | None = None
    colors: dict[str, int] = field(default_factory=dict)
    numbers: bool = False
    icons: bool = False
    pipeline: bool = False
    thumbnails: bool = True
    checks: str = "text"
    author: bool = True
    compact: bool = True


_current = Appearance()


def get() -> Appearance:
    return _current


def reset() -> None:
    global _current
    _current = Appearance()


def _bool(value: Any, *, key: str) -> bool:
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in {"on", "true", "yes", "1", "enable", "enabled"}:
        return True
    if text in {"off", "false", "no", "0", "disable", "disabled"}:
        return False
    raise ValueError(f"`{key}` needs `on` or `off`.")


def parse_colour(value: Any) -> int | None:
    text = str(value).strip().lower()
    if text in {"reset", "none", "default", "clear"}:
        return None
    text = text.removeprefix("#").removeprefix("0x")
    if len(text) != 6 or any(char not in "0123456789abcdef" for char in text):
        raise ValueError("Use a six-digit hex colour such as `#4A90E2`.")
    return int(text, 16)


def apply_theme(name: str) -> str:
    key = name.strip().lower()
    preset = THEMES.get(key)
    if preset is None:
        raise ValueError("Unknown theme. Choose `clean`, `classic`, `mono` or `neon`.")
    for field_name, value in preset.items():
        setattr(_current, field_name, dict(value) if field_name == "colors" else value)
    _current.theme = key
    return key


def set_option(key: str, raw: Any) -> str:
    """Update one setting and return a short human-readable summary."""
    key = key.strip().lower().replace("-", "_")
    if key == "brand":
        value = str(raw or "").strip()
        if not value:
            raise ValueError("Brand cannot be empty.")
        _current.brand = value[:48]
        return f"Brand set to **{_current.brand}**."
    if key == "footer":
        value = str(raw or "").strip()
        _current.footer = "" if value.lower() in {"reset", "none", "clear"} else value[:160]
        return "Footer text cleared." if not _current.footer else f"Footer set to **{_current.footer}**."
    if key == "accent":
        _current.accent = parse_colour(raw)
        _current.theme = "custom"
        return "Accent colour reset." if _current.accent is None else f"Accent set to `#{_current.accent:06X}`."
    if key in {"numbers", "icons", "pipeline", "thumbnails", "author", "compact"}:
        setattr(_current, key, _bool(raw, key=key))
        _current.theme = "custom"
        state = "on" if getattr(_current, key) else "off"
        return f"`{key}` is now **{state}**."
    if key == "checks":
        value = str(raw or "").strip().lower()
        if value not in {"text", "emoji"}:
            raise ValueError("`checks` needs `text` or `emoji`.")
        _current.checks = value
        _current.theme = "custom"
        return f"Check style set to **{value}**."
    raise ValueError(
        "Unknown option. Use `brand`, `footer`, `accent`, `numbers`, `icons`, "
        "`pipeline`, `thumbnails`, `checks`, `author` or `compact`."
    )


def set_colour(category: str, raw: Any) -> str:
    key = category.strip().lower()
    if key == "all":
        return set_option("accent", raw)
    if key not in CATEGORIES:
        raise ValueError("Unknown category. Use one of: " + ", ".join(CATEGORIES) + ".")
    colour = parse_colour(raw)
    if colour is None:
        _current.colors.pop(key, None)
        _current.theme = "custom"
        return f"Colour override for **{key}** cleared."
    _current.colors[key] = colour
    _current.theme = "custom"
    return f"**{key}** now uses `#{colour:06X}`."


def colour(category: str, fallback: int) -> int:
    if category in _current.colors:
        return _current.colors[category]
    if _current.accent is not None:
        return _current.accent
    return fallback


def snapshot() -> dict[str, Any]:
    return {
        "theme": _current.theme,
        "brand": _current.brand,
        "footer": _current.footer,
        "accent": _current.accent,
        "colors": dict(_current.colors),
        "numbers": _current.numbers,
        "icons": _current.icons,
        "pipeline": _current.pipeline,
        "thumbnails": _current.thumbnails,
        "checks": _current.checks,
        "author": _current.author,
        "compact": _current.compact,
    }


def apply_payload(payload: Any) -> None:
    reset()
    if not isinstance(payload, dict):
        return
    if isinstance(payload.get("brand"), str) and payload["brand"].strip():
        _current.brand = payload["brand"].strip()[:48]
    if isinstance(payload.get("footer"), str):
        _current.footer = payload["footer"].strip()[:160]
    try:
        if payload.get("accent") is None:
            _current.accent = None
        elif isinstance(payload.get("accent"), int):
            _current.accent = max(0, min(0xFFFFFF, payload["accent"]))
    except (TypeError, ValueError):
        pass
    colors = payload.get("colors")
    if isinstance(colors, dict):
        _current.colors = {
            str(key): int(value)
            for key, value in colors.items()
            if str(key) in CATEGORIES and isinstance(value, int) and 0 <= value <= 0xFFFFFF
        }
    for key in ("numbers", "icons", "pipeline", "thumbnails", "author", "compact"):
        if isinstance(payload.get(key), bool):
            setattr(_current, key, payload[key])
    if payload.get("checks") in {"text", "emoji"}:
        _current.checks = payload["checks"]
    if payload.get("theme") in THEMES or payload.get("theme") == "custom":
        _current.theme = payload["theme"]


async def load(store: Any) -> None:
    try:
        raw = await store.kv_get("appearance")
        if not raw:
            reset()
            return
        apply_payload(json.loads(raw))
    except (TypeError, ValueError, json.JSONDecodeError):
        LOG.warning("stored appearance is invalid; using defaults", exc_info=True)
        reset()


async def save(store: Any) -> None:
    await store.kv_set("appearance", json.dumps(snapshot(), separators=(",", ":")))

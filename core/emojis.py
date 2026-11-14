"""Per-command application emoji registry.

Discord renders custom emoji only in embed descriptions and field values, not
titles or names. This module keeps the name/id pairs returned by the application
emoji API and builds small markup fragments for those two places.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

from core.utils import clip

_EMOJI: dict[str, tuple[str, int]] = {}
_SAFE = re.compile(r"[^a-z0-9_]+")


def normalise(command: Any) -> str:
    return str(command or "").strip().lower().replace(" ", "_")


def name_for(command: Any) -> str:
    key = normalise(command)
    safe = _SAFE.sub("_", key).strip("_") or "cmd"
    digest = hashlib.sha1(key.encode("utf-8")).hexdigest()[:5]
    return f"cmd_{safe[:20]}_{digest}"[:32]


def register(command: Any, emoji: Any) -> None:
    name = getattr(emoji, "name", None)
    identifier = getattr(emoji, "id", None)
    if name and identifier:
        _EMOJI[normalise(command)] = (str(name), int(identifier))


def remember(command: Any, name: str, identifier: int) -> None:
    if name and identifier:
        _EMOJI[normalise(command)] = (name, int(identifier))


def markup(command: Any) -> str:
    item = _EMOJI.get(normalise(command))
    if item is None:
        return ""
    name, identifier = item
    return f"<:{name}:{identifier}>"


def label(command: Any) -> str:
    mark = markup(command)
    return f"{mark} `{command}`" if mark else f"`{command}`"


def header(command: Any, target: Any = None) -> str:
    """Build the compact description line used at the top of minimal embeds."""
    mark = markup(command)
    name = str(command or "command")
    line = f"{mark} **{name}**" if mark else f"**{name}**"
    if target not in (None, ""):
        safe = str(target).replace("`", "'").replace("\n", " ")
        line += f"  ·  `{clip(safe, 120)}`"
    return line


def count() -> int:
    return len(_EMOJI)

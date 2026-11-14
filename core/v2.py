"""Components V2 rendering for dossier data.

Discord does not allow ``content`` or ``embeds`` beside the
``IS_COMPONENTS_V2`` flag. The rest of the project still uses the embed object
as a compact data model, so this module converts that model into TextDisplay,
Section, Thumbnail and Container items at the transport boundary.
"""

from __future__ import annotations

import copy
import re
from typing import Any, Iterable, Sequence

import discord
from discord import ui

_TITLE_LIMIT = 3800
_FIELD_LIMIT = 3500
_EMOJI = re.compile(r"<a?:[A-Za-z0-9_]+:\d+>")


def _clip(value: Any, limit: int) -> str:
    text = "" if value is None else str(value)
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 1)].rstrip() + "…"


def _footer(page: discord.Embed) -> str:
    try:
        text = page.footer.text or ""
    except Exception:  # noqa: BLE001 - footer is optional
        text = ""
    return _clip(text, 3800)


def _header(page: discord.Embed) -> str:
    title = _clip(page.title or "", 240)
    description = _clip(page.description or "", _TITLE_LIMIT)
    author = ""
    try:
        author = _clip(page.author.name or "", 180)
    except Exception:  # noqa: BLE001 - author is optional
        author = ""
    parts: list[str] = []
    if title:
        parts.append(f"## {title}")
    if author:
        parts.append(f"-# {author}")
    if description:
        parts.append(description)
    return _clip("\n".join(parts), 3900) or "-# No data"


def _field_text(page: discord.Embed) -> list[str]:
    """Group fields into displays that stay below the 4,000 character cap."""
    chunks: list[str] = []
    current: list[str] = []
    size = 0
    for field in page.fields:
        name = _clip(field.name or "FIELD", 240)
        value = _clip(field.value or "—", 3500)
        block = f"**{name}**\n{value}"
        if current and size + len(block) + 2 > _FIELD_LIMIT:
            chunks.append("\n\n".join(current))
            current = []
            size = 0
        current.append(block)
        size += len(block) + 2
    if current:
        chunks.append("\n\n".join(current))
    return chunks


def _attachment_ok(url: str, files: Sequence[discord.File]) -> bool:
    if not url.startswith("attachment://"):
        return True
    filename = url.removeprefix("attachment://")
    return any(getattr(item, "filename", "") == filename for item in files)


def _thumbnail(page: discord.Embed, files: Sequence[discord.File]) -> Any | None:
    try:
        url = page.thumbnail.url
    except Exception:  # noqa: BLE001 - thumbnail is optional
        return None
    if not url or not _attachment_ok(url, files):
        return None
    try:
        return ui.Thumbnail(url, description="Command badge")
    except Exception:  # noqa: BLE001 - ignore malformed image URLs
        return None


def _gallery(page: discord.Embed, files: Sequence[discord.File]) -> Any | None:
    try:
        url = page.image.url
    except Exception:  # noqa: BLE001 - image is optional
        return None
    if not url or not _attachment_ok(url, files):
        return None
    try:
        return ui.MediaGallery(
            discord.MediaGalleryItem(url, description="Source image")
        )
    except Exception:  # noqa: BLE001 - ignore malformed image URLs
        return None


def page_items(
    page: discord.Embed,
    *,
    files: Sequence[discord.File] = (),
) -> list[ui.Item[Any]]:
    """Build the top-level content for one dossier, without action buttons."""
    header = _header(page)
    chunks = _field_text(page)
    thumb = _thumbnail(page, files)
    accent = None
    try:
        accent = discord.Colour(page.colour.value)
    except Exception:  # noqa: BLE001 - colour is optional
        pass

    children: list[Any] = []
    if thumb is not None:
        children.append(ui.Section(ui.TextDisplay(header), accessory=thumb))
    else:
        children.append(ui.TextDisplay(header))
    if chunks:
        children.append(ui.Separator(spacing=discord.SeparatorSpacing.small))
        for chunk in chunks:
            children.append(ui.TextDisplay(chunk))
    gallery = _gallery(page, files)
    if gallery is not None:
        children.append(gallery)
    footer = _footer(page)
    if footer:
        children.append(ui.TextDisplay(f"-# {footer}"))

    container = ui.Container(*children, accent_colour=accent)
    return [container]


def build_layout(
    page: discord.Embed,
    *,
    files: Sequence[discord.File] = (),
    timeout: float | None = None,
) -> ui.LayoutView:
    """Return one ready-to-send Components V2 message."""
    view = ui.LayoutView(timeout=timeout)
    for item in page_items(page, files=files):
        view.add_item(item)
    return view


def text_layout(text: str, *, accent: int | None = None) -> ui.LayoutView:
    """A small V2 layout used for confirmations and status messages."""
    view = ui.LayoutView(timeout=None)
    container = ui.Container(
        ui.TextDisplay(_clip(text, 3800)),
        accent_colour=discord.Colour(accent) if accent is not None else None,
    )
    view.add_item(container)
    return view


def paginate_embed(
    page: discord.Embed,
    *,
    max_chars: int = 6200,
    max_fields: int = 10,
) -> list[discord.Embed]:
    """Split a very large dossier into readable V2 pages."""
    fields = list(page.fields)
    if len(fields) <= max_fields and sum(len(item.value or "") for item in fields) <= max_chars:
        return [page]
    pages: list[discord.Embed] = []
    current = copy.deepcopy(page)
    current.clear_fields()
    size = 0
    count = 0
    for field in fields:
        width = len(field.value or "") + len(field.name or "")
        if count and (count >= max_fields or size + width > max_chars):
            pages.append(current)
            current = copy.deepcopy(page)
            current.clear_fields()
            size = 0
            count = 0
        current.add_field(name=field.name, value=field.value, inline=field.inline)
        size += width
        count += 1
    if count or not pages:
        pages.append(current)
    total = len(pages)
    for index, item in enumerate(pages, 1):
        try:
            footer = item.footer.text or ""
        except Exception:  # noqa: BLE001
            footer = ""
        marker = f"part {index}/{total}"
        item.set_footer(text=(footer + "  •  " + marker) if footer else marker)
    return pages


def clean_markup(text: str) -> str:
    """Remove custom emoji markup when a plain-text fallback is needed."""
    return _EMOJI.sub("", text)


def chunk_lines(lines: Iterable[str], limit: int = 3500) -> list[str]:
    """Split markdown lines into TextDisplay-sized blocks."""
    output: list[str] = []
    current: list[str] = []
    size = 0
    for line in lines:
        line = str(line)
        if current and size + len(line) + 1 > limit:
            output.append("\n".join(current))
            current = []
            size = 0
        current.append(line)
        size += len(line) + 1
    if current:
        output.append("\n".join(current))
    return output or [""]

"""Components V2 rendering for report data.

Discord does not allow ``content`` or ``embeds`` beside the
``IS_COMPONENTS_V2`` flag. The rest of the project still uses the embed object
as a compact data model, so this module converts that model into TextDisplay,
Section, Thumbnail and Container items at the transport boundary.

Two things matter for readability here:

* short inline fields are paired onto one line, the way Discord lays out
  inline embed fields, so a report stops being a tall single column;
* long results are split across pages that each carry their own section
  range (``sections 13–24 of 31``) so a reader always knows where they are.
"""

from __future__ import annotations

import copy
import logging
import re
from typing import Any, Iterable, Sequence

import discord
from discord import ui

_TITLE_LIMIT = 3800
_FIELD_LIMIT = 3500
_PAGE_CHARS = 3400
_PAGE_FIELDS = 16
_INLINE_VALUE_MAX = 44
_INLINE_LINE_MAX = 86
_INLINE_JOIN = "   ·   "
_TEXT_BUDGET = 3900
_EMOJI = re.compile(r"<a?:[A-Za-z0-9_]+:\d+>")

LOG = logging.getLogger("osint.v2")


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


def _timestamp(page: discord.Embed) -> str:
    """Render the embed timestamp the way a reader expects in Discord."""
    value = getattr(page, "timestamp", None)
    if value is None:
        return ""
    try:
        epoch = int(value.timestamp())
    except (AttributeError, ValueError, OSError):
        return ""
    return f"-# <t:{epoch}:f>  ·  <t:{epoch}:R>"


def _header(page: discord.Embed) -> str:
    title = _clip(page.title or "", 240)
    description = _clip(page.description or "", _TITLE_LIMIT)
    author = ""
    try:
        author = _clip(page.author.name or "", 180)
    except Exception:  # noqa: BLE001 - author is optional
        author = ""
    link = str(getattr(page, "url", "") or "")
    parts: list[str] = []
    if title:
        parts.append(f"## [{title}]({link})" if link.startswith("http") else f"## {title}")
    if author:
        parts.append(f"-# {author}")
    stamp = _timestamp(page)
    if stamp:
        parts.append(stamp)
    if description:
        parts.append(description)
    return _clip("\n".join(parts), 3900) or "-# No data"


def _inline_ready(field: Any) -> bool:
    """A field is safe to pair when it is short and single-line."""
    name = str(field.name or "")
    value = str(field.value or "")
    if not getattr(field, "inline", False):
        return False
    if not value or len(value) > _INLINE_VALUE_MAX:
        return False
    if "\n" in value or value.startswith("```") or value.startswith("**"):
        return False
    return len(name) + len(value) <= _INLINE_LINE_MAX


def _field_blocks(page: discord.Embed) -> list[str]:
    """Render fields as readable blocks, pairing short inline fields."""
    blocks: list[str] = []
    pair: list[str] = []
    for field in page.fields:
        name = _clip(field.name or "FIELD", 240)
        value = _clip(field.value or "—", 3500)
        if _inline_ready(field):
            pair.append(f"**{name}**  {value}")
            if len(pair) >= 2:
                blocks.append(_INLINE_JOIN.join(pair))
                pair = []
            continue
        if pair:
            blocks.append(_INLINE_JOIN.join(pair))
            pair = []
        blocks.append(f"**{name}**\n{value}")
    if pair:
        blocks.append(_INLINE_JOIN.join(pair))
    return blocks


def _field_text(page: discord.Embed) -> list[str]:
    """Group field blocks into displays that stay below the 4,000 char cap."""
    chunks: list[str] = []
    current: list[str] = []
    size = 0
    for block in _field_blocks(page):
        if current and size + len(block) + 2 > _FIELD_LIMIT:
            chunks.append("\n\n".join(current))
            current = []
            size = 0
        current.append(block)
        size += len(block) + 2
    if current:
        chunks.append("\n\n".join(current))
    return chunks


def _fit_text(
    header: str, chunks: list[str], footer: str, *, label: str = ""
) -> tuple[str, list[str], str]:
    """Keep the whole message under Discord's 4,000-character V2 text budget.

    Pagination is responsible for keeping report fields small. If something is
    still too large, shrink the description (metadata) before field data, and
    only then trim the tail of the last field block. Any field trim is logged so
    a too-long report never silently loses content.
    """
    keep = [chunk for chunk in chunks if chunk]
    footer = footer or ""

    def total() -> int:
        return len(header) + len(footer) + sum(len(chunk) for chunk in keep)

    if total() <= _TEXT_BUDGET:
        return header, keep, footer

    # The header is title/description/timestamp, not report data. Trim it first
    # so a verbose summary cannot force field content off the page.
    non_header = len(footer) + sum(len(chunk) for chunk in keep)
    if len(header) > 200 and non_header + 200 < _TEXT_BUDGET:
        header = header[: max(200, _TEXT_BUDGET - non_header - 1)].rstrip() + "…"

    trimmed = 0
    while keep and total() > _TEXT_BUDGET:
        excess = total() - _TEXT_BUDGET
        last = keep[-1]
        if len(last) <= excess + 40:
            trimmed += len(last)
            keep.pop()
            continue
        keep[-1] = last[: max(0, len(last) - excess - 1)].rstrip() + "…"
        trimmed += excess + 1
        break
    if total() > _TEXT_BUDGET:
        room = max(200, _TEXT_BUDGET - len(footer) - 2)
        header = header[:room].rstrip() + "…"
    if trimmed:
        LOG.warning(
            "Components V2 text budget trimmed %d characters of field data%s; "
            "the report should have paginated earlier",
            trimmed,
            f" for {label!r}" if label else "",
        )
    return header, keep, footer


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


def _author_icon(page: discord.Embed, files: Sequence[discord.File]) -> Any | None:
    """Fall back to the author avatar when a report has no artwork of its own."""
    try:
        url = page.author.icon_url
    except Exception:  # noqa: BLE001 - author icon is optional
        return None
    if not url or not str(url).startswith(("http://", "https://", "attachment://")):
        return None
    if not _attachment_ok(str(url), files):
        return None
    try:
        return ui.Thumbnail(str(url), description="Report author")
    except Exception:  # noqa: BLE001 - ignore malformed icon URLs
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
    """Build the top-level content for one report, without action buttons."""
    header = _header(page)
    chunks = _field_text(page)
    footer_text = f"-# {_footer(page)}" if _footer(page) else ""
    header, chunks, footer_text = _fit_text(
        header, chunks, footer_text, label=str(page.title or "")
    )
    thumb = _thumbnail(page, files) or _author_icon(page, files)
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
        children.append(ui.Separator(spacing=discord.SeparatorSpacing.large))
        for index, chunk in enumerate(chunks):
            if index:
                children.append(ui.Separator(spacing=discord.SeparatorSpacing.small))
            children.append(ui.TextDisplay(chunk))
    gallery = _gallery(page, files)
    if gallery is not None:
        children.append(ui.Separator(spacing=discord.SeparatorSpacing.small))
        children.append(gallery)
    if footer_text:
        children.append(ui.Separator(spacing=discord.SeparatorSpacing.small))
        children.append(ui.TextDisplay(footer_text))

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
        ui.TextDisplay(_clip(text, _TEXT_BUDGET - 100)),
        accent_colour=discord.Colour(accent) if accent is not None else None,
    )
    view.add_item(container)
    return view


def _page_ranges(count: int, total: int) -> str:
    return f"sections {count:02d}/{total:02d}"


def _field_cost(field: Any) -> int:
    """Approximate the rendered cost of one field block."""
    return len(str(field.name or "")) + len(str(field.value or "")) + 14


def _split_field_value(value: str, limit: int) -> list[str]:
    """Split one oversized value on line/word boundaries without losing text."""
    limit = max(120, limit)
    parts: list[str] = []
    rest = value
    while len(rest) > limit:
        cut = rest.rfind("\n", 0, limit)
        if cut < limit // 3:
            cut = rest.rfind(" ", 0, limit)
        if cut < limit // 3:
            cut = limit
        parts.append(rest[:cut].rstrip())
        rest = rest[cut:].lstrip("\n")
    parts.append(rest)
    return parts


def _page_budget(page: discord.Embed, max_chars: int) -> int:
    """Characters available for fields after this page's header and footer."""
    header = len(_header(page))
    footer = len(_footer(page)) + 12
    reserve = 180  # page marker, section span and separators
    room = _TEXT_BUDGET - header - footer - reserve
    return max(600, min(max_chars, room))


def paginate_embed(
    page: discord.Embed,
    *,
    max_chars: int = _PAGE_CHARS,
    max_fields: int = _PAGE_FIELDS,
) -> list[discord.Embed]:
    """Split a report so every page fits the V2 text budget without data loss.

    The old version counted only field text, so a long description or one huge
    field could still overflow the 4,000-character budget and be trimmed by
    :func:`_fit_text`. This version budgets the header and footer too, and
    splits an oversized field across continuation fields instead of cutting it.
    """
    fields = list(page.fields)
    if not fields:
        return [page]

    budget = _page_budget(page, max_chars)
    total_chars = sum(_field_cost(field) for field in fields)
    if (
        len(fields) <= max_fields
        and total_chars + 60 <= budget
        and len(_header(page)) + total_chars + len(_footer(page)) <= _TEXT_BUDGET
    ):
        return [page]

    # A unit is one field block. Oversized values become several units that
    # share the original field's section number and carry a (i/n) suffix.
    units: list[tuple[str, str, bool, int]] = []
    for index, field in enumerate(fields):
        name = str(field.name or "FIELD")
        value = str(field.value or "")
        if len(name) + len(value) + 14 <= budget:
            units.append((name, value, bool(field.inline), index))
            continue
        parts = _split_field_value(value, max(160, budget - len(name) - 30))
        for part_index, part in enumerate(parts, 1):
            label = f"{name} ({part_index}/{len(parts)})"
            units.append((label, part, False, index))

    groups: list[list[tuple[str, str, bool, int]]] = []
    current: list[tuple[str, str, bool, int]] = []
    size = 0
    for unit in units:
        cost = len(unit[0]) + len(unit[1]) + 14
        if current and (len(current) >= max_fields or size + cost > budget):
            groups.append(current)
            current = []
            size = 0
        current.append(unit)
        size += cost
    if current or not groups:
        groups.append(current)

    total_pages = len(groups)
    total_fields = len(fields)
    base_title = _clip(page.title or "", 180)
    base_description = page.description or ""
    pages: list[discord.Embed] = []
    for number, group in enumerate(groups, 1):
        item = copy.deepcopy(page)
        item.clear_fields()
        for name, value, inline, _ in group:
            item.add_field(name=name, value=value, inline=inline)

        start = min(unit[3] for unit in group) + 1
        stop = max(unit[3] for unit in group) + 1
        item.title = _clip(f"{base_title}  ·  {number}/{total_pages}", 250) if base_title else None
        section = (
            f"section {start:02d} of {total_fields:02d}"
            if start == stop
            else f"sections {start:02d}–{stop:02d} of {total_fields:02d}"
        )
        span = f"-# part {number}/{total_pages}  ·  {section}"
        if number > 1 and number < total_pages:
            span += "  ·  continued"
        if number == total_pages and total_pages > 1:
            span += "  ·  end"
        item.description = _clip(
            f"{base_description}\n{span}" if base_description else span, 4000
        )
        try:
            footer = item.footer.text or ""
        except Exception:  # noqa: BLE001
            footer = ""
        marker = f"page {number}/{total_pages}"
        item.set_footer(text=_clip((footer + "  •  " + marker) if footer else marker, 2048))
        pages.append(item)
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

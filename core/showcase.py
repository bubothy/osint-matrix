"""A bespoke Components V2 card for anonymity verdicts.

The shared renderer turns an embed-shaped report into a generic container. This
module is deliberately different: it is a purpose-built card for one answer —
how anonymous is this address — with a verdict headline, an exposure meter and
a signal row that can be read in a second. Only the source buttons are
interactive, so nothing here needs a callback or a timeout.

The card degrades cleanly: callers still build the usual embed, and
``core.embeds.respond`` falls back to it when a client rejects the layout.
"""

from __future__ import annotations

import time
from typing import Any, Iterable

import discord
from discord import ui

# One accent per verdict, so the container edge carries the severity before a
# single word is read.
ACCENTS: dict[str, int] = {
    "tor": 0xEF4444,
    "vpn": 0xF97316,
    "proxy": 0xF59E0B,
    "abuser": 0xDC2626,
    "datacenter": 0x3B82F6,
    "mobile": 0x0EA5E9,
    "clean": 0x22C55E,
    "private": 0x64748B,
}

SOURCE_URLS: dict[str, str] = {
    "ipquery.io": "https://ipquery.io/",
    "ip-api.com": "https://ip-api.com/",
    "ipapi.is": "https://ipapi.is/",
}

SIGNALS: tuple[tuple[str, str], ...] = (
    ("vpn", "VPN"),
    ("proxy", "PROXY"),
    ("tor", "TOR"),
    ("datacenter", "HOSTING"),
    ("abuser", "ABUSE"),
    ("mobile", "MOBILE"),
)


def _accent(verdict: Any) -> int:
    if not getattr(verdict, "public", True):
        return ACCENTS["private"]
    for key in ("tor", "vpn", "proxy", "abuser", "datacenter", "mobile"):
        if getattr(verdict, key, False):
            return ACCENTS[key]
    return ACCENTS["clean"]


def _meter(score: int, width: int = 18) -> str:
    score = max(0, min(100, int(score)))
    filled = round(score / 100 * width)
    return "█" * filled + "░" * (width - filled)


def _signal_row(verdict: Any) -> str:
    cells = []
    for key, label in SIGNALS:
        mark = "●" if getattr(verdict, key, False) else "○"
        cells.append(f"`{mark} {label}`")
    return "  ".join(cells)


def _network_block(verdict: Any) -> str:
    lines = ["**▸ NETWORK**"]
    rows = (
        ("Provider", getattr(verdict, "provider", None)),
        ("ASN", getattr(verdict, "asn", None)),
        ("Organisation", getattr(verdict, "org", None)),
        ("Country", getattr(verdict, "country", None)),
    )
    for label, value in rows:
        if value:
            lines.append(f"**{label}**  {value}")
    if len(lines) == 1:
        lines.append("**Provider**  not attributed by the responding sources")
    return "\n".join(lines)


def _sources(sources: Iterable[str]) -> list[ui.Button]:
    buttons: list[ui.Button] = []
    for name in sources:
        url = SOURCE_URLS.get(str(name).strip().lower())
        if not url:
            continue
        buttons.append(
            ui.Button(label=f"{name} ↗", style=discord.ButtonStyle.link, url=url)
        )
        if len(buttons) >= 3:
            break
    return buttons


def verdict_layout(
    *,
    address: str,
    verdict: Any,
    avatar_url: str | None = None,
    sources: Iterable[str] | None = None,
    note: str | None = None,
) -> ui.LayoutView:
    """Build the anonymity card for one merged verdict."""
    label = str(getattr(verdict, "label", "unclassified")).upper()
    confidence = int(getattr(verdict, "confidence", 0) or 0)
    score = int(getattr(verdict, "score", 0) or 0)
    glyph = "◈"
    if getattr(verdict, "tor", False):
        glyph = "⚠"
    elif not getattr(verdict, "public", True):
        glyph = "⌂"

    identity = " · ".join(
        str(value)
        for value in (
            getattr(verdict, "org", None),
            getattr(verdict, "asn", None),
            getattr(verdict, "country", None),
        )
        if value
    )
    hero = f"# {glyph} {label}\n### `{address}`"
    if identity:
        hero += f"\n-# {identity}"

    exposure = (
        "**EXPOSURE**\n"
        f"`{_meter(score)}`  **{score}**/100\n"
        f"**{confidence}%** confidence  ·  "
        f"{len(list(getattr(verdict, 'sources', []) or []))} independent sources"
    )

    children: list[Any] = []
    headline = ui.TextDisplay(hero)
    if avatar_url:
        try:
            children.append(
                ui.Section(headline, accessory=ui.Thumbnail(avatar_url, description="0SWALD"))
            )
        except Exception:  # noqa: BLE001 - an odd avatar URL must not lose the card
            children.append(headline)
    else:
        children.append(headline)

    children.append(ui.Separator(spacing=discord.SeparatorSpacing.large))
    children.append(ui.TextDisplay(exposure))
    children.append(ui.Separator(spacing=discord.SeparatorSpacing.small))
    children.append(ui.TextDisplay(f"**▸ SIGNALS**\n{_signal_row(verdict)}"))
    children.append(ui.Separator(spacing=discord.SeparatorSpacing.small))
    children.append(ui.TextDisplay(_network_block(verdict)))

    notes = [str(item) for item in (getattr(verdict, "notes", None) or [])][:2]
    if note:
        notes.insert(0, note)
    if notes:
        children.append(ui.Separator(spacing=discord.SeparatorSpacing.small))
        children.append(ui.TextDisplay("\n".join(f"> {item}" for item in notes)))

    buttons = _sources(sources if sources is not None else getattr(verdict, "sources", []) or [])
    if buttons:
        children.append(ui.ActionRow(*buttons))

    stamp = int(time.time())
    children.append(
        ui.TextDisplay(
            f"-# 0SWALD · public data only · <t:{stamp}:R> · "
            "a clean verdict means nothing was flagged, not that the address is trustworthy"
        )
    )

    view = ui.LayoutView(timeout=None)
    view.add_item(ui.Container(*children, accent_colour=discord.Colour(_accent(verdict))))
    return view

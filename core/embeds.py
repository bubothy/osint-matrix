"""Embed engine.

Every response in this bot is built through :class:`Intel` so that command
output is structurally identical: a category banner, a target title, labelled
data panes in aligned code blocks, an analysis pipeline, a risk index and a
footer carrying the source, latency and requester.
"""

from __future__ import annotations

import re
import time
from collections.abc import Iterable, Mapping, Sequence
from typing import Any
from urllib.parse import quote

import discord

from core import appearance
from core.utils import bar, clip, is_ip, kv_block, normalize_host, risk_label, unique, utcnow

# category -> (colour, glyph, label)
PALETTE: dict[str, tuple[int, str, str]] = {
    "network": (0x3B82F6, "◈", "NETWORK INTELLIGENCE"),
    "domain": (0x8B5CF6, "◇", "DOMAIN INTELLIGENCE"),
    "web": (0x06B6D4, "△", "WEB INTELLIGENCE"),
    "identity": (0xF59E0B, "◉", "IDENTITY INTELLIGENCE"),
    "social": (0xEC4899, "◐", "SOCIAL INTELLIGENCE"),
    "discord": (0x5865F2, "✦", "DISCORD INTELLIGENCE"),
    "vuln": (0xEF4444, "⚠", "VULNERABILITY INTELLIGENCE"),
    "crypto": (0x10B981, "⬡", "CRYPTO INTELLIGENCE"),
    "admin": (0x64748B, "⌘", "SYSTEM CONTROL"),
    "error": (0x991B1B, "✕", "FAULT"),
    "ok": (0x22C55E, "✓", "ACKNOWLEDGED"),
}

SEVERITY_COLOURS = {
    "CRITICAL": 0xB91C1C,
    "HIGH": 0xEA580C,
    "MEDIUM": 0xD97706,
    "LOW": 0x65A30D,
    "NONE": 0x475569,
}

RISK_COLOURS = {
    "CRITICAL": 0xB91C1C,
    "HIGH": 0xEA580C,
    "ELEVATED": 0xD97706,
    "GUARDED": 0x65A30D,
    "MINIMAL": 0x22C55E,
}

RISK_GLYPHS = {
    "CRITICAL": "🔴",
    "HIGH": "🟠",
    "ELEVATED": "🟡",
    "GUARDED": "🟢",
    "MINIMAL": "⚪",
}

CHECK_GLYPHS = {True: "✅", False: "❌", None: "➖"}


def _bot_icon(ctx: Any) -> str | None:
    try:
        return ctx.bot.user.display_avatar.url
    except Exception:  # noqa: BLE001 - cosmetic only
        return None


def _user_icon(ctx: Any) -> str | None:
    try:
        return ctx.author.display_avatar.url
    except Exception:  # noqa: BLE001 - cosmetic only
        return None


_FIELD_PREFIX = re.compile(r"^\d{2}\s{1,2}(?:▸\s+)?")


def _field_label(index: int, name: Any) -> str:
    """Render a field name using the current appearance settings."""
    cfg = appearance.get()
    label = _FIELD_PREFIX.sub("", str(name).strip())
    if label.startswith("▸ "):
        label = label[2:]
    prefix = ""
    if cfg.numbers:
        prefix += f"{index:02d}  "
    if cfg.icons:
        prefix += "▸ "
    return clip(prefix + label, 250)


def _normalise_fields(embed: discord.Embed) -> None:
    """Apply the current label style to fields added outside the builder."""
    for index, field in enumerate(list(embed.fields), 1):
        embed.set_field_at(
            index - 1,
            name=_field_label(index, field.name),
            value=field.value,
            inline=field.inline,
        )


class Intel:
    """Fluent builder for a detailed intelligence embed."""

    def __init__(
        self,
        *,
        category: str,
        command: str,
        ctx: Any = None,
        target: Any = None,
        summary: str | None = None,
        color: int | None = None,
    ) -> None:
        self.category = category
        self.command = command
        self.ctx = ctx
        self.target = str(target) if target is not None else None
        self.sources: list[str] = []
        self.started = time.perf_counter()
        self.cached = False
        self._section = 0

        cfg = appearance.get()
        colour, glyph, label = PALETTE.get(category, PALETTE["admin"])
        self.glyph = glyph if cfg.icons else ""
        self.label = label
        self.embed = discord.Embed(color=color or appearance.colour(category, colour), timestamp=utcnow())
        if cfg.author:
            author = cfg.brand
            if cfg.icons:
                author = f"{glyph}  {author}"
            self.embed.set_author(name=clip(f"{author}  ·  {label.title()}", 256), icon_url=_bot_icon(ctx))
        title = command
        if self.target:
            title = f"{command}  ·  {clip(self.target, 140)}"
        self.embed.title = clip(title, 250)
        if summary:
            self.embed.description = clip(summary, 4000)

    # ── content ──────────────────────────────────────────────────────────

    def field(self, name: str, value: Any, *, inline: bool = False) -> "Intel":
        if len(self.embed.fields) >= 24:
            return self
        self._section += 1
        rendered = clip(value, 1024) if value not in (None, "") else "—"
        self.embed.add_field(name=_field_label(self._section, name), value=rendered, inline=inline)
        return self

    def kv(self, name: str, pairs: Mapping[str, Any] | Sequence[tuple[str, Any]], *, inline: bool = True, lang: str = "ini") -> "Intel":
        return self.field(f"▸ {name}", kv_block(pairs, lang=lang), inline=inline)

    def text(self, name: str, value: Any, *, inline: bool = False) -> "Intel":
        return self.field(f"▸ {name}", value, inline=inline)

    def code(self, name: str, value: Any, *, lang: str = "json", inline: bool = False) -> "Intel":
        body = clip(str(value), 980)
        return self.field(f"▸ {name}", f"```{lang}\n{body}\n```", inline=inline)

    def steps(self, items: Iterable[Any], *, name: str = "ANALYSIS PIPELINE", inline: bool = False) -> "Intel":
        if name == "ANALYSIS PIPELINE" and not appearance.get().pipeline:
            return self
        lines = [f"`{index:02d}` {clip(str(item), 190)}" for index, item in enumerate(items, 1)]
        return self.field(f"▸ {name}", "\n".join(lines) or "—", inline=inline)

    def checks(self, name: str, results: Sequence[tuple[bool | None, str, str]], *, inline: bool = False) -> "Intel":
        rows = list(results)
        if not rows:
            return self.field(f"▸ {name}", "`no checks recorded`", inline=inline)
        passed = sum(1 for state, _, _ in rows if state is True)
        failed = sum(1 for state, _, _ in rows if state is False)
        unknown = len(rows) - passed - failed
        summary = f"**{passed} passed**"
        if failed:
            summary += f"  ·  **{failed} failed**"
        if unknown:
            summary += f"  ·  **{unknown} unknown**"
        marks = CHECK_GLYPHS if appearance.get().checks == "emoji" else {True: "PASS", False: "FAIL", None: "N/A"}
        lines = []
        for state, label, detail in rows:
            suffix = f"  ·  {clip(detail, 150)}" if detail else ""
            lines.append(f"`{marks.get(state, 'N/A')}` **{clip(label, 60)}**{suffix}")
        return self.field(f"▸ {name}", summary + "\n" + "\n".join(lines), inline=inline)

    def risk(self, score: float, *, name: str = "RISK INDEX", verdict: str | None = None, inline: bool = False) -> "Intel":
        score = max(0, min(100, int(round(float(score)))))
        label = verdict or risk_label(score)
        tone = RISK_COLOURS.get(label.upper())
        if tone is not None:
            self.embed.color = tone
        glyph = RISK_GLYPHS.get(label.upper(), "") if appearance.get().icons else ""
        tail = f"{glyph}  **{label}**" if glyph else f"**{label}**"
        return self.field(
            f"▸ {name}",
            f"`{bar(score, width=16)}`  **{score}/100**  ·  {tail}",
            inline=inline,
        )

    def quote(self, text: str) -> "Intel":
        self.embed.description = clip((self.embed.description or "") + f"\n\n> {text}", 4000)
        return self

    def thumbnail(self, url: str | None) -> "Intel":
        if url:
            try:
                self.embed.set_thumbnail(url=url)
            except Exception:  # noqa: BLE001 - cosmetic only
                pass
        return self

    def image(self, url: str | None) -> "Intel":
        if url:
            try:
                self.embed.set_image(url=url)
            except Exception:  # noqa: BLE001 - cosmetic only
                pass
        return self

    def source(self, *names: str) -> "Intel":
        for name in names:
            if name and name not in self.sources:
                self.sources.append(name)
        return self

    # ── finalise ─────────────────────────────────────────────────────────

    def _auto_thumbnail(self) -> None:
        """Give web/domain dossiers a favicon when a command did not set one."""
        if not appearance.get().thumbnails:
            return
        if self.embed.thumbnail.url or not self.target or self.category not in {"web", "domain"}:
            return
        host = normalize_host(self.target)
        if not host or is_ip(host) or "." not in host:
            return
        try:
            self.embed.set_thumbnail(url=f"https://www.google.com/s2/favicons?domain={quote(host)}&sz=128")
        except Exception:  # noqa: BLE001 - cosmetic only
            pass

    def finish(self, ctx: Any = None, *, source: str | None = None, elapsed_ms: float | None = None, extra: str | None = None) -> discord.Embed:
        cfg = appearance.get()
        ctx = ctx if ctx is not None else self.ctx
        if source:
            self.source(source)
        self._auto_thumbnail()
        elapsed = elapsed_ms if elapsed_ms is not None else (time.perf_counter() - self.started) * 1000
        parts: list[str] = []
        if ctx is not None:
            try:
                parts.append(str(ctx.author))
            except Exception:  # noqa: BLE001 - cosmetic only
                pass
        if not cfg.compact:
            if self.command:
                parts.append(self.command)
            if self.embed.fields:
                parts.append(f"{len(self.embed.fields)} sections")
        if self.sources:
            prefix = "via " if cfg.compact else "source "
            parts.append(prefix + " · ".join(str(item) for item in unique(self.sources)[:3]))
        parts.append(f"{elapsed:.0f} ms")
        if self.cached:
            parts.append("cache hit")
        if extra:
            parts.append(extra)
        if cfg.footer:
            parts.append(cfg.footer)
        elif not cfg.compact:
            parts.append(cfg.brand)
        if not parts:
            parts.append(cfg.brand)
        self.embed.set_footer(text=clip("  •  ".join(parts), 2048), icon_url=_user_icon(ctx) if ctx else None)
        return self.embed

    async def send(self, ctx: Any = None, *, view: discord.ui.View | None = None, files: list[discord.File] | None = None, source: str | None = None) -> discord.Message | None:
        ctx = ctx if ctx is not None else self.ctx
        embed = self.finish(ctx, source=source)
        return await respond(ctx, embed, view=view, files=files)


async def respond(
    ctx: Any,
    embed: discord.Embed,
    *,
    view: discord.ui.View | None = None,
    files: list[discord.File] | None = None,
) -> discord.Message | None:
    """Reply correctly whether the invocation came from chat or an interaction."""
    _normalise_fields(embed)
    kwargs: dict[str, Any] = {"embed": embed, "allowed_mentions": discord.AllowedMentions.none()}
    if view is not None:
        kwargs["view"] = view
    if files:
        kwargs["files"] = files
    try:
        if getattr(ctx, "interaction", None) is not None:
            return await ctx.send(**kwargs)
        return await ctx.reply(mention_author=False, **kwargs)
    except discord.HTTPException:
        try:
            return await ctx.send(**kwargs)
        except discord.HTTPException:
            return None


def notice(
    title: str,
    description: str = "",
    *,
    category: str = "admin",
    fields: Sequence[tuple[str, Any, bool]] = (),
    footer: str | None = None,
) -> discord.Embed:
    cfg = appearance.get()
    colour, glyph, label = PALETTE.get(category, PALETTE["admin"])
    title_prefix = f"{glyph}  " if cfg.icons else ""
    embed = discord.Embed(
        title=clip(f"{title_prefix}{title}", 250),
        description=clip(description, 4000) or None,
        color=appearance.colour(category, colour),
        timestamp=utcnow(),
    )
    if cfg.author:
        author = f"{glyph}  {cfg.brand}" if cfg.icons else cfg.brand
        embed.set_author(name=clip(author, 256))
    for index, (name, value, inline) in enumerate(fields, 1):
        embed.add_field(name=_field_label(index, name), value=clip(value, 1024) or "—", inline=inline)
    if footer:
        embed.set_footer(text=clip(footer, 2048))
    elif cfg.footer:
        embed.set_footer(text=clip(cfg.footer, 2048))
    elif not cfg.compact:
        embed.set_footer(text=clip(cfg.brand, 2048))
    return embed


def error_embed(
    title: str,
    description: str,
    *,
    hint: str | None = None,
    usage: str | None = None,
    command: str | None = None,
) -> discord.Embed:
    embed = notice(title, description, category="error")
    if usage:
        embed.add_field(name="▸ USAGE", value=f"```ini\n{clip(usage, 900)}\n```", inline=False)
    if hint:
        embed.add_field(name="▸ RESOLUTION", value=clip(hint, 1024), inline=False)
    if command:
        embed.set_footer(text=clip(f"command: {command}  •  {appearance.get().brand}", 2048))
    return embed


def denied_embed(user_id: int) -> discord.Embed:
    return notice(
        "ACCESS DENIED",
        "This instance is private. Your Discord ID is not on the operator's allow-list, "
        "so no data was fetched and no command was executed.",
        category="error",
        fields=[
            ("YOUR ID", f"`{user_id}`", False),
            ("HOW TO REQUEST ACCESS", "Send your ID to the operator of this bot. They can authorise you with the `approve` command.", False),
        ],
        footer=f"{appearance.get().brand}  •  private deployment",
    )


def maintenance_embed() -> discord.Embed:
    return notice(
        "MAINTENANCE MODE",
        "The operator has locked this instance to owners only. Try again once maintenance ends.",
        category="error",
        footer=f"{appearance.get().brand}  •  maintenance",
    )


def paginate(
    base: discord.Embed,
    sections: Sequence[tuple[str, str]],
    *,
    per_page: int = 6,
    title_suffix: str = " · PART {page}/{total}",
) -> list[discord.Embed]:
    """Split long field lists across several copies of an embed."""
    pages: list[discord.Embed] = []
    groups = [sections[i : i + per_page] for i in range(0, len(sections), per_page)] or [()]
    for page_index, group in enumerate(groups, 1):
        embed = base.copy()
        start = len(embed.fields) + 1
        for offset, (name, value) in enumerate(group, start):
            embed.add_field(name=_field_label(offset, name), value=clip(value, 1024) or "—", inline=False)
        suffix = title_suffix.format(page=page_index, total=len(groups))
        embed.title = clip(f"{base.title or ''}{suffix}", 250)
        pages.append(embed)
    return pages

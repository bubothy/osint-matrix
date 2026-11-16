"""Embed engine.

Every intelligence response is built through :class:`Intel`. The default view is
minimal: one custom-emoji command line, data fields in working code blocks and
tables, and a cv2 badge thumbnail. The classic view keeps the author, title,
summary, checks, risk bar and source/latency footer.
"""

from __future__ import annotations

import copy
import io
import logging
import re
import time
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

import discord

from core import appearance, emojis
from core.utils import bar, clip, is_ip, kv_block, normalize_host, risk_label, unique, utcnow

LOG = logging.getLogger("osint.embeds")

# Home pages only. Dynamic deep links are added by the commands that know the
# record exists, so a reference cannot become a 404 just because an account or
# identifier was not found.
SOURCE_LINKS: dict[str, str] = {
    "ipwho.is": "https://ipwho.is/",
    "cloudflare doh": "https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/",
    "google doh": "https://developers.google.com/speed/public-dns/docs/doh",
    "quad9": "https://www.quad9.net/",
    "adguard": "https://adguard-dns.io/",
    "ripestat": "https://stat.ripe.net/",
    "rdap": "https://rdap.org/",
    "crt.sh": "https://crt.sh/",
    "cert spotter": "https://sslmate.com/certspotter/",
    "nvd": "https://nvd.nist.gov/",
    "cisa kev": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
    "epss": "https://www.first.org/epss/",
    "cwe": "https://cwe.mitre.org/",
    "urlscan.io": "https://urlscan.io/",
    "virustotal": "https://www.virustotal.com/",
    "shodan": "https://www.shodan.io/",
    "abuseipdb": "https://www.abuseipdb.com/",
    "abuse.ch": "https://abuse.ch/",
    "github": "https://github.com/",
    "gitlab": "https://gitlab.com/",
    "reddit": "https://www.reddit.com/",
    "hacker news": "https://news.ycombinator.com/",
    "npm": "https://www.npmjs.com/",
    "pypi": "https://pypi.org/",
    "steam": "https://steamcommunity.com/",
    "mojang": "https://www.minecraft.net/",
    "roblox": "https://www.roblox.com/",
    "keybase": "https://keybase.io/",
    "mastodon": "https://joinmastodon.org/",
    "bluesky": "https://bsky.app/",
    "bitcoin": "https://blockstream.info/",
    "ethereum": "https://etherscan.io/",
    "solana": "https://explorer.solana.com/",
    "gravatar": "https://gravatar.com/",
    "hibp": "https://haveibeenpwned.com/",
    "direct http": "https://developer.mozilla.org/docs/Web/HTTP",
    "direct tcp": "https://www.rfc-editor.org/rfc/rfc9293",
    "direct tls handshake": "https://www.rfc-editor.org/rfc/rfc8446",
    "local computation": "https://docs.python.org/3/library/ipaddress.html",
    "libphonenumber offline metadata": "https://github.com/google/libphonenumber",
}

CATEGORY_PIVOTS: dict[str, tuple[str, ...]] = {
    "network": ("rdns", "netblock", "geo", "tls"),
    "domain": ("dns", "whois", "certificates", "propagation"),
    "web": ("headers", "robots", "securitytxt", "tls"),
    "identity": ("email", "username", "hash", "msisdn"),
    "social": ("username", "github", "reddit", "profile"),
    "discord": ("snowflake", "invite", "guild", "bot"),
    "vuln": ("cve", "cwe", "epss", "kev"),
    "crypto": ("btc", "eth", "sol", "tx"),
    "craft": ("uncaesar", "iocs", "phishlure"),
}

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
    "craft": (0x64748B, "⌬", "PAYLOAD CRAFT"),
    "toolkit": (0x475569, "⌁", "LOCAL TOOLKIT"),
    "generator": (0x64748B, "✧", "SYNTHETIC DATA"),
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
_FENCE = re.compile(r"^```([A-Za-z0-9_+-]*)\n(.*)\n```$", re.DOTALL)
_LANGUAGE = re.compile(r"[^A-Za-z0-9_+-]")


def _field_value(value: Any, limit: int = 1024) -> str:
    """Clip a field value without destroying intentional code fences."""
    if value is None or value == "":
        return "—"
    text = str(value)
    match = _FENCE.match(text)
    if match is None:
        return clip(text, limit)
    language, body = match.groups()
    opening = f"```{language}\n"
    if len(text) <= limit:
        return text
    available = max(0, limit - len(opening) - 4)
    return f"{opening}{body[:available].rstrip()}\n```"


def _language(value: str) -> str:
    return _LANGUAGE.sub("", value or "")[:20]


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
        colour, glyph, label = PALETTE.get(category, PALETTE['admin'])
        self.glyph = glyph if cfg.icons else ''
        self.label = label
        self.embed = discord.Embed(color=color or appearance.colour(category, colour), timestamp=utcnow())
        if cfg.minimal:
            self.embed.description = emojis.header(command, self.target)
        else:
            if cfg.author:
                author = cfg.brand
                if cfg.icons:
                    author = f'{glyph}  {author}'
                self.embed.set_author(name=clip(f'{author}  ·  {label.title()}', 256), icon_url=_bot_icon(ctx))
            title = command
            if self.target:
                title = f'{command}  ·  {clip(self.target, 140)}'
            self.embed.title = clip(title, 250)
            if summary and cfg.summary:
                self.embed.description = clip(summary, 4000)

    # ── content ──────────────────────────────────────────────────────────

    def field(self, name: str, value: Any, *, inline: bool = False) -> "Intel":
        if len(self.embed.fields) >= 60:
            LOG.warning(
                "report %r dropped field %r: 60-field model limit reached",
                self.command,
                name,
            )
            return self
        self._section += 1
        if _FENCE.match(str(value)):
            inline = False
        # V2 renders through paginated TextDisplays, so a report field is not
        # bound by Discord's 1,024-character classic-embed value limit here.
        self.embed.add_field(name=_field_label(self._section, name), value=_field_value(value, 3500), inline=inline)
        return self

    def metrics(self, items: Sequence[tuple[str, Any]], *, inline: bool = True) -> "Intel":
        """Add a compact row of labelled values, rendered inline."""
        for label, value in list(items)[:6]:
            self.field(label, f"`{clip(value, 120)}`", inline=inline)
        return self

    def kv(self, name: str, pairs: Mapping[str, Any] | Sequence[tuple[str, Any]], *, inline: bool = True, lang: str = "ini") -> "Intel":
        return self.field(f"▸ {name}", kv_block(pairs, lang=lang), inline=inline)

    def text(self, name: str, value: Any, *, inline: bool = False) -> "Intel":
        return self.field(f"▸ {name}", value, inline=inline)

    def code(self, name: str, value: Any, *, lang: str = "json", inline: bool = False) -> "Intel":
        body = clip(str(value), 980)
        return self.field(f"▸ {name}", f"```{_language(lang)}\n{body}\n```", inline=inline)

    def table(
        self,
        name: str,
        headers: Sequence[str],
        rows: Sequence[Sequence[Any]],
        *,
        inline: bool = False,
        lang: str = "ini",
        max_column: int = 32,
    ) -> "Intel":
        """Render a fixed-width table inside a working Discord code block."""
        def cell(item: Any) -> str:
            if item is None:
                return "—"
            return str(item).replace("\r", " ").replace("\n", " ")

        head = [cell(item) for item in headers]
        body = [[cell(item) for item in row] for row in rows]
        widths: list[int] = []
        for index, title in enumerate(head):
            width = len(title)
            for row in body:
                if index < len(row):
                    width = max(width, len(row[index]))
            widths.append(min(width, max_column))

        def fit(value: str, width: int) -> str:
            return clip(value, width).ljust(width)

        lines = ["  ".join(fit(title, widths[index]) for index, title in enumerate(head))]
        if body:
            lines.append("  ".join("─" * width for width in widths))
        for row in body:
            lines.append(
                "  ".join(fit(row[index] if index < len(row) else "", widths[index]) for index in range(len(head)))
            )
        return self.code(name, "\n".join(lines), lang=lang, inline=inline)

    def steps(self, items: Iterable[Any], *, name: str = 'TRACE', inline: bool = False) -> 'Intel':
        if appearance.get().minimal:
            return self
        if name == 'TRACE' and not appearance.get().pipeline:
            return self
        lines = [f"`{index:02d}` {clip(str(item), 190)}" for index, item in enumerate(items, 1)]
        return self.field(f"▸ {name}", "\n".join(lines) or "—", inline=inline)

    def checks(self, name: str, results: Sequence[tuple[bool | None, str, str]], *, inline: bool = False) -> 'Intel':
        rows = list(results)
        if appearance.get().minimal:
            failures = [
                f"**{clip(label, 60)}**" + (f" — {clip(detail, 120)}" if detail else "")
                for state, label, detail in rows
                if state is False
            ]
            return self.field('WARNINGS', clip('  ·  '.join(failures), 1000), inline=False) if failures else self
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
        if appearance.get().minimal:
            return self
        glyph = RISK_GLYPHS.get(label.upper(), '') if appearance.get().icons else ''
        tail = f"{glyph}  **{label}**" if glyph else f"**{label}**"
        return self.field(
            f"▸ {name}",
            f"`{bar(score, width=16)}`  **{score}/100**  ·  {tail}",
            inline=inline,
        )

    def quote(self, text: str) -> 'Intel':
        if appearance.get().minimal:
            return self
        self.embed.description = clip((self.embed.description or '') + f'\n\n> {text}', 4000)
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

    def _add_findability(self) -> None:
        """Add useful references and next steps without creating dead links."""
        if getattr(self, "_findability_added", False):
            return
        self._findability_added = True
        if len(self.embed.fields) >= 22:
            return

        links: list[str] = []
        seen: set[str] = set()
        for source in self.sources:
            url = SOURCE_LINKS.get(source.strip().lower())
            if url and url not in seen:
                links.append(f"[{source}]({url})")
                seen.add(url)
        if not links:
            fallback = {
                "network": ("ipwho.is", "https://ipwho.is/"),
                "domain": ("crt.sh", "https://crt.sh/"),
                "web": ("HTTP reference", "https://developer.mozilla.org/docs/Web/HTTP"),
                "identity": ("Have I Been Pwned", "https://haveibeenpwned.com/"),
                "vuln": ("NVD", "https://nvd.nist.gov/"),
                "crypto": ("Blockstream", "https://blockstream.info/"),
                "craft": ("Python reference", "https://docs.python.org/3/library/codecs.html"),
    "toolkit": ("Python reference", "https://docs.python.org/3/"),
                "generator": ("Python secrets", "https://docs.python.org/3/library/secrets.html"),
                "discord": ("Discord API", "https://discord.com/developers/docs/intro"),
            }.get(self.category)
            if fallback:
                links.append(f"[{fallback[0]}]({fallback[1]})")
        if links:
            self.embed.add_field(name="▸ REFERENCES", value="  ·  ".join(links[:8]), inline=False)

        if self.target and len(self.embed.fields) < 22:
            commands = CATEGORY_PIVOTS.get(self.category, ())
            if commands:
                target = clip(str(self.target).replace("`", "'"), 80)
                pivots = "  ·  ".join(f"`.{name} {target}`" for name in commands[:4])
                self.embed.add_field(name="▸ NEXT LOOKUPS", value=pivots, inline=False)

    def _add_provenance(self, elapsed: float) -> None:
        """Close a long result with a block naming the data it came from."""
        if len(self.embed.fields) < 4 or len(self.embed.fields) >= 23:
            return
        rows: list[tuple[str, Any]] = [
            ("category", self.category),
            ("command", self.command),
            ("sections", f"{len(self.embed.fields) + 1:02d}"),
        ]
        if self.target:
            rows.append(("target", clip(self.target, 46)))
        rows.append(("sources", ", ".join(str(item) for item in unique(self.sources)[:3]) or "internal"))
        rows.append(("runtime", f"{elapsed:.0f} ms"))
        if self.cached:
            rows.append(("cache", "hit"))
        self.field("PROVENANCE", kv_block(rows), inline=False)

    def _add_index(self) -> None:
        """Insert a numbered section index so long results stay navigable."""
        if len(self.embed.fields) < 9 or len(self.embed.fields) >= 24:
            return
        labels = []
        for index, field in enumerate(list(self.embed.fields), 1):
            label = _FIELD_PREFIX.sub("", str(field.name or "")).strip()[:20]
            labels.append(f"{index:02d} {label}")
        lines = ["  ·  ".join(labels[i : i + 3]) for i in range(0, len(labels), 3)]
        self.embed.insert_field_at(
            0,
            name="▸ INDEX",
            value=clip("\n".join(lines), 1000),
            inline=False,
        )

    def finish(self, ctx: Any = None, *, source: str | None = None, elapsed_ms: float | None = None, extra: str | None = None) -> discord.Embed:
        cfg = appearance.get()
        ctx = ctx if ctx is not None else self.ctx
        if source:
            self.source(source)
        self._add_findability()
        elapsed = elapsed_ms if elapsed_ms is not None else (time.perf_counter() - self.started) * 1000
        self._add_provenance(elapsed)
        self._add_index()
        if cfg.minimal:
            parts = [self.command] if self.command else []
            if self.sources:
                parts.append("source " + " · ".join(str(item) for item in unique(self.sources)[:3]))
            parts.append(f"{elapsed:.0f} ms")
            parts.append(utcnow().strftime("%Y-%m-%d %H:%M UTC"))
            if cfg.footer:
                parts.append(cfg.footer)
            if parts:
                self.embed.set_footer(text=clip("  •  ".join(parts), 2048))
            return self.embed
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
        cfg = appearance.get()
        original_files = list(files or [])
        icon_added = False
        if cfg.minimal and cfg.thumbnails and not getattr(embed.thumbnail, 'url', None):
            try:
                from core import visuals

                accent = appearance.colour(self.category, PALETTE.get(self.category, PALETTE['admin'])[0])
                png = visuals.icon_png(self.command, self.category, accent)
                name = visuals.filename(self.command)
                embed.set_thumbnail(url=f'attachment://{name}')
                files = original_files + [discord.File(io.BytesIO(png), filename=name)]
                icon_added = True
            except Exception:  # noqa: BLE001 - artwork is decorative
                files = original_files
        message = await respond(ctx, embed, view=view, files=files)
        if message is None and icon_added:
            # Some channels reject file uploads; the data embed is still useful.
            embed.set_thumbnail(url=None)
            return await respond(ctx, embed, view=view, files=original_files)
        return message


def _exc_detail(exc: BaseException) -> str:
    """One log line for a rejected Discord request."""
    parts: list[str] = [exc.__class__.__name__]
    status = getattr(exc, "status", None)
    code = getattr(exc, "code", None)
    text = getattr(exc, "text", None)
    if status:
        parts.append(f"HTTP {status}")
    if code:
        parts.append(f"code {code}")
    detail = str(text or exc or "").strip()
    if detail:
        parts.append(clip(detail, 300))
    return " · ".join(parts)


def _layout_chars(layout: Any) -> int:
    """Count the TextDisplay characters in a V2 layout for diagnostics."""
    try:
        components = layout.to_components()
    except Exception:  # noqa: BLE001 - diagnostics only
        return -1
    total = 0
    stack: list[Any] = list(components)
    while stack:
        node = stack.pop()
        if not isinstance(node, dict):
            continue
        content = node.get("content")
        if isinstance(content, str):
            total += len(content)
        for key in ("components", "accessory"):
            child = node.get(key)
            if isinstance(child, list):
                stack.extend(child)
            elif isinstance(child, dict):
                stack.append(child)
    return total


def _origin(ctx: Any) -> str:
    """Identify the command and destination in a rejection log line."""
    interaction = getattr(ctx, "interaction", None)
    command = getattr(getattr(ctx, "command", None), "qualified_name", None)
    if not command:
        command = getattr(getattr(interaction, "command", None), "qualified_name", None)
    user = getattr(ctx, "author", None) or getattr(interaction, "user", None)
    guild = getattr(ctx, "guild", None) or getattr(interaction, "guild", None)
    channel = getattr(ctx, "channel", None) or getattr(interaction, "channel", None)
    return (
        f"command={command or 'unknown'} user={getattr(user, 'id', '?')} "
        f"guild={getattr(guild, 'id', 'dm')} channel={getattr(channel, 'id', '?')}"
    )


def _summary_text(embed: discord.Embed, limit: int = 1900) -> str:
    """A compact text-only form of an embed, used when embeds are rejected."""
    parts: list[str] = []
    if embed.title:
        parts.append(f"**{embed.title}**")
    if embed.description:
        parts.append(embed.description)
    for field in embed.fields:
        parts.append(f"**{field.name}**\n{field.value}")
    text = "\n\n".join(part for part in parts if part).strip()
    text = text or "The report could not be rendered."
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


async def _deliver(ctx: Any, **kwargs: Any) -> Any:
    """Send a payload through the prefix or interaction path."""
    kwargs.setdefault("allowed_mentions", discord.AllowedMentions.none())
    if not kwargs.get("files"):
        kwargs.pop("files", None)
    if getattr(ctx, "interaction", None) is not None:
        return await ctx.send(**kwargs)
    return await ctx.reply(mention_author=False, **kwargs)


async def respond(
    ctx: Any,
    embed: discord.Embed,
    *,
    view: discord.ui.LayoutView | None = None,
    files: list[discord.File] | None = None,
) -> discord.Message | None:
    """Send a Components V2 message, with logged plain fallbacks.

    Discord rejects a whole V2 message when one limit is exceeded. Previously
    that rejection was swallowed, so a broken ``.help`` simply looked like the
    bot ignoring the command. Every rejection is now logged with the command,
    user, guild and layout size, then retried as a plain embed, then as text.
    """
    _normalise_fields(embed)
    from core import v2
    from core.ui import Paginator

    files = list(files or [])
    if view is not None:
        layout = view
        if files and hasattr(layout, "files"):
            layout.files = files  # type: ignore[attr-defined]
            if hasattr(layout, "_build"):
                layout._build()  # type: ignore[attr-defined]
    else:
        pages = v2.paginate_embed(embed)
        if len(pages) > 1:
            author_id = getattr(getattr(ctx, "author", None), "id", None)
            layout = Paginator(pages, author_id=author_id, files=files)
        else:
            layout = v2.build_layout(embed, files=files)

    kwargs: dict[str, Any] = {
        "view": layout,
        "allowed_mentions": discord.AllowedMentions.none(),
    }
    if files:
        kwargs["files"] = files
    origin = _origin(ctx)
    label = clip(str(embed.title or ""), 100)
    try:
        if getattr(ctx, "interaction", None) is not None:
            message = await ctx.send(**kwargs)
        else:
            message = await ctx.reply(mention_author=False, **kwargs)
        if message is not None and hasattr(layout, "message"):
            layout.message = message  # type: ignore[attr-defined]
        return message
    except (discord.HTTPException, ValueError) as exc:
        LOG.warning(
            "Components V2 send rejected for %s (title=%r, %d text chars): %s — "
            "retrying as a plain embed",
            origin,
            label,
            _layout_chars(layout),
            _exc_detail(exc),
            exc_info=True,
        )

    # Fallback 1: the same data as a normal embed, which has no V2 text budget.
    try:
        message = await _deliver(ctx, embed=embed, files=files)
        LOG.warning("plain-embed fallback delivered for %s (title=%r)", origin, label)
        return message
    except (discord.HTTPException, ValueError) as exc:
        LOG.error(
            "plain-embed fallback rejected for %s (title=%r): %s",
            origin,
            label,
            _exc_detail(exc),
            exc_info=True,
        )

    # Fallback 2: some channels reject attachments as well as embeds.
    if files:
        try:
            message = await _deliver(ctx, embed=embed)
            LOG.warning(
                "plain-embed fallback without attachments delivered for %s (title=%r)",
                origin,
                label,
            )
            return message
        except (discord.HTTPException, ValueError) as exc:
            LOG.error(
                "attachment-free plain-embed fallback rejected for %s: %s",
                origin,
                _exc_detail(exc),
                exc_info=True,
            )

    # Fallback 3: plain text always fits and is still visible to the user.
    try:
        message = await _deliver(ctx, content=_summary_text(embed))
        LOG.warning("plain-text fallback delivered for %s (title=%r)", origin, label)
        return message
    except (discord.HTTPException, ValueError):
        LOG.exception("all Components V2 fallbacks failed for %s (title=%r)", origin, label)
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
    if cfg.author and not cfg.minimal:
        author = f'{glyph}  {cfg.brand}' if cfg.icons else cfg.brand
        embed.set_author(name=clip(author, 256))
    for index, (name, value, inline) in enumerate(fields, 1):
        if _FENCE.match(str(value)):
            inline = False
        embed.add_field(name=_field_label(index, name), value=_field_value(value, 1024), inline=inline)
    if footer:
        embed.set_footer(text=clip(footer, 2048))
    elif cfg.footer:
        embed.set_footer(text=clip(cfg.footer, 2048))
    elif not cfg.compact and not cfg.minimal:
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


def denied_embed(user_id: int, note: str | None = None) -> discord.Embed:
    return notice(
        "ACCESS DENIED",
        note
        or (
            "This instance is private. Your Discord ID is not on the operator's allow-list, "
            "so no data was fetched and no command was executed."
        ),
        category="error",
        fields=[
            ("YOUR ID", f"`{user_id}`", False),
            ("HOW TO REQUEST ACCESS", "Send your ID to the operator of this bot. They can authorise you with the `approve` command.", False),
        ],
        footer=f"{appearance.get().brand}  •  private deployment",
    )


def maintenance_embed(note: str | None = None) -> discord.Embed:
    return notice(
        "MAINTENANCE MODE",
        note
        or "The operator has locked this instance to owners only. Try again once maintenance ends.",
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
        embed = copy.deepcopy(base)
        start = len(embed.fields) + 1
        for offset, (name, value) in enumerate(group, start):
            embed.add_field(name=_field_label(offset, name), value=_field_value(value, 1024), inline=False)
        suffix = title_suffix.format(page=page_index, total=len(groups))
        embed.title = clip(f"{base.title or ''}{suffix}", 250)
        pages.append(embed)
    return pages

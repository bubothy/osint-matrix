"""Operator controls for the embed style.

Everything here writes to the same small appearance record used by the embed
builder, so changes apply to the next response without restarting the bot.
"""

from __future__ import annotations

from typing import Any

from discord.ext import commands

from core import appearance as style
from core.checks import owner_only
from core.embeds import Intel, notice, respond
from core.errors import UsageError
from core.utils import ack

ON_OFF = {True: "on", False: "off"}


class AppearanceCog(commands.Cog, name="Appearance"):
    """Themes and layout controls for the operator."""

    def __init__(self, bot: Any) -> None:
        self.bot = bot

    # ── display ───────────────────────────────────────────────────────────

    def _summary_fields(self) -> list[tuple[str, str, bool]]:
        cfg = style.get()
        accent = f"`#{cfg.accent:06X}`" if cfg.accent is not None else "category default"
        colors = ", ".join(f"{key}=#{value:06X}" for key, value in cfg.colors.items()) or "none"
        return [
            ("THEME", f"`{cfg.theme}`", True),
            ("BRAND", cfg.brand, True),
            ("ACCENT", accent, True),
            ("MINIMAL", ON_OFF[cfg.minimal], True),
            ("NUMBERS", ON_OFF[cfg.numbers], True),
            ("ICONS", ON_OFF[cfg.icons], True),
            ("TRACE", ON_OFF[cfg.pipeline], True),
            ("THUMBNAILS", ON_OFF[cfg.thumbnails], True),
            ("CHECKS", cfg.checks, True),
            ("SUMMARY", ON_OFF[cfg.summary], True),
            ("AUTHOR LINE", ON_OFF[cfg.author], True),
            ("FOOTER", cfg.footer or "—", True),
            ("COLOR OVERRIDES", colors, False),
        ]

    async def _show(self, ctx: commands.Context) -> None:
        cfg = style.get()
        fields = self._summary_fields()
        fields.append(
            (
                "CONTROLS",
                "`.appearance theme clean|classic|mono|neon`\n"
                "`.appearance set <option> <value>`\n"
                "`.appearance set minimal on|off`\n"
                "`.appearance color <category|all> <#hex|reset>`\n"
                "`.appearance preview`\n"
                "`.appearance reset`",
                False,
            )
        )
        await respond(
            ctx,
            notice(
                "APPEARANCE",
                f"Current look: **{cfg.theme}**. Changes apply to new messages immediately.",
                category="admin",
                fields=fields,
            ),
        )

    # ── commands ──────────────────────────────────────────────────────────

    @commands.group(
        name="appearance",
        aliases=["appear", "look"],
        invoke_without_command=True,
        usage="[theme|set|color|preview|reset]",
    )
    @owner_only()
    async def appearance_group(self, ctx: commands.Context) -> None:
        """Show or change the bot's embed style."""
        await ack(ctx)
        await self._show(ctx)

    @appearance_group.command(name="theme", usage="<clean|classic|mono|neon>")
    @owner_only()
    async def theme(self, ctx: commands.Context, name: str = None) -> None:
        """Apply a preset theme."""
        await ack(ctx)
        if not name:
            raise UsageError("Choose `clean`, `classic`, `mono` or `neon`.")
        try:
            applied = style.apply_theme(name)
        except ValueError as exc:
            raise UsageError(str(exc)) from None
        await style.save(self.bot.store)
        await respond(
            ctx,
            notice(
                "THEME APPLIED",
                f"Embed theme is now **{applied}**.",
                category="ok",
                fields=[("PREVIEW", "Run `.appearance preview` to see it on a sample dossier.", False)],
            ),
        )

    @appearance_group.command(name="set", usage="<option> <value>")
    @owner_only()
    async def set_option(self, ctx: commands.Context, option: str = None, *, value: str = None) -> None:
        """Change one appearance option."""
        await ack(ctx)
        if not option or value is None:
            raise UsageError(
                "Use `.appearance set <option> <value>`. Options: brand, footer, accent, "
                "minimal, numbers, icons, pipeline, thumbnails, checks, summary, author, compact."
            )
        try:
            summary = style.set_option(option, value)
        except ValueError as exc:
            raise UsageError(str(exc)) from None
        await style.save(self.bot.store)
        await respond(
            ctx,
            notice(
                "APPEARANCE UPDATED",
                summary,
                category="ok",
                fields=[("PREVIEW", "Run `.appearance preview` to see the result.", False)],
            ),
        )

    @appearance_group.command(name="color", aliases=["colour"], usage="<category|all> <#hex|reset>")
    @owner_only()
    async def color(self, ctx: commands.Context, category: str = None, value: str = None) -> None:
        """Override the accent colour for one category or all embeds."""
        await ack(ctx)
        if not category or value is None:
            raise UsageError("Use `.appearance color network #4A90E2` or `.appearance color all #4A90E2`.")
        try:
            summary = style.set_colour(category, value)
        except ValueError as exc:
            raise UsageError(str(exc)) from None
        await style.save(self.bot.store)
        await respond(ctx, notice("COLOR UPDATED", summary, category="ok"))

    @appearance_group.command(name="preview", usage="")
    @owner_only()
    async def preview(self, ctx: commands.Context) -> None:
        """Render a sample dossier with the current style."""
        await ack(ctx)
        embed = Intel(
            category="network",
            command="ip",
            ctx=ctx,
            target="1.1.1.1",
            summary="A sample dossier showing the current appearance settings.",
        )
        embed.kv(
            "ADDRESS",
            {"Country": "Australia", "City": "Sydney", "ASN": "AS13335", "Organisation": "Cloudflare"},
            inline=True,
        )
        embed.kv(
            "TRANSPORT",
            {"TLS": "1.3", "Latency": "8 ms", "Reverse DNS": "one.one.one.one"},
            inline=True,
        )
        embed.table(
            "SAMPLE ANSWERS",
            ["ADDRESS", "TTL", "PTR"],
            [
                ["104.16.132.229", 300, "one.one.one.one"],
                ["104.16.133.229", 300, "one.one.one.one"],
            ],
        )
        embed.code(
            "SAMPLE RAW",
            '{\n  "status": "success",\n  "country": "Australia",\n  "asn": 13335\n}',
            lang="json",
        )
        embed.checks(
            "CHECKS",
            [
                (True, "Resolution", "the name resolves"),
                (False, "DNSSEC", "not validated"),
                (None, "Abuse reports", "not checked"),
            ],
        )
        embed.risk(24, name="RISK")
        embed.steps(["Trace blocks appear only when the pipeline option is enabled."])
        embed.source("sample source")
        await embed.send(ctx)

    @appearance_group.command(name="reset", usage="")
    @owner_only()
    async def reset(self, ctx: commands.Context) -> None:
        """Return to the clean defaults."""
        await ack(ctx)
        style.reset()
        await style.save(self.bot.store)
        await respond(ctx, notice("APPEARANCE RESET", "Back to the clean default style.", category="ok"))


async def setup(bot: Any) -> None:
    await bot.add_cog(AppearanceCog(bot))

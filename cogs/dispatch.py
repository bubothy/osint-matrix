"""Slash entry points.

Every intelligence command is a prefix command. This module exposes eight
category shortcuts (``/net``, ``/domain``, …) with autocomplete, then invokes
the matching prefix command against a lightweight interaction context. That
keeps one implementation per command and stays far below Discord's 100-command
application limit.
"""

import inspect
import time
from typing import Any

import discord
from discord import app_commands
from discord.ext import commands

from core.embeds import notice
from core.utils import clip, shlex_split

GROUPS: tuple[tuple[str, str, str], ...] = (
    ("net", "network", "IP addresses, ASN/BGP, DNS transport, TLS, CDN and blocklists."),
    ("domain", "domain", "DNS records, WHOIS/RDAP, certificate transparency and mail posture."),
    ("web", "web", "URLs, technology fingerprints, headers, robots and phishing heuristics."),
    ("identity", "identity", "Email, handles, phone numbers, hashes, tokens and encodings."),
    ("social", "social", "Public profiles on developer, gaming and social platforms."),
    ("discord", "discord", "Snowflakes, invites, accounts, guilds, webhooks and status."),
    ("vuln", "vuln", "CVEs, KEV, EPSS, CWE, malware metadata and reputation."),
    ("crypto", "crypto", "Bitcoin, Ethereum and Solana public ledger intelligence."),
)


class AppContext:
    """Duck-typed context so prefix commands can run from an interaction."""

    def __init__(self, interaction: discord.Interaction, bot: commands.Bot) -> None:
        self.interaction = interaction
        self.bot = bot
        self.author = interaction.user
        self.guild = interaction.guild
        self.channel = interaction.channel
        self.message = interaction.message
        self.prefix = "/"
        self.command: commands.Command | None = None
        self.me = interaction.guild.me if interaction.guild else bot.user

    async def send(self, **kwargs: Any) -> Any:
        return await self.interaction.followup.send(**kwargs)

    async def reply(self, **kwargs: Any) -> Any:
        return await self.interaction.followup.send(**kwargs)

    async def typing(self) -> None:  # pragma: no cover - interface parity
        return None


class Dispatch(commands.Cog, name="Slash"):
    """Category shortcuts for the application command surface."""

    def __init__(self, bot: Any) -> None:
        self.bot = bot
        self._registered: list[app_commands.Command] = []
        self._stamps: dict[int, list[float]] = {}
        self._help_command: app_commands.Command | None = None

    # ── registration ─────────────────────────────────────────────────────

    async def cog_load(self) -> None:
        for slug, category, description in GROUPS:
            callback = self._make_callback(category)
            callback = app_commands.describe(
                command="Command to run (autocompletes from this category).",
                args="Arguments exactly as you would type them after the prefix.",
            )(callback)
            callback = app_commands.autocomplete(command=self._make_autocomplete(category))(callback)
            command = app_commands.Command(name=slug, description=description, callback=callback)
            self.bot.tree.add_command(command)
            self._registered.append(command)

        help_command = app_commands.Command(
            name="help",
            description="How this private instance works.",
            callback=self._help_callback,
        )
        self.bot.tree.add_command(help_command)
        self._help_command = help_command

    async def cog_unload(self) -> None:
        for command in self._registered:
            self.bot.tree.remove_command(command.name)
        if self._help_command is not None:
            self.bot.tree.remove_command("help")

    # ── callbacks ────────────────────────────────────────────────────────

    def _make_callback(self, category: str):
        async def callback(interaction: discord.Interaction, command: str, args: str = "") -> None:
            await self._dispatch(interaction, category, command, args)

        return callback

    def _make_autocomplete(self, category: str):
        async def completer(interaction: discord.Interaction, current: str) -> list[app_commands.Choice[str]]:
            needle = (current or "").lower()
            choices: list[app_commands.Choice[str]] = []
            for command in sorted(self.bot.commands, key=lambda item: item.name):
                if command.hidden or command.extras.get("category") != category:
                    continue
                haystack = " ".join([command.name, *command.aliases]).lower()
                if needle and needle not in haystack:
                    continue
                label = f"{command.name} — {command.brief or 'no description'}"[:100]
                choices.append(app_commands.Choice(name=label, value=command.name))
                if len(choices) >= 25:
                    break
            return choices

        return completer

    async def _help_callback(self, interaction: discord.Interaction) -> None:
        prefix = "."
        try:
            custom = await self.bot.store.get_prefix(interaction.guild_id) if interaction.guild_id else None
            prefix = custom or __import__("config").settings.prefix
        except Exception:  # noqa: BLE001 - cosmetic
            pass
        total = sum(1 for command in self.bot.commands if command.extras.get("category"))
        embed = notice(
            "OSINT MATRIX — SLASH GUIDE",
            "This is a private, approval-gated instance. Every lookup is audited.",
            category="admin",
            footer=f"{total} intel commands  •  prefix `{prefix}`",
        )
        embed.add_field(
            name="▸ HOW TO USE",
            value=(
                f"```ini\n{prefix}ip 1.1.1.1\n{prefix}dns example.com\n"
                f"{prefix}help dns\n/net command:dns args:example.com```"
            ),
            inline=False,
        )
        embed.add_field(
            name="▸ SLASH SHORTCUTS",
            value="\n".join(f"`/{slug}` — {description}" for slug, _, description in GROUPS),
            inline=False,
        )
        embed.add_field(
            name="▸ ACCESS",
            value="Ask the operator to approve your Discord ID. Without approval no command executes.",
            inline=False,
        )
        await interaction.response.send_message(embed=embed, ephemeral=True)

    # ── dispatch ─────────────────────────────────────────────────────────

    async def _dispatch(self, interaction: discord.Interaction, category: str, name: str, args: str) -> None:
        now = time.monotonic()
        recent = [stamp for stamp in self._stamps.get(interaction.user.id, []) if now - stamp < 10]
        if len(recent) >= 8:
            await interaction.response.send_message(
                embed=notice("SLOW DOWN", "Eight slash lookups in ten seconds is the ceiling. Wait a moment.", category="error"),
                ephemeral=True,
            )
            return
        recent.append(now)
        self._stamps[interaction.user.id] = recent

        await interaction.response.defer(thinking=True)
        ctx = AppContext(interaction, self.bot)
        cleaned = (name or "").strip().lstrip("./")
        command = self.bot.get_command(cleaned)
        if command is None:
            await interaction.followup.send(
                embed=notice(
                    "UNKNOWN COMMAND",
                    f"No command named `{clip(cleaned, 60)}`.",
                    category="error",
                    fields=[("TIP", f"Use the autocomplete list or `/help`.", False)],
                ),
                ephemeral=True,
            )
            return
        if command.extras.get("category") != category:
            sibling = next((slug for slug, cat, _ in GROUPS if cat == command.extras.get("category")), "net")
            await interaction.followup.send(
                embed=notice(
                    "WRONG CATEGORY",
                    f"`{command.name}` belongs to **{command.extras.get('category')}**, not `{category}`.",
                    category="error",
                    fields=[("USE INSTEAD", f"`/{sibling} command:{command.name} args:{clip(args or '<target>', 60)}`", False)],
                ),
                ephemeral=True,
            )
            return

        tokens = shlex_split(args or "")
        ctx.command = command
        try:
            callback = command.callback
            params = list(command.clean_params.values())
            keyword_only = params and params[-1].kind is inspect.Parameter.KEYWORD_ONLY
            if keyword_only and tokens:
                payload = {params[-1].name: " ".join(tokens)}
                result = callback(command.cog, ctx, **payload) if command.cog is not None else callback(ctx, **payload)
            elif command.cog is not None:
                result = callback(command.cog, ctx, *tokens)
            else:
                result = callback(ctx, *tokens)
            await result
        except Exception as exc:  # noqa: BLE001 - rendered through the shared policy
            embed = self.bot.describe_error(exc, command=command.qualified_name, usage=command.usage)
            try:
                await interaction.followup.send(embed=embed, ephemeral=True)
            except discord.HTTPException:
                pass
            return

        await self.bot.record_command(interaction.user, command.qualified_name, interaction.guild)


async def setup(bot: Any) -> None:
    await bot.add_cog(Dispatch(bot))

"""Slash entry points.

Every intelligence command is a prefix command. This module exposes eight
category shortcuts (``/net``, ``/domain``, …) with autocomplete, then invokes
the matching prefix command against a lightweight interaction context. That
keeps one implementation per command and stays far below Discord's 100-command
application limit.
"""

import inspect
import logging
import time
from contextlib import asynccontextmanager
from typing import Any

import discord
from discord import app_commands
from discord.ext import commands

from core import v2
from core.embeds import notice
from core.utils import clip, shlex_split

LOG = logging.getLogger("osint.dispatch")

# Commands offered first in an empty autocomplete list, before the alphabetical
# tail. Without this the 25-choice cap would hide recent additions such as
# vpncheck from the unfiltered menu.
POPULAR: tuple[str, ...] = (
    "ip", "vpncheck", "dns", "whois", "usernamecheck", "vanitycheck", "headers",
    "certs", "cve", "email", "github", "snowflake", "btc", "hash", "jwt",
    "rdns", "asn", "geo", "myip", "subnetinfo",
)

GROUPS: tuple[tuple[str, str, str], ...] = (
    ("net", "network", "IP addresses, ASN/BGP, DNS transport, TLS, CDN and blocklists."),
    ("domain", "domain", "DNS records, WHOIS/RDAP, certificate transparency and mail posture."),
    ("web", "web", "URLs, technology fingerprints, headers, robots and phishing heuristics."),
    ("identity", "identity", "Email, handles, phone numbers, hashes, tokens and encodings."),
    ("social", "social", "Public profiles on developer, gaming and social platforms."),
    ("discord", "discord", "Snowflakes, invites, accounts, guilds, webhooks and status."),
    ("vuln", "vuln", "CVEs, KEV, EPSS, CWE, malware metadata and reputation."),
    ("crypto", "crypto", "Bitcoin, Ethereum and Solana public ledger intelligence."),
    ("craft", "craft", "Ciphers, encoders, lure analysis and local payload helpers."),
    ("tools", "toolkit", "Local encoders, hashes, address arithmetic and text utilities."),
)


class AppContext:
    """Duck-typed context so prefix commands can run from an interaction."""

    def __init__(self, interaction: discord.Interaction, bot: commands.Bot) -> None:
        self.interaction = interaction
        self.response = interaction.response
        self.followup = interaction.followup
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

    async def defer(self, **kwargs: Any) -> None:
        """Interface parity with prefix contexts; a slash call is already deferred."""
        if not self.interaction.response.is_done():
            await self.interaction.response.defer(**kwargs)

    def typing(self) -> Any:
        """Interface parity: prefix code uses ``async with ctx.typing()``."""

        @asynccontextmanager
        async def _typing():
            yield

        return _typing()


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

        # The most-used lookups get their own top-level command with a typed
        # option, so nobody has to spell the wrapper by hand.
        for slug, target, description in (
            ("vpncheck", "vpncheck", "VPN, proxy, Tor and datacenter verdict for one address."),
            ("ip", "ip", "Full address report: geography, network, anonymity and reverse DNS."),
        ):
            callback = self._make_direct_callback(target)
            callback = app_commands.describe(address="IPv4 or IPv6 address.")(callback)
            command = app_commands.Command(name=slug, description=description, callback=callback)
            self.bot.tree.add_command(command)
            self._registered.append(command)

        sync_command = app_commands.Command(
            name="sync",
            description="Re-register the slash tree and report what Discord accepted.",
            callback=self._sync_callback,
        )
        self.bot.tree.add_command(sync_command)
        self._registered.append(sync_command)

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

    def _make_direct_callback(self, target: str):
        async def callback(interaction: discord.Interaction, address: str) -> None:
            await self._dispatch(interaction, "network", target, address)

        return callback

    def _make_autocomplete(self, category: str):
        async def completer(interaction: discord.Interaction, current: str) -> list[app_commands.Choice[str]]:
            needle = (current or "").strip().lower()
            ranked: list[tuple[int, str, Any]] = []
            for command in self.bot.commands:
                if command.hidden or command.extras.get("category") != category:
                    continue
                aliases = [alias.lower() for alias in command.aliases]
                if needle:
                    if needle not in " ".join([command.name, *aliases]):
                        continue
                    # Names beat aliases, prefixes beat substring matches, so a
                    # short query surfaces the intended command first.
                    if command.name.lower().startswith(needle):
                        score = 0
                    elif any(alias.startswith(needle) for alias in aliases):
                        score = 1
                    else:
                        score = 2
                else:
                    score = POPULAR.index(command.name) if command.name in POPULAR else 50
                ranked.append((score, command.name, command))
            ranked.sort(key=lambda row: (row[0], row[1]))
            choices: list[app_commands.Choice[str]] = []
            for _, _, command in ranked[:25]:
                suffix = " /" + " /".join(command.aliases[:2]) if command.aliases else ""
                label = f"{command.name}{suffix} — {command.brief or 'no description'}"[:100]
                choices.append(app_commands.Choice(name=label, value=command.name))
            return choices

        return completer

    async def _help_callback(self, interaction: discord.Interaction) -> None:
        prefix = "."
        try:
            custom = await self.bot.store.get_prefix(interaction.guild_id) if interaction.guild_id else None
            prefix = custom or __import__("config").settings.prefix
        except Exception:  # noqa: BLE001 - cosmetic
            pass
        system = self.bot.get_cog("System")
        catalogue = system._catalogue() if system is not None and hasattr(system, "_catalogue") else None
        registered = int(catalogue["total"]) if catalogue else len(self.bot.commands)
        routes = int(catalogue["routes"]) if catalogue else registered
        embed = notice(
            "0SWALD — SLASH GUIDE",
            "This is a private, approval-gated instance. Every lookup is audited.",
            category="admin",
            footer=f"{registered} commands  •  {routes} names  •  {len(self.bot.tree.get_commands())} slash  •  prefix `{prefix}`",
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
            value="\n".join([f"`/{slug}` — {description}" for slug, _, description in GROUPS] + [
                "`/vpncheck address:` — VPN, proxy and Tor verdict",
                "`/ip address:` — full address report",
                "`/sync` — operator: re-register the tree",
            ]),
            inline=False,
        )
        embed.add_field(
            name="▸ WHERE IT WORKS",
            value=(
                "Servers, direct messages with the bot, and group DMs. If the app is not "
                "in your DMs yet, run `.botinvite` and install it to your account."
            ),
            inline=False,
        )
        embed.add_field(
            name="▸ ACCESS",
            value="Ask the operator to approve your Discord ID. Without approval no command executes.",
            inline=False,
        )
        try:
            await interaction.response.send_message(view=v2.build_layout(embed), ephemeral=True)
        except (discord.HTTPException, ValueError) as exc:
            LOG.warning(
                "slash help V2 send rejected for user=%s guild=%s: %s — "
                "falling back to a plain embed",
                interaction.user.id,
                interaction.guild_id,
                exc,
                exc_info=True,
            )
            try:
                await interaction.response.send_message(embed=embed, ephemeral=True)
                LOG.warning(
                    "slash help plain-embed fallback delivered for user=%s guild=%s",
                    interaction.user.id,
                    interaction.guild_id,
                )
            except (discord.HTTPException, ValueError):
                LOG.exception("slash help plain-embed fallback failed")
                try:
                    await interaction.response.send_message(
                        content=f"**{embed.title or '0SWALD'}**\n{embed.description or ''}",
                        ephemeral=True,
                    )
                    LOG.warning(
                        "slash help plain-text fallback delivered for user=%s guild=%s",
                        interaction.user.id,
                        interaction.guild_id,
                    )
                except (discord.HTTPException, ValueError):
                    LOG.exception("slash help plain-text fallback failed")

    async def _sync_callback(self, interaction: discord.Interaction) -> None:
        if not await self.bot.is_owner(interaction.user):
            await interaction.response.send_message(
                view=v2.build_layout(
                    notice(
                        "OPERATOR ONLY",
                        "The slash tree can only be re-registered by an owner of this instance.",
                        category="error",
                    )
                ),
                ephemeral=True,
            )
            return
        await interaction.response.defer(thinking=True, ephemeral=True)
        await self.bot.sync_commands(force=True)
        report = getattr(self.bot, "last_sync", {}) or {}
        error = report.get("error")
        embed = notice(
            "SLASH TREE SYNCED" if not error else "SLASH SYNC FAILED",
            (
                f"`{report.get('global', 0)}` global entries were accepted; "
                f"duplicate guild copies were {'removed' if report.get('guild_cleared') else 'not present'}."
                if not error
                else "Discord rejected part of the tree. The reason is below and in `logs/bot.log`."
            ),
            category="ok" if not error else "error",
            fields=[
                ("GLOBAL", f"`{report.get('global', 0)}` commands", True),
                ("GUILD COPIES", "cleared" if report.get("guild_cleared") else "none", True),
                ("USER INSTALL", "enabled" if report.get("user_install") else "off", True),
                ("ERROR", f"```{error}```" if error else "none", False),
            ],
            footer="Reconnect or restart Discord if a stale command is still cached.",
        )
        await interaction.followup.send(view=v2.build_layout(embed), ephemeral=True)

    # ── dispatch ─────────────────────────────────────────────────────────

    async def _dispatch(self, interaction: discord.Interaction, category: str, name: str, args: str) -> None:
        from core import access

        cfg = await access.load(self.bot.store)
        window = float(cfg["cooldown_seconds"])
        ceiling = int(cfg["rate_limit_per_10s"])
        now = time.monotonic()
        recent = [stamp for stamp in self._stamps.get(interaction.user.id, []) if now - stamp < window]
        if len(recent) >= ceiling:
            await interaction.response.send_message(
                view=v2.build_layout(
                    notice(
                        "SLOW DOWN",
                        f"{ceiling} slash lookups per {window:.0f} seconds is the ceiling configured on this instance.",
                        category="error",
                        fields=[("LIMIT", f"`{ceiling}` per `{window:.0f}s`", False)],
                    )
                ),
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
                view=v2.build_layout(
                    notice(
                        "UNKNOWN COMMAND",
                        f"No command named `{clip(cleaned, 60)}`.",
                        category="error",
                        fields=[("TIP", f"Use the autocomplete list or `/help`.", False)],
                    )
                ),
                ephemeral=True,
            )
            return
        if command.extras.get("category") != category:
            sibling = next((slug for slug, cat, _ in GROUPS if cat == command.extras.get("category")), "net")
            await interaction.followup.send(
                view=v2.build_layout(
                    notice(
                        "WRONG CATEGORY",
                        f"`{command.name}` belongs to **{command.extras.get('category')}**, not `{category}`.",
                        category="error",
                        fields=[("USE INSTEAD", f"`/{sibling} command:{command.name} args:{clip(args or '<target>', 60)}`", False)],
                    )
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
                await interaction.followup.send(
                    view=v2.build_layout(embed), ephemeral=True
                )
            except discord.HTTPException:
                pass
            return

        await self.bot.record_command(interaction.user, command.qualified_name, interaction.guild)


async def setup(bot: Any) -> None:
    await bot.add_cog(Dispatch(bot))

"""OSINT MATRIX — a private, approval-gated OSINT toolkit for Discord.

Run with:  python bot.py     (or double-click run.bat on Windows)
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import logging.handlers
import sys
import time
import traceback
from typing import Any

import discord
from discord import app_commands
from discord.ext import commands

from config import DATA_DIR, LOG_DIR, settings
from core import appearance, v2
from core.checks import prefix_allowed
from core.embeds import PALETTE, denied_embed, error_embed, maintenance_embed, notice, respond
from core.errors import (
    AccessDenied,
    IntelError,
    MaintenanceMode,
    NotConfigured,
    NotFound,
    SourceUnavailable,
    UsageError,
)
from core.http import HTTPClient
from core.store import Store
from core.utils import human_delta, utcnow

LOG = logging.getLogger("osint")

COGS: tuple[str, ...] = (
    "cogs.network",
    "cogs.domain",
    "cogs.web",
    "cogs.identity",
    "cogs.social",
    "cogs.discordint",
    "cogs.vuln",
    "cogs.crypto",
    "cogs.toolkit",
    "cogs.generator",
    "cogs.admin",
    "cogs.appearance",
    "cogs.dispatch",
)

BANNER = r"""
  ___   ___  ___  _  _  _____     __  __   _  _____  _____  __
 / _ \ / __||_ _|| \| ||_   _|   |  \/  | /_\|_   _||_   _| \ \
| (_) |\__ \ | | | .` |  | |     | |\/| |/ _ \ | |    | |    | |
 \___/ |___/|___||_|\_|  |_|     |_|  |_/_/ \_\|_|    |_|    | |
"""


# ── prefix resolution ──────────────────────────────────────────────────────


def get_prefix(bot: "OsintBot", message: discord.Message) -> list[str]:
    prefixes: set[str] = {settings.prefix}
    if message.guild is not None:
        custom = getattr(bot, "prefix_cache", {}).get(message.guild.id)
        if custom:
            prefixes.add(custom)
    if bot.user is not None:
        prefixes.add(f"<@{bot.user.id}> ")
        prefixes.add(f"<@!{bot.user.id}> ")
    return sorted(prefixes)


class OsintBot(commands.Bot):
    """Bot subclass owning configuration, storage, transport and error policy."""

    def __init__(self) -> None:
        intents = discord.Intents.default()
        intents.message_content = True  # required for prefix commands
        intents.members = False
        super().__init__(
            command_prefix=get_prefix,
            intents=intents,
            help_command=None,
            case_insensitive=True,
            strip_after_prefix=True,
            owner_ids=set(settings.owner_ids),
            allowed_mentions=discord.AllowedMentions(everyone=False, roles=False, users=True, replied_user=False),
        )
        # Global commands make the slash surface available in servers, bot DMs
        # and group DMs. User install is required for private-channel contexts.
        self.tree.allowed_contexts = app_commands.AppCommandContext(
            guild=True, dm_channel=True, private_channel=True
        )
        self.tree.allowed_installs = app_commands.AppInstallationType(guild=True, user=True)
        self.store: Store
        self.net: HTTPClient
        self.launch_time: float = time.time()
        self.prefix_cache: dict[int, str] = {}
        self.command_errors: int = 0
        self._emoji_task: asyncio.Task[None] | None = None

    # ── lifecycle ────────────────────────────────────────────────────────

    async def setup_hook(self) -> None:
        self.store = Store(DATA_DIR / "osint.sqlite3")
        await appearance.load(self.store)
        self.net = HTTPClient(settings.http_timeout, settings.cache_ttl)
        await self.net.start()
        self.launch_time = time.time()
        self.prefix_cache = await self.store.prefixes()

        if await self.store.kv_get("maintenance") is None:
            await self.store.kv_set("maintenance", "1" if settings.maintenance else "0")
        if await self.store.kv_get("boot") is None:
            await self.store.kv_set("boot", utcnow().isoformat(timespec="seconds"))

        for extension in COGS:
            try:
                await self.load_extension(extension)
                LOG.info("loaded extension %s", extension)
            except Exception:
                LOG.exception("failed to load %s", extension)
                raise

        self.add_check(self._global_check)
        self.tree.interaction_check = self._tree_check
        await self.sync_commands(verbose=False)

    async def sync_emojis(self) -> None:
        """Create or fetch the application-owned badge for every command."""
        try:
            from core.emoji_sync import sync

            known, created = await sync(self)
            LOG.info("command badges ready: %d existing, %d new", known, created)
        except Exception:  # noqa: BLE001 - badges must never stop the bot
            LOG.exception("command badge sync failed")

    async def close(self) -> None:
        if self._emoji_task is not None and not self._emoji_task.done():
            self._emoji_task.cancel()
        try:
            await self.net.close()
        except Exception:  # noqa: BLE001 - shutdown must not raise
            pass
        try:
            await self.store.close()
        except Exception:  # noqa: BLE001
            pass
        await super().close()

    # ── access control ───────────────────────────────────────────────────

    async def _global_check(self, ctx: commands.Context) -> bool:
        return await prefix_allowed(ctx)

    async def _tree_check(self, interaction: discord.Interaction) -> bool:
        from core.checks import evaluate_access

        allowed, reason = await evaluate_access(self, interaction.user.id)
        if not allowed:
            embed = maintenance_embed() if reason == "maintenance" else denied_embed(interaction.user.id)
            try:
                await interaction.response.send_message(
                    view=v2.build_layout(embed), ephemeral=True
                )
            except discord.HTTPException:
                pass
            await self.store.audit(interaction.user.id, "denied_slash", str(interaction.command), reason)
            return False
        if interaction.guild is None and not settings.allow_dms:
            try:
                await interaction.response.send_message(
                    view=v2.build_layout(
                        error_embed("GUILD ONLY", "Direct messages are disabled on this instance.")
                    ),
                    ephemeral=True,
                )
            except discord.HTTPException:
                pass
            return False
        return True

    # ── slash sync ───────────────────────────────────────────────────────

    async def sync_commands(self, *, verbose: bool = True, force: bool = False) -> int:
        """Sync the global tree (servers, DMs, group DMs) and a guild copy.

        Global commands are required for DMs and group DMs. The guild copy is
        synced too so the same commands appear instantly in the operator's
        server instead of waiting for global propagation.
        """
        try:
            payload = [command.to_dict(self.tree) for command in self.tree.get_commands()]
            fingerprint = hashlib.sha256(
                json.dumps(payload, sort_keys=True, ensure_ascii=False, default=str).encode()
            ).hexdigest()
        except Exception:  # noqa: BLE001 - a sync should still be attempted
            LOG.exception("could not fingerprint application commands")
            fingerprint = ""

        stored = await self.store.kv_get("slash_fingerprint")
        total = 0

        if force or not fingerprint or fingerprint != stored:
            try:
                synced = await self.tree.sync()
            except discord.HTTPException:
                LOG.exception("global application command sync failed")
            else:
                total += len(synced)
                LOG.info("synced %d global application commands (servers, DMs, group DMs)", len(synced))
                if fingerprint:
                    await self.store.kv_set("slash_fingerprint", fingerprint)
        else:
            LOG.info("global application commands unchanged; sync skipped")

        if settings.guild_id:
            try:
                guild = discord.Object(id=settings.guild_id)
                self.tree.copy_global_to(guild=guild)
                synced = await self.tree.sync(guild=guild)
            except discord.HTTPException:
                LOG.exception("guild application command sync failed")
            else:
                total += len(synced)
                LOG.info("synced %d guild application commands for %s", len(synced), settings.guild_id)

        if verbose:
            LOG.info("application command sync complete")
        return total

    # ── telemetry ────────────────────────────────────────────────────────

    async def record_command(self, user: discord.abc.User | None, command: str, guild: discord.Guild | None) -> None:
        if user is None:
            return
        try:
            await self.store.bump_metric("lookups")
            await self.store.bump_command(command)
            await self.store.audit(user.id, "lookup", command, f"guild={guild.id}" if guild else "dm")
        except Exception:  # noqa: BLE001 - telemetry must never break a lookup
            LOG.exception("failed to record command telemetry")
            return
        await self._audit_feed(user, command, guild)

    async def _audit_feed(self, user: discord.abc.User, command: str, guild: discord.Guild | None) -> None:
        if not settings.log_channel_id:
            return
        channel = self.get_channel(settings.log_channel_id)
        if channel is None:
            try:
                fetched = await self.fetch_channel(settings.log_channel_id)
                channel = fetched if isinstance(fetched, discord.abc.Messageable) else None
            except discord.HTTPException:
                return
        if channel is None:
            return
        embed = notice(
            "LOOKUP",
            f"`{command}` executed by {user.mention} (`{user.id}`)",
            category="admin",
            fields=[
                ("OPERATOR", f"{user} · `{user.id}`", True),
                ("CONTEXT", f"{guild.name} · `{guild.id}`" if guild else "Direct message", True),
                ("COMMAND", f"`{command}`", True),
            ],
            footer=utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        )
        try:
            await channel.send(
                view=v2.build_layout(embed),
                allowed_mentions=discord.AllowedMentions.none(),
            )
        except discord.HTTPException:
            pass

    # ── error rendering ──────────────────────────────────────────────────

    def describe_error(self, error: BaseException, *, command: str | None = None, usage: str | None = None) -> discord.Embed:
        original = getattr(error, "original", error)
        if isinstance(original, MaintenanceMode):
            return maintenance_embed()
        if isinstance(original, AccessDenied):
            return error_embed(
                "ACCESS DENIED",
                str(original) or "You are not authorised to use this instance.",
                hint="Ask the operator to run `approve` with your Discord ID.",
            )
        if isinstance(original, commands.CommandNotFound):
            return error_embed("UNKNOWN COMMAND", "No command matches that name.", hint="Run `help` to list every command.")
        if isinstance(original, commands.CommandOnCooldown):
            window = getattr(original, "cooldown", None)
            rate = getattr(window, "rate", "?")
            per = getattr(window, "per", 0)
            return notice(
                "COOLDOWN ACTIVE",
                f"That command is cooling down. Try again in **{original.retry_after:.1f}s**.",
                category="error",
                fields=[("LIMIT", f"{rate} uses per {per:.0f}s", True)],
            )
        if isinstance(original, commands.MaxConcurrencyReached):
            return notice(
                "CONCURRENCY LIMIT",
                "You already have lookups running against that command. Wait for them to finish.",
                category="error",
            )
        if isinstance(original, NotConfigured):
            return notice(
                "FEATURE NOT CONFIGURED",
                f"**{original.service}** needs an API key on this instance.",
                category="identity",
                fields=[
                    ("ENVIRONMENT VARIABLE", f"`{original.env}`", True),
                    ("WHAT IT UNLOCKS", original.unlocks, False),
                    ("GET A KEY", original.url, False),
                    ("HOW TO APPLY", "Add the value to `.env`, save, then restart the bot (or run `reload`).", False),
                ],
            )
        if isinstance(original, NotFound):
            return notice(
                "NO RECORDS FOUND",
                str(original),
                category="identity",
                fields=[("INTERPRETATION", "The source answered cleanly but holds no record for that target. That is a result, not an error.", False)],
            )
        if isinstance(original, (UsageError, commands.MissingRequiredArgument, commands.BadArgument, commands.UserInputError)):
            return error_embed(
                "INVALID INVOCATION",
                str(original).split("\n")[0] or "The arguments for that command are not valid.",
                usage=usage,
                hint="Run `help {command}` for the full syntax." if command else None,
                command=command,
            )
        if isinstance(original, SourceUnavailable):
            return notice(
                "UPSTREAM UNAVAILABLE",
                str(original),
                category="error",
                fields=[("RETRY", "Sources occasionally rate-limit or time out. Try again in a moment.", False)],
                footer=f"command: {command or 'unknown'}",
            )
        if isinstance(original, IntelError):
            embed = notice("LOOKUP FAILED", str(original), category="error", footer=f"command: {command or 'unknown'}")
            if original.hint:
                embed.add_field(name="▸ DETAIL", value=str(original.hint)[:1024], inline=False)
            return embed
        if isinstance(original, commands.CheckFailure):
            return error_embed("ACCESS DENIED", str(original) or "A permission check failed.")

        incident = hashlib.sha1("".join(traceback.format_exception(original)).encode()).hexdigest()[:10]
        LOG.error("unhandled command error [%s] in %s\n%s", incident, command, "".join(traceback.format_exception(original)))
        self.command_errors += 1
        return error_embed(
            "INTERNAL FAULT",
            "Something broke while running that command. The traceback was written to `logs/bot.log`.",
            hint=f"Incident `{incident}` — include it if you report the problem.",
            command=command,
        )

    # ── events ───────────────────────────────────────────────────────────

    async def on_ready(self) -> None:
        LOG.info("connected as %s (%s) · %d guilds", self.user, getattr(self.user, "id", "?"), len(self.guilds))
        activity = discord.Activity(type=discord.ActivityType.watching, name="the grid · .help")
        try:
            await self.change_presence(activity=activity, status=discord.Status.online)
        except discord.HTTPException:
            pass
        if self._emoji_task is None or self._emoji_task.done():
            self._emoji_task = asyncio.create_task(self.sync_emojis())

    async def on_command_completion(self, ctx: commands.Context) -> None:
        if ctx.command is None:
            return
        if ctx.command.name in {"help", "commands", "ping", "whoami", "sources", "apikeys"}:
            return
        await self.record_command(ctx.author, ctx.command.qualified_name, ctx.guild)

    async def on_command_error(self, ctx: commands.Context, error: commands.CommandError) -> None:
        if isinstance(error, commands.CommandNotFound):
            return
        embed = self.describe_error(error, command=ctx.command.qualified_name if ctx.command else None, usage=getattr(ctx.command, "usage", None))
        await respond(ctx, embed)

    async def on_app_command_error(self, interaction: discord.Interaction, error: Any) -> None:
        command = interaction.command.qualified_name if interaction.command else None
        embed = self.describe_error(error, command=command)
        try:
            layout = v2.build_layout(embed)
            if interaction.response.is_done():
                await interaction.followup.send(view=layout, ephemeral=True)
            else:
                await interaction.response.send_message(view=layout, ephemeral=True)
        except discord.HTTPException:
            LOG.exception("failed to deliver app command error")

    async def on_error(self, event_method: str, /, *args: Any, **kwargs: Any) -> None:
        LOG.exception("unhandled exception in event %s", event_method)


# ── entry point ────────────────────────────────────────────────────────────


def configure_logging() -> None:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    formatter = logging.Formatter("%(asctime)s  %(levelname)-7s  %(name)s: %(message)s", "%H:%M:%S")
    stream = logging.StreamHandler(sys.stdout)
    stream.setFormatter(formatter)
    file_handler = logging.handlers.RotatingFileHandler(
        LOG_DIR / "bot.log", maxBytes=2_000_000, backupCount=3, encoding="utf-8"
    )
    file_handler.setFormatter(
        logging.Formatter("%(asctime)s  %(levelname)-7s  %(name)s: %(message)s")
    )
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    root.handlers = [stream, file_handler]
    logging.getLogger("discord").setLevel(logging.WARNING)
    logging.getLogger("discord.http").setLevel(logging.WARNING)
    logging.getLogger("aiohttp").setLevel(logging.WARNING)


def main() -> int:
    configure_logging()
    print(BANNER)
    missing = settings.missing_required()
    if missing:
        print("  Configuration incomplete. Missing:", ", ".join(missing))
        print("  Copy .env.example to .env and fill in those values, then run again.")
        print("  → https://discord.com/developers/applications\n")
        return 2
    if not settings.owner_ids:
        print("  Warn: no OWNER_IDS configured — nobody will be able to approve users.\n")

    print(f"  Prefix       : {settings.prefix}")
    print(f"  Owners       : {len(settings.owner_ids)}")
    scope = "global + guild (guild instant, DMs up to 1 hour)" if settings.guild_id else "global (DMs, up to 1 hour)"
    print(f"  Slash sync   : {scope}")
    print(f"  Audit channel: {settings.log_channel_id or 'disabled'}")
    print(f"  Slash        : {'/net /domain /web /identity /social /discord /vuln /crypto'}")
    print()

    bot = OsintBot()
    try:
        bot.run(settings.token, log_handler=None)
    except discord.LoginFailure:
        print("\n  Login failed: DISCORD_TOKEN is invalid or has been reset.")
        print("  Generate a new token in the Developer Portal → Bot → Reset Token.\n")
        return 3
    except discord.PrivilegedIntentsRequired:
        print("\n  MESSAGE CONTENT INTENT is not enabled for this application.")
        print("  Developer Portal → your app → Bot → Privileged Gateway Intents →")
        print("  enable MESSAGE CONTENT INTENT, then Save and restart.\n")
        return 4
    except KeyboardInterrupt:
        print("\n  Stopped.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(0)

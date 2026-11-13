"""Access-control predicates shared by prefix and slash command paths."""

from __future__ import annotations

from typing import Any

from discord.ext import commands

from core.errors import AccessDenied, MaintenanceMode
from config import settings


async def evaluate_access(bot: Any, user_id: int) -> tuple[bool, str]:
    """Return (allowed, reason) for a Discord user id."""
    if user_id in settings.owner_ids or user_id in getattr(bot, "owner_ids", frozenset()):
        return True, "owner"
    if await bot.store.kv_get("maintenance") == "1":
        return False, "maintenance"
    if await bot.store.is_approved(user_id):
        return True, "approved"
    return False, "unapproved"


def owner_only():
    """Restrict a command to the operator(s) declared in OWNER_IDS."""

    async def predicate(ctx: commands.Context) -> bool:
        if ctx.author.id not in ctx.bot.owner_ids:
            raise AccessDenied("This command is restricted to the bot operator.")
        return True

    return commands.check(predicate)


def guild_only():
    async def predicate(ctx: commands.Context) -> bool:
        if ctx.guild is None:
            raise AccessDenied("This command needs to run inside a server.")
        return True

    return commands.check(predicate)


async def prefix_allowed(ctx: commands.Context) -> bool:
    ok, reason = await evaluate_access(ctx.bot, ctx.author.id)
    if not ok:
        if reason == "maintenance":
            raise MaintenanceMode("The instance is in maintenance mode.")
        raise AccessDenied("You are not on this instance's allow-list.")
    if ctx.guild is None and not settings.allow_dms:
        raise AccessDenied("Direct messages are disabled on this instance.")
    return True

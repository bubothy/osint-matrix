"""Typed exceptions.

Commands raise these instead of formatting error strings themselves; the global
error handler turns each one into a consistent, detailed embed.
"""

from __future__ import annotations

from discord.ext import commands


class IntelError(commands.CommandError):
    """An upstream source returned something we cannot use."""

    def __init__(self, message: str, *, hint: str | None = None) -> None:
        super().__init__(message)
        self.detail = message
        self.hint = hint


class NotFound(IntelError):
    """The source answered cleanly but has no record for the target."""


class NotConfigured(IntelError):
    """The operator has not supplied a key this command needs."""

    def __init__(self, env: str, service: str, unlocks: str, url: str) -> None:
        super().__init__(
            f"**{service}** is not configured on this instance.",
            hint=f"Add `{env}` to your `.env` file, then restart the bot.\n{url}",
        )
        self.env = env
        self.service = service
        self.unlocks = unlocks
        self.url = url


class UsageError(commands.UserInputError):
    """The invocation itself is malformed."""


class AccessDenied(commands.CheckFailure):
    """The caller is not on the allow-list."""


class MaintenanceMode(commands.CheckFailure):
    """The operator locked the bot to owners only."""


class SourceUnavailable(IntelError):
    """The upstream service refused or timed out."""

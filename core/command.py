"""Shared command decorator.

Keeps category, usage, examples, data sources and cooldown metadata attached to
every intelligence command so ``help`` can render it without special cases.
"""

from __future__ import annotations

from typing import Any, Callable, Iterable

from discord.ext import commands


def intel(
    *,
    category: str,
    brief: str,
    usage: str,
    aliases: Iterable[str] = (),
    examples: Iterable[str] = (),
    sources: Iterable[str] = (),
    cooldown: tuple[float, float] = (3.0, 10.0),
    name: str | None = None,
    concurrency: int = 3,
) -> Callable[[Any], commands.Command]:
    """Attach metadata and limits, then wrap the function in a Command."""

    def decorator(func: Callable[..., Any]) -> commands.Command:
        command = commands.cooldown(cooldown[0], cooldown[1], commands.BucketType.user)(func)
        command = commands.max_concurrency(concurrency, commands.BucketType.user)(command)
        return commands.command(
            name=name or func.__name__,
            aliases=list(aliases),
            usage=usage,
            brief=brief,
            help=brief,
            extras={
                "category": category,
                "examples": list(examples),
                "sources": list(sources),
                "cooldown": cooldown,
            },
        )(command)

    return decorator

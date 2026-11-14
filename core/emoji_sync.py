"""Synchronise generated command badges with Discord application emojis.

Application emojis are owned by the bot rather than by a guild, so the same
badge works in servers, DMs and group DMs. The first run uploads one badge per
command; later runs only fetch the existing IDs and rebuild the local registry.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import discord

from core import emojis, visuals
from core.embeds import PALETTE

LOG = logging.getLogger("osint.emojis")


async def sync(bot: Any, *, ceiling: int = 2000) -> tuple[int, int]:
    """Return ``(known, created)`` after reconciling app emojis with commands."""
    if not hasattr(bot, "fetch_application_emojis") or not hasattr(bot, "create_application_emoji"):
        LOG.warning("discord.py does not expose application emoji methods; skipping badges")
        return 0, 0
    try:
        visuals.icon_png("preflight", "admin")
    except Exception as exc:  # noqa: BLE001 - report the missing renderer once
        LOG.warning("cv2 renderer unavailable; skipping command badges: %s", exc)
        return 0, 0
    try:
        existing = await bot.fetch_application_emojis()
    except discord.HTTPException as exc:
        LOG.warning("could not list application emojis: %s", exc)
        return 0, 0

    by_name = {getattr(item, "name", ""): item for item in existing}
    known = 0
    created = 0
    commands = sorted(bot.commands, key=lambda item: item.name)
    total = len(commands)

    def remember(command: Any, badge: Any) -> None:
        emojis.register(command.name, badge)
        for alias in getattr(command, "aliases", []):
            emojis.register(alias, badge)

    for index, command in enumerate(commands, 1):
        name = emojis.name_for(command.name)
        current = by_name.get(name)
        if current is not None:
            remember(command, current)
            known += 1
            continue
        if len(by_name) >= ceiling:
            LOG.warning("application emoji ceiling reached; stopping at %s", len(by_name))
            break

        category = str(command.extras.get("category") or "admin")
        accent = PALETTE.get(category, PALETTE["admin"])[0]
        try:
            image = visuals.icon_png(command.name, category, accent)
            badge = await bot.create_application_emoji(name=name, image=image)
        except discord.HTTPException as exc:
            LOG.warning("could not create emoji for %s: %s", command.name, exc)
            continue
        except Exception:  # noqa: BLE001 - one badge must not stop the rest
            LOG.exception("unexpected failure creating emoji for %s", command.name)
            continue

        by_name[name] = badge
        remember(command, badge)
        created += 1
        if index % 20 == 0:
            LOG.info("application emojis: %s/%s commands reconciled", index, total)
        await asyncio.sleep(0.06)

    LOG.info(
        "application emojis ready: %s known, %s created, registry size %s",
        known,
        created,
        emojis.count(),
    )
    return known, created

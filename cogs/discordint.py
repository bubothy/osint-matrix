"""Discord-native intelligence: identifiers, invites, assets and platform status."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlsplit

import discord
from discord.ext import commands

from core.command import intel
from core.embeds import Intel
from core.errors import NotFound, SourceUnavailable, UsageError
from core.utils import (
    ack,
    clip,
    fmt_dt,
    human_delta,
    num,
    parse_snowflake,
    require,
    snowflake_parts,
    snowflake_time,
    utcnow,
)

WEBHOOK_TYPES = {1: "Incoming", 2: "Channel Follower", 3: "Application"}
VERIFICATION = {0: "none", 1: "low", 2: "medium", 3: "high", 4: "very high"}
CHANNEL_TYPES = {
    0: "text", 1: "DM", 2: "voice", 3: "group DM", 4: "category", 5: "announcement",
    10: "announcement thread", 11: "public thread", 12: "private thread", 13: "stage",
    14: "directory", 15: "forum", 16: "media",
}


class DiscordIntel(commands.Cog, name="Discord"):
    """Snowflakes, invites, accounts, guilds and Discord-hosted assets."""

    def __init__(self, bot: Any) -> None:
        self.bot = bot
        self.http = bot.http

    # ── helpers ──────────────────────────────────────────────────────────

    async def _user(self, raw: str | None, example: str) -> discord.User:
        uid = parse_snowflake(require(raw, "user ID or mention", example=example))
        try:
            return await self.bot.fetch_user(uid)
        except discord.NotFound:
            raise NotFound(f"Discord has no user with ID `{uid}`.") from None
        except discord.HTTPException as exc:
            raise SourceUnavailable(f"Discord rejected the user lookup ({exc.status}).") from exc

    @staticmethod
    def _invite_code(raw: str) -> str:
        value = raw.strip()
        match = re.search(r"(?:discord\.gg/|discord(?:app)?\.com/invite/)([A-Za-z0-9-]{2,32})", value)
        if match:
            return match.group(1)
        if re.fullmatch(r"[A-Za-z0-9-]{2,32}", value):
            return value
        raise UsageError("That is not a Discord invite code or link.")

    # ── identifiers ──────────────────────────────────────────────────────

    @intel(
        category="discord",
        brief="Decompose a Discord snowflake into timestamp, worker, process and sequence.",
        usage="<id|message link>",
        aliases=["sf", "id"],
        examples=["snowflake 175928847299117063"],
        sources=["local computation"],
        cooldown=(4, 8),
    )
    async def snowflake(self, ctx: commands.Context, target: str = None) -> None:
        await ack(ctx)
        sid = parse_snowflake(require(target, "snowflake", example=".snowflake 175928847299117063"))
        parts = snowflake_parts(sid)
        created = snowflake_time(sid)
        embed = Intel(
            category="discord",
            command="snowflake",
            ctx=ctx,
            target=str(sid),
            summary="Every Discord object ID is a 64-bit snowflake. The high 42 bits are the creation timestamp.",
        )
        embed.kv(
            "DECOMPOSITION",
            {
                "Snowflake": sid,
                "Timestamp (ms)": parts["timestamp_ms"],
                "Created": fmt_dt(created),
                "Age": human_delta((utcnow() - created).total_seconds()),
                "Worker ID": parts["worker"],
                "Process ID": parts["process"],
                "Increment": parts["increment"],
            },
            inline=True,
        )
        embed.kv(
            "MACHINE FORM",
            {
                "Binary": format(sid, "b"),
                "Hex": hex(sid),
                "Digits": len(str(sid)),
                "Epoch": "2015-01-01T00:00:00Z (Discord)",
                "Fits 64-bit": sid < 2**64,
            },
            inline=True,
        )
        embed.code(
            "BIT LAYOUT",
            f"timestamp  {format(parts['timestamp_ms'], '042b')}\n"
            f"worker     {format(parts['worker'], '05b')}\n"
            f"process    {format(parts['process'], '05b')}\n"
            f"increment  {format(parts['increment'], '012b')}",
            lang="yaml",
        )
        embed.checks(
            "SANITY",
            [
                (15 <= len(str(sid)) <= 21, "Plausible length", f"{len(str(sid))} digits"),
                (created <= utcnow(), "Not in the future", created.strftime("%Y-%m-%d")),
                (None, "Note", "the worker/process fields are not stable identifiers of a physical machine"),
            ],
        )
        embed.source("local computation")
        await embed.send(ctx)

    @intel(
        category="discord",
        brief="Account creation date and age from a Discord ID.",
        usage="<id|mention>",
        aliases=["idage", "created"],
        examples=["accountage 175928847299117063"],
        sources=["local computation"],
        cooldown=(4, 8),
    )
    async def accountage(self, ctx: commands.Context, target: str = None) -> None:
        await ack(ctx)
        sid = parse_snowflake(require(target, "user ID or mention", example=".accountage 175928847299117063"))
        created = snowflake_time(sid)
        age = (utcnow() - created).total_seconds()
        embed = Intel(
            category="discord",
            command="accountage",
            ctx=ctx,
            target=str(sid),
            summary="Account age is a useful trust signal: throwaway accounts are almost always young.",
        )
        embed.kv(
            "TIMELINE",
            {
                "User ID": sid,
                "Created": fmt_dt(created),
                "Unix": int(created.timestamp()),
                "Age": human_delta(age),
                "Days": num(age // 86400),
                "Years": f"{age / 31_557_600:.2f}",
            },
            inline=True,
        )
        embed.risk(
            85 if age < 86400 * 7 else 55 if age < 86400 * 30 else 25 if age < 86400 * 180 else 8,
            name="TRUST INDEX",
            verdict="BRAND NEW" if age < 86400 * 7 else "YOUNG" if age < 86400 * 90 else "ESTABLISHED",
        )
        embed.checks(
            "SIGNALS",
            [
                (age > 86400 * 365, "Older than a year", f"{age / 31_557_600:.1f} years"),
                (age > 86400 * 30, "Older than a month", human_delta(age)),
                (None, "Caveat", "age says nothing about intent — correlate with behaviour"),
            ],
        )
        embed.source("local computation")
        await embed.send(ctx)

    @intel(
        category="discord",
        brief="Invite intelligence: guild, channel, inviter, member counts and expiry.",
        usage="<code|invite link>",
        aliases=["inv"],
        examples=["invite discord-developers"],
        sources=["Discord REST API"],
        cooldown=(3, 12),
    )
    async def invite(self, ctx: commands.Context, target: str = None) -> None:
        await ack(ctx)
        code = self._invite_code(require(target, "invite code or link", example=".invite discord-developers"))
        payload = await self.http.discord(
            f"/invites/{code}", params={"with_counts": "true", "with_expiration": "true"}
        )
        guild = payload.get("guild") or {}
        channel = payload.get("channel") or {}
        inviter = payload.get("inviter") or {}
        icon = f"https://cdn.discordapp.com/icons/{guild.get('id')}/{guild.get('icon')}.png?size=256" if guild.get("icon") else None
        embed = Intel(
            category="discord",
            command="invite",
            ctx=ctx,
            target=payload.get("code", code),
            summary="Public invite metadata. Joining is never attempted; this is a read-only REST lookup.",
        )
        embed.kv(
            "GUILD",
            {
                "Name": guild.get("name"),
                "ID": guild.get("id"),
                "Description": clip(guild.get("description") or "", 180),
                "Verification": VERIFICATION.get(guild.get("verification_level"), guild.get("verification_level")),
                "NSFW level": guild.get("nsfw_level"),
                "Boosts": guild.get("premium_subscription_count"),
                "Tier": guild.get("premium_tier"),
            },
            inline=True,
        )
        embed.kv(
            "INVITE",
            {
                "Channel": f"#{channel.get('name')}" if channel.get("name") else None,
                "Channel ID": channel.get("id"),
                "Channel type": CHANNEL_TYPES.get(channel.get("type"), channel.get("type")),
                "Inviter": f"{inviter.get('username')} (`{inviter.get('id')}`)" if inviter.get("id") else "hidden",
                "Expires": fmt_dt(payload.get("expires_at")) if payload.get("expires_at") else "never",
                "Temporary": payload.get("temporary"),
                "Uses": payload.get("uses"),
                "Max uses": payload.get("max_uses"),
                "Max age": payload.get("max_age"),
            },
            inline=True,
        )
        embed.kv(
            "POPULATION",
            {
                "Members": num(payload.get("approximate_member_count")),
                "Online": num(payload.get("approximate_presence_count")),
                "Features": (guild.get("features") or [])[:10] or "none",
            },
            inline=False,
        )
        embed.thumbnail(icon)
        embed.checks(
            "SIGNALS",
            [
                (bool(payload.get("approximate_member_count")), "Counts visible", num(payload.get("approximate_member_count"))),
                (payload.get("expires_at") is None, "Permanent invite", "no expiry" if payload.get("expires_at") is None else str(payload.get("expires_at"))),
                (None, "Caveat", "invite metadata is public to any bot — treat the guild description as untrusted"),
            ],
        )
        embed.source("Discord REST")
        await embed.send(ctx)

    # ── accounts ─────────────────────────────────────────────────────────

    @intel(
        category="discord",
        brief="Discord account dossier: creation date, badges, avatar, banner and shared guilds.",
        usage="<id|mention>",
        aliases=["user", "whoisuser"],
        examples=["userinfo 175928847299117063"],
        sources=["Discord REST API"],
        cooldown=(3, 10),
    )
    async def userinfo(self, ctx: commands.Context, target: str = None) -> None:
        await ack(ctx)
        user = await self._user(target, ".userinfo 175928847299117063")
        try:
            flags = [flag.name.replace("_", " ").title() for flag in user.public_flags.all()]
        except Exception:  # noqa: BLE001 - flag set API variance
            flags = []
        shared = [guild.name for guild in self.bot.guilds if guild.get_member(user.id)]
        embed = Intel(
            category="discord",
            command="userinfo",
            ctx=ctx,
            target=f"{user}",
            summary="Public account fields only. The bot cannot read DMs, email addresses or private connections.",
        )
        embed.kv(
            "ACCOUNT",
            {
                "Username": user.name,
                "Display name": user.global_name or user.display_name,
                "ID": user.id,
                "Bot": user.bot,
                "System": user.system,
                "Created": fmt_dt(user.created_at),
                "Age": human_delta((utcnow() - user.created_at).total_seconds()),
            },
            inline=True,
        )
        embed.kv(
            "APPEARANCE",
            {
                "Avatar": bool(user.avatar),
                "Animated avatar": bool(user.avatar and user.avatar.is_animated()),
                "Banner": bool(user.banner),
                "Accent colour": f"#{user.accent_color}" if user.accent_color else None,
                "Default avatar": str(user.default_avatar),
            },
            inline=True,
        )
        embed.kv(
            "BADGES",
            {
                "Public flags": flags[:12] or "none",
                "Shared guilds (cache)": shared[:8] or "none visible",
            },
            inline=False,
        )
        embed.thumbnail(user.display_avatar.url)
        embed.checks(
            "SIGNALS",
            [
                (not user.bot, "Human account", "bot" if user.bot else "human"),
                (bool(user.avatar), "Custom avatar", "set" if user.avatar else "default"),
                (None, "Limit", "presence, email and connections are not exposed by the API"),
            ],
        )
        embed.source("Discord REST")
        await embed.send(ctx)

    @intel(
        category="discord",
        brief="Every CDN rendition of a user's avatar.",
        usage="<id|mention>",
        aliases=["pfp"],
        examples=["avatar 175928847299117063"],
        sources=["Discord CDN"],
        cooldown=(4, 8),
    )
    async def avatar(self, ctx: commands.Context, target: str = None) -> None:
        await ack(ctx)
        user = await self._user(target, ".avatar 175928847299117063")
        asset = user.display_avatar
        embed = Intel(
            category="discord",
            command="avatar",
            ctx=ctx,
            target=str(user),
            summary="Avatar URLs are stable per hash. A hash change means the image changed.",
        )
        embed.kv(
            "ASSET",
            {
                "Hash": asset.key,
                "Animated": asset.is_animated(),
                "Format": "gif" if asset.is_animated() else "png",
                "Default": user.avatar is None,
            },
            inline=True,
        )
        embed.kv(
            "RENDITIONS",
            {
                "128 px": asset.with_size(128).url,
                "256 px": asset.with_size(256).url,
                "512 px": asset.with_size(512).url,
                "1024 px": asset.with_size(1024).url,
            },
            inline=False,
        )
        embed.image(asset.with_size(1024).url)
        embed.source("Discord CDN")
        await embed.send(ctx)

    @intel(
        category="discord",
        brief="Banner and accent colour for a Discord account.",
        usage="<id|mention>",
        aliases=["profilebanner"],
        examples=["banner 175928847299117063"],
        sources=["Discord REST API", "Discord CDN"],
        cooldown=(3, 10),
    )
    async def banner(self, ctx: commands.Context, target: str = None) -> None:
        await ack(ctx)
        user = await self._user(target, ".banner 175928847299117063")
        if user.banner is None:
            raise NotFound(f"`{user}` has no banner set (or the account has no Nitro profile customisation).")
        embed = Intel(
            category="discord",
            command="banner",
            ctx=ctx,
            target=str(user),
            summary="Banners are profile customisation, not identity data — but they are a useful visual fingerprint.",
        )
        embed.kv(
            "BANNER",
            {
                "Hash": user.banner.key,
                "Animated": user.banner.is_animated(),
                "Colour": f"#{user.accent_color}" if user.accent_color else "none",
                "512 px": user.banner.with_size(512).url,
                "1024 px": user.banner.with_size(1024).url,
            },
            inline=False,
        )
        embed.image(user.banner.with_size(1024).url)
        embed.source("Discord CDN")
        await embed.send(ctx)

    # ── guilds and assets ────────────────────────────────────────────────

    @intel(
        category="discord",
        brief="Guild dossier for a server this bot is a member of.",
        usage="[guild id]",
        aliases=["serverinfo", "guild"],
        examples=["guildinfo", "guildinfo 81384788765712384"],
        sources=["Discord gateway cache"],
        cooldown=(3, 10),
    )
    async def guildinfo(self, ctx: commands.Context, target: str = None) -> None:
        await ack(ctx)
        if target:
            guild_id = parse_snowflake(target)
            guild = self.bot.get_guild(guild_id)
            if guild is None:
                try:
                    guild = await self.bot.fetch_guild(guild_id)
                except discord.NotFound:
                    raise NotFound("This bot is not a member of that guild.") from None
                except discord.HTTPException as exc:
                    raise SourceUnavailable(f"Discord rejected the guild lookup ({exc.status}).") from exc
        else:
            if ctx.guild is None:
                raise UsageError("Run this in a server or supply a guild ID.")
            guild = ctx.guild
        embed = Intel(
            category="discord",
            command="guildinfo",
            ctx=ctx,
            target=f"{guild.name}",
            summary="Only guilds this bot has joined are visible. Membership is required by Discord's API.",
        )
        embed.kv(
            "GUILD",
            {
                "Name": guild.name,
                "ID": guild.id,
                "Owner ID": guild.owner_id,
                "Created": fmt_dt(guild.created_at),
                "Age": human_delta((utcnow() - guild.created_at).total_seconds()),
                "Locale": str(guild.preferred_locale),
                "Verification": VERIFICATION.get(int(guild.verification_level), str(guild.verification_level)),
                "NSFW level": str(guild.nsfw_level),
            },
            inline=True,
        )
        embed.kv(
            "SCALE",
            {
                "Members (cached)": num(guild.member_count),
                "Roles": num(len(guild.roles)),
                "Emojis": num(len(guild.emojis)),
                "Stickers": num(len(guild.stickers)),
                "Boost tier": guild.premium_tier,
                "Boosts": num(guild.premium_subscription_count),
                "Channels": num(len(guild.channels)),
            },
            inline=True,
        )
        embed.kv(
            "FEATURES",
            {"Enabled": (guild.features or [])[:14] or "none", "Banner": bool(guild.banner), "Splash": bool(guild.splash)},
            inline=False,
        )
        embed.thumbnail(guild.icon.url if guild.icon else None)
        embed.source("Discord gateway")
        await embed.send(ctx)

    @intel(
        category="discord",
        brief="Webhook metadata from a webhook URL without executing it.",
        usage="<webhook url>",
        aliases=["wh"],
        examples=["webhook https://discord.com/api/webhooks/123456789012345678/token"],
        sources=["Discord REST API"],
        cooldown=(3, 15),
    )
    async def webhook(self, ctx: commands.Context, target: str = None) -> None:
        await ack(ctx)
        raw = require(target, "webhook URL", example=".webhook https://discord.com/api/webhooks/<id>/<token>")
        parts = [part for part in urlsplit(raw).path.split("/") if part]
        if len(parts) < 4 or parts[0] != "api" or parts[1] != "webhooks":
            raise UsageError("Expected `https://discord.com/api/webhooks/<id>/<token>`.")
        webhook_id, token = parts[2], parts[3]
        if not webhook_id.isdigit():
            raise UsageError("The webhook ID is not numeric.")
        payload = await self.http.discord(f"/webhooks/{webhook_id}/{token}")
        embed = Intel(
            category="discord",
            command="webhook",
            ctx=ctx,
            target=webhook_id,
            summary="The token authenticates the webhook, so this endpoint works without bot permissions. Nothing is posted.",
        )
        embed.kv(
            "WEBHOOK",
            {
                "ID": payload.get("id"),
                "Name": payload.get("name"),
                "Type": WEBHOOK_TYPES.get(payload.get("type"), payload.get("type")),
                "Channel ID": payload.get("channel_id"),
                "Guild ID": payload.get("guild_id"),
                "Application": payload.get("application_id"),
                "Token present": bool(payload.get("token")),
                "URL": f"https://discord.com/api/webhooks/{payload.get('id')}/…",
            },
            inline=True,
        )
        owner = payload.get("user") or {}
        embed.kv(
            "OWNER",
            {
                "Username": owner.get("username"),
                "ID": owner.get("id"),
                "Bot": owner.get("bot"),
                "Avatar": bool(owner.get("avatar")),
            },
            inline=True,
        )
        embed.checks(
            "HYGIENE",
            [
                (True, "Read-only", "no message was sent"),
                (None, "Warning", "a leaked webhook token lets anyone post as that webhook — rotate it if exposed"),
            ],
        )
        embed.source("Discord REST")
        await embed.send(ctx)

    @intel(
        category="discord",
        brief="Resolve a custom emoji to its CDN asset and metadata.",
        usage="<emoji>",
        aliases=["emojiinfo"],
        examples=["emoji <:wave:123456789012345678>"],
        sources=["local parse", "Discord CDN"],
        cooldown=(4, 8),
    )
    async def emoji(self, ctx: commands.Context, target: str = None) -> None:
        await ack(ctx)
        raw = require(target, "custom emoji", example=".emoji <:wave:123456789012345678>")
        match = re.fullmatch(r"<(a?):([A-Za-z0-9_~]{2,32}):(\d{15,21})>", raw.strip())
        if not match:
            raise UsageError("Expected a custom emoji in `<:name:id>` or `<a:name:id>` form.")
        animated, name, emoji_id = match.group(1) == "a", match.group(2), match.group(3)
        extension = "gif" if animated else "png"
        embed = Intel(
            category="discord",
            command="emoji",
            ctx=ctx,
            target=f":{name}:",
            summary="Custom emoji IDs are snowflakes, so you can recover the upload time from the CDN identifier alone.",
        )
        embed.kv(
            "EMOJI",
            {
                "Name": name,
                "ID": emoji_id,
                "Animated": animated,
                "Created": fmt_dt(snowflake_time(int(emoji_id))),
                "Type": "application emoji" if int(emoji_id) > 2**62 else "standard",
            },
            inline=True,
        )
        embed.kv(
            "ASSETS",
            {
                "128 px": f"https://cdn.discordapp.com/emojis/{emoji_id}.{extension}?size=128",
                "512 px": f"https://cdn.discordapp.com/emojis/{emoji_id}.{extension}?size=512",
                "Markdown": raw,
            },
            inline=False,
        )
        embed.thumbnail(f"https://cdn.discordapp.com/emojis/{emoji_id}.{extension}?size=128")
        embed.source("Discord CDN")
        await embed.send(ctx)

    @intel(
        category="discord",
        brief="Live Discord platform status, degraded components and active incidents.",
        usage="",
        aliases=["discordstatus", "dstatus"],
        sources=["discordstatus.com"],
        cooldown=(3, 20),
    )
    async def status(self, ctx: commands.Context) -> None:
        await ack(ctx)
        payload = await self.http.get_json("https://discordstatus.com/api/v2/summary.json", cache_ttl=120)
        indicator = (payload.get("status") or {}).get("indicator", "unknown")
        components = payload.get("components") or []
        degraded = [component for component in components if component.get("status") != "operational"]
        incidents = payload.get("incidents") or []
        maintenances = payload.get("scheduled_maintenances") or []
        embed = Intel(
            category="discord",
            command="status",
            ctx=ctx,
            target="discord.com",
            summary="The official Statuspage feed, cached for two minutes. Useful before blaming your own code for a 502.",
        )
        embed.kv(
            "PLATFORM",
            {
                "Indicator": indicator,
                "Description": (payload.get("status") or {}).get("description"),
                "Components": len(components),
                "Degraded": len(degraded),
                "Incidents": len(incidents),
                "Scheduled maintenance": len(maintenances),
            },
            inline=True,
        )
        embed.checks(
            "COMPONENT HEALTH",
            [
                (component.get("status") == "operational", component.get("name", "?"), component.get("status", "?"))
                for component in components[:14]
            ],
        )
        if incidents:
            rows = [
                f"**{incident.get('name')}** — {incident.get('status')} / {incident.get('impact')}\n{clip(incident.get('shortlink') or '', 90)}"
                for incident in incidents[:5]
            ]
            embed.text("ACTIVE INCIDENTS", "\n".join(rows), inline=False)
        if maintenances:
            rows = [
                f"**{item.get('name')}** — {item.get('status')} · {item.get('scheduled_for')}"
                for item in maintenances[:5]
            ]
            embed.text("MAINTENANCE", "\n".join(rows), inline=False)
        embed.source("discordstatus.com")
        await embed.send(ctx)


async def setup(bot: Any) -> None:
    await bot.add_cog(DiscordIntel(bot))

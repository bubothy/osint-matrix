"""Watchtower: vanity and username availability, plus a patient sniper.

Two Discord properties are worth watching:

* **vanity URLs** (``discord.gg/name``) are guild-owned. A code that returns no
  invite is not held by any guild this token can see, which is the closest a
  bot can get to "available" without trying to claim it;
* **usernames** are checked through the same unauthenticated endpoint the web
  client uses, so the answer reflects Discord's own reservation rules.

The sniper is a small polling loop per target. It never claims anything: it
watches, reports the moment a target frees up, and stops. Claiming a vanity
needs ``MANAGE_GUILD`` on the guild and is left to the operator.
"""

from __future__ import annotations

import asyncio
import re
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Any

import discord
from discord.ext import commands

from config import settings
from core import v2
from core.command import intel
from core.embeds import Intel, notice
from core.errors import IntelError, SourceUnavailable, UsageError
from core.utils import ack, clip, human_delta, utcnow

API = "https://discord.com/api"
MIN_INTERVAL = 30
MAX_WATCHES = 8
_CACHE_SECONDS = 30
_VANITY_RE = re.compile(r"^[a-z0-9-]{2,32}$")
_VANITY_INPUT_RE = re.compile(r"^[A-Za-z0-9_-]{2,64}$")
_USERNAME_RE = re.compile(r"^[a-z0-9._]{2,32}$")


def _clean_vanity(raw: str | None) -> str:
    """Normalise any invite form: URL, path, `discord.gg/x`, or bare token."""
    value = (raw or "").strip().strip("<>")
    if not value:
        raise UsageError("Give a vanity code, e.g. `.vanitycheck greed`.")
    value = re.sub(
        r"^(?:https?://)?(?:www\.)?(?:discord\.gg|discord(?:app)?\.com/invite|discord\.com/invite)/",
        "",
        value,
        flags=re.IGNORECASE,
    )
    value = value.split("?")[0].strip("/ ")
    if "discord.gg" in value.lower():
        value = re.sub(r"^.*discord\.gg/", "", value, flags=re.IGNORECASE)
    if not _VANITY_INPUT_RE.fullmatch(value):
        raise UsageError("A vanity code is 2–64 characters of `a-z`, `0-9` and `-`.")
    return value


def _invite_candidates(value: str) -> list[str]:
    """Vanity codes and full invite codes resolve through the same endpoint.

    A 8–32 character token may be a base64 invite code rather than a vanity, so
    the candidates include the decoded ASCII forms before giving up.
    """
    import base64

    candidates = [value]
    if 6 <= len(value) <= 64:
        for pad in ("", "=", "=="):
            try:
                decoded = base64.urlsafe_b64decode(value + pad)
            except Exception:  # noqa: BLE001 - not every token is base64
                continue
            if decoded and all(32 <= byte < 127 for byte in decoded):
                text = decoded.decode("ascii")
                if text not in candidates:
                    candidates.append(text)
    return candidates[:4]


def _clean_username(raw: str | None) -> str:
    value = (raw or "").strip().lstrip("@").lower()
    if not value:
        raise UsageError("Give a username, e.g. `.usercheck greed`.")
    if not _USERNAME_RE.fullmatch(value):
        raise UsageError("A Discord username is 2–32 characters of `a-z`, `0-9`, `.` and `_`.")
    if ".." in value or value.startswith(".") or value.endswith("."):
        raise UsageError("A username cannot start, end or contain consecutive periods.")
    if "discord" in value:
        raise UsageError("Discord reserves usernames that contain `discord`.")
    return value


@dataclass
class Watch:
    """One polling loop for a target that is not available yet."""

    key: str
    kind: str
    target: str
    interval: int
    channel_id: int
    user_id: int
    started: float = field(default_factory=time.monotonic)
    checks: int = 0
    note: str = "waiting for the first poll"
    task: asyncio.Task[None] | None = None


class Watchtower(commands.Cog, name="Watchtower"):
    """Vanity and username checkers with a background sniper."""

    def __init__(self, bot: Any) -> None:
        self.bot = bot
        self.net = bot.net
        self.watches: dict[str, Watch] = {}
        self._vanity_cache: dict[str, tuple[float, dict[str, Any]]] = {}

    async def cog_unload(self) -> None:
        for watch in list(self.watches.values()):
            if watch.task is not None:
                watch.task.cancel()
        self.watches.clear()

    # ── transport ────────────────────────────────────────────────────────

    async def _api(
        self,
        path: str,
        *,
        method: str = "GET",
        params: dict[str, Any] | None = None,
        json_body: Any = None,
        version: str = "v10",
        auth: bool = True,
    ) -> tuple[int, Any]:
        headers = {"Accept": "application/json", "User-Agent": "DiscordBot (0swald, 1.0)"}
        if auth:
            headers["Authorization"] = f"Bot {settings.token}"
        response = await self.net.request(
            method,
            f"{API}/{version}{path}",
            params=params,
            json_body=json_body,
            headers=headers,
            cache=False,
        )
        try:
            payload = response.json()
        except Exception:  # noqa: BLE001 - a body may be empty on 404
            payload = {}
        return response.status, payload

    # ── state probes ─────────────────────────────────────────────────────

    async def _min_interval(self) -> int:
        """Polling floor, operator-configurable through the website config card."""
        raw = await self.bot.store.kv_get("wt_interval")
        try:
            return max(MIN_INTERVAL, min(3600, int(str(raw or MIN_INTERVAL))))
        except (TypeError, ValueError):
            return MIN_INTERVAL

    async def _resolve_vanity(self, raw: str | None) -> tuple[str, dict[str, Any]]:
        """Find whichever form of the code is actually held, then report it.

        This is what makes every vanity command work with pasted invite links and
        full invite codes, not just vanity slugs.
        """
        value = _clean_vanity(raw)
        seen: list[str] = []
        for candidate in _invite_candidates(value):
            for variant in (candidate, candidate.lower()):
                if variant in seen:
                    continue
                seen.append(variant)
                state = await self._vanity_state(variant)
                if not state["available"]:
                    return variant, state
        return value, await self._vanity_state(value)

    async def _vanity_state(self, code: str) -> dict[str, Any]:
        cached = self._vanity_cache.get(code)
        if cached is not None and time.monotonic() - cached[0] < _CACHE_SECONDS:
            return cached[1]
        status, payload = await self._api(
            f"/invites/{urllib.parse.quote(code)}",
            params={"with_counts": "true", "with_expiration": "true"},
        )
        if status == 404:
            state = {
                "available": True,
                "summary": "no invite exists for this code",
                "detail": "Discord answered 404 — no guild holds this vanity right now",
            }
            self._vanity_cache[code] = (time.monotonic(), state)
            return state
        if status == 429:
            retry = float(payload.get("retry_after", 5) or 5)
            raise SourceUnavailable(f"Discord rate-limited the invite lookup. Retry in {retry:.0f}s.")
        if status in {401, 403}:
            raise IntelError("Discord refused the invite lookup with this token.")
        if status != 200:
            raise SourceUnavailable(f"Discord answered HTTP {status} for that vanity code.")
        guild = payload.get("guild") or {}
        state = {
            "available": False,
            "summary": guild.get("name") or payload.get("channel", {}).get("name") or "held",
            "detail": "this vanity resolves to a live invite",
            "payload": payload,
            "guild": guild,
        }
        self._vanity_cache[code] = (time.monotonic(), state)
        return state

    async def _username_state(self, name: str) -> dict[str, Any]:
        status, payload = await self._api(
            "/unique-username/username-attempt-unauthed",
            method="POST",
            json_body={"username": name},
            version="v9",
            auth=False,
        )
        if status == 200 and isinstance(payload, dict) and "taken" in payload:
            taken = bool(payload.get("taken"))
            return {
                "available": not taken,
                "summary": "taken" if taken else "available",
                "detail": "Discord's own username reservation check",
            }
        if status == 400:
            raise UsageError("Discord rejected that username shape.")
        if status in {401, 403, 404, 429, 500, 502, 503}:
            retry = payload.get("retry_after") if isinstance(payload, dict) else None
            hint = f" Retry in {float(retry):.0f}s." if retry else ""
            raise SourceUnavailable(
                f"Discord's username endpoint answered HTTP {status}.{hint} It is unauthenticated and rate-limited by IP."
            )
        raise SourceUnavailable(f"Unexpected answer from Discord (HTTP {status}).")

    async def _state(self, kind: str, target: str) -> dict[str, Any]:
        if kind == "vanity":
            return await self._vanity_state(target)
        return await self._username_state(target)

    # ── presentation ─────────────────────────────────────────────────────

    def _vanity_embed(self, code: str, state: dict[str, Any], *, command: str, ctx: Any) -> Intel:
        payload = state.get("payload") or {}
        guild = state.get("guild") or {}
        channel = payload.get("channel") or {}
        embed = Intel(
            category="discord",
            command=command,
            ctx=ctx,
            target=f"discord.gg/{code}",
            summary="Availability is inferred from Discord's public invite resolution.",
        )
        embed.kv(
            "VANITY",
            {
                "code": code,
                "status": "AVAILABLE" if state["available"] else "HELD",
                "url": f"https://discord.gg/{code}",
                "checked": utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
            },
            inline=True,
        )
        if state["available"]:
            embed.kv(
                "READING",
                {
                    "answer": "no guild holds this code",
                    "meaning": "any guild with MANAGE_GUILD can claim it",
                    "limits": "a vanity can be claimed the moment you release it, so act fast",
                },
                inline=False,
            )
        else:
            embed.kv(
                "HOLDER",
                {
                    "guild": guild.get("name") or "unknown",
                    "guild id": guild.get("id") or "—",
                    "features": ", ".join((guild.get("features") or [])[:4]) or "—",
                    "verified": "yes" if "VERIFIED" in (guild.get("features") or []) else "no",
                    "channel": f"#{channel.get('name')}" if channel.get("name") else "—",
                    "members": payload.get("approximate_member_count") or "—",
                    "online": payload.get("approximate_presence_count") or "—",
                    "expires": payload.get("expires_at") or "never",
                },
                inline=False,
            )
            embed.checks(
                "SIGNALS",
                [
                    (True, "invite resolves", "code is in use"),
                    (payload.get("approximate_member_count", 0) >= 1000, "sizeable guild", f"{payload.get('approximate_member_count')} members"),
                    (not payload.get("expires_at"), "permanent invite", "no expiry field"),
                ],
            )
        embed.source("discord invites api")
        return embed

    def _username_embed(self, name: str, state: dict[str, Any], *, command: str, ctx: Any) -> Intel:
        embed = Intel(
            category="discord",
            command=command,
            ctx=ctx,
            target=name,
            summary="Checked against Discord's username reservation endpoint.",
        )
        embed.kv(
            "USERNAME",
            {
                "handle": name,
                "status": "AVAILABLE" if state["available"] else "TAKEN",
                "length": len(name),
                "shape": "lowercase" if name == name.lower() else "mixed",
                "checked": utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
            },
            inline=True,
        )
        embed.checks(
            "RULES",
            [
                (2 <= len(name) <= 32, "length 2–32", f"{len(name)} characters"),
                (bool(_USERNAME_RE.fullmatch(name)), "allowed characters", "a-z, 0-9, dot, underscore"),
                (".." not in name, "no consecutive periods", "reserved by Discord"),
                ("discord" not in name, "no reserved word", "`discord` is blocked"),
            ],
        )
        embed.source("discord username check")
        return embed

    # ── announcements ────────────────────────────────────────────────────

    async def _announce(self, watch: Watch, state: dict[str, Any]) -> None:
        channel = self.bot.get_channel(watch.channel_id)
        if channel is None:
            try:
                fetched = await self.bot.fetch_channel(watch.channel_id)
                channel = fetched if isinstance(fetched, discord.abc.Messageable) else None
            except discord.HTTPException:
                channel = None
        if channel is None:
            return
        label = "VANITY" if watch.kind == "vanity" else "USERNAME"
        embed = notice(
            f"{label} RELEASED",
            f"`{watch.target}` is available. The watch ran {watch.checks} checks in "
            f"{human_delta(time.monotonic() - watch.started)}.",
            category="ok",
            fields=[
                ("TARGET", f"`{watch.target}`", True),
                ("KIND", watch.kind, True),
                ("CHECKED", utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"), True),
                ("NEXT STEP", f"`{settings.prefix}sniperstop {watch.target}` to clear the watch, then claim it yourself.", False),
            ],
            footer="watchtower · watch closed",
        )
        try:
            await channel.send(
                view=v2.build_layout(embed),
                allowed_mentions=discord.AllowedMentions.none(),
            )
        except discord.HTTPException:
            pass

    async def _loop(self, watch: Watch) -> None:
        try:
            while True:
                await asyncio.sleep(watch.interval)
                watch.checks += 1
                try:
                    state = await self._state(watch.kind, watch.target)
                except (SourceUnavailable, IntelError, UsageError) as exc:
                    watch.note = f"poll error · {clip(str(exc), 90)}"
                    continue
                if state["available"]:
                    await self._announce(watch, state)
                    return
                watch.note = f"held by {clip(str(state.get('summary')), 60)}"
        except asyncio.CancelledError:  # pragma: no cover - shutdown path
            raise
        finally:
            self.watches.pop(watch.key, None)

    # ── commands ─────────────────────────────────────────────────────────

    @intel(
        category="discord",
        brief="Check whether a Discord vanity URL is available.",
        usage="vanitycheck <code>",
        aliases=["vcheck", "vanity"],
        examples=["vanitycheck greed", "vcheck discord.gg/greed"],
        sources=["discord invites api"],
        cooldown=(2, 5),
    )
    async def vanitycheck(self, ctx: commands.Context, target: str = None) -> None:
        await ack(ctx)
        requested = _clean_vanity(target)
        code, state = await self._resolve_vanity(target)
        embed = self._vanity_embed(code, state, command="vanitycheck", ctx=ctx)
        if code != requested:
            embed.quote(f"resolved from `{clip(requested, 40)}`")
        await embed.send(ctx)

    @intel(
        category="discord",
        brief="Watch a vanity URL and report the moment it frees up.",
        usage="vanitysnipe <code> [seconds]",
        aliases=["vsnipe"],
        examples=["vanitysnipe greed", "vsnipe greed 120"],
        sources=["discord invites api"],
        cooldown=(2, 8),
    )
    async def vanitysnipe(self, ctx: commands.Context, target: str = None, interval: str = None) -> None:
        await ack(ctx)
        code, state = await self._resolve_vanity(target)
        await self._start_watch(
            ctx, "vanity", code, interval, command="vanitysnipe", state=state
        )

    @intel(
        category="discord",
        brief="Check several vanity codes in one pass.",
        usage="vanitywatch <code> [code …]",
        aliases=["vbatch", "vanityscan"],
        examples=["vanitywatch greed nitro boost", "vanitywatch greed, nitro"],
        sources=["discord invites api"],
        cooldown=(2, 15),
    )
    async def vanitywatch(self, ctx: commands.Context, target: str = None) -> None:
        await ack(ctx)
        if not target or not target.strip():
            raise UsageError(f"Give one or more codes: `{settings.prefix}vanitywatch greed nitro`.")
        tokens = [token for token in re.split(r"[,\s]+", target) if token][:MAX_WATCHES]
        rows: list[tuple[Any, ...]] = []
        free: list[str] = []
        for token in tokens:
            try:
                code, state = await self._resolve_vanity(token)
            except (SourceUnavailable, IntelError) as exc:
                rows.append((clip(token, 18), "ERROR", clip(str(exc), 26), "—"))
                continue
            rows.append(
                (
                    clip(token, 18),
                    "FREE" if state["available"] else "HELD",
                    "—" if state["available"] else clip(str(state.get("summary")), 26),
                    clip(code, 20) if code != token else "—",
                )
            )
            if state["available"]:
                free.append(code)
            await asyncio.sleep(0.25)

        embed = Intel(
            category="discord",
            command="vanitywatch",
            ctx=ctx,
            target=f"{len(tokens)} codes",
            summary="Each code is resolved as a vanity, a path or a full invite code.",
        )
        embed.table("VANITY BATCH", ("INPUT", "STATUS", "HOLDER", "RESOLVED"), rows, max_column=26)
        embed.kv(
            "SUMMARY",
            {
                "free": str(len(free)),
                "held": str(len(tokens) - len(free)),
                "checked": utcnow().strftime("%H:%M:%S UTC"),
            },
            inline=True,
        )
        if free:
            embed.kv("FREE CODES", {"claim": ", ".join(f"discord.gg/{code}" for code in free)}, inline=False)
        embed.source("discord invites api")
        await embed.send(ctx)

    @intel(
        category="discord",
        brief="Check whether a Discord username is still available.",
        usage="usernamecheck <username>",
        aliases=["ucheck", "useravail"],
        examples=["usernamecheck greed", "ucheck osint"],
        sources=["discord username check"],
        cooldown=(2, 5),
    )
    async def usernamecheck(self, ctx: commands.Context, target: str = None) -> None:
        await ack(ctx)
        name = _clean_username(target)
        state = await self._username_state(name)
        await self._username_embed(name, state, command="usernamecheck", ctx=ctx).send(ctx)

    @intel(
        category="discord",
        brief="Watch a username and report the moment it frees up.",
        usage="usernamesnipe <username> [seconds]",
        aliases=["usersnipe", "usnipe"],
        examples=["usernamesnipe greed", "usnipe greed 120"],
        sources=["discord username check"],
        cooldown=(2, 8),
    )
    async def usernamesnipe(self, ctx: commands.Context, target: str = None, interval: str = None) -> None:
        await ack(ctx)
        name = _clean_username(target)
        await self._start_watch(ctx, "username", name, interval, command="usernamesnipe")

    @intel(
        category="discord",
        brief="List the active sniper watches on this instance.",
        usage="sniperlist",
        aliases=["watches", "snipe"],
        sources=["local computation"],
        cooldown=(1, 4),
    )
    async def sniperlist(self, ctx: commands.Context) -> None:
        await ack(ctx)
        embed = Intel(
            category="discord",
            command="sniperlist",
            ctx=ctx,
            target=f"{len(self.watches)} active",
            summary="Each watch polls on its own timer and closes when the target frees up.",
        )
        if not self.watches:
            embed.kv(
                "WATCHES",
                {
                    "active": "none",
                    "start one": f"`{settings.prefix}vanitysnipe <code>` or `{settings.prefix}usernamesnipe <name>`",
                    "limits": f"minimum {await self._min_interval()}s interval · up to {MAX_WATCHES} watches",
                },
                inline=False,
            )
            await embed.send(ctx)
            return
        rows = []
        for watch in self.watches.values():
            rows.append(
                (
                    watch.kind,
                    watch.target,
                    f"{watch.interval}s",
                    str(watch.checks),
                    human_delta(time.monotonic() - watch.started),
                    clip(watch.note, 34),
                )
            )
        embed.table(
            "ACTIVE WATCHES",
            ("KIND", "TARGET", "EVERY", "POLLS", "AGE", "LAST"),
            rows,
            max_column=34,
        )
        embed.source("local computation")
        await embed.send(ctx)

    @intel(
        category="discord",
        brief="Stop one sniper watch, or all of them.",
        usage="sniperstop <target|all>",
        aliases=["snipecancel"],
        examples=["sniperstop greed", "sniperstop all"],
        sources=["local computation"],
        cooldown=(1, 4),
    )
    async def sniperstop(self, ctx: commands.Context, target: str = None) -> None:
        await ack(ctx)
        needle = (target or "").strip().lower()
        if not needle:
            raise UsageError(f"Give a target or `all`. Active watches: {', '.join(self.watches) or 'none'}.")
        if needle == "all":
            stopped = len(self.watches)
            for watch in list(self.watches.values()):
                if watch.task is not None:
                    watch.task.cancel()
            self.watches.clear()
            await v2_send(
                ctx,
                notice(
                    "WATCHES CLEARED",
                    f"{stopped} watch{'es' if stopped != 1 else ''} stopped.",
                    category="ok",
                ),
            )
            return
        match = next(
            (watch for key, watch in self.watches.items() if key.endswith(needle)),
            None,
        )
        if match is None:
            raise UsageError(f"No watch matches `{needle}`. Active: {', '.join(self.watches) or 'none'}.")
        if match.task is not None:
            match.task.cancel()
        self.watches.pop(match.key, None)
        await v2_send(
            ctx,
            notice(
                "WATCH STOPPED",
                f"`{match.target}` is no longer being polled after {match.checks} checks.",
                category="ok",
            ),
        )

    # ── shared watch start ───────────────────────────────────────────────

    async def _start_watch(
        self,
        ctx: commands.Context,
        kind: str,
        target: str,
        interval_raw: str | None,
        *,
        command: str,
        state: dict[str, Any] | None = None,
    ) -> None:
        minimum = await self._min_interval()
        interval = minimum
        if interval_raw and interval_raw.strip():
            try:
                interval = int(interval_raw.strip())
            except ValueError:
                raise UsageError("The interval must be a whole number of seconds.") from None
            interval = max(minimum, min(86_400, interval))
        if len(self.watches) >= MAX_WATCHES:
            raise UsageError(
                f"{MAX_WATCHES} watches already run. Stop one with `{settings.prefix}sniperstop all`."
            )
        key = f"{kind}:{target}"
        if key in self.watches:
            raise UsageError(f"`{target}` is already being watched. Use `{settings.prefix}sniperlist`.")

        if state is None:
            state = await self._state(kind, target)
        if state["available"]:
            if kind == "vanity":
                embed = self._vanity_embed(target, state, command=command, ctx=ctx)
            else:
                embed = self._username_embed(target, state, command=command, ctx=ctx)
            embed.quote("already available — no watch was started")
            await embed.send(ctx)
            return

        watch = Watch(
            key=key,
            kind=kind,
            target=target,
            interval=interval,
            channel_id=getattr(ctx.channel, "id", 0) or 0,
            user_id=getattr(ctx.author, "id", 0) or 0,
            note=f"held by {clip(str(state.get('summary')), 60)}",
        )
        self.watches[key] = watch
        watch.task = asyncio.create_task(self._loop(watch))

        embed = Intel(
            category="discord",
            command=command,
            ctx=ctx,
            target=target,
            summary="The watch polls until the target frees up, then posts one notice and closes itself.",
        )
        embed.kv(
            "WATCH",
            {
                "kind": kind,
                "target": target,
                "interval": f"{interval}s",
                "channel": f"<#{watch.channel_id}>" if watch.channel_id else "this channel",
                "active watches": f"{len(self.watches)}/{MAX_WATCHES}",
            },
            inline=True,
        )
        embed.kv(
            "CURRENT STATE",
            {
                "status": "HELD" if not state["available"] else "AVAILABLE",
                "holder": clip(str(state.get("summary")), 60),
                "reading": clip(str(state.get("detail")), 120),
            },
            inline=False,
        )
        embed.source("discord invites api" if kind == "vanity" else "discord username check")
        await embed.send(ctx)


async def v2_send(ctx: Any, embed: discord.Embed) -> None:
    """Send a plain notice through the V2 transport."""
    from core.embeds import respond

    await respond(ctx, embed)


async def setup(bot: Any) -> None:
    await bot.add_cog(Watchtower(bot))

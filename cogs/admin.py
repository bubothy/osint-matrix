"""System, access-control and self-documentation commands."""

from __future__ import annotations

import difflib
import platform
import time
from typing import Any

import discord
from discord.ext import commands

from config import OPTIONAL_KEYS, settings
from core import emojis
from core.checks import owner_only
from core.embeds import notice, respond
from core.errors import UsageError
from core.ui import Confirm, Paginator
from core.utils import (
    ack,
    as_int,
    clip,
    human_delta,
    num,
    require,
    strip_target,
    utcnow,
)

CATEGORY_ORDER = [
    ("network", "NETWORK", "IP, ASN, routing, transport, TLS, edge"),
    ("domain", "DOMAIN", "DNS records, WHOIS/RDAP, certificates, posture"),
    ("web", "WEB", "URLs, fingerprints, headers, robots, phishing heuristics"),
    ("identity", "IDENTITY", "Email, phone, usernames, hashes, tokens, encoding"),
    ("social", "SOCIAL", "Public profiles across developer and social platforms"),
    ("discord", "DISCORD", "Snowflakes, invites, guild and asset intelligence"),
    ("vuln", "VULNERABILITY", "CVEs, KEV, EPSS, CWE, malware and reputation"),
    ("crypto", "CRYPTO", "Public ledger address and transaction intelligence"),
]

SOURCE_REGISTRY: list[tuple[str, str, str]] = [
    ("DNS", "Cloudflare DoH, Google DoH, Quad9, AdGuard", "no key"),
    ("WHOIS", "IANA referral chain, port 43", "no key"),
    ("RDAP", "rdap.org bootstrap", "no key"),
    ("Certificates", "crt.sh, Cert Spotter", "no key"),
    ("IP geolocation", "ipwho.is", "no key"),
    ("BGP", "RIPEstat (stat.ripe.net)", "no key"),
    ("HTTP", "direct fetch, no proxy", "no key"),
    ("TLS", "local handshake inspection", "no key"),
    ("GitHub", "api.github.com", "optional GITHUB_TOKEN"),
    ("GitLab", "gitlab.com/api/v4", "no key"),
    ("Reddit", "reddit.com JSON", "no key"),
    ("Hacker News", "Firebase API", "no key"),
    ("Steam", "public XML / Web API", "optional STEAM_API_KEY"),
    ("Mojang", "api.mojang.com", "no key"),
    ("Roblox", "users.roblox.com", "no key"),
    ("Keybase", "keybase.io API", "no key"),
    ("Mastodon", "per-instance API", "no key"),
    ("Bluesky", "public.api.bsky.app", "no key"),
    ("npm", "registry.npmjs.org", "no key"),
    ("PyPI", "pypi.org JSON", "no key"),
    ("telegram", "t.me preview", "no key"),
    ("NVD", "services.nvd.nist.gov", "optional NVD_API_KEY"),
    ("CISA KEV", "cisa.gov feed", "no key"),
    ("EPSS", "api.first.org", "no key"),
    ("CWE", "cwe-api.mitre.org", "no key"),
    ("urlscan.io", "urlscan.io API", "optional URLSCAN_API_KEY"),
    ("VirusTotal", "www.virustotal.com/api/v3", "optional VIRUSTOTAL_API_KEY"),
    ("Shodan", "api.shodan.io", "optional SHODAN_API_KEY"),
    ("AbuseIPDB", "api.abuseipdb.com", "optional ABUSEIPDB_API_KEY"),
    ("abuse.ch", "mb-api.abuse.ch", "optional ABUSECH_AUTH_KEY"),
    ("HIBP", "haveibeenpwned.com/api/v3", "optional HIBP_API_KEY"),
    ("Bitcoin", "blockstream.info", "no key"),
    ("Ethereum", "cloudflare-eth.com", "no key"),
    ("Solana", "api.mainnet-beta.solana.com", "no key"),
]


class Admin(commands.Cog, name="System"):
    """Access control, telemetry, documentation and operator commands."""

    def __init__(self, bot: Any) -> None:
        self.bot = bot

    # ── helpers ──────────────────────────────────────────────────────────

    async def _resolve_user(self, raw: str) -> Any:
        value = strip_target(raw)
        if not value.isdigit():
            raise UsageError("Provide a numeric Discord user ID or a mention.")
        try:
            return await self.bot.fetch_user(int(value))
        except discord.HTTPException:
            return discord.Object(id=int(value))

    @staticmethod
    def _label(user: Any) -> str:
        mention = getattr(user, "mention", None)
        return f"{mention} · `{user.id}`" if mention else f"`{user.id}`"

    def _command_index(self) -> dict[str, commands.Command]:
        index: dict[str, commands.Command] = {}
        for command in self.bot.commands:
            if command.hidden:
                continue
            index[command.name.lower()] = command
            for alias in command.aliases:
                index.setdefault(alias.lower(), command)
        return index

    def _counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for command in self.bot.commands:
            if command.hidden:
                continue
            category = command.extras.get("category", "other")
            counts[category] = counts.get(category, 0) + 1
        return counts

    # ── documentation ────────────────────────────────────────────────────

    @commands.command(name="help", aliases=["h"], usage="[command]")
    async def help_command(self, ctx: commands.Context, *, target: str = None) -> None:
        """Show the command index or deep help for one command."""
        await ack(ctx)
        if target:
            await self._command_detail(ctx, target.strip())
            return
        counts = self._counts()
        total = sum(counts.values())
        prefix = await self.bot.store.get_prefix(ctx.guild.id) if ctx.guild else settings.prefix
        prefix = prefix or settings.prefix

        embed = notice(
            "OSINT MATRIX — COMMAND INDEX",
            "A private intelligence grid. Every lookup is logged, cached and rendered "
            "as a structured dossier. Prefix commands and slash shortcuts are both available.",
            category="admin",
            footer=f"{num(total)} commands  •  prefix `{prefix}`  •  slash /net /domain /web /identity /social /discord /vuln /crypto",
        )
        embed.add_field(
            name="▸ QUICK START",
            value=(
                f"```ini\n{prefix}ip 1.1.1.1\n{prefix}dns example.com\n"
                f"{prefix}username somehandle\n{prefix}recon example.com\n{prefix}help dns```"
            ),
            inline=False,
        )
        for key, label, blurb in CATEGORY_ORDER:
            names = sorted(
                command.name
                for command in self.bot.commands
                if not command.hidden and command.extras.get("category") == key
            )
            if not names:
                continue
            embed.add_field(
                name=f'▸ {label}  ·  {len(names)} commands',
                value=f'{blurb}\n' + clip(' '.join(emojis.label(name) for name in names), 1000),
                inline=False,
            )
        system = sorted(
            command.name for command in self.bot.commands if command.extras.get("category") in (None, "system")
        )
        if system:
            embed.add_field(
                name=f'▸ SYSTEM  ·  {len(system)} commands',
                value='Access control, telemetry and operator tooling\n' + clip(' '.join(emojis.label(name) for name in system), 1000),
                inline=False,
            )
        await respond(ctx, embed)

    async def _command_detail(self, ctx: commands.Context, query: str) -> None:
        index = self._command_index()
        command = self.bot.get_command(query) or index.get(query.lower())
        if command is None:
            close = difflib.get_close_matches(query.lower(), list(index), n=4, cutoff=0.5)
            await respond(
                ctx,
                notice(
                    "UNKNOWN COMMAND",
                    f"No command named `{clip(query, 60)}`.",
                    category="error",
                    fields=[("DID YOU MEAN", " · ".join(f"`{name}`" for name in close) or "run `help`", False)],
                ),
            )
            return

        category = command.extras.get("category", "system")
        sources = command.extras.get("sources", [])
        examples = command.extras.get("examples", [])
        cooldown = command.extras.get("cooldown")
        prefix = (await self.bot.store.get_prefix(ctx.guild.id)) if ctx.guild else settings.prefix
        prefix = prefix or settings.prefix

        mark = emojis.markup(command.name)
        brief = command.brief or command.help or 'No description registered.'
        embed = notice(
            f'{command.name.upper()}',
            f'{mark} {brief}' if mark else brief,
            category=category if category in {key for key, _, _ in CATEGORY_ORDER} else 'admin',
            footer=f'{len(command.aliases)} aliases  ·  category {category}',
        )
        embed.add_field(name="▸ SYNTAX", value=f"```ini\n{prefix}{command.qualified_name} {command.usage or ''}```", inline=False)
        if command.aliases:
            embed.add_field(name="▸ ALIASES", value="`" + "` `".join(command.aliases) + "`", inline=True)
        if cooldown:
            embed.add_field(name="▸ COOLDOWN", value=f"{cooldown[0]:.0f} uses / {cooldown[1]:.0f}s per user", inline=True)
        embed.add_field(name="▸ CATEGORY", value=f"`{category}`", inline=True)
        if examples:
            embed.add_field(
                name="▸ EXAMPLES",
                value="```ini\n" + "\n".join(f"{prefix}{example}" for example in examples) + "```",
                inline=False,
            )
        if sources:
            embed.add_field(name="▸ DATA SOURCES", value="\n".join(f"• {source}" for source in sources), inline=False)
        embed.add_field(
            name="▸ SLASH EQUIVALENT",
            value=f"`/{self._slash_group(category)} command:{command.name} args:<target>`",
            inline=False,
        )
        await respond(ctx, embed)

    @staticmethod
    def _slash_group(category: str) -> str:
        return {
            "network": "net",
            "domain": "domain",
            "web": "web",
            "identity": "identity",
            "social": "social",
            "discord": "discord",
            "vuln": "vuln",
            "crypto": "crypto",
        }.get(category, "net")

    @commands.command(name="commands", aliases=["cmds", "list"], usage="[category]")
    async def commands_list(self, ctx: commands.Context, category: str = None) -> None:
        """Paginated index with one field per command."""
        await ack(ctx)
        selected = category.lower().strip() if category else None
        base = notice(
            "COMMAND REGISTRY",
            "Every registered command, its syntax and its data sources.",
            category="admin",
        )
        sections: list[tuple[str, str]] = []
        for command in sorted(self.bot.commands, key=lambda c: (c.extras.get("category", "zz"), c.name)):
            if command.hidden:
                continue
            cat = command.extras.get("category", "system")
            if selected and cat != selected:
                continue
            sources = command.extras.get('sources', [])
            mark = emojis.markup(command.name)
            value = (
                f"{mark} `{command.usage or command.name}`\n"
                f"{command.brief or '—'}\n"
                f"-# {', '.join(sources) if sources else 'internal'}"
            ) if mark else (
                f"`{command.usage or command.name}`\n"
                f"{command.brief or '—'}\n"
                f"-# {', '.join(sources) if sources else 'internal'}"
            )
            sections.append((f"{command.name.upper()}  ·  {cat}", value))
        if not sections:
            await respond(ctx, notice("NO MATCH", f"No commands in category `{selected}`.", category="error"))
            return
        sections.insert(0, ("SUMMARY", f"`{len(sections)}` commands shown · filter: `{selected or 'all'}`"))
        from core.embeds import paginate

        pages = paginate(base, sections, per_page=4)
        await respond(ctx, pages[0], view=Paginator(pages, author_id=ctx.author.id))

    # ── access control ───────────────────────────────────────────────────

    @commands.command(name="approve", usage="<user id> [note]")
    @owner_only()
    async def approve(self, ctx: commands.Context, user: str = None, *, note: str = None) -> None:
        """Authorise a Discord user to use the bot."""
        await ack(ctx)
        raw = require(user, "user ID or mention", example=".approve 123456789012345678")
        target = await self._resolve_user(raw)
        await self.bot.store.approve(target.id, ctx.author.id, note)
        await self.bot.store.audit(ctx.author.id, "approve", str(target.id), note)
        embed = notice(
            "ACCESS GRANTED",
            "The user can now run every intelligence command. Their activity will be audited.",
            category="ok",
            fields=[
                ("TARGET", self._label(target), False),
                ("APPROVED BY", f"{ctx.author.mention} · `{ctx.author.id}`", True),
                ("SCOPE", "all intel commands" if not note else f"all commands · note: {clip(note, 200)}", True),
            ],
            footer="OSINT MATRIX  •  allow-list updated",
        )
        await respond(ctx, embed)
        await self._notify(target.id, "You have been authorised on a private OSINT MATRIX instance.")

    @commands.command(name="revoke", usage="<user id>")
    @owner_only()
    async def revoke(self, ctx: commands.Context, user: str = None) -> None:
        """Remove a user from the allow-list."""
        await ack(ctx)
        raw = require(user, "user ID or mention", example=".revoke 123456789012345678")
        target = await self._resolve_user(raw)
        removed = await self.bot.store.revoke(target.id)
        await self.bot.store.audit(ctx.author.id, "revoke", str(target.id), "removed" if removed else "absent")
        await respond(
            ctx,
            notice(
                "ACCESS REVOKED" if removed else "NOT ON THE LIST",
                "The user can no longer invoke any command." if removed else "That ID was not approved to begin with.",
                category="ok" if removed else "error",
                fields=[("TARGET", self._label(target), False)],
            ),
        )

    @commands.command(name="approvals", aliases=["allowlist"], usage="")
    @owner_only()
    async def approvals(self, ctx: commands.Context) -> None:
        """Show every approved user."""
        await ack(ctx)
        rows = await self.bot.store.approvals()
        base = notice(
            "ALLOW-LIST",
            f"`{len(rows)}` approved users. Owners are implicit and not listed here.",
            category="admin",
        )
        if not rows:
            await respond(ctx, notice("ALLOW-LIST EMPTY", "Only owners can use the bot right now.", category="admin"))
            return
        sections = []
        for row in rows:
            sections.append(
                (
                    f"USER {row['user_id']}",
                    f"approved by `{row['approved_by']}`\n"
                    f"at {row['approved_at']}\n"
                    f"note: {row.get('note') or '—'}",
                )
            )
        from core.embeds import paginate

        pages = paginate(base, sections, per_page=5)
        await respond(ctx, pages[0], view=Paginator(pages, author_id=ctx.author.id))

    @commands.command(name="audit", usage="[count]")
    @owner_only()
    async def audit(self, ctx: commands.Context, count: str = None) -> None:
        """Show recent audit entries from the database."""
        await ack(ctx)
        limit = as_int(count, default=12, low=1, high=50, label="count")
        rows = await self.bot.store.recent_audit(limit)
        lines = [
            f"`{row['ts'][5:19]}`  **{row['action']}**  {row['target'] or '—'}  · {row['actor'] or '—'}"
            + (f"  · {clip(row['detail'], 40)}" if row.get("detail") else "")
            for row in rows
        ]
        await respond(
            ctx,
            notice(
                "AUDIT TRAIL",
                "\n".join(lines) or "No entries yet.",
                category="admin",
                footer=f"last {len(rows)} events  •  SQLite data/osint.sqlite3",
            ),
        )

    # ── configuration ────────────────────────────────────────────────────

    @commands.group(name="prefix", invoke_without_command=True, usage="[set <value>]")
    async def prefix(self, ctx: commands.Context) -> None:
        """Show the prefix for this server."""
        await ack(ctx)
        custom = await self.bot.store.get_prefix(ctx.guild.id) if ctx.guild else None
        await respond(
            ctx,
            notice(
                "PREFIX CONFIGURATION",
                f"Effective prefix in this context: `{custom or settings.prefix}`",
                category="admin",
                fields=[
                    ("GLOBAL DEFAULT", f"`{settings.prefix}`", True),
                    ("THIS SERVER", f"`{custom}`" if custom else "inherits default", True),
                    ("MENTION", f"`@{ctx.me.display_name} help` also works", False),
                ],
                footer="Owners can change the server prefix with: prefix set <value>",
            ),
        )

    @prefix.command(name="set", usage="<value>")
    @owner_only()
    async def prefix_set(self, ctx: commands.Context, value: str = None) -> None:
        await ack(ctx)
        if ctx.guild is None:
            raise UsageError("Per-server prefixes only apply inside a server.")
        raw = require(value, "new prefix", example=".prefix set !")
        if len(raw) > 5 or " " in raw:
            raise UsageError("Prefix must be 1–5 characters with no spaces.")
        await self.bot.store.set_prefix(ctx.guild.id, raw)
        self.bot.prefix_cache[ctx.guild.id] = raw
        await self.bot.store.audit(ctx.author.id, "prefix", str(ctx.guild.id), raw)
        await respond(ctx, notice("PREFIX UPDATED", f"This server now uses `{raw}`.", category="ok"))

    @commands.command(name="maintenance", usage="[on|off|status]")
    @owner_only()
    async def maintenance(self, ctx: commands.Context, state: str = "status") -> None:
        """Lock the instance to owners only."""
        await ack(ctx)
        current = await self.bot.store.kv_get("maintenance") == "1"
        choice = state.strip().lower()
        if choice in {"on", "enable", "true", "1"}:
            await self.bot.store.kv_set("maintenance", "1")
            await self.bot.store.audit(ctx.author.id, "maintenance", "on", None)
            await respond(ctx, notice("MAINTENANCE ENABLED", "Only owners can run commands now.", category="ok"))
            return
        if choice in {"off", "disable", "false", "0"}:
            await self.bot.store.kv_set("maintenance", "0")
            await self.bot.store.audit(ctx.author.id, "maintenance", "off", None)
            await respond(ctx, notice("MAINTENANCE DISABLED", "The allow-list is active again.", category="ok"))
            return
        await respond(
            ctx,
            notice(
                "MAINTENANCE STATE",
                f"Currently **{'ENABLED' if current else 'DISABLED'}**.",
                category="admin",
                fields=[("TOGGLE", "`maintenance on` or `maintenance off`", False)],
            ),
        )

    # ── telemetry ────────────────────────────────────────────────────────

    @commands.command(name="ping", usage="")
    async def ping(self, ctx: commands.Context) -> None:
        """Latency, database and cache health."""
        started = time.perf_counter()
        db_started = time.perf_counter()
        await self.bot.store.metric("lookups")
        db_ms = (time.perf_counter() - db_started) * 1000
        embed = notice(
            "SYSTEM LATENCY",
            "Round-trip and subsystem timings for this shard.",
            category="admin",
            footer=f"OSINT MATRIX  •  {utcnow():%H:%M:%S} UTC",
        )
        embed.add_field(
            name="▸ TRANSPORT",
            value=f"```ini\ngateway   {self.bot.latency * 1000:.0f} ms\nsqlite    {db_ms:.1f} ms\ncache     {self.bot.net.cache_size()} entries```",
            inline=True,
        )
        embed.add_field(
            name="▸ PROCESS",
            value=f"```ini\nuptime    {human_delta(time.time() - self.bot.launch_time)}\npython    {platform.python_version()}\ndiscord   {discord.__version__}```",
            inline=True,
        )
        embed.add_field(
            name="▸ REQUESTS",
            value=f"```ini\nrequests  {num(self.bot.net.stats['requests'])}\ncached    {num(self.bot.net.stats['cache_hits'])}\nerrors    {num(self.bot.net.stats['errors'])}```",
            inline=False,
        )
        embed.add_field(name="▸ EDIT LATENCY", value=f"`{(time.perf_counter() - started) * 1000:.0f} ms`", inline=True)
        await respond(ctx, embed)

    @commands.command(name="stats", usage="")
    async def stats(self, ctx: commands.Context) -> None:
        """Instance-wide counters."""
        await ack(ctx)
        store = self.bot.store
        metrics = await store.metrics()
        top = await store.top_commands(7)
        total = await store.command_total()
        approved = await store.approved_count()
        audits = await store.audit_count()
        unique_commands = len(self.bot.commands)
        intel_commands = sum(1 for c in self.bot.commands if c.extras.get("category") in {k for k, _, _ in CATEGORY_ORDER})
        embed = notice(
            "INSTANCE TELEMETRY",
            "Aggregate counters from this deployment's SQLite store.",
            category="admin",
            footer=f"uptime {human_delta(time.time() - self.bot.launch_time)}  •  {unique_commands} commands",
        )
        embed.add_field(
            name="▸ FLEET",
            value=f"```ini\nguilds      {num(len(self.bot.guilds))}\napproved    {num(approved)}\nowners      {num(len(self.bot.owner_ids))}\naudit rows  {num(audits)}```",
            inline=True,
        )
        embed.add_field(
            name="▸ USAGE",
            value=f"```ini\nlookups     {num(total)}\nintel cmds  {num(intel_commands)}\nregistered  {num(unique_commands)}\nkeys        {num(len(OPTIONAL_KEYS))}```",
            inline=True,
        )
        embed.add_field(
            name="▸ TOP COMMANDS",
            value="\n".join(f"`{index:02d}` **{name}** — {num(count)}" for index, (name, count) in enumerate(top, 1)) or "no data",
            inline=False,
        )
        embed.add_field(
            name="▸ TRANSPORT",
            value=f"```ini\nhttp requests  {num(self.bot.net.stats['requests'])}\ncache hits     {num(self.bot.net.stats['cache_hits'])}\nbytes read     {num(self.bot.net.stats['bytes'])}\nretries        {num(self.bot.net.stats['retries'])}```",
            inline=False,
        )
        await respond(ctx, embed)

    @commands.command(name="whoami", aliases=["access"], usage="")
    async def whoami(self, ctx: commands.Context) -> None:
        """Show your access level and effective limits."""
        await ack(ctx)
        from core.checks import evaluate_access

        allowed, reason = await evaluate_access(self.bot, ctx.author.id)
        approvals = await self.bot.store.approvals()
        record = next((row for row in approvals if int(row["user_id"]) == ctx.author.id), None)
        custom = await self.bot.store.get_prefix(ctx.guild.id) if ctx.guild else None
        embed = notice(
            "IDENTITY & ACCESS",
            f"Signed in as {ctx.author.mention}.",
            category="ok" if allowed else "error",
            fields=[
                ("USER ID", f"`{ctx.author.id}`", True),
                ("ACCESS", f"`{reason.upper()}`", True),
                ("ALLOW-LIST", "yes" if record else ("implicit (owner)" if reason == "owner" else "no"), True),
            ],
        )
        if record:
            embed.add_field(
                name="▸ APPROVAL RECORD",
                value=f"approved by `{record['approved_by']}` at {record['approved_at']}\nnote: {record.get('note') or '—'}",
                inline=False,
            )
        embed.add_field(
            name="▸ CONTEXT",
            value=f"```ini\nprefix      {custom or settings.prefix}\nguild       {ctx.guild.name if ctx.guild else 'direct message'}\nchannel     #{getattr(ctx.channel, 'name', 'dm')}\nowners      {len(self.bot.owner_ids)}```",
            inline=False,
        )
        embed.add_field(
            name="▸ LIMITS",
            value="Per-command cooldowns and a shared upstream throttle apply. "
            "Every lookup is cached for faster repeats and logged to the operator's audit feed.",
            inline=False,
        )
        await respond(ctx, embed)

    @commands.command(name="sources", usage="")
    async def sources(self, ctx: commands.Context) -> None:
        """List every upstream data source and its key requirement."""
        await ack(ctx)
        embed = notice(
            "DATA SOURCE REGISTRY",
            "Every external service this instance can reach. No source is scraped: each is a documented API, "
            "public dataset or direct protocol.",
            category="admin",
            footer="OSINT MATRIX  •  data provenance",
        )
        chunk = SOURCE_REGISTRY[:12]
        embed.add_field(
            name="▸ PASSIVE",
            value="\n".join(f"**{name}** — {detail} `({key})`" for name, detail, key in chunk),
            inline=False,
        )
        rest = SOURCE_REGISTRY[12:]
        for index in range(0, len(rest), 12):
            embed.add_field(
                name=f"▸ SOURCES {index + 13}–{min(index + 24, len(SOURCE_REGISTRY))}",
                value="\n".join(f"**{name}** — {detail} `({key})`" for name, detail, key in rest[index : index + 12]),
                inline=False,
            )
        await respond(ctx, embed)

    @commands.command(name="apikeys", aliases=["keys"], usage="")
    async def apikeys(self, ctx: commands.Context) -> None:
        """Show which optional integrations are configured."""
        await ack(ctx)
        status = settings.optional_status()
        configured = [meta for meta, ok in status if ok]
        lines = []
        for meta, ok in status:
            glyph = "✓" if ok else "·"
            lines.append(f"`{glyph}` **{meta.service}** `{meta.env}` — {meta.cost}")
        embed = notice(
            "OPTIONAL INTEGRATIONS",
            f"{len(configured)}/{len(status)} configured. Missing keys never crash a command — "
            "it returns setup instructions instead.",
            category="admin",
            fields=[("▸ STATUS", "\n".join(lines), False)],
            footer="Add keys to .env, then restart or reload the relevant module.",
        )
        embed.add_field(
            name="▸ WHERE TO GET THEM",
            value="\n".join(f"**{meta.service}** — {meta.url}" for meta, ok in status if not ok) or "everything is configured",
            inline=False,
        )
        await respond(ctx, embed)

    # ── lifecycle ────────────────────────────────────────────────────────

    @commands.command(name="reload", usage="<module>")
    @owner_only()
    async def reload(self, ctx: commands.Context, module: str = None) -> None:
        """Hot-reload one cog or every cog."""
        await ack(ctx)
        raw = require(module, "module name", example=".reload network")
        name = raw if raw.startswith("cogs.") else f"cogs.{raw.replace('cogs.', '')}"
        if name == "cogs.all":
            await self.bot.sync_commands(verbose=False)
            await respond(ctx, notice("SYNC", "Application commands re-synced.", category="ok"))
            return
        await self.bot.reload_extension(name)
        self.bot.prefix_cache = await self.bot.store.prefixes()
        await respond(ctx, notice("MODULE RELOADED", f"`{name}` reloaded and commands re-registered.", category="ok"))

    @commands.command(name="sync", usage="")
    @owner_only()
    async def sync(self, ctx: commands.Context) -> None:
        """Force a slash-command sync."""
        await ack(ctx)
        count = await self.bot.sync_commands(force=True)
        await respond(
            ctx,
            notice(
                "APPLICATION COMMANDS SYNCED",
                f"`{count}` command entries pushed to Discord.",
                category="ok",
                fields=[
                    ("SCOPE", "global (servers, DMs, group DMs) + guild copy", False),
                    ("PROPAGATION", "guild copy is instant; global DMs can take up to 1 hour", False),
                ],
            ),
        )

    @commands.command(name="botinvite", usage="")
    async def botinvite(self, ctx: commands.Context) -> None:
        """Generate the OAuth2 invite URL for this bot."""
        await ack(ctx)
        permissions = discord.Permissions(
            view_channel=True,
            send_messages=True,
            embed_links=True,
            attach_files=True,
            read_message_history=True,
            add_reactions=True,
            use_external_emojis=True,
        )
        url = discord.utils.oauth_url(
            self.bot.user.id,
            permissions=permissions,
            scopes=("bot", "applications.commands"),
        )
        user_url = (
            f"https://discord.com/oauth2/authorize?client_id={self.bot.user.id}"
            "&integration_type=1&scope=applications.commands"
        )
        await respond(
            ctx,
            notice(
                "INVITE LINKS",
                f"[Add to a server]({url})\n[Add to your account for DMs and group DMs]({user_url})",
                category="admin",
                fields=[
                    ("SERVER SCOPES", "`bot` · `applications.commands`", True),
                    ("USER SCOPES", "`applications.commands` only — no server permissions", True),
                    ("PERMISSIONS", "read, send, embed, attach, history, reactions", False),
                    ("NOTE", "This bot is private: only approved IDs can invoke commands after install.", False),
                ],
            ),
        )

    @commands.command(name="about", usage="")
    async def about(self, ctx: commands.Context) -> None:
        """Version, scope and responsible-use notice."""
        await ack(ctx)
        total = len(self.bot.commands)
        intel_total = sum(1 for c in self.bot.commands if c.extras.get("category") in {k for k, _, _ in CATEGORY_ORDER})
        embed = notice(
            "OSINT MATRIX",
            "A private, self-hosted Open Source Intelligence console. It queries documented public APIs and "
            "never touches private accounts, leaked credential dumps or breach marketplaces.",
            category="admin",
            footer=f"v1.0.0  •  {intel_total} intel commands  •  {total} total commands",
        )
        embed.add_field(name="▸ SCOPE", value="\n".join(f"• {label}: {blurb}" for _, label, blurb in CATEGORY_ORDER), inline=False)
        embed.add_field(
            name="▸ ACCESS MODEL",
            value="Owners bypass the gate, everyone else must be approved by ID. Every invocation is written "
            "to a local SQLite audit log and optionally mirrored to a private channel.",
            inline=False,
        )
        embed.add_field(
            name="▸ RESPONSIBLE USE",
            value="Query only infrastructure you own or are authorised to assess, and respect local law, "
            "site terms and privacy expectations. The operator of this instance is accountable for its use.",
            inline=False,
        )
        await respond(ctx, embed)

    @commands.command(name="shutdown", usage="")
    @owner_only()
    async def shutdown(self, ctx: commands.Context) -> None:
        """Stop the bot process."""
        await ack(ctx)
        view = Confirm(author_id=ctx.author.id, confirm_label="Shut down")
        prompt = notice("CONFIRM SHUTDOWN", "This stops the bot process. Restart it with `run.bat`.", category="error")
        message = await respond(ctx, prompt, view=view)
        await view.wait()
        if view.value:
            await self.bot.store.audit(ctx.author.id, "shutdown", None, None)
            await self.bot.close()
        elif message is not None:
            await message.edit(embed=notice("SHUTDOWN CANCELLED", "Still running.", category="admin"), view=None)

    async def _notify(self, user_id: int, text: str) -> None:
        try:
            user = self.bot.get_user(user_id) or await self.bot.fetch_user(user_id)
            await user.send(embed=notice("OSINT MATRIX", text, category="admin"))
        except (discord.HTTPException, AttributeError):
            pass


async def setup(bot: Any) -> None:
    await bot.add_cog(Admin(bot))

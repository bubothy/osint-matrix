"""Operator console: read and write the access configuration.

The website's access page builds the same document and emits one
``accessimport`` line, so a config can be tuned in a browser and applied here
without hand-editing JSON. Keys are generated here and never leave the store.
"""

from __future__ import annotations

from typing import Any

from discord.ext import commands

from config import settings
from core import access
from core.checks import owner_only
from core.command import intel
from core.embeds import Intel, notice, respond
from core.errors import UsageError
from core.utils import ack, clip, num, utcnow

FIELD_HELP: dict[str, str] = {
    "brand": "Instance name used in headers and footers.",
    "prefix": "Prefix for text commands (1–5 characters).",
    "approval_required": "Only approved Discord IDs may run commands.",
    "allow_dms": "Permit prefix and slash commands in DMs.",
    "maintenance": "Owners only, everything else refused.",
    "maintenance_note": "Message shown while maintenance is on.",
    "denied_note": "Message shown to unapproved users.",
    "log_channel_id": "Channel that receives the audit feed.",
    "rate_limit_per_10s": "Dispatch ceiling for slash lookups.",
    "cooldown_seconds": "Window used by the dispatch limiter.",
    "watch_interval": "Default and minimum sniper poll interval.",
    "max_watches": "Ceiling on simultaneous sniper watches.",
    "audit": "Write lookups to the audit table.",
    "notes": "Free-form note stored with the config.",
}


class ConfigPanel(commands.Cog, name="Console"):
    """Access configuration, pairing key and import/export."""

    def __init__(self, bot: Any) -> None:
        self.bot = bot

    @property
    def store(self) -> Any:
        """Resolved lazily so the cog can load before the store exists."""
        return self.bot.store

    # ── rendering helpers ────────────────────────────────────────────────

    @staticmethod
    def _flag(value: Any) -> str:
        return "on" if bool(value) else "off"

    async def _snapshot(self, ctx: Any, *, command: str) -> None:
        cfg = await access.load(self.store)
        approved = await self.store.approved_count()
        audits = await self.store.audit_count()
        key = await self.store.kv_get(access.KEY_KV)
        total = sum(1 for c in self.bot.commands if not c.hidden)

        embed = Intel(
            category="admin",
            command=command,
            ctx=ctx,
            target=clip(str(cfg.get("brand")), 40),
            summary="Every value below is enforced by the check layer, not just displayed.",
        )
        embed.kv(
            "GATE",
            {
                "approval required": self._flag(cfg["approval_required"]),
                "maintenance": self._flag(cfg["maintenance"]),
                "dms": self._flag(cfg["allow_dms"]),
                "audit": self._flag(cfg["audit"]),
                "owners": num(len(self.bot.owner_ids)),
                "approved users": num(approved),
                "audit rows": num(audits),
            },
            inline=True,
        )
        embed.kv(
            "SURFACE",
            {
                "prefix": cfg["prefix"],
                "brand": cfg["brand"],
                "registered commands": num(total),
                "log channel": f"<#{cfg['log_channel_id']}>" if cfg["log_channel_id"] else "disabled",
                "rate limit": f"{cfg['rate_limit_per_10s']} / 10s",
                "watch interval": f"{cfg['watch_interval']}s",
                "max watches": str(cfg["max_watches"]),
            },
            inline=True,
        )
        embed.kv(
            "PAIRING KEY",
            {
                "state": "issued" if key else "not issued",
                "fingerprint": access.fingerprint(key),
                "rotate": f"`{settings.prefix}accesskey rotate`",
                "console": "site/access.html",
            },
            inline=False,
        )
        notes = access.warnings(cfg)
        if notes:
            embed.kv("WARNINGS", {"note": "  ·  ".join(notes[:4])}, inline=False)
        embed.source("local computation")
        await embed.send(ctx)

    # ── commands ─────────────────────────────────────────────────────────

    @commands.command(name="accesspanel", aliases=["config", "panel"], usage="")
    @owner_only()
    async def accesspanel(self, ctx: commands.Context) -> None:
        """Show the enforced access configuration."""
        await ack(ctx)
        await self._snapshot(ctx, command="accesspanel")

    @commands.command(name="accesskey", usage="[rotate|revoke|show]")
    @owner_only()
    async def accesskey(self, ctx: commands.Context, action: str = "show") -> None:
        """Issue, rotate, revoke or display the console pairing key."""
        await ack(ctx)
        choice = (action or "show").strip().lower()
        stored = await self.store.kv_get(access.KEY_KV)

        if choice in {"rotate", "new", "issue"}:
            key = access.new_key()
            await self.store.kv_set(access.KEY_KV, key)
            await self.store.audit(ctx.author.id, "accesskey", "rotate", None)
            await respond(
                ctx,
                notice(
                    "PAIRING KEY ROTATED",
                    "The previous key is now invalid. Keep this out of public channels.",
                    category="ok",
                    fields=[
                        ("KEY", f"```ini\n{key}\n```", False),
                        ("FINGERPRINT", f"`{access.fingerprint(key)}`", True),
                        ("ISSUED", utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"), True),
                    ],
                    footer="console · shown once",
                ),
            )
            return

        if choice in {"revoke", "delete", "clear"}:
            await self.store.kv_set(access.KEY_KV, None)
            await self.store.audit(ctx.author.id, "accesskey", "revoke", None)
            await respond(
                ctx,
                notice(
                    "PAIRING KEY REVOKED",
                    "No key is stored. The website console stays in preview mode until a new one is issued.",
                    category="ok",
                ),
            )
            return

        if not stored:
            await respond(
                ctx,
                notice(
                    "NO PAIRING KEY",
                    "Issue one with `accesskey rotate`. The key is generated locally and stored in SQLite.",
                    category="admin",
                    fields=[("ROTATE", f"`{settings.prefix}accesskey rotate`", False)],
                ),
            )
            return

        await respond(
            ctx,
            notice(
                "PAIRING KEY",
                "Only the fingerprint is rendered here. Rotate to mint a new key; the old one stops working.",
                category="admin",
                fields=[
                    ("FINGERPRINT", f"`{access.fingerprint(stored)}`", True),
                    ("LENGTH", f"`{len(stored)}`", True),
                    ("ROTATE", f"`{settings.prefix}accesskey rotate`", True),
                ],
            ),
        )

    @commands.command(name="accessset", usage="<field> <value>")
    @owner_only()
    async def accessset(self, ctx: commands.Context, field: str = None, *, value: str = None) -> None:
        """Set one access field. Run `accesspanel` for the current values."""
        await ack(ctx)
        if not field:
            raise UsageError(
                "Give a field and a value. Fields: `" + "`, `".join(FIELD_HELP) + "`."
            )
        key = field.strip().lower()
        if key not in access.DEFAULTS:
            raise UsageError(f"`{key}` is not a configuration field. Try `accesspanel`.")
        cfg = await access.load(self.store)
        if value is None or not str(value).strip():
            raise UsageError(f"`{key}` needs a value.")
        raw = str(value).strip()
        if key in {"approval_required", "allow_dms", "maintenance", "audit"}:
            cfg[key] = raw.lower() in {"1", "true", "on", "yes", "enabled"}
        else:
            cfg[key] = raw
        cfg = await access.save(self.store, cfg)
        await self.store.audit(ctx.author.id, "accessset", key, raw[:90])
        await respond(
            ctx,
            notice(
                "CONFIGURATION UPDATED",
                f"`{key}` is now applied. {FIELD_HELP.get(key, '')}",
                category="ok",
                fields=[
                    ("FIELD", f"`{key}`", True),
                    ("EFFECTIVE VALUE", f"`{clip(str(cfg[key]), 60)}`", True),
                    ("UPDATED", cfg["updated_at"], False),
                ],
            ),
        )

    @commands.command(name="accessexport", usage="")
    @owner_only()
    async def accessexport(self, ctx: commands.Context) -> None:
        """Export the configuration as one pasteable block for the console."""
        await ack(ctx)
        cfg = await access.load(self.store)
        blob = access.encode(cfg)
        embed = Intel(
            category="admin",
            command="accessexport",
            ctx=ctx,
            target=f"{len(blob)} chars",
            summary="Paste this into site/access.html → Import to load the live configuration.",
        )
        embed.code("EXPORT", blob, lang="text")
        embed.kv(
            "HOW TO USE IT",
            {
                "step 1": "open site/access.html",
                "step 2": "paste into the import box",
                "step 3": "edit, then copy the generated command",
                "step 4": f"`{settings.prefix}accessimport <code>`",
            },
            inline=False,
        )
        embed.source("local computation")
        await embed.send(ctx)

    @commands.command(name="accessimport", usage="<export>")
    @owner_only()
    async def accessimport(self, ctx: commands.Context, *, blob: str = None) -> None:
        """Apply a configuration exported by the website console."""
        await ack(ctx)
        if not blob or not blob.strip():
            raise UsageError(f"Paste the export after the command: `{settings.prefix}accessimport <code>`.")
        try:
            cfg = access.decode(blob)
        except ValueError as exc:
            raise UsageError(str(exc)) from None
        before = await access.load(self.store)
        cfg = await access.save(self.store, cfg)
        changed = [
            key
            for key in access.DEFAULTS
            if key not in {"updated_at"} and before.get(key) != cfg.get(key)
        ]
        await self.store.audit(ctx.author.id, "accessimport", "config", ", ".join(changed)[:120])
        embed = Intel(
            category="admin",
            command="accessimport",
            ctx=ctx,
            target=f"{len(changed)} field(s) changed",
            summary="The configuration is live; no restart is required.",
        )
        embed.kv(
            "APPLIED",
            {key: clip(str(cfg[key]), 40) for key in changed[:10]} if changed else {"result": "no changes"},
            inline=False,
        )
        notes = access.warnings(cfg)
        if notes:
            embed.kv("WARNINGS", {"note": "  ·  ".join(notes[:4])}, inline=False)
        embed.checks(
            "VERIFICATION",
            [
                (True, "configuration stored", cfg["updated_at"]),
                (before.get("maintenance") == cfg.get("maintenance"), "maintenance unchanged", self._flag(cfg["maintenance"])),
                (cfg["watch_interval"] >= 45, "watch interval safe", f"{cfg['watch_interval']}s"),
            ],
        )
        embed.source("local computation")
        await embed.send(ctx)

    @commands.command(name="accessfields", usage="")
    async def accessfields(self, ctx: commands.Context) -> None:
        """List every configuration field, its type and its current value."""
        await ack(ctx)
        cfg = await access.load(self.store)
        rows = []
        for key, help_text in FIELD_HELP.items():
            value = cfg.get(key)
            if isinstance(value, bool):
                rendered = self._flag(value)
            elif isinstance(value, int):
                rendered = str(value)
            else:
                rendered = clip(str(value or "—"), 30) or "—"
            rows.append((key, rendered, clip(help_text, 46)))
        embed = Intel(
            category="admin",
            command="accessfields",
            ctx=ctx,
            target=f"{len(FIELD_HELP)} fields",
            summary="Set any of these with `accessset <field> <value>`.",
        )
        embed.table("FIELDS", ("FIELD", "VALUE", "PURPOSE"), rows, max_column=46)
        embed.source("local computation")
        await embed.send(ctx)


async def setup(bot: Any) -> None:
    await bot.add_cog(ConfigPanel(bot))

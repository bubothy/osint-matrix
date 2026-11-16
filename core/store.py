"""SQLite persistence for approvals, prefixes, audit lines and telemetry."""

from __future__ import annotations

import asyncio
import sqlite3
import threading
from pathlib import Path
from typing import Any

from core.utils import utcnow

SCHEMA = """
CREATE TABLE IF NOT EXISTS approvals (
    user_id     INTEGER PRIMARY KEY,
    approved_by INTEGER,
    approved_at TEXT NOT NULL,
    note        TEXT
);
CREATE TABLE IF NOT EXISTS guilds (
    guild_id   INTEGER PRIMARY KEY,
    prefix     TEXT,
    updated_at TEXT
);
CREATE TABLE IF NOT EXISTS audit (
    id     INTEGER PRIMARY KEY AUTOINCREMENT,
    ts     TEXT NOT NULL,
    actor  INTEGER,
    action TEXT NOT NULL,
    target TEXT,
    detail TEXT
);
CREATE TABLE IF NOT EXISTS metrics (
    key   TEXT PRIMARY KEY,
    value INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS commands (
    name  TEXT PRIMARY KEY,
    count INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS kv (
    key   TEXT PRIMARY KEY,
    value TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit (ts DESC);
"""


class Store:
    """Thin async wrapper around a single SQLite connection."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._lock = threading.Lock()
        with self._lock:
            self._conn.executescript(SCHEMA)
            self._conn.commit()
        self._approval_cache: dict[int, bool] = {}

    # ── plumbing ─────────────────────────────────────────────────────────

    async def _write(self, sql: str, params: tuple[Any, ...] = ()) -> int:
        def run() -> int:
            with self._lock:
                cursor = self._conn.execute(sql, params)
                self._conn.commit()
                return cursor.rowcount

        return await asyncio.to_thread(run)

    async def _read(self, sql: str, params: tuple[Any, ...] = ()) -> list[sqlite3.Row]:
        def run() -> list[sqlite3.Row]:
            with self._lock:
                return self._conn.execute(sql, params).fetchall()

        return await asyncio.to_thread(run)

    async def close(self) -> None:
        await asyncio.to_thread(self._conn.close)

    # ── approvals ────────────────────────────────────────────────────────

    async def is_approved(self, user_id: int) -> bool:
        cached = self._approval_cache.get(user_id)
        if cached is not None:
            return cached
        rows = await self._read("SELECT 1 FROM approvals WHERE user_id = ?", (user_id,))
        approved = bool(rows)
        self._approval_cache[user_id] = approved
        return approved

    async def approve(self, user_id: int, actor: int, note: str | None = None) -> None:
        await self._write(
            "INSERT INTO approvals (user_id, approved_by, approved_at, note) VALUES (?, ?, ?, ?) "
            "ON CONFLICT(user_id) DO UPDATE SET approved_by = excluded.approved_by, "
            "approved_at = excluded.approved_at, note = excluded.note",
            (user_id, actor, utcnow().isoformat(timespec="seconds"), note),
        )
        self._approval_cache[user_id] = True

    async def revoke(self, user_id: int) -> bool:
        changed = await self._write("DELETE FROM approvals WHERE user_id = ?", (user_id,))
        self._approval_cache[user_id] = False
        return changed > 0

    async def approvals(self) -> list[dict[str, Any]]:
        rows = await self._read(
            "SELECT user_id, approved_by, approved_at, note FROM approvals ORDER BY approved_at DESC"
        )
        return [dict(row) for row in rows]

    async def approved_count(self) -> int:
        rows = await self._read("SELECT COUNT(*) AS n FROM approvals")
        return int(rows[0]["n"]) if rows else 0

    # ── prefixes ─────────────────────────────────────────────────────────

    async def set_prefix(self, guild_id: int, prefix: str) -> None:
        await self._write(
            "INSERT INTO guilds (guild_id, prefix, updated_at) VALUES (?, ?, ?) "
            "ON CONFLICT(guild_id) DO UPDATE SET prefix = excluded.prefix, updated_at = excluded.updated_at",
            (guild_id, prefix, utcnow().isoformat(timespec="seconds")),
        )

    async def get_prefix(self, guild_id: int) -> str | None:
        rows = await self._read("SELECT prefix FROM guilds WHERE guild_id = ?", (guild_id,))
        return rows[0]["prefix"] if rows else None

    async def prefixes(self) -> dict[int, str]:
        rows = await self._read("SELECT guild_id, prefix FROM guilds WHERE prefix IS NOT NULL")
        return {int(row["guild_id"]): row["prefix"] for row in rows}

    # ── audit / telemetry ────────────────────────────────────────────────

    async def audit(self, actor: int | None, action: str, target: str | None, detail: str | None = None) -> None:
        await self._write(
            "INSERT INTO audit (ts, actor, action, target, detail) VALUES (?, ?, ?, ?, ?)",
            (utcnow().isoformat(timespec="seconds"), actor, action, target, detail),
        )

    async def recent_audit(self, limit: int = 10) -> list[dict[str, Any]]:
        rows = await self._read(
            "SELECT ts, actor, action, target, detail FROM audit ORDER BY id DESC LIMIT ?", (limit,)
        )
        return [dict(row) for row in rows]

    async def audit_count(self) -> int:
        rows = await self._read("SELECT COUNT(*) AS n FROM audit")
        return int(rows[0]["n"]) if rows else 0

    async def bump_metric(self, key: str, amount: int = 1) -> None:
        await self._write(
            "INSERT INTO metrics (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = value + excluded.value",
            (key, amount),
        )

    async def metric(self, key: str) -> int:
        rows = await self._read("SELECT value FROM metrics WHERE key = ?", (key,))
        return int(rows[0]["value"]) if rows else 0

    async def metrics(self) -> dict[str, int]:
        rows = await self._read("SELECT key, value FROM metrics")
        return {row["key"]: int(row["value"]) for row in rows}

    async def bump_command(self, name: str) -> None:
        await self._write(
            "INSERT INTO commands (name, count) VALUES (?, 1) "
            "ON CONFLICT(name) DO UPDATE SET count = count + 1",
            (name,),
        )

    async def command_total(self) -> int:
        rows = await self._read("SELECT COALESCE(SUM(count), 0) AS n FROM commands")
        return int(rows[0]["n"]) if rows else 0

    async def top_commands(self, limit: int = 10) -> list[tuple[str, int]]:
        rows = await self._read("SELECT name, count FROM commands ORDER BY count DESC LIMIT ?", (limit,))
        return [(row["name"], int(row["count"])) for row in rows]

    # ── key/value ────────────────────────────────────────────────────────

    async def kv_set(self, key: str, value: str | None) -> None:
        if value is None:
            await self._write("DELETE FROM kv WHERE key = ?", (key,))
            return
        await self._write(
            "INSERT INTO kv (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )

    async def kv_get(self, key: str) -> str | None:
        rows = await self._read("SELECT value FROM kv WHERE key = ?", (key,))
        return rows[0]["value"] if rows else None

"""Access configuration shared by the bot and the operator console.

One JSON document in the key/value store describes who may use the instance and
how it behaves. The website's access page edits the same document offline and
hands back a single ``accessimport`` command, so the panel always describes the
real deployment instead of a mock.

Nothing here reads a secret from disk: the pairing key lives in the store, and
only its fingerprint is ever rendered into a report.
"""

from __future__ import annotations

import base64
import binascii
import hmac
import json
import secrets
import time
from typing import Any

from core.utils import utcnow

KV_KEY = "access_config"
KEY_KV = "access_key"
_CACHE: dict[int, tuple[float, dict[str, Any]]] = {}
_CACHE_TTL = 3.0

DEFAULTS: dict[str, Any] = {
    "brand": "0SWALD",
    "prefix": ".",
    "approval_required": True,
    "allow_dms": True,
    "maintenance": False,
    "maintenance_note": "The operator has locked this instance to owners only. Try again once maintenance ends.",
    "denied_note": "This instance is private. Your Discord ID is not on the operator's allow-list.",
    "log_channel_id": "",
    "rate_limit_per_10s": 8,
    "cooldown_seconds": 10,
    "watch_interval": 60,
    "max_watches": 8,
    "audit": True,
    "notes": "",
    "updated_at": "",
}

_BOOL_KEYS = ("approval_required", "allow_dms", "maintenance", "audit")
_INT_RANGES = {
    "rate_limit_per_10s": (1, 30),
    "cooldown_seconds": (1, 120),
    "watch_interval": (30, 3600),
    "max_watches": (1, 25),
}
_TEXT_LIMITS = {
    "brand": 60,
    "prefix": 5,
    "maintenance_note": 320,
    "denied_note": 320,
    "log_channel_id": 24,
    "notes": 600,
}


def default() -> dict[str, Any]:
    return dict(DEFAULTS)


def _as_bool(value: Any, fallback: bool) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on", "enabled"}
    return fallback


def normalise(raw: Any) -> dict[str, Any]:
    """Coerce an arbitrary document into a valid configuration."""
    cfg = default()
    if isinstance(raw, dict):
        for key in DEFAULTS:
            if key in raw:
                cfg[key] = raw[key]

    for key in _BOOL_KEYS:
        cfg[key] = _as_bool(cfg[key], bool(DEFAULTS[key]))

    for key, limit in _TEXT_LIMITS.items():
        text = str(cfg.get(key) or "").strip()[:limit]
        cfg[key] = text if text else DEFAULTS[key] if key in {"brand", "prefix"} else ""

    for key, (low, high) in _INT_RANGES.items():
        try:
            value = int(cfg.get(key))
        except (TypeError, ValueError):
            value = int(DEFAULTS[key])
        cfg[key] = max(low, min(high, value))

    log_channel = str(cfg.get("log_channel_id") or "").strip()
    cfg["log_channel_id"] = log_channel if log_channel.isdigit() else ""

    prefix = str(cfg.get("prefix") or ".")
    cfg["prefix"] = prefix[:5] or "."

    return cfg


async def load(store: Any) -> dict[str, Any]:
    """Read the configuration, with a short cache to keep the hot path cheap."""
    cache = _CACHE.get(id(store))
    now = time.monotonic()
    if cache and now - cache[0] < _CACHE_TTL:
        return cache[1]

    raw = None
    try:
        raw = await store.kv_get(KV_KEY)
    except Exception:  # noqa: BLE001 - a cold store must not break a command
        raw = None

    cfg = default()
    if raw:
        try:
            cfg = normalise(json.loads(raw))
        except (TypeError, ValueError):
            cfg = default()
    else:
        try:
            cfg["maintenance"] = await store.kv_get("maintenance") == "1"
        except Exception:  # noqa: BLE001
            pass

    _CACHE[id(store)] = (now, cfg)
    return cfg


async def save(store: Any, config: Any) -> dict[str, Any]:
    """Persist a configuration and mirror the values other cogs already read."""
    cfg = normalise(config)
    cfg["updated_at"] = utcnow().isoformat(timespec="seconds")
    await store.kv_set(KV_KEY, json.dumps(cfg, sort_keys=True))
    await store.kv_set("maintenance", "1" if cfg["maintenance"] else "0")
    await store.kv_set("wt_interval", str(cfg["watch_interval"]))
    _CACHE[id(store)] = (time.monotonic(), cfg)
    return cfg


def invalidate() -> None:
    _CACHE.clear()


def new_key() -> str:
    return "osx_" + secrets.token_hex(20)


def fingerprint(key: str | None) -> str:
    if not key or len(key) < 12:
        return "—"
    return f"{key[:9]}…{key[-4:]}"


def key_matches(stored: str | None, presented: str | None) -> bool:
    if not stored or not presented:
        return False
    return hmac.compare_digest(str(stored).strip(), str(presented).strip())


def warnings(cfg: dict[str, Any]) -> list[str]:
    """Human-readable risks the operator should see before applying a config."""
    notes: list[str] = []
    if not cfg["approval_required"]:
        notes.append("Approval is off — anyone who can see the bot can run commands.")
    if cfg["maintenance"]:
        notes.append("Maintenance lock is on — approved users cannot run commands.")
    if not cfg["allow_dms"]:
        notes.append("Direct messages are disabled; slash commands work in servers only.")
    if cfg["rate_limit_per_10s"] > 15:
        notes.append("A rate limit above 15 per 10s is generous for a private instance.")
    if cfg["watch_interval"] < 45:
        notes.append("Watch intervals below 45s will attract Discord rate limits.")
    if not cfg["audit"]:
        notes.append("Audit logging is off — .audit will stay empty.")
    return notes


def encode(cfg: dict[str, Any]) -> str:
    payload = json.dumps(normalise(cfg), sort_keys=True, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(payload).decode().rstrip("=")


def decode(blob: str) -> dict[str, Any]:
    text = (blob or "").strip().strip("`").replace("\n", "")
    if not text:
        raise ValueError("That export is empty.")
    padding = "=" * (-len(text) % 4)
    try:
        raw = base64.urlsafe_b64decode(text + padding)
    except (binascii.Error, ValueError):
        raise ValueError("That does not look like an access export.") from None
    try:
        data = json.loads(raw)
    except (TypeError, ValueError):
        raise ValueError("The export decoded to something that is not JSON.") from None
    if not isinstance(data, dict):
        raise ValueError("The export is not a configuration object.")
    return normalise(data)

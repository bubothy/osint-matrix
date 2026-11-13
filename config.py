"""Central configuration for OSINT MATRIX.

Everything is loaded from ``.env`` (see ``.env.example``). Nothing in this
module performs network I/O, so it is safe to import from anywhere.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
LOG_DIR = BASE_DIR / "logs"

load_dotenv(BASE_DIR / ".env")


# ── primitive readers ──────────────────────────────────────────────────────


def _str(key: str, default: str = "") -> str:
    value = os.getenv(key, "").strip()
    return value or default


def _bool(key: str, default: bool = False) -> bool:
    raw = os.getenv(key)
    if raw is None or not raw.strip():
        return default
    return raw.strip().lower() in {"1", "true", "yes", "y", "on"}


def _int(key: str, default: int, *, low: int | None = None, high: int | None = None) -> int:
    try:
        value = int(str(os.getenv(key, "")).strip())
    except (TypeError, ValueError):
        return default
    if low is not None:
        value = max(low, value)
    if high is not None:
        value = min(high, value)
    return value


def _float(key: str, default: float) -> float:
    try:
        return float(str(os.getenv(key, "")).strip())
    except (TypeError, ValueError):
        return default


def _id_set(key: str) -> frozenset[int]:
    found: set[int] = set()
    for chunk in os.getenv(key, "").replace(";", ",").split(","):
        chunk = chunk.strip().lstrip("<@!").rstrip(">")
        if chunk.isdigit():
            found.add(int(chunk))
    return frozenset(found)


def _optional_id(key: str) -> int | None:
    value = _str(key)
    return int(value) if value.isdigit() else None


# ── optional third-party keys ──────────────────────────────────────────────


@dataclass(frozen=True)
class OptionalKey:
    """Metadata for a feature that needs the operator to supply a key."""

    env: str
    service: str
    unlocks: str
    url: str
    cost: str = "free"


OPTIONAL_KEYS: tuple[OptionalKey, ...] = (
    OptionalKey(
        "GITHUB_TOKEN",
        "GitHub",
        "Raises the GitHub API ceiling from 60 to 5,000 requests/hour and unlocks "
        "organisation, commit and rate-limit metadata.",
        "https://github.com/settings/tokens",
    ),
    OptionalKey(
        "HIBP_API_KEY",
        "Have I Been Pwned",
        "Full breach history per email address. Password exposure checks work "
        "without a key via the k-anonymity range API.",
        "https://haveibeenpwned.com/API/Key",
        "paid (~$3.95/mo)",
    ),
    OptionalKey(
        "STEAM_API_KEY",
        "Steam",
        "Exact SteamID64 resolution, ban flags and playtime. Vanity profiles "
        "are read from the public XML feed without a key.",
        "https://steamcommunity.com/dev/apikey",
    ),
    OptionalKey(
        "VIRUSTOTAL_API_KEY",
        "VirusTotal",
        "Multi-engine reputation for domains, URLs, IPs and file hashes.",
        "https://www.virustotal.com/gui/my-apikey",
    ),
    OptionalKey(
        "SHODAN_API_KEY",
        "Shodan",
        "Exposed-service and banner intelligence for a host.",
        "https://account.shodan.io",
    ),
    OptionalKey(
        "ABUSEIPDB_API_KEY",
        "AbuseIPDB",
        "Abuse confidence score and report history for an IP address.",
        "https://www.abuseipdb.com/account/api",
    ),
    OptionalKey(
        "URLSCAN_API_KEY",
        "urlscan.io",
        "Submitting new scans. Passive result search works without a key.",
        "https://urlscan.io/user/apikey",
    ),
    OptionalKey(
        "ABUSECH_AUTH_KEY",
        "abuse.ch",
        "MalwareBazaar sample metadata and ThreatFox IOC correlation.",
        "https://auth.abuse.ch/",
    ),
    OptionalKey(
        "NVD_API_KEY",
        "NIST NVD",
        "Raises CVE query limits from 5 to 50 requests per 30 seconds.",
        "https://nvd.nist.gov/developers/request-an-api-key",
    ),
    OptionalKey(
        "TWITCH_CLIENT_ID",
        "Twitch",
        "Account creation date, follower counts and ban status. Requires the "
        "matching TWITCH_CLIENT_SECRET as well.",
        "https://dev.twitch.tv/console/apps",
    ),
)


class Settings:
    """Runtime settings singleton."""

    def __init__(self) -> None:
        self.token: str = _str("DISCORD_TOKEN")
        self.prefix: str = _str("COMMAND_PREFIX", ".")
        self.owner_ids: frozenset[int] = _id_set("OWNER_IDS")
        self.guild_id: int | None = _optional_id("GUILD_ID")
        self.log_channel_id: int | None = _optional_id("LOG_CHANNEL_ID")
        self.allow_dms: bool = _bool("ALLOW_DMS", True)
        self.maintenance: bool = _bool("MAINTENANCE", False)
        self.http_timeout: float = _float("HTTP_TIMEOUT", 15.0)
        self.cache_ttl: int = _int("CACHE_TTL", 300, low=0, high=86_400)
        self.max_concurrency: int = _int("MAX_CONCURRENCY", 4, low=1, high=32)
        self.max_results: int = _int("MAX_RESULTS", 25, low=5, high=100)

    # -- helpers ----------------------------------------------------------

    def key(self, env: str) -> str:
        """Return an optional API key (empty string when not configured)."""
        return os.getenv(env, "").strip()

    def has(self, env: str) -> bool:
        return bool(self.key(env))

    def optional_status(self) -> list[tuple[OptionalKey, bool]]:
        return [(meta, self.has(meta.env)) for meta in OPTIONAL_KEYS]

    def twitch_ready(self) -> bool:
        return self.has("TWITCH_CLIENT_ID") and self.has("TWITCH_CLIENT_SECRET")

    def missing_required(self) -> list[str]:
        missing = []
        if not self.token:
            missing.append("DISCORD_TOKEN")
        if not self.owner_ids:
            missing.append("OWNER_IDS")
        return missing


settings = Settings()

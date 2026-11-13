"""Small, dependency-free helpers shared by every command."""

from __future__ import annotations

import asyncio
import datetime as dt
import ipaddress
import json
import math
import re
import shlex
import unicodedata
from collections.abc import Iterable, Mapping, Sequence
from typing import Any
from urllib.parse import urlsplit

from core.errors import UsageError

UTC = dt.timezone.utc
DISCORD_EPOCH = 1_420_070_400_000

MULTI_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk", "sch.uk", "ltd.uk", "plc.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "id.au", "asn.au",
    "co.nz", "net.nz", "org.nz", "govt.nz", "ac.nz",
    "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp", "ad.jp", "ed.jp", "gr.jp", "lg.jp",
    "co.kr", "or.kr", "ne.kr", "go.kr", "ac.kr", "re.kr",
    "com.br", "net.br", "org.br", "gov.br", "edu.br", "art.br", "blog.br",
    "com.mx", "org.mx", "gob.mx", "edu.mx", "net.mx",
    "com.ar", "net.ar", "org.ar", "gob.ar", "edu.ar",
    "com.co", "net.co", "org.co", "edu.co", "gov.co",
    "com.pe", "net.pe", "org.pe", "gob.pe", "edu.pe",
    "com.ve", "com.ec", "com.uy", "com.py", "com.bo",
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "ac.cn",
    "com.tw", "org.tw", "net.tw", "edu.tw", "gov.tw", "idv.tw",
    "com.hk", "org.hk", "net.hk", "edu.hk", "gov.hk",
    "com.sg", "net.sg", "org.sg", "edu.sg", "gov.sg",
    "com.my", "net.my", "org.my", "edu.my", "gov.my",
    "com.ph", "net.ph", "org.ph", "edu.ph", "gov.ph",
    "com.vn", "net.vn", "org.vn", "edu.vn", "gov.vn",
    "com.pk", "net.pk", "org.pk", "edu.pk", "gov.pk",
    "com.bd", "com.np", "com.lk", "com.mm", "com.kh",
    "com.sa", "com.eg", "com.qa", "com.kw", "com.bh", "com.om", "com.jo", "com.lb",
    "com.tr", "net.tr", "org.tr", "edu.tr", "gov.tr",
    "com.ua", "net.ua", "org.ua", "edu.ua", "gov.ua", "in.ua", "kiev.ua",
    "com.ru", "net.ru", "org.ru", "msk.ru", "spb.ru",
    "com.pl", "net.pl", "org.pl", "edu.pl", "gov.pl", "waw.pl",
    "co.za", "org.za", "net.za", "gov.za", "ac.za", "web.za",
    "co.ke", "or.ke", "ne.ke", "go.ke", "ac.ke",
    "com.ng", "org.ng", "net.ng", "gov.ng", "edu.ng",
    "com.gh", "com.tz", "com.ug", "co.tz", "co.ug",
    "co.il", "org.il", "net.il", "ac.il", "gov.il", "muni.il",
    "com.es", "org.es", "nom.es", "gob.es", "edu.es",
    "com.pt", "org.pt", "gov.pt", "edu.pt",
    "co.it", "com.it", "org.it", "net.it", "gov.it", "edu.it",
    "com.gr", "org.gr", "net.gr", "gov.gr", "edu.gr",
    "com.cy", "com.mt", "com.hr", "com.ro", "com.bg", "com.al", "com.mk",
    "co.at", "or.at", "ac.at", "gv.at",
    "co.hu", "com.hu", "org.hu", "edu.hu", "gov.hu",
    "com.sk", "com.cz", "co.cz", "com.hr",
    "com.by", "com.kz", "com.uz", "com.ge", "com.az", "com.am",
}

FREE_EMAIL = {
    "gmail.com", "googlemail.com", "yahoo.com", "yahoo.co.uk", "yahoo.co.jp", "ymail.com",
    "outlook.com", "hotmail.com", "live.com", "msn.com", "hotmail.co.uk", "outlook.co.uk",
    "icloud.com", "me.com", "mac.com", "aol.com", "gmx.com", "gmx.net", "gmx.de",
    "mail.com", "email.com", "zoho.com", "zohomail.com", "yandex.ru", "yandex.com",
    "protonmail.com", "proton.me", "pm.me", "tutanota.com", "tuta.com", "fastmail.com",
    "hushmail.com", "inbox.com", "lycos.com", "rediffmail.com", "qq.com", "163.com",
    "126.com", "naver.com", "daum.net", "hanmail.net", "web.de", "t-online.de",
    "orange.fr", "laposte.net", "free.fr", "libero.it", "virgilio.it", "seznam.cz",
}

RESERVED_DOMAINS = {
    "example.com", "example.net", "example.org", "localhost", "invalid", "test",
}

_EMAIL_RE = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$")
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$")
_HOST_RE = re.compile(r"^[A-Za-z0-9_.:\[\]-]+$")


# ── time ───────────────────────────────────────────────────────────────────


def utcnow() -> dt.datetime:
    return dt.datetime.now(UTC)


def parse_dt(value: Any) -> dt.datetime | None:
    """Best-effort date parser for WHOIS / RDAP / API timestamps."""
    if value in (None, "", 0, "0"):
        return None
    if isinstance(value, dt.datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    if isinstance(value, (int, float)):
        seconds = value / 1000 if value > 10_000_000_000 else value
        try:
            return dt.datetime.fromtimestamp(seconds, UTC)
        except (OverflowError, OSError, ValueError):
            return None
    text = str(value).strip()
    if text.isdigit():
        return parse_dt(int(text))
    cleaned = text.replace("Z", "+00:00")
    for candidate in (cleaned, cleaned.replace("/", "-")):
        try:
            parsed = dt.datetime.fromisoformat(candidate)
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
        except ValueError:
            pass
    for fmt in (
        "%Y-%m-%d", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f",
        "%d-%b-%Y", "%d.%m.%Y", "%Y.%m.%d", "%d/%m/%Y", "%m/%d/%Y",
        "%Y-%m-%dT%H:%M:%S%z", "%a %b %d %H:%M:%S %Y", "%Y%m%d",
    ):
        try:
            parsed = dt.datetime.strptime(text[: len(fmt) + 6], fmt)
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
        except ValueError:
            continue
    return None


def fmt_dt(value: Any, *, style: str = "full") -> str:
    """Render a timestamp as a Discord relative+absolute timestamp."""
    parsed = parse_dt(value)
    if parsed is None:
        return "—"
    stamp = int(parsed.timestamp())
    if style == "relative":
        return f"<t:{stamp}:R>"
    if style == "date":
        return f"<t:{stamp}:D>"
    return f"<t:{stamp}:f> · <t:{stamp}:R>"


def human_delta(seconds: float | int | None) -> str:
    if seconds is None:
        return "—"
    seconds = int(abs(seconds))
    if seconds < 60:
        return f"{seconds}s"
    minutes, seconds = divmod(seconds, 60)
    if minutes < 60:
        return f"{minutes}m {seconds}s"
    hours, minutes = divmod(minutes, 60)
    if hours < 24:
        return f"{hours}h {minutes}m"
    days, hours = divmod(hours, 24)
    if days < 365:
        return f"{days}d {hours}h"
    years, days = divmod(days, 365)
    return f"{years}y {days}d"


def uptime(seconds: float) -> str:
    return human_delta(seconds)


# ── formatting ─────────────────────────────────────────────────────────────


def clip(text: Any, limit: int = 1024) -> str:
    value = "" if text is None else str(text)
    value = value.replace("```", "ˋˋˋ")
    if len(value) <= limit:
        return value
    return value[: max(0, limit - 1)].rstrip() + "…"


def num(value: Any) -> str:
    try:
        return f"{int(value):,}"
    except (TypeError, ValueError):
        return str(value)


def pct(part: float, whole: float) -> str:
    if not whole:
        return "—"
    return f"{part / whole * 100:.1f}%"


def human_bytes(size: float | int | None) -> str:
    if size is None:
        return "—"
    value = float(size)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.2f} {unit}"
        value /= 1024
    return f"{value:.2f} TB"


def yes_no(flag: Any) -> str:
    return "yes" if flag else "no"


def bool_glyph(flag: bool | None) -> str:
    if flag is True:
        return "✓"
    if flag is False:
        return "✗"
    return "•"


def bar(score: float, width: int = 12, filled: str = "█", empty: str = "░") -> str:
    score = max(0.0, min(100.0, float(score)))
    units = round(score / 100 * width)
    return filled * units + empty * (width - units)


def risk_label(score: float) -> str:
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 40:
        return "ELEVATED"
    if score >= 20:
        return "GUARDED"
    return "MINIMAL"


def entropy_bits(text: str) -> float:
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for char in text:
        counts[char] = counts.get(char, 0) + 1
    total = len(text)
    return -sum((n / total) * math.log2(n / total) for n in counts.values()) * total


def kv_block(pairs: Mapping[str, Any] | Sequence[tuple[str, Any]], *, lang: str = "ini", limit: int = 960) -> str:
    items: list[tuple[str, str]] = []
    source = pairs.items() if isinstance(pairs, Mapping) else pairs
    for key, value in source:
        if value is None or value == "" or value == [] or value == {}:
            continue
        if isinstance(value, bool):
            rendered = "yes" if value else "no"
        elif isinstance(value, (list, tuple, set)):
            rendered = ", ".join(str(v) for v in value)
        elif isinstance(value, dict):
            rendered = json.dumps(value, ensure_ascii=False, default=str)
        else:
            rendered = str(value)
        rendered = rendered.replace("`", "ˋ").replace("\n", " ") or "—"
        items.append((str(key), clip(rendered, 220)))
    if not items:
        return "`no data`"
    width = min(max(len(k) for k, _ in items), 24)
    body = "\n".join(f"{k[:width].ljust(width)}  {v}" for k, v in items)
    return f"```{lang}\n{clip(body, limit)}\n```"


def bullet_list(items: Iterable[Any], *, marker: str = "•", limit: int = 900) -> str:
    lines = [f"{marker} {clip(str(item), 200)}" for item in items]
    return clip("\n".join(lines) or "—", limit)


def numbered(items: Iterable[Any], *, pad: int = 2) -> str:
    return "\n".join(f"`{i:0{pad}d}` {clip(str(item), 200)}" for i, item in enumerate(items, 1)) or "—"


def truncate_middle(text: str, limit: int = 60) -> str:
    if len(text) <= limit:
        return text
    half = max(1, (limit - 1) // 2)
    return f"{text[:half]}…{text[-half:]}"


def chunks(items: Sequence[Any], size: int) -> list[Sequence[Any]]:
    return [items[i : i + size] for i in range(0, len(items), size)]


def unique(items: Iterable[Any]) -> list[Any]:
    seen: set[Any] = set()
    out = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def plural(count: int, singular: str, plural_form: str | None = None) -> str:
    return singular if count == 1 else (plural_form or singular + "s")


# ── validation / parsing ───────────────────────────────────────────────────


def require(value: Any, what: str, *, example: str | None = None) -> str:
    if value is None or not str(value).strip():
        hint = f" Example: `{example}`" if example else ""
        raise UsageError(f"Missing required argument: **{what}**.{hint}")
    return str(value).strip()


def strip_target(raw: str) -> str:
    value = raw.strip().strip("<>[]'\"`")
    value = value.replace("\\", "/")
    return value.strip().strip("<>[]'\"`")


def normalize_host(raw: str) -> str:
    """Turn a URL, host:port or bare host into a lowercase hostname."""
    value = strip_target(raw)
    if "://" in value:
        value = urlsplit(value).hostname or value
    elif "/" in value:
        value = value.split("/", 1)[0]
    if value.startswith("[") and "]" in value:
        value = value[1 : value.index("]")]
    elif value.count(":") == 1 and not is_ip(value):
        host, _, port = value.partition(":")
        if port.isdigit():
            value = host
    return value.strip().rstrip(".").lower()


def normalize_domain(raw: str) -> str:
    host = normalize_host(raw)
    try:
        return host.encode("idna").decode("ascii").lower()
    except (UnicodeError, ValueError):
        return host.lower()


def unicode_domain(raw: str) -> str:
    try:
        return raw.encode("ascii").decode("idna")
    except (UnicodeError, ValueError):
        return raw


def is_ip(value: str, version: int | None = None) -> bool:
    try:
        parsed = ipaddress.ip_address(value.strip().strip("[]"))
    except ValueError:
        return False
    return version is None or parsed.version == version


def parse_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    return ipaddress.ip_address(value.strip().strip("[]"))


def is_private_ip(value: str) -> bool:
    try:
        parsed = parse_ip(value)
    except ValueError:
        return False
    return parsed.is_private or parsed.is_loopback or parsed.is_link_local or parsed.is_reserved


def is_domain(value: str) -> bool:
    value = value.strip().rstrip(".")
    if not value or len(value) > 253 or " " in value:
        return False
    if is_ip(value):
        return False
    return bool(_DOMAIN_RE.match(value))


def is_email(value: str) -> bool:
    value = value.strip()
    return len(value) <= 254 and bool(_EMAIL_RE.match(value))


def is_url(value: str) -> bool:
    value = value.strip()
    if " " in value or "." not in value:
        return False
    parsed = urlsplit(value if "://" in value else f"http://{value}")
    return bool(parsed.hostname) and ("." in parsed.hostname or is_ip(parsed.hostname))


def ensure_url(value: str) -> str:
    value = strip_target(value)
    return value if "://" in value else f"https://{value}"


def base_domain(host: str) -> str:
    """Registrable domain approximation using a curated multi-label suffix list."""
    host = normalize_host(host)
    if is_ip(host):
        return host
    labels = [label for label in host.split(".") if label]
    if len(labels) <= 2:
        return ".".join(labels)
    if ".".join(labels[-2:]) in MULTI_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def guess_type(value: str) -> str:
    raw = strip_target(value)
    if is_ip(raw):
        return "ipv4" if ":" not in raw else "ipv6"
    if is_email(raw):
        return "email"
    if raw.startswith(("http://", "https://")):
        return "url"
    if raw.count(".") == 2 and raw.replace(".", "").isdigit():
        return "ipv4"
    if is_domain(raw):
        return "domain"
    if len(raw) >= 32 and re.fullmatch(r"[A-Fa-f0-9]+", raw) and len(raw) % 2 == 0:
        return "hash"
    if raw.isdigit() and 17 <= len(raw) <= 20:
        return "snowflake"
    return "unknown"


def shlex_split(text: str) -> list[str]:
    try:
        return shlex.split(text or "")
    except ValueError:
        return (text or "").split()


def as_int(raw: Any, *, default: int, low: int, high: int, label: str = "value") -> int:
    if raw is None or str(raw).strip() == "":
        return default
    try:
        value = int(str(raw).strip())
    except (TypeError, ValueError):
        raise UsageError(f"`{raw}` is not a valid **{label}**.") from None
    return max(low, min(high, value))


def parse_asn(raw: str) -> str:
    value = strip_target(raw).upper().replace("AS", "").strip()
    if not value.isdigit():
        raise UsageError("ASN must look like `13335` or `AS13335`.")
    return value.lstrip("0") or "0"


def parse_snowflake(raw: str) -> int:
    value = strip_target(raw)
    match = re.search(r"\d{15,21}", value)
    if not match:
        raise UsageError("That does not contain a Discord snowflake (15–21 digits).")
    return int(match.group(0))


def snowflake_time(snowflake: int) -> dt.datetime:
    return dt.datetime.fromtimestamp(((snowflake >> 22) + DISCORD_EPOCH) / 1000, UTC)


def snowflake_parts(snowflake: int) -> dict[str, int]:
    return {
        "timestamp_ms": (snowflake >> 22) + DISCORD_EPOCH,
        "worker": (snowflake & 0x3E0000) >> 17,
        "process": (snowflake & 0x1F000) >> 12,
        "increment": snowflake & 0xFFF,
    }


def duration(seconds: float | None) -> str:
    if seconds is None:
        return "—"
    seconds = max(0, int(seconds))
    hours, remainder = divmod(seconds, 3600)
    minutes, secs = divmod(remainder, 60)
    return f"{hours:02d}:{minutes:02d}:{secs:02d}"


def severity_from_score(score: float) -> str:
    if score >= 9:
        return "CRITICAL"
    if score >= 7:
        return "HIGH"
    if score >= 4:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "NONE"


def clamp(value: float, low: float = 0, high: float = 100) -> float:
    return max(low, min(high, value))


def score_from_checks(checks: Sequence[tuple[bool | None, float]]) -> float:
    total = sum(weight for _, weight in checks)
    if not total:
        return 0.0
    earned = sum(weight for state, weight in checks if state is True)
    return round(earned / total * 100, 1)


# ── Discord interaction plumbing ───────────────────────────────────────────


async def ack(ctx: Any) -> None:
    """Acknowledge an invocation so slow lookups do not time out.

    Slash commands defer; prefix commands get a magnifier reaction.
    """
    interaction = getattr(ctx, "interaction", None)
    if interaction is not None:
        try:
            if not interaction.response.is_done():
                await interaction.response.defer(thinking=True)
        except Exception:  # pragma: no cover - interaction already handled
            pass
        return
    message = getattr(ctx, "message", None)
    if message is not None:
        try:
            await message.add_reaction("🔎")
        except Exception:  # pragma: no cover - missing permissions
            pass


async def gather_limited(*coros: Any, limit: int = 6) -> list[Any]:
    """Run coroutines concurrently, returning exceptions instead of raising."""
    semaphore = asyncio.Semaphore(limit)

    async def runner(coro: Any) -> Any:
        async with semaphore:
            try:
                return await coro
            except Exception as exc:  # noqa: BLE001 - intentionally collected
                return exc

    return await asyncio.gather(*(runner(c) for c in coros))


def json_block(payload: Any, *, limit: int = 950) -> str:
    try:
        text = json.dumps(payload, indent=2, ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        text = str(payload)
    return clip(text, limit)


def clean_unicode(text: str) -> str:
    return unicodedata.normalize("NFKC", text)

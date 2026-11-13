"""DNS-over-HTTPS toolkit.

No dnspython and no local resolver required: everything goes through RFC 8484
JSON endpoints, which work on any Windows laptop behind any network.
"""

from __future__ import annotations

from typing import Any

from core.errors import IntelError, NotFound, SourceUnavailable

PROVIDERS = {
    "cloudflare": "https://cloudflare-dns.com/dns-query",
    "google": "https://dns.google/resolve",
    "quad9": "https://dns.quad9.net:5053/dns-query",
    "adguard": "https://dns.adguard-dns.com/resolve",
}

TYPE_CODES = {
    "A": 1,
    "NS": 2,
    "CNAME": 5,
    "SOA": 6,
    "PTR": 12,
    "MX": 15,
    "TXT": 16,
    "AAAA": 28,
    "SRV": 33,
    "NAPTR": 35,
    "DS": 43,
    "RRSIG": 46,
    "DNSKEY": 48,
    "TLSA": 52,
    "SVCB": 64,
    "HTTPS": 65,
    "SPF": 99,
    "CAA": 257,
}
CODE_TYPES = {value: key for key, value in TYPE_CODES.items()}

STATUS_TEXT = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
}


async def query(
    http: Any,
    name: str,
    rrtype: str = "A",
    *,
    provider: str = "cloudflare",
    cache_ttl: int = 300,
) -> dict[str, Any]:
    """Return the raw DoH JSON document for one question."""
    endpoint = PROVIDERS.get(provider, provider)
    rrtype = rrtype.upper()
    if rrtype not in TYPE_CODES:
        raise IntelError(f"Unsupported DNS record type `{rrtype}`.")
    payload = await http.get_json(
        endpoint,
        params={"name": name, "type": rrtype, "cd": "0"},
        headers={"accept": "application/dns-json"},
        cache_ttl=cache_ttl,
    )
    status = int(payload.get("Status", 0))
    if status == 3:
        raise NotFound(f"`{name}` does not exist (NXDOMAIN).")
    if status not in (0, 3):
        raise SourceUnavailable(
            f"Resolver `{provider}` returned {STATUS_TEXT.get(status, status)} for {rrtype}.",
            hint="Try another record type or provider.",
        )
    return payload


async def answers(http: Any, name: str, rrtype: str, *, provider: str = "cloudflare", cache_ttl: int = 300) -> list[dict[str, Any]]:
    payload = await query(http, name, rrtype, provider=provider, cache_ttl=cache_ttl)
    return list(payload.get("Answer") or [])


async def values(http: Any, name: str, rrtype: str, *, provider: str = "cloudflare") -> list[str]:
    """Return record data strings with TXT quotes removed."""
    records = await answers(http, name, rrtype, provider=provider)
    out: list[str] = []
    for record in records:
        data = str(record.get("data", "")).strip()
        if rrtype.upper() == "TXT" and data.startswith('"'):
            data = _join_txt(data)
        out.append(data.rstrip("."))
    return out


def _join_txt(data: str) -> str:
    parts: list[str] = []
    current = ""
    quoted = False
    for char in data:
        if char == '"':
            quoted = not quoted
            if not quoted and current:
                parts.append(current)
                current = ""
            continue
        if quoted:
            current += char
    if current:
        parts.append(current)
    return "".join(parts)


async def txt(http: Any, name: str) -> list[str]:
    try:
        return await values(http, name, "TXT")
    except (NotFound, SourceUnavailable):
        return []


async def mx(http: Any, name: str) -> list[tuple[int, str]]:
    try:
        records = await values(http, name, "MX")
    except NotFound:
        return []
    out: list[tuple[int, str]] = []
    for record in records:
        priority, _, host = record.partition(" ")
        host = host.strip().rstrip(".")
        out.append((int(priority) if priority.isdigit() else 0, host))
    return sorted(out)


async def ns(http: Any, name: str) -> list[str]:
    try:
        return sorted({record.rstrip(".") for record in await values(http, name, "NS")})
    except NotFound:
        return []


async def ptr(http: Any, address: str) -> list[str]:
    return sorted({record.rstrip(".") for record in await values(http, address, "PTR")})


async def address_records(http: Any, name: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for rrtype in ("A", "AAAA"):
        try:
            records = await values(http, name, rrtype)
        except (NotFound, SourceUnavailable):
            records = []
        if records:
            out[rrtype] = records
    return out


async def soa(http: Any, name: str) -> dict[str, Any]:
    try:
        records = await values(http, name, "SOA")
    except NotFound:
        return {}
    if not records:
        return {}
    parts = records[0].split()
    keys = ("primary_ns", "hostmaster", "serial", "refresh", "retry", "expire", "minimum")
    parsed = dict(zip(keys, parts))
    for key in ("serial", "refresh", "retry", "expire", "minimum"):
        try:
            parsed[key] = int(parsed.get(key, 0))
        except (TypeError, ValueError):
            parsed[key] = 0
    return parsed


async def caa(http: Any, name: str) -> list[str]:
    try:
        return await values(http, name, "CAA")
    except NotFound:
        return []


async def srv(http: Any, name: str) -> list[str]:
    try:
        return await values(http, name, "SRV")
    except NotFound:
        return []


async def ds(http: Any, name: str) -> list[str]:
    try:
        return await values(http, name, "DS")
    except NotFound:
        return []


async def dnskey(http: Any, name: str) -> list[str]:
    try:
        return await values(http, name, "DNSKEY")
    except NotFound:
        return []


async def propagation(http: Any, name: str, rrtype: str = "A") -> dict[str, str]:
    """Ask several independent resolvers the same question."""
    results: dict[str, str] = {}
    for provider in PROVIDERS:
        try:
            records = await values(http, name, rrtype, provider=provider)
            results[provider] = ", ".join(records) if records else "none"
        except NotFound:
            results[provider] = "NXDOMAIN"
        except (SourceUnavailable, IntelError):
            results[provider] = "unreachable"
    return results


def flatten(payload: dict[str, Any]) -> list[dict[str, Any]]:
    return list(payload.get("Answer") or []) + list(payload.get("Authority") or [])

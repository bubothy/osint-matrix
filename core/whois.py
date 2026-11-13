"""Minimal WHOIS client.

Uses raw TCP/43 directly, following the IANA referral chain like a normal
registrar-agnostic client. No external whois binary is needed, so this works
unchanged on Windows.
"""

from __future__ import annotations

import asyncio
import re
import socket
from typing import Any

from core.errors import SourceUnavailable
from core.utils import parse_dt

REFERRAL_RE = re.compile(r"(?im)^\s*(?:refer|whois server|registrar whois server|whois)\s*:\s*(\S+)")

FIELDS: dict[str, tuple[str, ...]] = {
    "registrar": (
        "registrar name", "registrar", "sponsoring registrar", "registrar organization",
        "registrar_org", "registrar organisation",
    ),
    "registrar_url": ("registrar url", "registrar website", "registrar_url", "url"),
    "created": (
        "creation date", "created", "created on", "created date", "domain registration date",
        "registered on", "registration date", "registration time", "registered", "domain_dateregistered",
    ),
    "updated": (
        "updated date", "last updated", "last modified", "modified", "changed", "domain_last_modified",
    ),
    "expires": (
        "registry expiry date", "registrar registration expiration date", "expiration date",
        "expiry date", "expires", "expires on", "domain expiration date", "paid-till",
    ),
    "status": ("domain status", "status", "registration status", "domain_status"),
    "nameservers": ("name server", "name servers", "nserver", "nameserver", "nameservers", "domain_nameserver"),
    "dnssec": ("dnssec", "dnssec signed"),
    "org": ("registrant organization", "registrant organisation", "registrant org", "org", "organisation", "owner"),
    "country": ("registrant country", "country", "registrar country"),
    "email": ("registrant email", "email", "registrar email", "registrar abuse contact email", "abuse-mailbox"),
    "abuse": ("registrar abuse contact email", "abuse contact email", "abuse-mailbox", "abuse email"),
    "address": ("registrant street", "registrant address", "address"),
    "id": ("registry domain id", "domain id", "registrar id", "nic-hdl"),
}

NOISE = re.compile(
    r"(?i)(ICANN|TERMS OF USE|WHOIS DATA|last updated on|copyright|"
    r"NOTICE:|By submitting|The Registrar of Record|"
    r"you agree|redacted for privacy|GDPR|Consent)"
)


async def _query(server: str, query: str, *, timeout: float = 12.0) -> str:
    def blocking() -> str:
        try:
            with socket.create_connection((server, 43), timeout=timeout) as sock:
                sock.settimeout(timeout)
                sock.sendall(query.encode("utf-8", "replace") + b"\r\n")
                chunks: list[bytes] = []
                total = 0
                while True:
                    data = sock.recv(4096)
                    if not data:
                        break
                    chunks.append(data)
                    total += len(data)
                    if total > 300_000:
                        break
                return b"".join(chunks).decode("utf-8", "replace")
        except OSError as exc:
            raise SourceUnavailable(f"WHOIS server `{server}` is unreachable.") from exc

    return await asyncio.to_thread(blocking)


async def lookup(domain: str, *, timeout: float = 12.0) -> tuple[str, str]:
    """Return (raw_text, server_used)."""
    domain = domain.strip().lower()
    server = "whois.iana.org"
    raw = await _query(server, domain, timeout=timeout)
    match = REFERRAL_RE.search(raw)
    if match:
        candidate = match.group(1).strip().lower()
        if candidate and candidate not in {"whois.iana.org", "none"}:
            try:
                referred = await _query(candidate, domain, timeout=timeout)
                if referred.strip():
                    return referred, candidate
            except SourceUnavailable:
                pass
    return raw, server


def parse(raw: str) -> dict[str, Any]:
    """Best-effort field extraction from messy WHOIS output."""
    values: dict[str, list[str]] = {}
    last_key: str | None = None
    for line in raw.splitlines():
        line = line.rstrip()
        if not line.strip() or line.lstrip().startswith(("%", "#", ">>>", "--", "//")):
            continue
        if NOISE.search(line):
            continue
        if ":" in line:
            key, _, value = line.partition(":")
            key = key.strip().lower()
            value = value.strip()
            last_key = key
            if value:
                values.setdefault(key, []).append(value)
        elif last_key and line.startswith((" ", "\t")):
            values.setdefault(last_key, []).append(line.strip())

    parsed: dict[str, Any] = {}
    for canonical, aliases in FIELDS.items():
        for alias in aliases:
            hits = values.get(alias)
            if hits:
                cleaned = [
                    re.sub(r"\s{2,}", " ", hit).strip()
                    for hit in hits
                    if hit.strip() and not NOISE.search(hit)
                ]
                if cleaned:
                    parsed[canonical] = cleaned
                    break

    for key in ("created", "updated", "expires"):
        if key in parsed:
            parsed[key] = parsed[key][0]

    if parsed.get("nameservers"):
        parsed["nameservers"] = sorted({ns.lower().rstrip(".") for ns in parsed["nameservers"]})
    if parsed.get("status"):
        parsed["status"] = sorted({status.split(" ")[0].upper() for status in parsed["status"]})
    return parsed


def age_days(raw_date: Any) -> int | None:
    from core.utils import utcnow

    parsed = parse_dt(raw_date)
    if not parsed:
        return None
    return (utcnow() - parsed).days

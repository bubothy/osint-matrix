"""Identity intelligence: email, handles, phone numbers, secrets and encodings."""

from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
import html
import math
import re
import struct
import unicodedata
import urllib.parse
import uuid as uuid_module
from typing import Any

from discord.ext import commands

from config import settings
from core.command import intel
from core.embeds import Intel, notice, respond
from core.errors import IntelError, NotFound, NotConfigured, SourceUnavailable, UsageError
from core.signatures import COMMON_PASSWORDS, DISPOSABLE_DOMAINS, HASH_PATTERNS, IBAN_LENGTHS, UA_PATTERNS, USERNAME_SITES
from core.ui import Paginator
from core.utils import (
    FREE_EMAIL,
    ack,
    as_int,
    base_domain,
    clip,
    entropy_bits,
    fmt_dt,
    human_delta,
    is_domain,
    is_email,
    normalize_domain,
    num,
    parse_dt,
    require,
    utcnow,
)

try:  # optional, installed through requirements.txt
    import phonenumbers
    from phonenumbers import carrier as pn_carrier
    from phonenumbers import geocoder as pn_geocoder
    from phonenumbers import timezone as pn_timezone
except ImportError:  # pragma: no cover - only if dependencies were skipped
    phonenumbers = None  # type: ignore[assignment]

ROLE_ACCOUNTS = {
    "admin", "administrator", "info", "support", "sales", "billing", "abuse", "postmaster",
    "webmaster", "hostmaster", "security", "contact", "help", "noreply", "no-reply", "office",
    "team", "hello", "press", "legal", "privacy", "jobs", "careers", "marketing", "hr",
}

L33T = str.maketrans({"4": "a", "@": "a", "3": "e", "1": "i", "!": "i", "0": "o", "5": "s", "$": "s", "7": "t"})

PHONE_TYPES = {
    0: "fixed line", 1: "mobile", 2: "fixed line or mobile", 3: "toll free", 4: "premium rate",
    5: "shared cost", 6: "VoIP", 7: "personal number", 8: "pager", 9: "universal access",
    10: "voicemail", 27: "unknown",
}

IBAN_BANK_LABELS = {
    "GB": "sort code + account", "DE": "bank code + account", "FR": "bank code + branch + account",
    "NL": "bank code + account", "ES": "bank code + branch + check + account",
    "IT": "check + bank + branch + account", "IE": "bank + branch + account",
    "CH": "bank + account", "PL": "bank + branch + account", "PT": "bank + branch + account + check",
}


def _decode_ssh_blob(blob: bytes) -> dict[str, Any]:
    """Parse the SSH wire format enough to recover key type and RSA modulus size."""
    offset = 0
    fields: list[bytes] = []
    try:
        while offset + 4 <= len(blob):
            (length,) = struct.unpack(">I", blob[offset : offset + 4])
            offset += 4
            if offset + length > len(blob):
                break
            fields.append(blob[offset : offset + length])
            offset += length
    except struct.error:
        return {}
    if not fields:
        return {}
    key_type = fields[0].decode("ascii", "replace")
    info: dict[str, Any] = {"type": key_type, "fields": len(fields)}
    if key_type == "ssh-rsa" and len(fields) >= 3:
        exponent = int.from_bytes(fields[1], "big")
        modulus = int.from_bytes(fields[2], "big")
        info["bits"] = modulus.bit_length()
        info["exponent"] = exponent
    elif key_type == "ssh-ed25519":
        info["bits"] = 256
    elif key_type.startswith("ecdsa-sha2-"):
        info["bits"] = {"nistp256": 256, "nistp384": 384, "nistp521": 521}.get(key_type.rsplit("-", 1)[-1], "unknown")
    elif key_type == "ssh-dss":
        info["bits"] = 1024
    return info


class Identity(commands.Cog, name="Identity"):
    """Email, handle, phone, credential-hygiene and encoding intelligence."""

    def __init__(self, bot: Any) -> None:
        self.bot = bot
        self.net = bot.net

    # ── email ────────────────────────────────────────────────────────────

    async def _gravatar_exists(self, email: str) -> tuple[bool, str]:
        digest = hashlib.md5(email.strip().lower().encode()).hexdigest()
        url = f"https://gravatar.com/avatar/{digest}?d=404"
        try:
            response = await self.net.get(url, cache_ttl=3600, timeout=10)
            return response.status == 200, digest
        except IntelError:
            return False, digest

    async def _hibp(self, email: str) -> list[dict[str, Any]]:
        key = settings.key("HIBP_API_KEY")
        if not key:
            raise NotConfigured(
                "HIBP_API_KEY",
                "Have I Been Pwned",
                "Breach history per email address. Password exposure checks work without a key.",
                "https://haveibeenpwned.com/API/Key",
            )
        response = await self.net.request(
            "GET",
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{urllib.parse.quote(email)}",
            params={"truncateResponse": "false"},
            headers={"hibp-api-key": key, "user-agent": "OSINT-MATRIX"},
            cache_ttl=3600,
            timeout=20,
        )
        if response.status == 404:
            return []
        if response.status == 401:
            raise IntelError("HIBP rejected the configured API key.", hint="Generate a new key and update `HIBP_API_KEY`.")
        if response.status == 429:
            raise SourceUnavailable("HIBP rate-limited this instance. Wait a minute and retry.")
        if not response.ok:
            raise SourceUnavailable(f"HIBP answered HTTP {response.status}.")
        payload = response.json()
        return payload if isinstance(payload, list) else []

    @intel(
        category="identity",
        brief="Email dossier: syntax, MX routing, disposable/free provider, Gravatar and breach status.",
        usage="<address>",
        aliases=["mailbox", "emailinfo"],
        examples=["email someone@example.com"],
        sources=["Cloudflare DoH", "Gravatar", "HIBP (optional key)"],
        cooldown=(3, 12),
    )
    async def email(self, ctx: commands.Context, target: str = None) -> None:
        await ack(ctx)
        address = require(target, "email address", example=".email someone@example.com").strip()
        if not is_email(address):
            raise UsageError("That does not look like a valid email address.")
        local, _, domain = address.rpartition("@")
        domain = normalize_domain(domain)
        from core import dns

        try:
            mx = await dns.mx(self.net, domain)
        except IntelError:
            mx = []
        disposable = domain in DISPOSABLE_DOMAINS
        free = domain in FREE_EMAIL
        role = local.lower().split("+")[0] in ROLE_ACCOUNTS
        exists, digest = await self._gravatar_exists(address)
        breaches: list[dict[str, Any]] | None = None
        breach_note = "HIBP key not configured"
        if settings.has("HIBP_API_KEY"):
            try:
                breaches = await self._hibp(address)
                breach_note = f"{len(breaches)} breach(es)"
            except IntelError as exc:
                breach_note = str(exc.detail)
        embed = Intel(
            category="identity",
            command="email",
            ctx=ctx,
            target=address,
            summary="Address hygiene check. Nothing is sent to the mailbox and no login is attempted.",
        )
        embed.kv(
            "SYNTAX",
            {
                "Local part": local,
                "Domain": domain,
                "Length": len(address),
                "Valid syntax": True,
                "Normalised": address.lower(),
                "Plus tag": local.split("+", 1)[1] if "+" in local else "none",
            },
            inline=True,
        )
        embed.kv(
            "DELIVERY",
            {
                "MX records": len(mx),
                "Primary MX": mx[0][1] if mx else "none — domain cannot receive mail",
                "Provider": base_domain(mx[0][1]) if mx else "n/a",
                "Disposable": disposable,
                "Free provider": free,
                "Role account": role,
            },
            inline=True,
        )
        embed.kv(
            "PRESENCE",
            {
                "Gravatar": "registered" if exists else "no avatar",
                "Gravatar hash": digest,
                "Breaches": breach_note,
                "Breach names": [breach.get("Name") for breach in (breaches or [])][:8] or "none",
            },
            inline=False,
        )
        risk = 6
        if disposable:
            risk += 45
        if not mx:
            risk += 30
        if role:
            risk += 8
        if breaches:
            risk += min(35, 8 + len(breaches) * 3)
        embed.risk(risk, name="HYGIENE INDEX")
        embed.checks(
            "SIGNALS",
            [
                (bool(mx), "Deliverable", f"{len(mx)} MX records" if mx else "no MX — undeliverable"),
                (not disposable, "Not disposable", "disposable provider" if disposable else "permanent provider"),
                (not role, "Personal mailbox", "role/shared mailbox" if role else "personal-looking"),
                (breaches is None or not breaches, "No known breaches", breach_note),
            ],
        )
        embed.source("Cloudflare DoH", "Gravatar", "HIBP")
        await embed.send(ctx)

    @intel(
        category="identity",
        brief="Full breach history for an email address from Have I Been Pwned.",
        usage="<address>",
        aliases=["breaches", "pwned"],
        examples=["breaches someone@example.com"],
        sources=["Have I Been Pwned"],
        cooldown=(2, 20),
    )
    async def emailbreach(self, ctx: commands.Context, target: str = None) -> None:
        await ack(ctx)
        address = require(target, "email address", example=".breaches someone@example.com").strip()
        if not is_email(address):
            raise UsageError("That does not look like a valid email address.")
        breaches = await self._hibp(address)
        embed = Intel(
            category="identity",
            command="emailbreach",
            ctx=ctx,
            target=address,
            summary="Breach exposure is a credential-hygiene signal, not evidence of compromise. Rotate anything reused.",
        )
        if not breaches:
            embed.checks("RESULT", [(True, "No breaches", "HIBP holds no record for this address")])
            embed.risk(0, name="EXPOSURE")
            await embed.send(ctx, source="HIBP")
            return
        total_records = sum(int(breach.get("PwnCount") or 0) for breach in breaches)
        classes: dict[str, int] = {}
        for breach in breaches:
            for item in breach.get("DataClasses") or []:
                classes[item] = classes.get(item, 0) + 1
        embed.kv(
            "EXPOSURE",
            {
                "Breaches": len(breaches),
                "Records involved": num(total_records),
                "Verified breaches": sum(1 for breach in breaches if breach.get("IsVerified")),
                "Sensitive": sum(1 for breach in breaches if breach.get("IsSensitive")),
                "Data classes": sorted(classes, key=lambda key: classes[key], reverse=True)[:10],
            },
            inline=True,
        )
        rows = []
        for breach in sorted(breaches, key=lambda item: str(item.get("BreachDate")), reverse=True)[:8]:
            rows.append(
                f"{str(breach.get('BreachDate'))[:10]:10}  {clip(breach.get('Name', '?'), 22):22}  "
                f"{num(breach.get('PwnCount') or 0):>12}  {clip(breach.get('Domain') or '-', 26)}"
            )
        embed.code("BREACH TIMELINE", "\n".join(rows), lang="yaml")
        descriptions = "\n\n".join(
            f"**{breach.get('Title')}** ({breach.get('BreachDate')}) — {clip(breach.get('Description') or '', 260)}"
            for breach in breaches[:3]
        )
        if descriptions:
            embed.text("NOTES", descriptions, inline=False)
        embed.risk(min(100, 25 + len(breaches) * 6), name="EXPOSURE INDEX", verdict=f"{len(breaches)} BREACHES")
        embed.steps(
            [
                "Queried HIBP's breached-account endpoint with the configured key",
                "Aggregated data classes across every breach",
                "Built a chronological exposure table",
            ]
        )
        embed.source("HIBP")
        await embed.send(ctx)

    @intel(
        category="identity",
        brief="Gravatar profile and avatar resolution for an email hash.",
        usage="<email|md5 hash>",
        examples=["gravatar someone@example.com", "gravatar 0c2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f"],
        sources=["gravatar.com"],
        cooldown=(3, 12),
    )
    async def gravatar(self, ctx: commands.Context, target: str = None) -> None:
        await ack(ctx)
        raw = require(target, "email or MD5 hash", example=".gravatar someone@example.com")
        if re.fullmatch(r"[a-fA-F0-9]{32}", raw.strip()):
            digest = raw.strip().lower()
            address = None
        elif is_email(raw):
            address = raw.strip().lower()
            digest = hashlib.md5(address.encode()).hexdigest()
        else:
            raise UsageError("Supply an email address or a 32-character MD5 hash.")
        profile_url = f"https://gravatar.com/{digest}.json"
        profile: dict[str, Any] = {}
        try:
            profile = await self.net.get_json(profile_url, cache_ttl=3600, timeout=12)
        except IntelError:
            profile = {}
        avatar = f"https://gravatar.com/avatar/{digest}?s=512"
        exists = bool(profile)
        embed = Intel(
            category="identity",
            command="gravatar",
            ctx=ctx,
            target=address or digest,
            summary="Gravatar is opt-in, but when present it links an email hash to a public profile and avatar.",
        )
        entry = (profile.get("entry") or [{}])[0] if isinstance(profile.get("entry"), list) else {}
        embed.kv(
            "IDENTITY",
            {
                "Email": address or "hash supplied",
                "MD5": digest,
                "Profile": "found" if exists else "not registered",
                "Display name": entry.get("displayName"),
                "Preferred username": entry.get("preferredUsername"),
                "About": clip(entry.get("aboutMe") or "", 200),
                "Location": entry.get("currentLocation"),
                "Job": f"{entry.get('jobTitle') or ''} {entry.get('company') or ''}".strip(),
            },
            inline=True,
        )
        accounts = [f"{item.get('shortname')}: {item.get('username') or item.get('url')}" for item in entry.get("accounts") or []]
        urls = [item.get("value") for item in entry.get("urls") or []]
        embed.kv(
            "LINKS",
            {"Verified accounts": accounts[:10] or "none", "Profile URLs": urls[:8] or "none", "Avatar": avatar},
            inline=False,
        )
        embed.thumbnail(avatar if exists else None)
        embed.checks(
            "RESULT",
            [
                (exists, "Public profile", "profile document returned" if exists else "no public profile"),
                (True, "Avatar endpoint", avatar),
            ],
        )
        embed.source("gravatar.com")
        await embed.send(ctx)

    # ── handles ──────────────────────────────────────────────────────────

    @intel(
        category="identity",
        brief="Enumerate one handle across 45 public platforms and classify each hit.",
        usage="<handle>",
        aliases=["usercheck", "handle"],
        examples=["username somehandle"],
        sources=["45 public profile endpoints"],
        cooldown=(2, 30),
    )
    async def username(self, ctx: commands.Context, target: str = None) -> None:
        await ack(ctx)
        handle = require(target, "username", example=".username somehandle").strip().lstrip("@")
        if not re.fullmatch(r"[A-Za-z0-9_.-]{2,40}", handle):
            raise UsageError("Handles can only contain letters, digits, dot, dash and underscore (2–40 characters).")

        async def check(site: dict[str, Any]) -> dict[str, Any]:
            url = site["url"].format(u=urllib.parse.quote(handle))
            try:
                response = await self.net.request(
                    "GET", url, cache_ttl=900, timeout=8, allow_redirects=True, read_limit=48_000
                )
            except IntelError as exc:
                return {**site, "state": "error", "detail": type(exc).__name__, "url": url}
            status = response.status
            if status in {403, 429, 999}:
                state, detail = "blocked", f"HTTP {status}"
            elif status in {404, 410}:
                state, detail = "absent", f"HTTP {status}"
            elif status == 200:
                if site.get("reliable"):
                    state, detail = "found", "HTTP 200"
                else:
                    state, detail = "unverified", "HTTP 200 (soft page — open manually)"
            else:
                state, detail = "unknown", f"HTTP {status}"
            return {**site, "state": state, "detail": detail, "url": response.url}

        results = await asyncio.gather(*(check(site) for site in USERNAME_SITES))
        found = [row for row in results if row["state"] == "found"]
        unverified = [row for row in results if row["state"] == "unverified"]
        absent = [row for row in results if row["state"] == "absent"]
        blocked = [row for row in results if row["state"] in {"blocked", "error"}]
        base = notice(
            "HANDLE ENUMERATION",
            f"`{handle}` · **{len(found)} confirmed**, {len(unverified)} unverified, {len(absent)} absent, "
            f"{len(blocked)} blocked. Only public profile pages were requested.",
            category="identity",
            footer=f"source: 45 platforms  •  passive requests only",
        )
        sections: list[tuple[str, str]] = []
        if found:
            sections.append(("CONFIRMED", "\n".join(f"`✓` **{row['name']}** · {row['category']}\n{row['url']}" for row in found)))
        if unverified:
            sections.append(("UNVERIFIED — OPEN MANUALLY", "\n".join(f"`?` **{row['name']}** · {row['category']}\n{row['url']}" for row in unverified)))
        if absent:
            sections.append(("ABSENT", "\n".join(f"`✗` **{row['name']}** · {row['detail']}" for row in absent)))
        if blocked:
            sections.append(("BLOCKED / RATE-LIMITED", "\n".join(f"`•` **{row['name']}** · {row['detail']}" for row in blocked)))
        pages = []
        for title, body in sections:
            for start in range(0, max(1, len(body)), 3500):
                page = base.copy()
                page.add_field(name=f"▸ {title}", value=clip(body[start : start + 3500], 1024), inline=False)
                pages.append(page)
        if not pages:
            pages = [base]
        if len(pages) == 1:
            await respond(ctx, pages[0])
        else:
            await respond(ctx, pages[0], view=Paginator(pages, author_id=ctx.author.id))

    @intel(
        category="identity",
        brief="Phone number anatomy: validity, carrier, region, type and timezone (no owner lookup).",
        usage="<number> [region]",
        aliases=["phone", "number"],
        examples=["msisdn +14155552671", "msisdn 02079460958 GB"],
        sources=["libphonenumber offline metadata"],
        cooldown=(3, 10),
    )
    async def msisdn(self, ctx: commands.Context, target: str = None, region: str = None) -> None:
        await ack(ctx)
        raw = require(target, "phone number", example=".msisdn +14155552671").strip()
        if phonenumbers is None:
            raise IntelError("The phonenumbers package is not installed.", hint="Run `pip install -r requirements.txt`.")
        hint = (region or "US").strip().upper()
        try:
            number = phonenumbers.parse(raw, hint)
        except phonenumbers.NumberParseException as exc:
            raise UsageError(f"Could not parse that number: {exc}") from None
        valid = phonenumbers.is_valid_number(number)
        possible = phonenumbers.is_possible_number(number)
        kind = PHONE_TYPES.get(phonenumbers.number_type(number), "unknown")
        carrier_name = pn_carrier.name_for_number(number, "en") or "unknown / ported"
        location = pn_geocoder.description_for_number(number, "en") or "unknown"
        zones = list(pn_timezone.time_zones_for_number(number))
        embed = Intel(
            category="identity",
            command="msisdn",
            ctx=ctx,
            target=raw,
            summary="Offline numbering-plan analysis. No carrier database query is made and no subscriber data is retrieved.",
        )
        embed.kv(
            "NUMBER",
            {
                "Valid": valid,
                "Possible": possible,
                "Country code": number.country_code,
                "Region": phonenumbers.region_code_for_number(number),
                "Type": kind,
                "E.164": phonenumbers.format_number(number, phonenumbers.PhoneNumberFormat.E164),
                "International": phonenumbers.format_number(number, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
                "National": phonenumbers.format_number(number, phonenumbers.PhoneNumberFormat.NATIONAL),
                "RFC 3966": phonenumbers.format_number(number, phonenumbers.PhoneNumberFormat.RFC3966),
            },
            inline=True,
        )
        embed.kv(
            "ATTRIBUTION",
            {
                "Carrier": carrier_name,
                "Location": location,
                "Timezones": zones,
                "Number type": kind,
            },
            inline=True,
        )
        embed.checks(
            "SIGNALS",
            [
                (valid, "Numbering plan", "valid for its region" if valid else "invalid for its region"),
                (kind in {"mobile", "fixed line or mobile"}, "Mobile class", kind),
                (None, "Limit", "carrier and region are numbering-plan facts — they do not identify a person"),
            ],
        )
        embed.source("libphonenumber")
        await embed.send(ctx)

    # ── secrets ──────────────────────────────────────────────────────────

    @intel(
        category="identity",
        brief="Offline password strength audit: entropy, patterns and crack-time estimates.",
        usage="<password>",
        aliases=["passstrength", "strength"],
        examples=["password correct-horse-battery-staple-42"],
        sources=["local computation"],
        cooldown=(2, 15),
    )
    async def password(self, ctx: commands.Context, target: str = None) -> None:
        await ack(ctx)
        secret = require(target, "password", example=".password correct-horse-battery-staple-42")
        length = len(secret)
        classes = {
            "lowercase": bool(re.search(r"[a-z]", secret)),
            "uppercase": bool(re.search(r"[A-Z]", secret)),
            "digits": bool(re.search(r"\d", secret)),
            "symbols": bool(re.search(r"[^A-Za-z0-9]", secret)),
            "spaces": " " in secret,
        }
        alphabet = 0
        if classes["lowercase"]:
            alphabet += 26
        if classes["uppercase"]:
            alphabet += 26
        if classes["digits"]:
            alphabet += 10
        if classes["symbols"]:
            alphabet += 33
        if classes["spaces"]:
            alphabet += 1
        keyspace_bits = length * math.log2(alphabet) if alphabet else 0
        normalized = secret.lower().translate(L33T)
        common = secret.lower() in COMMON_PASSWORDS or normalized in COMMON_PASSWORDS
        repeated = len(set(secret)) <= max(2, length // 3)
        sequences = bool(re.search(r"(0123|1234|2345|3456|4567|5678|6789|abcd|bcde|cdef|qwerty|asdf)", normalized))
        years = bool(re.search(r"(19|20)\d{2}", secret))
        score = min(100, keyspace_bits / 1.2)
        for penalty, condition in (
            (35, common), (20, repeated), (15, sequences), (8, years), (10, length < 12), (10, length < 8),
        ):
            if condition:
                score -= penalty
        score = max(0, score)
        offline = 2**keyspace_bits / 1e10 if keyspace_bits < 200 else float("inf")
        online = 2**keyspace_bits / 100 if keyspace_bits < 200 else float("inf")
        embed = Intel(
            category="identity",
            command="password",
            ctx=ctx,
            target=f"{length} characters · masked",
            summary="This value never leaves the process, is never logged, and is not stored. The message containing it is your responsibility.",
        )
        embed.kv(
            "COMPOSITION",
            {
                "Length": length,
                "Classes": [name for name, present in classes.items() if present],
                "Alphabet size": alphabet,
                "Keyspace": f"2^{keyspace_bits:.1f}",
                "Shannon entropy (observed)": f"{entropy_bits(secret):.1f} bits",
            },
            inline=True,
        )
        embed.kv(
            "CRACK TIME",
            {
                "Online (100/s)": human_delta(online) if math.isfinite(online) else "centuries",
                "Offline GPU (10^10/s)": human_delta(offline) if math.isfinite(offline) else "centuries",
                "Common password": common,
                "Repeated characters": repeated,
                "Keyboard/sequence run": sequences,
                "Contains a year": years,
            },
            inline=True,
        )
        embed.risk(100 - score, name="WEAKNESS INDEX", verdict="STRONG" if score >= 80 else "ADEQUATE" if score >= 55 else "WEAK" if score >= 30 else "CRITICAL")
        embed.checks(
            "RECOMMENDATIONS",
            [
                (length >= 16, "Length ≥ 16", f"{length} characters"),
                (not common, "Not a known password", "found in the common list" if common else "not in the common list"),
                (len(set(secret)) > 6, "Character diversity", f"{len(set(secret))} unique characters"),
                (None, "Better approach", "use a password manager and a unique passphrase per service"),
            ],
        )
        embed.source("local computation")
        await embed.send(ctx)

    @intel(
        category="identity",
        brief="Check a password against the Pwned Passwords range API using k-anonymity.",
        usage="<password>",
        aliases=["pwnedpassword", "hibp-pass"],
        examples=["pwnedpass correct-horse-battery-staple"],
        sources=["api.pwnedpasswords.com"],
        cooldown=(2, 15),
    )
    async def pwnedpass(self, ctx: commands.Context, target: str = None) -> None:
        await ack(ctx)
        secret = require(target, "password", example=".pwnedpass hunter2")
        digest = hashlib.sha1(secret.encode()).hexdigest().upper()
        prefix, suffix = digest[:5], digest[5:]
        response = await self.net.get_text(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            headers={"Add-Padding": "true", "User-Agent": "OSINT-MATRIX"},
            cache_ttl=3600,
            timeout=15,
        )
        count = 0
        for line in response.splitlines():
            candidate, _, hits = line.partition(":")
            if candidate.strip().upper() == suffix:
                count = int(hits.strip() or 0)
                break
        embed = Intel(
            category="identity",
            command="pwnedpass",
            ctx=ctx,
            target=f"{len(secret)} characters · masked",
            summary="Only the first five characters of the SHA-1 hash leave this machine. The full password and full hash never do.",
        )
        embed.kv(
            "RESULT",
            {
                "Times seen": num(count),
                "Status": "EXPOSED" if count else "not found",
                "Hash prefix sent": prefix,
                "Suffix compared locally": f"{suffix[:6]}…",
            },
            inline=True,
        )
        embed.risk(95 if count > 1000 else 75 if count > 10 else 55 if count else 0, name="EXPOSURE", verdict="BREACHED" if count else "CLEAN")
        embed.checks(
            "ADVICE",
            [
                (count == 0, "Not in the corpus", "no appearance in the Pwned Passwords dataset"),
                (count > 0, "Rotate immediately", f"seen {num(count)} times in breach corpora"),
                (None, "Rule", "k-anonymity means the API never learns the password"),
            ],
        )
        embed.source("api.pwnedpasswords.com")
        await embed.send(ctx)

    @intel(
        category="identity",
        brief="Identify a hash format and optionally test a candidate plaintext.",
        usage="<hash> [candidate]",
        aliases=["hashid", "identify"],
        examples=["hash 5f4dcc3b5aa765d61d8327deb882cf99", "hash 5f4dcc3b5aa765d61d8327deb882cf99 password"],
        sources=["local signature table", "hashlib"],
        cooldown=(3, 10),
    )
    async def hash(self, ctx: commands.Context, target: str = None, candidate: str = None) -> None:
        await ack(ctx)
        digest = require(target, "hash", example=".hash 5f4dcc3b5aa765d61d8327deb882cf99").strip()
        matches = [
            (label, note)
            for pattern, label, note in HASH_PATTERNS
            if re.fullmatch(pattern, digest)
        ]
        charset = "hexadecimal" if re.fullmatch(r"[a-fA-F0-9]+", digest) else "base64-ish" if re.fullmatch(r"[A-Za-z0-9+/=_-]+", digest) else "unknown"
        bits = len(digest) * 4 if charset == "hexadecimal" else len(digest) * 6
        embed = Intel(
            category="identity",
            command="hash",
            ctx=ctx,
            target=digest if len(digest) <= 60 else digest[:57] + "...",
            summary="Hashes are one-way: identification narrows the algorithm, it does not reverse the value.",
        )
        embed.kv(
            "FINGERPRINT",
            {
                "Length": len(digest),
                "Character set": charset,
                "Raw bits": bits,
                "Uppercase": digest.upper() == digest,
                "Matches": [label for label, _ in matches] or ["no known format"],
            },
            inline=True,
        )
        if matches:
            embed.checks("CANDIDATE ALGORITHMS", [(True, label, note) for label, note in matches[:8]])
        if candidate:
            checks = []
            for name, function in (
                ("MD5", hashlib.md5), ("SHA-1", hashlib.sha1), ("SHA-224", hashlib.sha224),
                ("SHA-256", hashlib.sha256), ("SHA-384", hashlib.sha384), ("SHA-512", hashlib.sha512),
                ("SHA3-256", hashlib.sha3_256), ("BLAKE2b", hashlib.blake2b),
            ):
                try:
                    computed = function(candidate.encode()).hexdigest()
                except (ValueError, TypeError):
                    continue
                checks.append((computed.lower() == digest.lower(), name, computed[:24] + "…"))
            embed.checks("CANDIDATE TEST", checks)
            embed.quote("A candidate was supplied, so this is a single verification — not a cracking attempt.")
        embed.steps(
            [
                "Measured length and character set",
                "Matched the value against structural signatures",
                "Estimated the algorithm family",
            ]
        )
        embed.source("local signature table")
        await embed.send(ctx)

    @intel(
        category="identity",
        brief="Decode a JWT without verifying it: header, claims, expiry and algorithm.",
        usage="<token>",
        aliases=["jwtdecode"],
        examples=["jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.signature"],
        sources=["local computation"],
        cooldown=(3, 10),
    )
    async def jwt(self, ctx: commands.Context, target: str = None) -> None:
        await ack(ctx)
        token = require(target, "JWT", example=".jwt eyJhbGciOi...")
        parts = token.split(".")
        if len(parts) != 3:
            raise UsageError("A JWT has exactly three dot-separated segments.")

        def decode(segment: str) -> Any:
            padded = segment + "=" * (-len(segment) % 4)
            try:
                return __import__("json").loads(base64.urlsafe_b64decode(padded))
            except (binascii.Error, ValueError, UnicodeDecodeError):
                return None

        header = decode(parts[0]) or {}
        payload = decode(parts[1]) or {}
        embed = Intel(
            category="identity",
            command="jwt",
            ctx=ctx,
            target=f"{len(token)} characters",
            summary="Decoded, not verified. A JWT is only trustworthy after signature and issuer validation by the relying party.",
        )
        embed.kv(
            "HEADER",
            {
                "alg": header.get("alg"),
                "typ": header.get("typ"),
                "kid": header.get("kid"),
                "jku": header.get("jku"),
                "crit": header.get("crit"),
            },
            inline=True,
        )
        interesting = ("iss", "sub", "aud", "exp", "nbf", "iat", "jti", "scope", "email", "name", "role", "roles")
        embed.kv("CLAIMS", {key: payload.get(key) for key in interesting if key in payload} or payload, inline=False)
        time_claims = {}
        for key in ("iat", "nbf", "exp"):
            if isinstance(payload.get(key), (int, float)):
                time_claims[key] = fmt_dt(payload[key])
        if time_claims:
            embed.kv("TIMESTAMPS", time_claims, inline=True)
        expiry = payload.get("exp")
        expired = None
        if isinstance(expiry, (int, float)):
            expired = utcnow().timestamp() > expiry
        embed.checks(
            "RED FLAGS",
            [
                (header.get("alg") != "none", "alg is not none", str(header.get("alg"))),
                (header.get("alg") not in {"HS256", "none"} or bool(header.get("kid")), "Algorithm choice", "HS256 is fine only with a secret no client knows"),
                (expired is not True, "Not expired", "expired" if expired else "within validity window"),
                (bool(payload.get("aud")), "Audience claim", str(payload.get("aud") or "missing")),
                (bool(payload.get("iss")), "Issuer claim", str(payload.get("iss") or "missing")),
            ],
        )
        embed.code("RAW PAYLOAD", __import__("json").dumps(payload, indent=2)[:900], lang="json")
        embed.source("local computation")
        await embed.send(ctx)

    # ── utilities ────────────────────────────────────────────────────────

    @intel(
        category="identity",
        brief="Decode a UUID: version, variant, embedded timestamp and node.",
        usage="<uuid>",
        aliases=["uuidlookup"],
        examples=["uuid 6ba7b810-9dad-11d1-80b4-00c04fd430c8"],
        sources=["local computation"],
        cooldown=(4, 10),
    )
    async def uuid(self, ctx: commands.Context, target: str = None) -> None:
        await ack(ctx)
        raw = require(target, "UUID", example=".uuid 6ba7b810-9dad-11d1-80b4-00c04fd430c8")
        try:
            value = uuid_module.UUID(raw)
        except ValueError:
            raise UsageError("That is not a valid UUID.") from None
        embed = Intel(
            category="identity",
            command="uuid",
            ctx=ctx,
            target=str(value),
            summary="UUIDs are opaque identifiers, but v1 and v7 leak a creation timestamp and v1 leaks the generating node.",
        )
        embed.kv(
            "ANATOMY",
            {
                "Canonical": str(value),
                "Hex": value.hex,
                "URN": value.urn,
                "Integer": value.int,
                "Version": value.version,
                "Variant": str(value.variant),
            },
            inline=True,
        )
        extra: dict[str, Any] = {}
        if value.version == 1:
            extra = {
                "Timestamp": fmt_dt((value.time - 0x01B21DD213814000) / 10_000_000),
                "Node": value.node.to_bytes(6, "big").hex(":"),
                "Clock sequence": value.clock_seq,
            }
        elif value.version == 7:
            milliseconds = value.int >> 80
            extra = {"Timestamp": fmt_dt(milliseconds / 1000), "Unix ms": milliseconds}
        embed.kv("EMBEDDED", extra or {"Note": "this version carries no intrinsic metadata"}, inline=True)
        embed.checks(
            "NOTES",
            [
                (value.version in {1, 7}, "Time-ordered", f"version {value.version}"),
                (value.version == 4, "Random", "122 random bits"),
                (None, "Limit", "a UUID identifies a record, not a person"),
            ],
        )
        embed.source("local computation")
        await embed.send(ctx)

    @intel(
        category="identity",
        brief="Convert between Unix time, ISO 8601, Discord timestamps and calendar fields.",
        usage="<unix|iso>",
        aliases=["time", "epoch"],
        examples=["timestamp 1700000000", "timestamp 2026-11-13T12:00:00Z"],
        sources=["local computation"],
        cooldown=(4, 10),
    )
    async def timestamp(self, ctx: commands.Context, target: str = None) -> None:
        await ack(ctx)
        raw = require(target, "timestamp", example=".timestamp 1700000000")
        parsed = parse_dt(raw)
        if parsed is None:
            raise UsageError("Supply Unix seconds/milliseconds or an ISO-8601 date.")
        stamp = int(parsed.timestamp())
        embed = Intel(
            category="identity",
            command="timestamp",
            ctx=ctx,
            target=raw,
            summary="Normalised time across every representation analysts routinely need to cross-reference.",
        )
        embed.kv(
            "FORMS",
            {
                "Unix seconds": stamp,
                "Unix milliseconds": stamp * 1000,
                "ISO 8601": parsed.isoformat(),
                "RFC 2822": parsed.strftime("%a, %d %b %Y %H:%M:%S +0000"),
                "Date": parsed.strftime("%Y-%m-%d"),
                "Time": parsed.strftime("%H:%M:%S UTC"),
            },
            inline=True,
        )
        embed.kv(
            "CALENDAR",
            {
                "Weekday": parsed.strftime("%A"),
                "ISO week": parsed.isocalendar().week,
                "Day of year": parsed.timetuple().tm_yday,
                "Quarter": (parsed.month - 1) // 3 + 1,
                "Relative": f"<t:{stamp}:R>",
                "Discord": f"<t:{stamp}:F>",
            },
            inline=True,
        )
        embed.checks(
            "SANITY",
            [
                (parsed <= utcnow(), "In the past", "yes" if parsed <= utcnow() else "future timestamp"),
                (1970 <= parsed.year <= 2100, "Plausible range", str(parsed.year)),
                (None, "Precision", "Unix values are UTC; local offsets require an explicit zone"),
            ],
        )
        embed.source("local computation")
        await embed.send(ctx)

    @intel(
        category="identity",
        brief="Multi-format decoder: base64, hex, URL, HTML, binary, ROT13.",
        usage="<value>",
        aliases=["decoder", "unbase64"],
        examples=["decode SGVsbG8sIHdvcmxk"],
        sources=["local computation"],
        cooldown=(3, 10),
    )
    async def decode(self, ctx: commands.Context, target: str = None) -> None:
        await ack(ctx)
        raw = require(target, "value", example=".decode SGVsbG8=")
        results: dict[str, str] = {}
        attempts = {
            "URL": lambda value: urllib.parse.unquote(value),
            "HTML entities": lambda value: html.unescape(value),
            "ROT13": lambda value: __import__("codecs").decode(value, "rot13"),
            "Base64": lambda value: base64.b64decode(value + "=" * (-len(value) % 4)).decode("utf-8"),
            "Base64 URL-safe": lambda value: base64.urlsafe_b64decode(value + "=" * (-len(value) % 4)).decode("utf-8"),
            "Base32": lambda value: base64.b32decode(value.upper() + "=" * (-len(value) % 8)).decode("utf-8"),
            "Hex": lambda value: bytes.fromhex(value).decode("utf-8"),
            "Binary": lambda value: int(value.replace(" ", ""), 2).to_bytes((len(value.replace(" ", "")) + 7) // 8, "big").decode("utf-8", "replace"),
            "Octal": lambda value: "".join(chr(int(value[i : i + 3], 8)) for i in range(0, len(value), 3)),
        }
        for label, function in attempts.items():
            try:
                decoded = function(raw.strip())
            except (ValueError, binascii.Error, UnicodeDecodeError, OverflowError):
                continue
            cleaned = decoded.replace("\x00", "").strip()
            if cleaned and cleaned != raw.strip() and sum(ch.isprintable() or ch in "\n\t" for ch in cleaned) / max(1, len(cleaned)) > 0.8:
                results[label] = clip(cleaned, 300)
        embed = Intel(
            category="identity",
            command="decode",
            ctx=ctx,
            target=clip(raw, 80),
            summary="Every plausible decoding is attempted locally. Nothing is transmitted.",
        )
        if results:
            embed.checks("DECODINGS", [(True, label, value) for label, value in results.items()])
        else:
            embed.field("▸ RESULT", "No printable decoding matched. The value may be encrypted, compressed or simply plaintext.", inline=False)
        embed.kv("INPUT", {"Length": len(raw), "Printable": raw.isprintable(), "Non-ASCII": any(ord(char) > 127 for char in raw)}, inline=True)
        embed.source("local computation")
        await embed.send(ctx)

    @intel(
        category="identity",
        brief="Encode a value into base64, hex, URL, HTML, binary and ROT13.",
        usage="<value>",
        aliases=["encoder", "b64"],
        examples=["encode hello world"],
        sources=["local computation"],
        cooldown=(3, 10),
    )
    async def encode(self, ctx: commands.Context, target: str = None) -> None:
        await ack(ctx)
        raw = require(target, "value", example=".encode hello world")
        encoded = {
            "Base64": base64.b64encode(raw.encode()).decode(),
            "Base64 URL-safe": base64.urlsafe_b64encode(raw.encode()).decode(),
            "Base32": base64.b32encode(raw.encode()).decode(),
            "Hex": raw.encode().hex(),
            "URL": urllib.parse.quote(raw, safe=""),
            "HTML": html.escape(raw),
            "Binary": " ".join(f"{byte:08b}" for byte in raw.encode()),
            "ROT13": __import__("codecs").encode(raw, "rot13"),
            "Reversed": raw[::-1],
            "Unicode escapes": raw.encode("unicode_escape").decode(),
        }
        embed = Intel(
            category="identity",
            command="encode",
            ctx=ctx,
            target=clip(raw, 80),
            summary="Local transformations for payload construction, signature testing and log-safe transport.",
        )
        embed.code("OUTPUT", "\n".join(f"{label:>18}: {clip(value, 180)}" for label, value in encoded.items()), lang="yaml")
        embed.kv("INPUT", {"Characters": len(raw), "Bytes": len(raw.encode()), "Printable": raw.isprintable()}, inline=True)
        embed.source("local computation")
        await embed.send(ctx)

    @intel(
        category="identity",
        brief="Parse a User-Agent string into browser, engine, OS and device class.",
        usage="<user agent>",
        aliases=["ua"],
        examples=["useragent Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36"],
        sources=["local signature table"],
        cooldown=(4, 10),
    )
    async def useragent(self, ctx: commands.Context, *, target: str = None) -> None:
        await ack(ctx)
        raw = require(target, "user agent", example=".useragent Mozilla/5.0 ...")
        found: dict[str, str] = {}
        for group, patterns in UA_PATTERNS.items():
            for label, pattern in patterns:
                match = re.search(pattern, raw, re.IGNORECASE)
                if match:
                    version = match.group(1) if match.groups() else ""
                    found[group] = f"{label} {version}".strip()
                    break
        embed = Intel(
            category="identity",
            command="useragent",
            ctx=ctx,
            target=clip(raw, 80),
            summary="User-Agent strings are client-supplied and trivially spoofed. Treat them as hints, not facts.",
        )
        embed.kv(
            "PARSED",
            {
                "Browser": found.get("browser", "unrecognised"),
                "Engine": found.get("engine", "unrecognised"),
                "Operating system": found.get("os", "unrecognised"),
                "Device class": found.get("device", "unrecognised"),
                "Length": len(raw),
            },
            inline=True,
        )
        embed.code("RAW", raw, lang="yaml")
        embed.checks(
            "SIGNALS",
            [
                ("Bot / script" in found.get("device", ""), "Automation", found.get("device") or "not detected"),
                ("Mobile" in found.get("device", "") or "Tablet" in found.get("device", ""), "Mobile class", found.get("device", "desktop")),
                (None, "Caveat", "spoofable in one header; correlate with TLS and header order"),
            ],
        )
        embed.source("local signature table")
        await embed.send(ctx)

    @intel(
        category="identity",
        brief="Validate an IBAN: country length, structure and MOD-97 checksum.",
        usage="<iban>",
        aliases=["bank"],
        examples=["iban GB82WEST12345698765432"],
        sources=["local computation"],
        cooldown=(4, 10),
    )
    async def iban(self, ctx: commands.Context, target: str = None) -> None:
        await ack(ctx)
        raw = require(target, "IBAN", example=".iban GB82WEST12345698765432")
        compact = re.sub(r"\s+", "", raw).upper()
        country = compact[:2]
        expected = IBAN_LENGTHS.get(country)
        valid_chars = bool(re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]+", compact))
        rearranged = compact[4:] + compact[:4]
        numeric = "".join(str(int(char, 36)) for char in rearranged)
        checksum = int(numeric) % 97 if numeric.isdigit() else -1
        embed = Intel(
            category="identity",
            command="iban",
            ctx=ctx,
            target=compact,
            summary="Structural validation only. It confirms the checksum, not that the account exists or belongs to anyone.",
        )
        embed.kv(
            "STRUCTURE",
            {
                "Country": country,
                "Check digits": compact[2:4],
                "BBAN": compact[4:],
                "Length": len(compact),
                "Expected length": expected or "unknown country",
                "Format": IBAN_BANK_LABELS.get(country, "country-specific"),
            },
            inline=True,
        )
        embed.kv(
            "CHECKSUM",
            {
                "MOD-97 remainder": checksum,
                "Valid checksum": checksum == 1,
                "Character set": "valid" if valid_chars else "invalid",
                "Formatted": " ".join(compact[i : i + 4] for i in range(0, len(compact), 4)),
            },
            inline=True,
        )
        embed.checks(
            "VERDICT",
            [
                (expected is not None, "Known country", country),
                (expected == len(compact), "Length matches", f"{len(compact)}/{expected or '?'}"),
                (checksum == 1, "MOD-97 passes", f"remainder {checksum}"),
                (valid_chars, "Character set", "alphanumeric"),
            ],
        )
        embed.source("local computation")
        await embed.send(ctx)

    @intel(
        category="identity",
        brief="SSH public key fingerprint and structural analysis.",
        usage="<ssh public key>",
        aliases=["ssh"],
        examples=["sshkey ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... user@host"],
        sources=["local computation"],
        cooldown=(3, 10),
    )
    async def sshkey(self, ctx: commands.Context, *, target: str = None) -> None:
        await ack(ctx)
        raw = require(target, "SSH public key", example=".sshkey ssh-ed25519 AAAAC3... comment")
        parts = raw.strip().split()
        if len(parts) < 2 or not parts[1].startswith("AAAA"):
            raise UsageError("Expected `<type> <base64> [comment]`.")
        key_type, blob_b64 = parts[0], parts[1]
        comment = " ".join(parts[2:]) or "none"
        try:
            blob = base64.b64decode(blob_b64 + "=" * (-len(blob_b64) % 4))
        except binascii.Error:
            raise UsageError("The key body is not valid base64.") from None
        sha256 = base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")
        md5 = ":".join(f"{byte:02x}" for byte in hashlib.md5(blob).digest())
        info = _decode_ssh_blob(blob)
        embed = Intel(
            category="identity",
            command="sshkey",
            ctx=ctx,
            target=f"{key_type} · {len(blob)} bytes",
            summary="Fingerprints let you compare a key against authorised_keys or a public key server without exposing the key itself.",
        )
        embed.kv(
            "KEY",
            {
                "Declared type": key_type,
                "Wire type": info.get("type"),
                "Bits": info.get("bits", "unknown"),
                "Exponent": info.get("exponent", "n/a"),
                "Comment": clip(comment, 80),
                "Blob bytes": len(blob),
            },
            inline=True,
        )
        embed.code(
            "FINGERPRINTS",
            f"SHA256  {sha256}\nMD5     {md5}",
            lang="yaml",
        )
        embed.checks(
            "SANITY",
            [
                (info.get("type") == key_type, "Type matches body", f"{info.get('type')} vs {key_type}"),
                (info.get("bits", 2048) >= 2048 if isinstance(info.get("bits"), int) else True, "Key size", str(info.get("bits"))),
                (None, "Usage", "compare against `~/.ssh/authorized_keys` with `ssh-keygen -lf`"),
            ],
        )
        embed.source("local computation")
        await embed.send(ctx)


async def setup(bot: Any) -> None:
    await bot.add_cog(Identity(bot))

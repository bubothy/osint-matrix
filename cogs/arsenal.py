"""Arsenal: local payload crafts, lure analysis and crypto helpers.

Everything here runs on the instance. No input is forwarded to a third party,
which is what makes the module useful for phishing triage, CTF work and
incident notes that should not leave the machine.

Two rules shaped the design:

* the phishing commands are *defensive*. ``phishmask`` shows the gap between a
  link's label and its destination using a reserved domain, ``typosquat``
  enumerates lookalikes so they can be registered or watchlisted, and nothing
  here sends, submits or hosts anything;
* every command is reachable through one small registry, so adding another
  craft is a single function plus one tuple.
"""

from __future__ import annotations

import base64
import binascii
import datetime as dt
import hashlib
import hmac
import ipaddress
import json
import math
import re
import secrets
import string
import urllib.parse
import zlib
from collections import Counter
from typing import Any, Callable

from discord.ext import commands

from core.command import intel
from core.embeds import Intel
from core.errors import UsageError
from core.utils import ack, base_domain, clip, parse_dt, strip_target, utcnow

Handler = Callable[[str], Any]

TEXT_LIMIT = 1300


# ── shared helpers ─────────────────────────────────────────────────────────


def _plain(value: Any, limit: int = TEXT_LIMIT) -> str:
    text = "" if value is None else str(value)
    text = text.replace("```", "ˋˋˋ")
    if len(text) > limit - 16:
        text = text[: limit - 17].rstrip() + "…"
    return f"```text\n{text}\n```"


def _pair(raw: str, what: str = "left|right") -> tuple[str, str]:
    if "|" not in raw:
        raise UsageError(f"Use `{what}` as the separator.")
    left, right = raw.split("|", 1)
    return left.strip(), right.strip()


def _table(headers: list[str], rows: list[list[Any]], *, limit: int = 32) -> str:
    def cell(value: Any) -> str:
        return str("" if value is None else value).replace("\n", " ").replace("\r", " ")

    body = [[cell(item) for item in row] for row in rows]
    widths = []
    for index, title in enumerate(headers):
        width = len(title)
        for row in body:
            if index < len(row):
                width = max(width, len(row[index]))
        widths.append(min(width, limit))
    lines = ["  ".join(headers[i].ljust(widths[i]) for i in range(len(headers)))]
    lines.append("  ".join("─" * width for width in widths))
    for row in body:
        lines.append(
            "  ".join(
                (row[i] if i < len(row) else "")[: widths[i]].ljust(widths[i])
                for i in range(len(headers))
            )
        )
    return "\n".join(lines)


def _int(raw: str, what: str, *, low: int | None = None, high: int | None = None) -> int:
    text = raw.strip().replace(",", "").replace("_", "")
    try:
        value = int(text, 0)
    except ValueError:
        raise UsageError(f"`{what}` needs a whole number.") from None
    if low is not None:
        value = max(low, value)
    if high is not None:
        value = min(high, value)
    return value


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _unb64u(raw: str) -> bytes:
    padding = "=" * (-len(raw) % 4)
    return base64.urlsafe_b64decode(raw + padding)


# ── phishing and lure analysis ─────────────────────────────────────────────


def _phishmask(raw: str) -> dict[str, Any]:
    url = raw if "://" in raw else f"https://{raw}"
    parsed = urllib.parse.urlsplit(url)
    host = (parsed.hostname or raw).lower()
    label = (host + (parsed.path or "/"))[:60]
    return {
        "LURE": f"[{label}]({url})",
        "WHAT THE VICTIM READS": label,
        "WHERE THE LINK GOES": clip(url, 220),
        "SCHEME": parsed.scheme or "—",
        "HOST": host,
        "REGISTRABLE": base_domain(host),
        "LABEL MATCHES DESTINATION": "yes" if label.split("/")[0] == host else "no — the classic mismatch",
        "SAFE DEMO": f"[{label}](https://example.com/phish-demo/{urllib.parse.quote(host)})",
        "HOW TO TRAIN ON IT": "show the demo link beside the real one and ask which host the browser would contact",
    }


_URGENCY = (
    "urgent", "immediately", "final notice", "last chance", "expires", "suspend",
    "verify now", "act now", "within 24 hours", "account locked", "unusual activity",
    "confirm your", "re-verify", "reactivate", "limited time", "avoid closure",
    "warning", "alert", "failure to", "terminated", "billing problem", "restricted",
)
_CREDENTIAL = (
    "password", "passcode", "one-time code", "otp", "2fa", "login", "sign in",
    "credentials", "username and password", "recovery code", "seed phrase",
    "wallet", "connect wallet", "verify identity", "card number", "cvv", "ssn",
)
_CHANNEL = ("whatsapp", "telegram", "dm me", "text me", "call this number", "reply to this")
_PRESSURE = ("legal action", "law enforcement", "account deleted", "permanently", "penalty", "fine")


def _phishlure(raw: str) -> dict[str, Any]:
    text = raw.strip()
    if len(text) < 8:
        raise UsageError("Paste the message text you want to score.")
    lowered = text.lower()
    signals: list[tuple[str, int, str]] = []

    def hit(words: tuple[str, ...], weight: int, name: str) -> None:
        found = [word for word in words if word in lowered]
        if found:
            signals.append((name, weight * min(3, len(found)), ", ".join(found[:4])))

    hit(_URGENCY, 9, "Urgency language")
    hit(_CREDENTIAL, 12, "Credential or wallet request")
    hit(_CHANNEL, 6, "Off-platform channel")
    hit(_PRESSURE, 10, "Threat of consequence")
    links = re.findall(r"(?:https?://|www\.)[^\s<>\"']+", text, re.IGNORECASE)
    if links:
        signals.append(("Embedded link", 8 * min(3, len(links)), ", ".join(links[:3])))
    if re.search(r"\b(?:bitcoin|btc|eth|usdt|trc20|wallet address)\b", lowered):
        signals.append(("Crypto payment rail", 10, "crypto terms in the body"))
    if re.search(r"\+?\d[\d\s().-]{7,}\d", text):
        signals.append(("Phone number", 5, "callback number present"))
    if re.search(r"\b(?:dear (?:customer|user|member)|valued customer)\b", lowered):
        signals.append(("Generic salutation", 4, "no recipient name"))
    if re.search(r"\b(?:apple|microsoft|paypal|discord|steam|amazon|netflix|bank)\b", lowered):
        signals.append(("Brand impersonation", 7, "known brand named"))
    base = sum(weight for _, weight, _ in signals)
    # Independent signal groups reinforce each other: one marker is weak evidence,
    # four markers acting together are not.
    diversity = 1 + 0.12 * max(0, len(signals) - 1)
    score = min(100, round(base * diversity))
    verdict = (
        "CRITICAL" if score >= 65 else "HIGH" if score >= 35 else "MEDIUM" if score >= 18 else "LOW"
    )
    return {
        "SCORE": f"{score}/100 · {verdict}",
        "SIGNALS": _table(["SIGNAL", "WEIGHT", "EVIDENCE"], [[n, w, e] for n, w, e in signals])
        if signals
        else "no known lure markers found",
        "LINKS": "\n".join(links[:6]) or "none",
        "NOTE": "heuristics only — a low score does not make a message safe",
    }


def _phishdork(raw: str) -> dict[str, Any]:
    brand = strip_target(raw).lower()
    if not brand:
        raise UsageError("Give a brand or hostname, e.g. `.phishdork paypal`.")
    slug = re.sub(r"[^a-z0-9.-]", "", brand)
    rows = [
        ("lookalike", f'site:{slug}.com inurl:login OR inurl:signin'),
        ("kit staging", f'"index of" {slug} login page'),
        ("credential harvest", f'intext:"{slug}" (intitle:"sign in" OR intitle:"log in") -site:{slug}.com'),
        ("paste leak", f'site:pastebin.com "{slug}" password'),
        ("config exposure", f'"{slug}" (inurl:.env OR inurl:config.php) -site:{slug}.com'),
        ("lookalike cert", f'"{slug}" site:crt.sh'),
        ("typo domain", f'"{slug}" site:whois.domaintools.com'),
        ("telegram lure", f"t.me {slug} login"),
        ("redirect abuse", f'"{slug}.com" inurl:redirect='),
        ("kit fingerprint", f'"{slug}" (inurl:login.php id=)'),
    ]
    return {
        "BRAND": slug,
        "DORKS": _table(["PURPOSE", "QUERY"], [[a, b] for a, b in rows]),
        "USE": "run these in a search engine you are allowed to query, then report hits to the brand's abuse contact",
        "NOTE": "dorks are read-only queries; they never touch the target",
    }


_KIT_FINGERPRINTS: tuple[tuple[str, str], ...] = (
    (r"api\.telegram\.org", "Telegram exfiltration endpoint"),
    (r"discord(?:app)?\.com/api/webhooks", "Discord webhook exfiltration"),
    (r"<form[^>]+action=\"(?:https?:)?//(?!.*%s)", "form posts to a third-party host"),
    (r"eval\(atob\(", "base64 blob executed with eval"),
    (r"document\.cookie", "cookie theft routine"),
    (r"fetch\(\s*['\"]https?://(?!localhost)", "credential POST to a remote host"),
    (r"captcha|hcaptcha|recaptcha", "fake captcha gate"),
    (r"btoa\(", "client-side base64 encoding"),
    (r"\.php\?.*(?:email|pass|login|token)=", "GET-based credential handoff"),
    (r"window\.location\.replace\(['\"]https?://(?!.*\.tk|\.ml)", "post-submit redirect"),
    (r"<iframe[^>]+src=\"https?://", "embedded third-party frame"),
    (r"obfuscator|javascript\.obfuscator", "client-side obfuscation toolkit"),
    (r"navigator\.userAgent\.includes\('(?:curl|bot|headless)", "anti-analysis user-agent gate"),
    (r"localStorage\.setItem\('token'", "token harvesting"),
    (r"sendBeacon\(", "beacon exfiltration"),
)


def _phishkit(raw: str) -> dict[str, Any]:
    text = raw.strip()
    if len(text) < 6:
        raise UsageError("Paste the HTML or source snippet to fingerprint.")
    lowered = text.lower()
    hits = []
    for pattern, label in _KIT_FINGERPRINTS:
        try:
            if re.search(pattern, text) or re.search(pattern, lowered):
                hits.append((label, pattern))
        except re.error:
            continue
    return {
        "FINGERPRINTS": _table(["INDICATOR", "MATCH"], [[a, clip(b, 42)] for a, b in hits])
        if hits
        else f"none of the {len(_KIT_FINGERPRINTS)} kit fingerprints matched",
        "VERDICT": f"{len(hits)} indicators" + (" — treat the sample as live" if hits else " — no kit markers"),
        "NEXT": "hand the sample to the hosting provider's abuse desk and to any brand the page imitates",
    }


def _typosquat(raw: str) -> dict[str, Any]:
    host = strip_target(raw).lower().split("/")[0]
    if "." not in host:
        raise UsageError("Give a domain, e.g. `.typosquat paypal.com`.")
    name, _, tld = host.partition(".")
    if len(name) < 3:
        raise UsageError("That label is too short to mutate.")
    keyboard = {
        "q": "wa", "w": "qes", "e": "wrd", "r": "etf", "t": "ryg", "y": "tuh",
        "u": "yij", "i": "uok", "o": "ipl", "p": "ol", "a": "qsz", "s": "awdx",
        "d": "sefc", "f": "drgv", "g": "fthb", "h": "gyjn", "j": "hukm",
        "k": "jil", "l": "kop", "z": "asx", "x": "sdc", "c": "dfv", "v": "cfgb",
        "b": "vghn", "n": "bhjm", "m": "njk",
    }
    seen: dict[str, str] = {}

    def add(value: str, kind: str) -> None:
        if value and value != host and value not in seen:
            seen[value] = kind

    for index in range(len(name)):
        add(name[:index] + name[index + 1:] + "." + tld, "omission")
        if index + 1 < len(name):
            add(name[:index] + name[index + 1] + name[index] + name[index + 2:] + "." + tld, "transposition")
        if index + 1 < len(name):
            add(name[:index] + name[index] * 2 + name[index + 1:] + "." + tld, "repetition")
        for char in keyboard.get(name[index], ""):
            add(name[:index] + char + name[index + 1:] + "." + tld, "keyboard swap")
        add(name[:index] + name[index] + name[index:] + "." + tld, "insertion")
    add(f"{name}-{tld}.com", "hyphen split")
    add(f"{name}.{tld}.example.com", "subdomain of a decoy")
    add(f"{name}{tld}", "TLD run together")
    for other in ("tk", "ml", "xyz", "top", "zip", "mov", "cc", "site", "online"):
        if other != tld:
            add(f"{name}.{other}", "cheap TLD swap")
    homoglyph = {"a": "а", "e": "е", "o": "о", "p": "р", "c": "с", "x": "х", "y": "у", "i": "і"}
    for index, char in enumerate(name):
        if char in homoglyph:
            add(name[:index] + homoglyph[char] + name[index + 1:] + "." + tld, "homoglyph")
            break
    rows = [[value, kind] for value, kind in list(seen.items())[:24]]
    return {
        "BASE": host,
        "VARIANTS": _table(["CANDIDATE", "MUTATION"], rows),
        "COUNT": f"{len(seen)} tracked · {len(rows)} shown",
        "WHY": "register or monitor these labels — lookalikes are the cheapest phishing infrastructure",
    }


_CONFUSABLES = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i",
    "ј": "j", "ѕ": "s", "һ": "h", "ԁ": "d", "ԛ": "q", "ԝ": "w", "ɡ": "g",
    "α": "a", "ε": "e", "ι": "i", "κ": "k", "ν": "v", "ο": "o", "ρ": "p", "τ": "t",
    "υ": "u", "χ": "x", "ѵ": "v", "ӏ": "l", "ı": "i", "ᴏ": "o",
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b",
}
_HOMOGLYPH_OUT = {
    "a": "а", "e": "е", "o": "о", "p": "р", "c": "с", "y": "у", "x": "х",
    "i": "і", "j": "ј", "s": "ѕ", "h": "һ", "d": "ԁ", "q": "ԛ", "w": "ԝ", "g": "ɡ",
}


def _homoglyph(raw: str) -> dict[str, Any]:
    text = raw.strip()
    if not text:
        raise UsageError("Give text to render with confusables.")
    rendered = "".join(_HOMOGLYPH_OUT.get(char.lower(), char) for char in text)
    mapped = sorted({f"{char}→{_HOMOGLYPH_OUT[char]}" for char in text.lower() if char in _HOMOGLYPH_OUT})
    return {
        "ASCII": text,
        "CONFUSABLE": rendered,
        "SUBSTITUTIONS": "  ".join(mapped) or "nothing to substitute",
        "CODE POINTS": " ".join(f"U+{ord(char):04X}" for char in rendered[:12]),
        "USE": "paste into a lookalike detector or a phishing-awareness slide",
    }


def _dehomoglyph(raw: str) -> dict[str, Any]:
    text = raw.strip()
    if not text:
        raise UsageError("Give text containing lookalike characters.")
    cleaned = "".join(_CONFUSABLES.get(char, char) for char in text)
    changed = sum(1 for a, b in zip(text, cleaned) if a != b)
    return {
        "ORIGINAL": text,
        "NORMALISED": cleaned,
        "NFKC": __import__("unicodedata").normalize("NFKC", text),
        "REPLACED": f"{changed} characters",
        "USE": "compare the two strings when a domain looks almost right",
    }


def _script_of(char: str) -> str:
    import unicodedata

    name = unicodedata.name(char, "")
    for script in ("CYRILLIC", "GREEK", "LATIN", "ARMENIAN", "HEBREW", "ARABIC", "CHEROKEE", "COPTIC"):
        if name.startswith(script):
            return script.title()
    if char.isdigit():
        return "Digit"
    if char in "-._":
        return "Punctuation"
    return "Other"


def _confusable(raw: str) -> dict[str, Any]:
    host = strip_target(raw).lower()
    host = host.split("/")[0]
    if not host:
        raise UsageError("Give a domain or label to inspect.")
    rows = []
    mixed = False
    for label in host.split("."):
        scripts = sorted({_script_of(char) for char in label if char not in "-"})
        interesting = [script for script in scripts if script not in {"Latin", "Digit"}]
        if interesting:
            mixed = True
        rows.append([label or "—", ", ".join(scripts) or "—", "mixed" if interesting else "ascii"])
    ascii_form = ""
    try:
        ascii_form = host.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        ascii_form = "not encodable"
    return {
        "LABELS": _table(["LABEL", "SCRIPTS", "VERDICT"], rows),
        "PUNYCODE": ascii_form,
        "VERDICT": "mixed-script label — classic homograph" if mixed else "single-script label",
        "NEXT": f"`confusable` says nothing about intent; check registration age and certificate history for `{ascii_form}`",
    }


def _urlentropy(raw: str) -> dict[str, Any]:
    url = raw if "://" in raw else f"https://{raw}"
    parsed = urllib.parse.urlsplit(url)
    host = parsed.hostname or ""
    path = parsed.path or "/"

    def entropy(value: str) -> float:
        if not value:
            return 0.0
        counts = Counter(value)
        total = len(value)
        return -sum((n / total) * math.log2(n / total) for n in counts.values())

    host_entropy = entropy(host)
    path_entropy = entropy(path)
    signals = []
    if host_entropy > 3.6 and len(host) > 20:
        signals.append("host looks generated (high entropy, long label)")
    if len(path) > 60:
        signals.append("long path")
    if re.search(r"[0-9a-f]{16,}", path, re.IGNORECASE):
        signals.append("hex blob in path")
    if len(parsed.query) > 80:
        signals.append("large query string")
    if parsed.port and parsed.port not in {80, 443}:
        signals.append(f"non-standard port {parsed.port}")
    return {
        "HOST": host or "—",
        "HOST ENTROPY": f"{host_entropy:.2f} bits/char",
        "PATH ENTROPY": f"{path_entropy:.2f} bits/char",
        "LENGTH": f"host {len(host)} · path {len(path)} · query {len(parsed.query)}",
        "SIGNALS": "\n".join(f"• {item}" for item in signals) or "nothing unusual in the shape",
    }


def _urlunwrap(raw: str) -> dict[str, Any]:
    current = strip_target(raw)
    if not current:
        raise UsageError("Give a URL to unwrap.")
    steps = [current]
    for _ in range(4):
        decoded = urllib.parse.unquote(steps[-1])
        if decoded == steps[-1]:
            break
        steps.append(decoded)
    for key in ("u", "url", "redirect", "target", "dest", "next", "r"):
        match = re.search(rf"[?&]{key}=([^&]+)", steps[-1], re.IGNORECASE)
        if not match:
            continue
        candidate = urllib.parse.unquote(match.group(1))
        if candidate.startswith("http"):
            steps.append(candidate)
            break
    match = re.search(r"https?://[^\s]+", steps[-1])
    if match and match.group(0) != steps[-1]:
        steps.append(match.group(0))
    return {
        "LAYERS": _table(
            ["#", "VALUE"],
            [[index, clip(value, 88)] for index, value in enumerate(steps, 1)],
            limit=88,
        ),
        "FINAL HOST": (urllib.parse.urlsplit(steps[-1]).hostname or "—"),
        "NOTE": "decoded offline — the destination was never contacted",
    }


_REDIRECT_KEYS = (
    "url", "u", "redirect", "redirect_uri", "redirect_url", "next", "target",
    "dest", "destination", "continue", "return", "returnurl", "goto", "out",
    "link", "to", "r", "callback",
)


def _redirects(raw: str) -> dict[str, Any]:
    url = raw if "://" in raw else f"https://{raw}"
    parsed = urllib.parse.urlsplit(url)
    pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    rows = []
    for key, value in pairs:
        if key.lower() in _REDIRECT_KEYS:
            decoded = urllib.parse.unquote(value)
            target = urllib.parse.urlsplit(decoded if "://" in decoded else f"https://{decoded}")
            rows.append([key, clip(decoded, 60), target.hostname or "—"])
    return {
        "REDIRECT PARAMETERS": _table(["KEY", "VALUE", "TARGET HOST"], rows)
        if rows
        else "no redirect-style parameters found",
        "QUERY PAIRS": f"{len(pairs)}",
        "HOST": parsed.hostname or "—",
        "RISK": "open redirects turn a trusted host into a phishing hop" if rows else "no open-redirect shape",
    }


def _defang(raw: str) -> dict[str, Any]:
    text = raw.strip()
    if not text:
        raise UsageError("Give a URL or indicator to defang.")
    out = (
        text.replace("http://", "hxxp://")
        .replace("https://", "hxxps://")
        .replace(".", "[.]")
        .replace("@", "[at]")
        .replace("://", "[://]")
    )
    return {
        "DEFANGED": out,
        "MODE": "share-safe form for reports and chat",
        "REVERSIBLE": "yes — use `.refang` to restore it",
    }


def _refang(raw: str) -> dict[str, Any]:
    text = raw.strip()
    if not text:
        raise UsageError("Give a defanged indicator.")
    out = (
        text.replace("hxxps://", "https://")
        .replace("hxxp://", "http://")
        .replace("[://]", "://")
        .replace("[.]", ".")
        .replace("(.)", ".")
        .replace("[at]", "@")
        .replace("[dot]", ".")
    )
    return {"REFANGED": out, "MODE": "restored", "NOTE": "do not click a restored link unless you trust the host"}


_IOC_PATTERNS: tuple[tuple[str, str], ...] = (
    ("IPv4", r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    ("IPv6", r"\b(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}\b"),
    ("URL", r"https?://[^\s<>\"')]+"),
    ("Email", r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    ("SHA-256", r"\b[A-Fa-f0-9]{64}\b"),
    ("SHA-1", r"\b[A-Fa-f0-9]{40}\b"),
    ("MD5", r"\b[A-Fa-f0-9]{32}\b"),
    ("Bitcoin", r"\b(?:bc1[a-z0-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b"),
    ("Ethereum", r"\b0x[a-fA-F0-9]{40}\b"),
    ("Domain", r"\b(?:[a-z0-9][a-z0-9-]{0,62}\.)+[a-z]{2,24}\b"),
    ("CVE", r"\bCVE-\d{4}-\d{4,7}\b"),
)


def _iocs(raw: str) -> dict[str, Any]:
    text = raw.strip()
    if len(text) < 4:
        raise UsageError("Paste text to extract indicators from.")
    found: dict[str, list[str]] = {}
    for label, pattern in _IOC_PATTERNS:
        values = []
        for match in re.findall(pattern, text, re.IGNORECASE):
            value = match if isinstance(match, str) else match[0]
            if value not in values and not value.endswith(".example"):
                values.append(value)
        if values:
            found[label] = values[:8]
    if not found:
        raise UsageError("No indicators matched.")
    blocks = {label: "\n".join(values) for label, values in found.items()}
    blocks["TOTAL"] = f"{sum(len(v) for v in found.values())} indicators across {len(found)} types"
    return blocks


# ── ciphers and encodings ──────────────────────────────────────────────────


def _caesar(raw: str) -> dict[str, Any]:
    shift_raw, text = _pair(raw, "shift|text")
    shift = _int(shift_raw, "shift") % 26
    out = "".join(
        chr((ord(char) - 65 + shift) % 26 + 65) if char.isupper()
        else chr((ord(char) - 97 + shift) % 26 + 97) if char.islower()
        else char
        for char in text
    )
    return {"SHIFT": f"ROT{shift}", "OUTPUT": out}


def _uncaesar(raw: str) -> dict[str, Any]:
    text = raw.strip()
    if not text:
        raise UsageError("Give the cipher text.")
    rows = []
    for shift in range(26):
        rows.append([f"{shift:02d}", "".join(
            chr((ord(char) - 65 - shift) % 26 + 65) if char.isupper()
            else chr((ord(char) - 97 - shift) % 26 + 97) if char.islower()
            else char
            for char in text
        )[:64]])
    return {"SHIFTS": _table(["ROT", "PLAINTEXT CANDIDATE"], rows, limit=64)}


def _rot47(raw: str) -> dict[str, Any]:
    out = "".join(chr(33 + (ord(char) - 33 + 47) % 94) if 33 <= ord(char) <= 126 else char for char in raw)
    return {"OUTPUT": out, "SELF INVERSE": "yes — run it again to decode"}


def _atbash(raw: str) -> dict[str, Any]:
    out = "".join(
        chr(219 - ord(char)) if "a" <= char <= "z" else chr(155 - ord(char)) if "A" <= char <= "Z" else char
        for char in raw
    )
    return {"OUTPUT": out}


def _a1z26(raw: str) -> dict[str, Any]:
    words = []
    for word in raw.split():
        words.append(" ".join(str(ord(char.lower()) - 96) for char in word if char.isalpha()))
    return {"OUTPUT": " / ".join(part for part in words if part) or "no letters", "STYLE": "1=A … 26=Z"}


def _una1z26(raw: str) -> dict[str, Any]:
    tokens = re.split(r"[^0-9]+", raw.strip())
    letters = []
    for token in tokens:
        if not token:
            continue
        value = int(token)
        if 1 <= value <= 26:
            letters.append(chr(value + 96))
        else:
            letters.append("?")
    return {"OUTPUT": "".join(letters) or "no numbers found"}


def _vigenere(raw: str, *, decrypt: bool = False) -> dict[str, Any]:
    key_raw, text = _pair(raw, "key|text")
    key = [ord(char.lower()) - 97 for char in key_raw if char.isalpha()]
    if not key:
        raise UsageError("The key needs at least one letter.")
    out = []
    index = 0
    for char in text:
        if char.isalpha():
            shift = key[index % len(key)]
            base = 65 if char.isupper() else 97
            offset = -shift if decrypt else shift
            out.append(chr((ord(char) - base + offset) % 26 + base))
            index += 1
        else:
            out.append(char)
    return {"KEY": "".join(chr(value + 97) for value in key), "OUTPUT": "".join(out)}


def _railfence(raw: str, *, decrypt: bool = False) -> dict[str, Any]:
    rails_raw, text = _pair(raw, "rails|text")
    rails = _int(rails_raw, "rails", low=2, high=10)
    if decrypt:
        pattern = list(range(rails)) + list(range(rails - 2, 0, -1))
        rails_len = [0] * rails
        for index in range(len(text)):
            rails_len[pattern[index % len(pattern)]] += 1
        chunks, cursor = [], 0
        for count in rails_len:
            chunks.append(text[cursor : cursor + count])
            cursor += count
        pointers = [0] * rails
        out = []
        for index in range(len(text)):
            rail = pattern[index % len(pattern)]
            out.append(chunks[rail][pointers[rail]])
            pointers[rail] += 1
        return {"RAILS": str(rails), "OUTPUT": "".join(out)}
    rows = [""] * rails
    pattern = list(range(rails)) + list(range(rails - 2, 0, -1))
    for index, char in enumerate(text):
        rows[pattern[index % len(pattern)]] += char
    return {"RAILS": str(rails), "OUTPUT": "".join(rows)}


def _bacon(raw: str) -> dict[str, Any]:
    groups = []
    for char in raw.upper():
        if "A" <= char <= "Z":
            bits = format(ord(char) - 65, "05b")
            groups.append(bits.replace("0", "A").replace("1", "B"))
    return {"OUTPUT": " ".join(groups) or "no letters", "ALPHABET": "A=0 · B=1 (Bacon's 24-letter variant transposes I/J and U/V)"}


def _unbacon(raw: str) -> dict[str, Any]:
    bits = re.sub(r"[^ABab]", "", raw).upper()
    if len(bits) < 5:
        raise UsageError("Give at least five A/B characters.")
    out = []
    for index in range(0, len(bits) - len(bits) % 5, 5):
        group = bits[index : index + 5]
        out.append(chr(int(group.replace("A", "0").replace("B", "1"), 2) + 65))
    return {"OUTPUT": "".join(out), "GROUPS": str(len(out))}


_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B36 = "0123456789abcdefghijklmnopqrstuvwxyz"


def _to_base(raw: str, alphabet: str, label: str) -> dict[str, Any]:
    data = raw.encode()
    number = int.from_bytes(data, "big")
    if number == 0:
        return {"OUTPUT": alphabet[0], "BASE": label}
    out = ""
    while number:
        number, remainder = divmod(number, len(alphabet))
        out = alphabet[remainder] + out
    pad = len(data) - len(data.lstrip(b"\x00"))
    return {"OUTPUT": alphabet[0] * pad + out, "BASE": label, "BYTES": str(len(data))}


def _from_base(raw: str, alphabet: str, label: str) -> dict[str, Any]:
    text = raw.strip()
    if not text:
        raise UsageError("Give an encoded value.")
    number = 0
    for char in text:
        position = alphabet.find(char)
        if position < 0:
            raise UsageError(f"`{char}` is not a {label} character.")
        number = number * len(alphabet) + position
    length = max(1, (number.bit_length() + 7) // 8)
    pad = len(text) - len(text.lstrip(alphabet[0]))
    data = b"\x00" * pad + number.to_bytes(length, "big")
    return {"OUTPUT": data.decode("utf-8", "replace"), "BASE": label, "BYTES": str(len(data))}


def _base58(raw: str) -> dict[str, Any]:
    return _to_base(raw, _B58, "58")


def _unbase58(raw: str) -> dict[str, Any]:
    return _from_base(raw, _B58, "base58")


def _base36(raw: str) -> dict[str, Any]:
    return _to_base(raw.lower(), _B36, "36")


def _unbase36(raw: str) -> dict[str, Any]:
    return _from_base(raw.lower(), _B36, "base36")


def _base85(raw: str) -> dict[str, Any]:
    return {"OUTPUT": base64.b85encode(raw.encode()).decode(), "BASE": "85 (RFC 1924 alphabet)"}


def _unbase85(raw: str) -> dict[str, Any]:
    try:
        return {"OUTPUT": base64.b85decode(raw.strip().encode()).decode("utf-8", "replace")}
    except (ValueError, binascii.Error):
        raise UsageError("That is not valid base85.") from None


def _hexdump(raw: str) -> dict[str, Any]:
    data = raw.encode()
    rows = []
    for offset in range(0, len(data), 16):
        chunk = data[offset : offset + 16]
        hexed = " ".join(f"{byte:02x}" for byte in chunk)
        printable = "".join(chr(byte) if 32 <= byte < 127 else "." for byte in chunk)
        rows.append([f"{offset:08x}", hexed.ljust(47), printable])
    return {"DUMP": _table(["OFFSET", "HEX", "ASCII"], rows, limit=48), "BYTES": str(len(data))}


def _fromhexdump(raw: str) -> dict[str, Any]:
    matches = re.findall(r"\b(?:[0-9a-fA-F]{2}[\s-]?){2,}\b", raw)
    if not matches:
        raise UsageError("No hex byte runs found.")
    data = b"".join(bytes.fromhex(re.sub(r"[^0-9a-fA-F]", "", chunk)) for chunk in matches)
    return {"OUTPUT": data.decode("utf-8", "replace"), "BYTES": str(len(data))}


def _xorhex(raw: str) -> dict[str, Any]:
    key_raw, text = _pair(raw, "keyhex|text")
    key = bytes.fromhex(re.sub(r"[^0-9a-fA-F]", "", key_raw))
    if not key:
        raise UsageError("The key needs at least one hex byte.")
    data = text.encode()
    out = bytes(data[index] ^ key[index % len(key)] for index in range(len(data)))
    return {
        "HEX": out.hex(),
        "ASCII": out.decode("utf-8", "replace"),
        "KEY BYTES": str(len(key)),
        "NOTE": "symmetric — the same key restores the plaintext",
    }


def _bitreverse(raw: str) -> dict[str, Any]:
    data = raw.encode()
    out = bytes(int(f"{byte:08b}"[::-1], 2) for byte in data)
    return {"HEX": out.hex(), "ASCII": out.decode("utf-8", "replace"), "BYTES": str(len(data))}


def _unicodeescape(raw: str) -> dict[str, Any]:
    return {"OUTPUT": raw.encode("unicode_escape").decode(), "STYLE": "\\uXXXX escapes"}


def _ununicode(raw: str) -> dict[str, Any]:
    text = raw.strip()
    try:
        decoded = text.encode().decode("unicode_escape")
    except UnicodeDecodeError:
        raise UsageError("Those escapes are not valid.") from None
    return {"OUTPUT": decoded}


_ZERO_WIDTH = {"\u200b", "\u200c", "\u200d", "\u2060", "\ufeff", "\u180e", "\u200e", "\u200f"}


def _zerowidth(raw: str) -> dict[str, Any]:
    hits = []
    for index, char in enumerate(raw):
        if char in _ZERO_WIDTH:
            hits.append([index, f"U+{ord(char):04X}", "zero-width"])
        elif 0xFE00 <= ord(char) <= 0xFE0F:
            hits.append([index, f"U+{ord(char):04X}", "variation selector"])
        elif char in "ᅟᅠ":
            hits.append([index, f"U+{ord(char):04X}", "hangul filler"])
    visible = "".join("·" if char in _ZERO_WIDTH else char for char in raw)
    return {
        "HIDDEN CHARACTERS": _table(["INDEX", "CODE POINT", "KIND"], hits)
        if hits
        else "no zero-width characters",
        "VISIBLE FORM": visible[:300],
        "LENGTH": f"{len(raw)} characters · {len(raw.encode())} bytes",
    }


def _stripzero(raw: str) -> dict[str, Any]:
    cleaned = "".join(char for char in raw if char not in _ZERO_WIDTH)
    return {"OUTPUT": cleaned, "REMOVED": str(len(raw) - len(cleaned))}


_LEET = {
    "a": "4@", "b": "8", "e": "3", "g": "96", "i": "1!|", "l": "1|", "o": "0",
    "s": "5$", "t": "7+", "z": "2",
}


def _leet(raw: str) -> dict[str, Any]:
    out = []
    for char in raw:
        options = _LEET.get(char.lower())
        out.append(char if not options else options[0] if char.islower() else options[0])
    return {
        "OUTPUT": "".join(out),
        "ALTERNATIVES": "  ".join(f"{char}→{opts}" for char, opts in _LEET.items()),
    }


def _unleet(raw: str) -> dict[str, Any]:
    table = {"4": "a", "@": "a", "8": "b", "3": "e", "9": "g", "6": "g", "1": "i", "!": "i", "0": "o", "5": "s", "$": "s", "7": "t", "+": "t", "2": "z"}
    return {"OUTPUT": "".join(table.get(char, char) for char in raw), "NOTE": "approximate — 1 and 7 are ambiguous"}


_NATO = {
    "a": "Alfa", "b": "Bravo", "c": "Charlie", "d": "Delta", "e": "Echo", "f": "Foxtrot",
    "g": "Golf", "h": "Hotel", "i": "India", "j": "Juliett", "k": "Kilo", "l": "Lima",
    "m": "Mike", "n": "November", "o": "Oscar", "p": "Papa", "q": "Quebec", "r": "Romeo",
    "s": "Sierra", "t": "Tango", "u": "Uniform", "v": "Victor", "w": "Whiskey",
    "x": "X-ray", "y": "Yankee", "z": "Zulu", "0": "Zero", "1": "One", "2": "Two",
    "3": "Three", "4": "Four", "5": "Five", "6": "Six", "7": "Seven", "8": "Eight",
    "9": "Nine", "-": "Dash", ".": "Stop",
}


def _nato(raw: str) -> dict[str, Any]:
    words = [_NATO.get(char.lower()) for char in raw if char.strip()]
    if not any(words):
        raise UsageError("Give text to spell out.")
    return {"OUTPUT": "  ".join(word for word in words if word), "COUNT": str(len([w for w in words if w]))}


def _unnato(raw: str) -> dict[str, Any]:
    reverse = {value.lower(): key for key, value in _NATO.items()}
    out = []
    for token in re.split(r"[\s,]+", raw.strip()):
        if not token:
            continue
        out.append(reverse.get(token.lower(), "?"))
    return {"OUTPUT": "".join(out) or "nothing recognised"}


def _freq(raw: str) -> dict[str, Any]:
    text = raw.strip()
    if not text:
        raise UsageError("Give text to measure.")
    counts = Counter(char for char in text if not char.isspace())
    total = sum(counts.values()) or 1
    rows = [[repr(char)[1:-1], count, f"{count / total * 100:.1f}%"] for char, count in counts.most_common(12)]
    return {
        "FREQUENCY": _table(["CHAR", "COUNT", "SHARE"], rows),
        "UNIQUE": f"{len(counts)} characters",
        "TOTAL": f"{total} non-space characters",
    }


# ── text and forensics ─────────────────────────────────────────────────────


def _ngrams(raw: str) -> dict[str, Any]:
    text = re.sub(r"[^a-z0-9 ]", "", raw.lower())
    bigrams = Counter(text[index : index + 2] for index in range(len(text) - 1) if " " not in text[index : index + 2])
    trigrams = Counter(text[index : index + 3] for index in range(len(text) - 2) if " " not in text[index : index + 3])
    return {
        "BIGRAMS": "  ".join(f"{gram}({count})" for gram, count in bigrams.most_common(10)) or "—",
        "TRIGRAMS": "  ".join(f"{gram}({count})" for gram, count in trigrams.most_common(10)) or "—",
    }


def _wordfreq(raw: str) -> dict[str, Any]:
    words = re.findall(r"[A-Za-z][A-Za-z'-]{1,}", raw.lower())
    if not words:
        raise UsageError("No words found.")
    counts = Counter(words)
    rows = [[word, count] for word, count in counts.most_common(12)]
    return {
        "WORDS": _table(["WORD", "COUNT"], rows),
        "UNIQUE": f"{len(counts)} of {len(words)}",
        "LONGEST": max(counts, key=len),
    }


def _acrostic(raw: str) -> dict[str, Any]:
    lines = [line.strip() for line in raw.splitlines() if line.strip()]
    if not lines:
        raise UsageError("Give text with lines.")
    letters = "".join(line[0] for line in lines)
    return {
        "ACROSTIC": letters,
        "READS AS": letters.lower().replace(" ", ""),
        "LINES": str(len(lines)),
    }


def _palindrome(raw: str) -> dict[str, Any]:
    cleaned = re.sub(r"[^a-z0-9]", "", raw.lower())
    if not cleaned:
        raise UsageError("No letters or digits found.")
    return {
        "NORMALISED": cleaned,
        "PALINDROME": "yes" if cleaned == cleaned[::-1] else "no",
        "REVERSED": cleaned[::-1],
    }


def _anagram(raw: str) -> dict[str, Any]:
    left, right = _pair(raw)
    key = lambda value: sorted(re.sub(r"[^a-z]", "", value.lower()))
    return {
        "LEFT": left,
        "RIGHT": right,
        "ANAGRAM": "yes" if key(left) == key(right) else "no",
        "SHARED LETTERS": "".join(key(left)),
    }


def _readability(raw: str) -> dict[str, Any]:
    sentences = [item for item in re.split(r"(?<=[.!?])\s+", raw.strip()) if item]
    words = re.findall(r"[A-Za-z']+", raw)
    if not words or not sentences:
        raise UsageError("Give at least one sentence.")
    syllables = 0
    for word in words:
        groups = re.findall(r"[aeiouy]+", word.lower())
        syllables += max(1, len(groups))
    words_per_sentence = len(words) / len(sentences)
    syllables_per_word = syllables / len(words)
    flesch = 206.835 - 1.015 * words_per_sentence - 84.6 * syllables_per_word
    grade = 0.39 * words_per_sentence + 11.8 * syllables_per_word - 15.59
    return {
        "WORDS": str(len(words)),
        "SENTENCES": str(len(sentences)),
        "WORDS/SENTENCE": f"{words_per_sentence:.1f}",
        "FLESCH EASE": f"{max(0.0, min(120.0, flesch)):.1f}",
        "GRADE LEVEL": f"{max(0.0, grade):.1f}",
        "READS": "plain language" if flesch >= 60 else "dense — split the sentences" if flesch >= 30 else "very dense",
    }


# ── hashes and keys ────────────────────────────────────────────────────────


def _adler32(raw: str) -> dict[str, Any]:
    return {"ADLER-32": f"{zlib.adler32(raw.encode()) & 0xFFFFFFFF:08x}", "BYTES": str(len(raw.encode()))}


def _fnv1a(raw: str) -> dict[str, Any]:
    data = raw.encode()
    hash32 = 0x811C9DC5
    hash64 = 0xCBF29CE484222325
    for byte in data:
        hash32 = ((hash32 ^ byte) * 0x01000193) & 0xFFFFFFFF
        hash64 = ((hash64 ^ byte) * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return {"FNV-1A 32": f"{hash32:08x}", "FNV-1A 64": f"{hash64:016x}", "BYTES": str(len(data))}


def _murmur3(raw: str) -> dict[str, Any]:
    data = raw.encode()
    c1, c2 = 0xCC9E2D51, 0x1B873593
    length = len(data)
    h1 = 0
    rounded = length & 0xFFFFFFFC
    for index in range(0, rounded, 4):
        k1 = int.from_bytes(data[index : index + 4], "little")
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
        h1 = (h1 * 5 + 0xE6546B64) & 0xFFFFFFFF
    tail = data[rounded:]
    k1 = 0
    if len(tail) >= 3:
        k1 ^= tail[2] << 16
    if len(tail) >= 2:
        k1 ^= tail[1] << 8
    if tail:
        k1 ^= tail[0]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
    h1 ^= length
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85EBCA6B) & 0xFFFFFFFF
    h1 ^= h1 >> 13
    h1 = (h1 * 0xC2B2AE35) & 0xFFFFFFFF
    h1 ^= h1 >> 16
    return {"MURMURHASH3": f"{h1:08x}", "SIGNED": str(h1 - 0x100000000 if h1 > 0x7FFFFFFF else h1), "USE": "favicon pivoting (Shodan `http.favicon.hash`)"}


def _hmac(raw: str, algorithm: str) -> dict[str, Any]:
    key_raw, message = _pair(raw, "key|message")
    digest = hmac.new(key_raw.encode(), message.encode(), getattr(hashlib, algorithm)).hexdigest()
    return {"ALGORITHM": f"HMAC-{algorithm.upper()}", "DIGEST": digest, "LENGTH": f"{len(digest) * 4} bits"}


def _pbkdf2(raw: str) -> dict[str, Any]:
    salt, _, remainder = raw.partition("|")
    iterations = 200_000
    if "|" in remainder:
        salt, iterations_raw, password = raw.split("|", 2)
        iterations = _int(iterations_raw, "iterations", low=1_000, high=2_000_000)
    else:
        password = remainder
    if not salt or not password:
        raise UsageError("Use `salt|password` or `salt|iterations|password`.")
    key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), iterations, dklen=32)
    return {
        "DERIVED KEY": key.hex(),
        "ITERATIONS": f"{iterations:,}",
        "KDF": "PBKDF2-HMAC-SHA256 · 256-bit",
        "NOTE": "derived locally; the password is never stored",
    }


_HASHCAT = (
    (16, "30", "LM / MD5 half (legacy)"),
    (32, "0", "MD5"),
    (40, "100", "SHA-1"),
    (56, "1300", "SHA2-224"),
    (64, "1400", "SHA2-256"),
    (96, "1700", "SHA2-384"),
    (128, "1700", "SHA2-512"),
)

_HASHCAT_PREFIX = {
    "$2": ("3200", "bcrypt"),
    "$argon2": ("3400", "Argon2"),
    "$pbkdf2": ("10900", "PBKDF2-HMAC-SHA256"),
    "$6$": ("1800", "sha512crypt"),
    "$5$": ("7400", "sha256crypt"),
}


def _hashmode(raw: str) -> dict[str, Any]:
    value = raw.strip()
    if not re.fullmatch(r"[A-Za-z0-9$./+=:_-]{6,200}", value):
        raise UsageError("That does not look like a hash.")
    length = len(value)
    rows: list[list[Any]] = []
    for prefix, (mode, family) in _HASHCAT_PREFIX.items():
        if value.startswith(prefix):
            rows = [[length, mode, family]]
            break
    if not rows:
        rows = [[length, mode, family] for size, mode, family in _HASHCAT if size == length]
    if not rows:
        raise UsageError("Length and prefix match no common family.")
    return {
        "LENGTH": str(length),
        "PREFIX": value[:6] if value.startswith("$") else "none",
        "CANDIDATES": _table(["LENGTH", "MODE", "FAMILY"], rows),
    }


def _johnmode(raw: str) -> dict[str, Any]:
    value = raw.strip()
    length = len(value)
    mapping = {
        32: "raw-md5",
        40: "raw-sha1",
        56: "raw-sha224",
        64: "raw-sha256",
        96: "raw-sha384",
        128: "raw-sha512",
    }
    if value.startswith("$2"):
        name = "bcrypt"
    elif value.startswith("$argon2"):
        name = "argon2"
    elif value.startswith("$6$"):
        name = "sha512crypt"
    elif value.startswith("$5$"):
        name = "sha256crypt"
    else:
        name = mapping.get(length)
    if not name:
        raise UsageError("No John format matches that length.")
    return {"JOHN FORMAT": name, "LENGTH": str(length), "HINT": "verify the algorithm from context before queueing a crack"}


# ── network-local parsing ──────────────────────────────────────────────────


def _subnet(raw: str) -> dict[str, Any]:
    try:
        network = ipaddress.ip_network(strip_target(raw), strict=False)
    except ValueError:
        raise UsageError("Give a CIDR block, e.g. `10.0.0.0/24`.") from None
    if network.version == 4:
        hosts = max(0, network.num_addresses - 2) if network.prefixlen < 31 else network.num_addresses
        return {
            "NETWORK": str(network.network_address),
            "CIDR": str(network),
            "BROADCAST": str(network.broadcast_address),
            "NETMASK": str(network.netmask),
            "WILDCARD": str(network.hostmask),
            "ADDRESSES": f"{network.num_addresses:,}",
            "USABLE": f"{hosts:,}",
            "RANGE": f"{network.network_address} – {network.broadcast_address}",
            "SCOPE": "private" if network.is_private else "public",
        }
    return {
        "CIDR": str(network),
        "NETMASK": str(network.netmask),
        "ADDRESSES": f"{network.num_addresses:,}",
        "FIRST": str(network.network_address),
        "LAST": str(network.broadcast_address),
        "SCOPE": "private" if network.is_private else "global",
    }


def _supernet(raw: str) -> dict[str, Any]:
    cidr, prefix = _pair(raw, "cidr|new prefix")
    try:
        network = ipaddress.ip_network(strip_target(cidr), strict=False)
    except ValueError:
        raise UsageError("Give a valid CIDR block.") from None
    size = _int(prefix, "prefix", low=0, high=network.max_prefixlen)
    if size >= network.prefixlen:
        raise UsageError(f"A parent prefix must be shorter than /{network.prefixlen}.")
    parent = network.supernet(new_prefix=size)
    return {
        "CHILD": str(network),
        "PARENT": str(parent),
        "BLOCKS IN PARENT": f"{2 ** (parent.prefixlen - network.prefixlen):,}",
        "NOTE": "use the parent when summarising firewall rules or BGP prefixes",
    }


def _ipv6type(raw: str) -> dict[str, Any]:
    address_raw = strip_target(raw)
    try:
        address = ipaddress.ip_address(address_raw)
    except ValueError:
        raise UsageError("Give an IPv6 address.") from None
    if address.version != 6:
        raise UsageError("That is IPv4. `.ipclass` already covers it.")
    kinds = []
    if address.is_global:
        kinds.append("global unicast")
    if address.is_private:
        kinds.append("unique local (ULA)")
    if address.is_link_local:
        kinds.append("link-local")
    if address.is_loopback:
        kinds.append("loopback")
    if address.is_multicast:
        kinds.append("multicast")
    if address.is_reserved:
        kinds.append("reserved")
    if address.sixtofour:
        kinds.append("6to4")
    if address.teredo:
        kinds.append("Teredo")
    if address.ipv4_mapped:
        kinds.append("IPv4-mapped")
    return {
        "ADDRESS": address.exploded,
        "COMPRESSED": address.compressed,
        "TYPE": ", ".join(kinds) or "unclassified",
        "ZONE": str(getattr(address, "scope_id", "")) or "—",
    }


def _portrange(raw: str) -> dict[str, Any]:
    ports: list[int] = []
    for chunk in re.split(r"[,\s]+", raw.strip()):
        if not chunk:
            continue
        if "-" in chunk:
            start_raw, end_raw = chunk.split("-", 1)
            start = _int(start_raw, "port", low=1, high=65535)
            end = _int(end_raw, "port", low=1, high=65535)
            if end < start:
                raise UsageError("Range end is below the start.")
            ports.extend(range(start, end + 1))
        else:
            ports.append(_int(chunk, "port", low=1, high=65535))
    if not ports:
        raise UsageError("Give ports, e.g. `80,443,8000-8100`.")
    unique = sorted(set(ports))
    return {
        "COUNT": str(len(unique)),
        "PORTS": clip(" ".join(str(port) for port in unique), 900),
        "BOUNDS": f"{unique[0]}–{unique[-1]}",
        "NOTE": "expand only ranges you actually own; scanners are noisy" ,
    }


_TCP_FLAGS = (("FIN", 1), ("SYN", 2), ("RST", 4), ("PSH", 8), ("ACK", 16), ("URG", 32), ("ECE", 64), ("CWR", 128))


def _tcpflags(raw: str) -> dict[str, Any]:
    value = 0
    text = raw.strip().upper()
    if re.fullmatch(r"0[Xx][0-9A-F]+|\d+", text):
        value = _int(text, "flags", low=0, high=255)
    else:
        for token in re.split(r"[,\s|+]+", text):
            for name, bit in _TCP_FLAGS:
                if token.startswith(name[:3]):
                    value |= bit
    if not value:
        raise UsageError("Give a flag byte or names, e.g. `0x12` or `SYN,ACK`.")
    active = [name for name, bit in _TCP_FLAGS if value & bit]
    return {
        "BYTE": f"0x{value:02x}",
        "BINARY": f"{value:08b}",
        "FLAGS": ", ".join(active) or "none",
        "READS AS": "  ".join(active),
    }


_ICMP = {
    0: "Echo reply", 3: "Destination unreachable", 4: "Source quench (deprecated)",
    5: "Redirect", 8: "Echo request", 9: "Router advertisement", 10: "Router solicitation",
    11: "Time exceeded", 12: "Parameter problem", 13: "Timestamp request", 14: "Timestamp reply",
    17: "Address mask request", 18: "Address mask reply", 30: "Traceroute",
}


def _icmpcode(raw: str) -> dict[str, Any]:
    if "|" in raw:
        type_raw, code_raw = _pair(raw, "type|code")
        code = _int(code_raw, "code", low=0, high=255)
    else:
        type_raw, code = raw, None
    icmp_type = _int(type_raw, "type", low=0, high=255)
    codes = {
        (3, 0): "net unreachable", (3, 1): "host unreachable", (3, 3): "port unreachable",
        (3, 9): "network administratively prohibited", (3, 13): "communication administratively filtered",
        (5, 0): "redirect for network", (11, 0): "TTL exceeded in transit",
        (11, 1): "fragment reassembly time exceeded",
    }
    detail = codes.get((icmp_type, code if code is not None else 0), "see RFC 792 / RFC 4443")
    return {
        "TYPE": f"{icmp_type}",
        "NAME": _ICMP.get(icmp_type, "unassigned"),
        "CODE": str(code) if code is not None else "—",
        "DETAIL": detail,
        "NOTE": "ICMPv6 mirrors this table with codes 0–6 for unreachable messages",
    }


_DNS_TYPES = {
    "A": "IPv4 address (RFC 1035)",
    "AAAA": "IPv6 address (RFC 3596)",
    "CNAME": "Canonical name alias (RFC 1035)",
    "MX": "Mail exchanger with preference (RFC 1035)",
    "NS": "Authoritative nameserver (RFC 1035)",
    "TXT": "Free-form text, SPF/DKIM/verification (RFC 1035)",
    "SOA": "Zone authority, serial and timers (RFC 1035)",
    "SRV": "Service location with port and weight (RFC 2782)",
    "CAA": "Which CAs may issue certificates (RFC 8659)",
    "PTR": "Reverse lookup pointer (RFC 1035)",
    "DS": "Delegation signer for DNSSEC (RFC 4034)",
    "DNSKEY": "Zone signing public key (RFC 4034)",
    "RRSIG": "DNSSEC signature (RFC 4034)",
    "NSEC": "Authenticated denial of existence (RFC 4034)",
    "NSEC3": "Hashed denial of existence (RFC 5155)",
    "TLSA": "Certificate association for DANE (RFC 6698)",
    "HTTPS": "Service binding for HTTPS (RFC 9460)",
    "SVCB": "Service binding (RFC 9460)",
    "SPF": "Legacy SPF record (obsoleted by RFC 7208)",
    "DNAME": "Non-terminal name redirection (RFC 6672)",
    "NAPTR": "Naming authority pointer (RFC 3403)",
    "SSHFP": "SSH key fingerprint (RFC 4255)",
    "LOC": "Geographic location (RFC 1876)",
}


def _dnstype(raw: str) -> dict[str, Any]:
    needle = raw.strip().upper()
    if not needle:
        raise UsageError("Give a record type or keyword.")
    if needle in _DNS_TYPES:
        return {"TYPE": needle, "PURPOSE": _DNS_TYPES[needle], "COUNT": str(len(_DNS_TYPES))}
    matches = {name: text for name, text in _DNS_TYPES.items() if needle in text.upper()}
    if not matches:
        raise UsageError(f"`{needle}` is not in the {len(_DNS_TYPES)}-type table.")
    return {"MATCHES": "\n".join(f"{name} — {text}" for name, text in matches.items())}


_HEADER_ALIASES = {
    "csp": "content-security-policy",
    "hsts": "strict-transport-security",
    "xcto": "x-content-type-options",
    "xfo": "x-frame-options",
    "cors": "access-control-allow-origin",
    "acao": "access-control-allow-origin",
    "acac": "access-control-allow-credentials",
    "referrer": "referrer-policy",
    "cookie": "set-cookie",
    "type": "content-type",
}

_HEADERS = {
    "content-security-policy": "CSP — which sources may execute content",
    "strict-transport-security": "HSTS — forces HTTPS for a period",
    "x-frame-options": "legacy clickjacking control",
    "x-content-type-options": "stops MIME sniffing",
    "referrer-policy": "how much referrer data leaks",
    "permissions-policy": "which browser features stay disabled",
    "cross-origin-opener-policy": "isolates the browsing context",
    "cross-origin-resource-policy": "controls cross-origin reads",
    "cross-origin-embedder-policy": "enables cross-origin isolation",
    "cache-control": "caching directives for intermediaries",
    "content-type": "media type and charset",
    "server": "software banner — leak minimisation target",
    "x-powered-by": "framework banner — leak minimisation target",
    "set-cookie": "cookie attributes and lifetime",
    "alt-svc": "advertising alternative services",
    "vary": "cache key variation",
    "etag": "validator for conditional requests",
    "last-modified": "resource freshness marker",
    "access-control-allow-origin": "CORS allow-list",
    "access-control-allow-credentials": "CORS credential sharing",
    "location": "redirect target",
    "content-encoding": "compression applied",
    "transfer-encoding": "framing of the body",
    "expect-ct": "obsoleted certificate transparency report",
    "report-to": "reporting endpoint for policy violations",
}


def _httphdr(raw: str) -> dict[str, Any]:
    needle = raw.strip().lower().rstrip(":")
    if not needle:
        raise UsageError("Give a header name.")
    needle = _HEADER_ALIASES.get(needle, needle)
    if needle in _HEADERS:
        return {"HEADER": needle, "MEANING": _HEADERS[needle], "COUNT": str(len(_HEADERS))}
    matches = {name: text for name, text in _HEADERS.items() if needle in name}
    if not matches:
        raise UsageError(f"`{needle}` is not in the {len(_HEADERS)}-header table.")
    return {"MATCHES": "\n".join(f"{name} — {text}" for name, text in matches.items())}


def _ciphersuite(raw: str) -> dict[str, Any]:
    name = raw.strip().upper().replace("-", "_")
    if not name:
        raise UsageError("Give a TLS cipher suite name.")
    tls13 = name.startswith("TLS_")
    parts = name.split("_")
    bits = "256" if "256" in name else "128" if "128" in name else "?"
    mac = next((part for part in parts if part in {"SHA", "SHA256", "SHA384", "MD5"}), "AEAD")
    kex = next((part for part in parts if part in {"ECDHE", "DHE", "RSA", "ECDH", "PSK"}), "—")
    auth = next((part for part in parts if part in {"RSA", "ECDSA", "PSK", "ED25519"}), "—")
    cipher = next((part for part in parts if part in {"AES", "CHACHA20", "DES", "RC4", "3DES", "CAMELLIA", "ARIA"}), "—")
    return {
        "SUITE": name,
        "VERSION": "TLS 1.3" if tls13 and kex == "—" else "TLS 1.2 or earlier",
        "KEY EXCHANGE": kex,
        "AUTHENTICATION": auth,
        "CIPHER": f"{cipher}-{bits}" if cipher != "—" else "—",
        "MAC / AEAD": mac,
        "FORWARD SECRECY": "yes" if kex in {"ECDHE", "DHE"} or tls13 else "no",
        "WEAK": "yes — legacy primitive" if any(token in name for token in ("RC4", "3DES", "DES_", "MD5", "NULL")) else "no",
    }


def _emailauth(raw: str) -> dict[str, Any]:
    text = raw.strip()
    if "=" not in text:
        raise UsageError("Paste an Authentication-Results value.")
    rows = []
    for token in re.findall(r"\b(spf|dkim|dmarc|arc|iprev|bimi|compauth)=([a-z]+)", text, re.IGNORECASE):
        rows.append([token[0].lower(), token[1].lower(), "pass" if token[1].lower() == "pass" else "fail"])
    if not rows:
        raise UsageError("No spf/dkim/dmarc results found.")
    passed = sum(1 for row in rows if row[2] == "pass")
    return {
        "MECHANISMS": _table(["MECHANISM", "RESULT", "VERDICT"], rows),
        "PASSED": f"{passed}/{len(rows)}",
        "ACTION": "treat a dmarc fail with a pass spf as an alignment problem, not a spoof",
    }


def _received(raw: str) -> dict[str, Any]:
    text = raw.strip()
    if "received:" not in text.lower() and "from " not in text.lower():
        raise UsageError("Paste the Received header chain.")
    hops = re.findall(r"(?:from\s+([^\s;]+))?[^;]*?(?:by\s+([^\s;]+))?[^;]*?;\s*([^;\n]+)", text, re.IGNORECASE)
    rows = []
    for from_host, by_host, stamp in hops:
        if not any((from_host, by_host)):
            continue
        rows.append([clip(from_host or "—", 26), clip(by_host or "—", 26), clip(stamp.strip(), 28)])
    return {
        "HOPS": _table(["FROM", "BY", "TIMESTAMP"], rows[:10]) if rows else "no hops parsed",
        "COUNT": str(len(rows)),
        "NOTE": "read the chain bottom-up: the lowest trusted hop is the one that matters",
    }


# ── synthetic generators ───────────────────────────────────────────────────


def _luhn_digit(partial: str) -> str:
    digits = [int(char) for char in partial]
    total = 0
    for index, digit in enumerate(reversed(digits)):
        if index % 2 == 0:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return str((10 - total % 10) % 10)


def _fakecard(raw: str) -> dict[str, Any]:
    prefix = re.sub(r"\D", "", raw)[:8] or "424242"
    body = prefix + "".join(secrets.choice(string.digits) for _ in range(15 - len(prefix)))
    number = body + _luhn_digit(body)
    return {
        "NUMBER": " ".join(number[index : index + 4] for index in range(0, 16, 4)),
        "BIN PREFIX": prefix,
        "LUHN": "valid",
        "USE": "test fixtures only — this PAN is not issued to anyone",
    }


def _mod97(value: str) -> int:
    remainder = 0
    for char in value:
        remainder = (remainder * 10 + int(char)) % 97
    return remainder


def _fakeiban(raw: str) -> dict[str, Any]:
    country = re.sub(r"[^A-Za-z]", "", raw).upper()[:2] or "GB"
    bban = "".join(secrets.choice(string.digits) for _ in range(18))
    rearranged = f"{bban}{country}00"
    digits = "".join(str(int(char, 36)) for char in rearranged)
    check = 98 - _mod97(digits)
    iban = f"{country}{check:02d}{bban}"
    return {
        "IBAN": " ".join(iban[index : index + 4] for index in range(0, len(iban), 4)),
        "COUNTRY": country,
        "CHECK DIGITS": f"{check:02d}",
        "MOD-97": "valid",
        "USE": "synthetic — never send funds or KYC documents to this value",
    }


def _fakeimei(raw: str) -> dict[str, Any]:
    prefix = re.sub(r"\D", "", raw)[:2] or "35"
    body = prefix + "".join(secrets.choice(string.digits) for _ in range(13))
    return {"IMEI": body + _luhn_digit(body), "TAC": body[:8], "LUHN": "valid", "USE": "device test fixtures"}


def _fakesnowflake(raw: str) -> dict[str, Any]:
    stamp = parse_dt(raw.strip()) if raw.strip() else utcnow()
    if stamp is None:
        raise UsageError("Give a date, or leave it empty for now.")
    millis = int(stamp.timestamp() * 1000)
    snowflake = (millis - 1_420_070_400_000) << 22
    return {
        "SNOWFLAKE": str(snowflake),
        "TIMESTAMP": stamp.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "NOTE": "sequence 0, worker 0 — a plausible placeholder, not a real account",
    }


def _fakehash(raw: str) -> dict[str, Any]:
    length = _int(raw.strip(), "length", low=16, high=128) if raw.strip() else 64
    return {
        "HASH": "".join(secrets.choice("0123456789abcdef") for _ in range(length)),
        "FAMILY": {32: "MD5", 40: "SHA-1", 64: "SHA-256", 128: "SHA-512"}.get(length, "custom"),
        "USE": "fixtures and regex testing",
    }


def _fakejwt(raw: str) -> dict[str, Any]:
    header = {"alg": "none", "typ": "JWT"}
    payload = {"sub": raw.strip() or "demo-subject", "iat": int(utcnow().timestamp()), "iss": "0swald/demo"}
    token = f"{_b64u(json.dumps(header).encode())}.{_b64u(json.dumps(payload).encode())}."
    return {
        "TOKEN": token,
        "HEADER": json.dumps(header),
        "PAYLOAD": json.dumps(payload),
        "SIGNATURE": "empty — unsigned, harmless by construction",
        "USE": "parser tests with `.jwtinspect`",
    }


# ── Discord-local helpers ──────────────────────────────────────────────────


def _tokentype(raw: str) -> dict[str, Any]:
    """Classify a token's shape without ever echoing it back."""
    value = raw.strip()
    if len(value) < 20:
        raise UsageError("That is too short to classify.")
    kinds = []
    if re.fullmatch(r"[A-Za-z0-9_-]{20,30}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,40}", value):
        kinds.append("Discord bot token shape")
    if re.fullmatch(r"[A-Za-z0-9_-]{24,28}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{38,40}", value):
        kinds.append("Discord user token shape")
    if value.startswith("mfa."):
        kinds.append("Discord MFA token shape")
    if re.match(r"https://(?:discord|discordapp)\.com/api/webhooks/", value):
        kinds.append("Discord webhook URL")
    if re.fullmatch(r"[0-9a-f]{64}", value):
        kinds.append("64-hex secret (API key shaped)")
    if value.startswith(("ghp_", "gho_", "github_pat_")):
        kinds.append("GitHub token")
    if value.startswith("sk-"):
        kinds.append("OpenAI-style API key")
    first = value.split(".")[0]
    note = "no known shape"
    if first.isdigit() and len(first) in {17, 18, 19}:
        note = f"first segment decodes to a Discord application id — do not act on it"
    return {
        "LENGTH": str(len(value)),
        "SHAPES": "\n".join(f"• {kind}" for kind in kinds) or "no known shape",
        "SEGMENTS": str(len(value.split("."))),
        "FIRST SEGMENT": "numeric application id" if first.isdigit() else f"{len(first)} chars",
        "NOTE": note,
        "POLICY": "classification only — the value is never logged, stored or used",
    }


def _snowflakerange(raw: str) -> dict[str, Any]:
    stamp = parse_dt(raw.strip()) if raw.strip() else utcnow()
    if stamp is None:
        raise UsageError("Give a date, e.g. `2024-05-01`.")
    start = dt.datetime(stamp.year, stamp.month, stamp.day, tzinfo=dt.timezone.utc)
    end = start + dt.timedelta(days=1)
    low = (int(start.timestamp() * 1000) - 1_420_070_400_000) << 22
    high = ((int(end.timestamp() * 1000) - 1_420_070_400_000) << 22) - 1
    return {
        "DAY": start.strftime("%Y-%m-%d"),
        "MIN": str(low),
        "MAX": str(high),
        "SPAN": str(high - low),
        "USE": "filter an ID dump to accounts created on that day",
    }


_PERMISSIONS: tuple[tuple[str, int], ...] = (
    ("CREATE_INSTANT_INVITE", 1 << 0), ("KICK_MEMBERS", 1 << 1), ("BAN_MEMBERS", 1 << 2),
    ("ADMINISTRATOR", 1 << 3), ("MANAGE_CHANNELS", 1 << 4), ("MANAGE_GUILD", 1 << 5),
    ("ADD_REACTIONS", 1 << 6), ("VIEW_AUDIT_LOG", 1 << 7), ("PRIORITY_SPEAKER", 1 << 8),
    ("STREAM", 1 << 9), ("VIEW_CHANNEL", 1 << 10), ("SEND_MESSAGES", 1 << 11),
    ("SEND_TTS_MESSAGES", 1 << 12), ("MANAGE_MESSAGES", 1 << 13), ("EMBED_LINKS", 1 << 14),
    ("ATTACH_FILES", 1 << 15), ("READ_MESSAGE_HISTORY", 1 << 16), ("MENTION_EVERYONE", 1 << 17),
    ("USE_EXTERNAL_EMOJIS", 1 << 18), ("VIEW_GUILD_INSIGHTS", 1 << 19), ("CONNECT", 1 << 20),
    ("SPEAK", 1 << 21), ("MUTE_MEMBERS", 1 << 22), ("DEAFEN_MEMBERS", 1 << 23),
    ("MOVE_MEMBERS", 1 << 24), ("USE_VAD", 1 << 25), ("CHANGE_NICKNAME", 1 << 26),
    ("MANAGE_NICKNAMES", 1 << 27), ("MANAGE_ROLES", 1 << 28), ("MANAGE_WEBHOOKS", 1 << 29),
    ("MANAGE_GUILD_EXPRESSIONS", 1 << 30), ("USE_APPLICATION_COMMANDS", 1 << 31),
    ("REQUEST_TO_SPEAK", 1 << 32), ("MANAGE_EVENTS", 1 << 33), ("MANAGE_THREADS", 1 << 34),
    ("CREATE_PUBLIC_THREADS", 1 << 35), ("CREATE_PRIVATE_THREADS", 1 << 36),
    ("USE_EXTERNAL_STICKERS", 1 << 37), ("SEND_MESSAGES_IN_THREADS", 1 << 38),
    ("USE_EMBEDDED_ACTIVITIES", 1 << 39), ("MODERATE_MEMBERS", 1 << 40),
    ("VIEW_CREATOR_MONETIZATION_ANALYTICS", 1 << 41), ("USE_SOUNDBOARD", 1 << 42),
    ("CREATE_GUILD_EXPRESSIONS", 1 << 43), ("CREATE_EVENTS", 1 << 44),
    ("USE_EXTERNAL_SOUNDS", 1 << 45), ("SEND_VOICE_MESSAGES", 1 << 46),
)


def _perms(raw: str) -> dict[str, Any]:
    value = _int(raw.strip(), "permissions", low=0, high=(1 << 64) - 1)
    active = [name for name, bit in _PERMISSIONS if value & bit]
    unknown = value & ~sum(bit for _, bit in _PERMISSIONS)
    return {
        "BITFIELD": str(value),
        "HEX": f"0x{value:X}",
        "GRANTED": f"{len(active)}",
        "PERMISSIONS": "\n".join(f"• {name}" for name in active) or "none",
        "UNKNOWN BITS": f"0x{unknown:X}" if unknown else "none",
        "ADMINISTRATOR": "yes — bypasses every channel overwrite" if 1 << 3 in [bit for name, bit in _PERMISSIONS if name in active] else "no",
    }


_INTENTS: tuple[tuple[str, int], ...] = (
    ("GUILDS", 1 << 0), ("GUILD_MEMBERS", 1 << 1), ("GUILD_MODERATION", 1 << 2),
    ("GUILD_EMOJIS_AND_STICKERS", 1 << 3), ("GUILD_INTEGRATIONS", 1 << 4),
    ("GUILD_WEBHOOKS", 1 << 5), ("GUILD_INVITES", 1 << 6), ("GUILD_VOICE_STATES", 1 << 7),
    ("GUILD_PRESENCES", 1 << 8), ("GUILD_MESSAGES", 1 << 9), ("GUILD_MESSAGE_REACTIONS", 1 << 10),
    ("GUILD_MESSAGE_TYPING", 1 << 11), ("DIRECT_MESSAGES", 1 << 12),
    ("DIRECT_MESSAGE_REACTIONS", 1 << 13), ("DIRECT_MESSAGE_TYPING", 1 << 14),
    ("MESSAGE_CONTENT", 1 << 15), ("GUILD_SCHEDULED_EVENTS", 1 << 16),
    ("AUTO_MODERATION_CONFIGURATION", 1 << 20), ("AUTO_MODERATION_EXECUTION", 1 << 21),
)


def _intents(raw: str) -> dict[str, Any]:
    value = _int(raw.strip(), "intents", low=0, high=(1 << 32) - 1)
    active = [name for name, bit in _INTENTS if value & bit]
    privileged = [name for name in active if name in {"GUILD_MEMBERS", "GUILD_PRESENCES", "MESSAGE_CONTENT"}]
    return {
        "BITFIELD": str(value),
        "HEX": f"0x{value:X}",
        "INTENTS": "\n".join(f"• {name}" for name in active) or "none",
        "PRIVILEGED": ", ".join(privileged) or "none",
        "NOTE": "privileged intents need a manual toggle in the developer portal",
    }


_SCOPES = {
    "identify": "read the basic account (id, username, avatar)",
    "email": "read the verified email address",
    "guilds": "read the list of guilds the user is in",
    "guilds.join": "add the user to a guild the app controls",
    "guilds.members.read": "read the user's member object in a guild",
    "connections": "read linked third-party accounts",
    "bot": "install a bot user",
    "applications.commands": "register and use application commands",
    "applications.commands.update": "update commands without reinstall",
    "webhook.incoming": "create an incoming webhook in a channel",
    "messages.read": "read messages in a channel the app was added to",
    "rpc": "allow the local RPC bridge",
    "rpc.activities.write": "publish rich presence activity",
    "role_connections.write": "write linked-role metadata",
    "voice": "join voice channels",
    "dm_channels.read": "read DM channels the app is part of",
}


def _oauthscopes(raw: str) -> dict[str, Any]:
    needle = raw.strip().lower()
    if not needle:
        return {"SCOPES": "\n".join(f"• `{name}` — {text}" for name, text in _SCOPES.items())}
    matches = {name: text for name, text in _SCOPES.items() if needle in name or needle in text}
    if not matches:
        raise UsageError(f"`{needle}` matches no scope.")
    return {"MATCHES": "\n".join(f"• `{name}` — {text}" for name, text in matches.items()), "COUNT": str(len(matches))}


# ── validation and misc utilities ──────────────────────────────────────────


_COMMON_PASSWORDS = {
    "password", "123456", "123456789", "qwerty", "letmein", "welcome", "admin",
    "iloveyou", "monkey", "dragon", "sunshine", "princess", "football", "charlie",
    "aa123456", "password1", "qwerty123", "1q2w3e4r", "trustno1", "abc123",
}


def _passwordpolicy(raw: str) -> dict[str, Any]:
    password = raw.strip()
    if not password:
        raise UsageError("Give a password to evaluate.")
    checks = [
        ("length 12+", len(password) >= 12),
        ("length 16+", len(password) >= 16),
        ("lowercase", any(char.islower() for char in password)),
        ("uppercase", any(char.isupper() for char in password)),
        ("digits", any(char.isdigit() for char in password)),
        ("symbols", any(not char.isalnum() for char in password)),
        ("not a known password", password.lower() not in _COMMON_PASSWORDS),
        ("no repeated run of 4", not re.search(r"(.)\1{3,}", password)),
        ("no keyboard run", not re.search(r"(?:qwer|asdf|zxcv|1234|abcd)", password.lower())),
    ]
    passed = sum(1 for _, ok in checks if ok)
    return {
        "CHECKS": "\n".join(f"{'PASS' if ok else 'FAIL'}  {name}" for name, ok in checks),
        "PASSED": f"{passed}/{len(checks)}",
        "VERDICT": "strong" if passed >= 8 else "acceptable" if passed >= 6 else "weak",
        "LENGTH": f"{len(password)} characters · {len(password.encode())} bytes",
    }


def _crondesc(raw: str) -> dict[str, Any]:
    parts = raw.split()
    if len(parts) == 5:
        names = ["minute", "hour", "day of month", "month", "day of week"]
    elif len(parts) == 6:
        names = ["second", "minute", "hour", "day of month", "month", "day of week"]
    else:
        raise UsageError("Give a 5- or 6-field cron expression.")
    rows = [[name, field, _cron_field(field)] for name, field in zip(names, parts)]
    return {
        "FIELDS": _table(["FIELD", "VALUE", "MEANING"], rows),
        "NEXT": "evaluate with `croniter` if you need real dates",
    }


def _cron_field(field: str) -> str:
    if field == "*":
        return "every value"
    if field.startswith("*/"):
        return f"every {field[2:]} steps"
    if "," in field:
        return "one of " + field.replace(",", ", ")
    if "-" in field:
        return "range " + field.replace("-", " to ")
    return f"exactly {field}"


def _semver(raw: str) -> dict[str, Any]:
    value = raw.strip()
    match = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+([0-9A-Za-z.-]+))?", value)
    if not match:
        raise UsageError("Not semantic versioning — use `1.2.3`, `1.2.3-rc.1` or `1.2.3+build`.")
    major, minor, patch, pre, build = match.groups()
    stage = "stable"
    if pre:
        stage = "prerelease"
    elif version.split(".")[0] == "0":
        stage = "unstable"
    return {
        "MAJOR": major,
        "MINOR": minor,
        "PATCH": patch,
        "PRERELEASE": pre or "—",
        "BUILD": build or "—",
        "STAGE": stage,
        "SORT KEY": f"{int(major):05d}.{int(minor):05d}.{int(patch):05d}",
    }


def _regexplain(raw: str) -> dict[str, Any]:
    pattern = raw.strip()
    if not pattern:
        raise UsageError("Give a regular expression.")
    rows = []
    for match in re.finditer(r"\\[A-Za-z]|\\[0-9]|\[[^\]]*\]|\((?:[^()]*)\)|\{\d+(?:,\d*)?\}|\*|\+|\?|\^|\$|\|", pattern):
        token = match.group(0)
        meaning = {
            "\\d": "digit", "\\w": "word character", "\\s": "whitespace",
            "\\b": "word boundary", "\\.": "literal dot", "\\n": "newline",
            "\\t": "tab", "\\A": "start of input", "\\Z": "end of input",
            "\\D": "non-digit", "\\W": "non-word", "\\S": "non-whitespace",
            "*": "zero or more", "+": "one or more", "?": "optional",
            "^": "anchor start", "$": "anchor end", "|": "alternation",
            ".": "any character",
        }.get(token)
        if token.startswith("["):
            meaning = "character class"
        elif token.startswith("{") or token.startswith("("):
            meaning = "quantifier" if token.startswith("{") else "group"
        rows.append([clip(token, 24), meaning or "construct"])
    return {
        "PATTERN": pattern,
        "CONSTRUCTS": _table(["TOKEN", "MEANING"], rows[:16]) if rows else "no special constructs",
        "LENGTH": str(len(pattern)),
    }


def _csvtable(raw: str) -> dict[str, Any]:
    lines = [line for line in raw.strip().splitlines() if line.strip()]
    if len(lines) < 2:
        raise UsageError("Give a CSV with a header row.")
    import csv
    import io

    rows = list(csv.reader(io.StringIO("\n".join(lines))))
    header = [cell.strip() or f"COL{index + 1}" for index, cell in enumerate(rows[0])]
    body = rows[1:9]
    widths = [max(len(header[index]), *(len(row[index]) if index < len(row) else 0 for row in body)) for index in range(len(header))]
    output = ["| " + " | ".join(header[index].ljust(widths[index]) for index in range(len(header))) + " |"]
    output.append("| " + " | ".join("-" * widths[index] for index in range(len(header))) + " |")
    for row in body:
        output.append("| " + " | ".join((row[index] if index < len(row) else "").ljust(widths[index]) for index in range(len(header))) + " |")
    return {
        "MARKDOWN": "\n".join(output),
        "ROWS": f"{len(rows) - 1} data rows · {len(header)} columns",
        "TRUNCATED": "yes" if len(rows) - 1 > 8 else "no",
    }


def _colorblind(raw: str) -> dict[str, Any]:
    value = raw.strip().lstrip("#")
    if not re.fullmatch(r"[0-9a-fA-F]{6}", value):
        raise UsageError("Give a six-digit hex colour.")
    r, g, b = (int(value[index : index + 2], 16) for index in (0, 2, 4))
    matrices = {
        "protanopia": ((0.567, 0.433, 0.0), (0.558, 0.442, 0.0), (0.0, 0.242, 0.758)),
        "deuteranopia": ((0.625, 0.375, 0.0), (0.7, 0.3, 0.0), (0.0, 0.3, 0.7)),
        "tritanopia": ((0.95, 0.05, 0.0), (0.0, 0.433, 0.567), (0.0, 0.475, 0.525)),
    }
    rows = [["normal", f"#{value.upper()}"]]
    for name, matrix in matrices.items():
        simulated = [
            max(0, min(255, round(r * matrix[0][0] + g * matrix[0][1] + b * matrix[0][2]))),
            max(0, min(255, round(r * matrix[1][0] + g * matrix[1][1] + b * matrix[1][2]))),
            max(0, min(255, round(r * matrix[2][0] + g * matrix[2][1] + b * matrix[2][2]))),
        ]
        rows.append([name, "#" + "".join(f"{channel:02X}" for channel in simulated)])
    return {
        "SOURCE": f"#{value.upper()}",
        "SIMULATIONS": _table(["VISION", "HEX"], rows),
        "USE": "check that a status colour still carries meaning without red/green perception",
    }


def _ts(raw: str) -> dict[str, Any]:
    text = raw.strip()
    parsed = utcnow() if not text else parse_dt(text)
    if parsed is None:
        raise UsageError("Could not read that timestamp — try a Unix value or an ISO date.")
    stamp = int(parsed.timestamp())
    return {
        "ISO 8601": parsed.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "UNIX": str(stamp),
        "MILLIS": str(stamp * 1000),
        "DISCORD": f"<t:{stamp}:F> · <t:{stamp}:R>",
        "DATE ONLY": parsed.strftime("%Y-%m-%d"),
        "UTC": parsed.strftime("%A %d %B %Y %H:%M:%S"),
    }


def _uuid7(raw: str) -> dict[str, Any]:
    millis = int(utcnow().timestamp() * 1000)
    if raw.strip():
        stamp = parse_dt(raw.strip())
        if stamp is None:
            raise UsageError("Could not read that timestamp.")
        millis = int(stamp.timestamp() * 1000)
    rand = secrets.randbits(74)
    value = (millis & ((1 << 48) - 1)) << 80 | (0x7 << 76) | (rand & ((1 << 76) - 1))
    value &= ~(0b11 << 62)
    value |= 0b10 << 62
    hexed = f"{value:032x}"
    formatted = f"{hexed[:8]}-{hexed[8:12]}-{hexed[12:16]}-{hexed[16:20]}-{hexed[20:]}"
    return {
        "UUIDv7": formatted,
        "VARIANT": "RFC 4122 (10xx)",
        "TIMESTAMP": dt.datetime.fromtimestamp(millis / 1000, dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "USE": "time-sorted identifiers that index well",
    }


def _nanoid(raw: str) -> dict[str, Any]:
    length = _int(raw.strip(), "length", low=8, high=64) if raw.strip() else 21
    alphabet = string.ascii_letters + string.digits + "_-"
    value = "".join(secrets.choice(alphabet) for _ in range(length))
    return {"NANOID": value, "LENGTH": str(length), "ALPHABET": "64 characters (URL safe)"}


def _b64url(raw: str) -> dict[str, Any]:
    return {"OUTPUT": _b64u(raw.encode()), "BYTES": str(len(raw.encode())), "STYLE": "URL-safe, padding stripped"}


def _unb64url(raw: str) -> dict[str, Any]:
    try:
        return {"OUTPUT": _unb64u(raw.strip()).decode("utf-8", "replace")}
    except (binascii.Error, ValueError):
        raise UsageError("That is not valid base64url.") from None


def _offsettime(raw: str) -> dict[str, Any]:
    from zoneinfo import ZoneInfo

    text = raw.strip()
    parsed = utcnow() if not text else parse_dt(text)
    if parsed is None:
        raise UsageError("Could not read that timestamp.")
    zones = ("UTC", "Europe/London", "Europe/Berlin", "America/New_York", "America/Los_Angeles", "Asia/Tokyo", "Australia/Sydney")
    rows = []
    for zone in zones:
        rows.append([zone, parsed.astimezone(ZoneInfo(zone)).strftime("%Y-%m-%d %H:%M")])
    return {
        "REFERENCE": parsed.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "ZONES": _table(["ZONE", "LOCAL TIME"], rows),
    }


def _httpdate(raw: str) -> dict[str, Any]:
    text = raw.strip()
    parsed = parse_dt(text) if text else None
    if parsed is None:
        for fmt in ("%a, %d %b %Y %H:%M:%S GMT", "%A, %d-%b-%y %H:%M:%S GMT", "%a %b %d %H:%M:%S %Y"):
            try:
                parsed = dt.datetime.strptime(text, fmt).replace(tzinfo=dt.timezone.utc)
                break
            except ValueError:
                continue
    if parsed is None:
        raise UsageError("Could not read that HTTP date.")
    return {
        "RFC 7231": parsed.strftime("%a, %d %b %Y %H:%M:%S GMT"),
        "ISO 8601": parsed.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "UNIX": str(int(parsed.timestamp())),
        "AGE": f"{(utcnow() - parsed).days:,} days",
    }


def _caseconv(raw: str) -> dict[str, Any]:
    style_raw, text = _pair(raw, "style|text")
    style = style_raw.strip().lower()
    words = [word for word in re.split(r"[^A-Za-z0-9]+", text) if word]
    words = [word if word.islower() or word.isupper() else re.sub(r"(?<!^)(?=[A-Z])", " ", word) for word in words]
    flattened: list[str] = []
    for word in words:
        flattened.extend(part for part in re.split(r"\s+", word.strip()) if part)
    lowered = [word.lower() for word in flattened]
    if not lowered:
        raise UsageError("No words to convert.")
    forms = {
        "snake": "_".join(lowered),
        "kebab": "-".join(lowered),
        "dot": ".".join(lowered),
        "path": "/".join(lowered),
        "camel": lowered[0] + "".join(word.title() for word in lowered[1:]),
        "pascal": "".join(word.title() for word in lowered),
        "const": "_".join(word.upper() for word in lowered),
        "train": "-".join(word.title() for word in lowered),
        "title": " ".join(word.title() for word in lowered),
        "sentence": " ".join(lowered).capitalize(),
        "upper": " ".join(lowered).upper(),
    }
    if style not in forms and style not in {"all", ""}:
        raise UsageError("Styles: " + ", ".join(sorted(forms)))
    if style in forms:
        return {"STYLE": style, "OUTPUT": forms[style]}
    return {name.upper(): value for name, value in forms.items()}


def _jsonflat(raw: str) -> dict[str, Any]:
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise UsageError(f"Invalid JSON: {exc.msg} at line {exc.lineno}.") from None
    rows: list[tuple[str, str]] = []

    def walk(node: Any, prefix: str) -> None:
        if len(rows) >= 40:
            return
        if isinstance(node, dict):
            for key, value in node.items():
                walk(value, f"{prefix}.{key}" if prefix else str(key))
        elif isinstance(node, list):
            for index, value in enumerate(node[:6]):
                walk(value, f"{prefix}[{index}]")
        else:
            rows.append((prefix or "$", str(node)))

    walk(data, "")
    return {
        "PATHS": _table(["PATH", "VALUE"], [[path, clip(value, 56)] for path, value in rows]) if rows else "empty document",
        "COUNT": str(len(rows)),
        "TYPE": type(data).__name__,
    }


def _idnlabels(raw: str) -> dict[str, Any]:
    host = strip_target(raw).lower().split("/")[0]
    if not host:
        raise UsageError("Give a domain or IDN.")
    rows = []
    for label in host.split("."):
        try:
            ascii_form = label.encode("idna").decode("ascii")
        except (UnicodeError, ValueError):
            ascii_form = "invalid"
        rows.append([label or "—", ascii_form, "punycode" if ascii_form.startswith("xn--") else "ascii"])
    try:
        full = host.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        full = "invalid"
    return {
        "LABELS": _table(["LABEL", "ASCII FORM", "KIND"], rows),
        "PUNYCODE": full,
        "UNICODE": host,
        "NOTE": "every `xn--` label is legitimate in isolation; the risk is which script it encodes",
    }


def _rangeexpand(raw: str) -> dict[str, Any]:
    first_raw, last_raw = _pair(raw, "first|last")
    try:
        first = ipaddress.ip_address(strip_target(first_raw))
        last = ipaddress.ip_address(strip_target(last_raw))
    except ValueError:
        raise UsageError("Give two IPv4 addresses.") from None
    if first.version != 4 or last.version != 4:
        raise UsageError("IPv4 only.")
    start, end = int(first), int(last)
    if end < start:
        raise UsageError("The end address is below the start.")
    size = end - start + 1
    listed = [str(ipaddress.ip_address(value)) for value in range(start, min(end, start + 63) + 1)]
    return {
        "FIRST": str(first),
        "LAST": str(last),
        "COUNT": f"{size:,}",
        "SAMPLE": "\n".join(listed),
        "TRUNCATED": "yes — first 64 addresses shown" if size > 64 else "no",
    }


def _epoch(raw: str) -> dict[str, Any]:
    text = raw.strip()
    if not text:
        stamp = utcnow()
        seconds = int(stamp.timestamp())
    elif re.fullmatch(r"\d{13}", text):
        milliseconds = int(text)
        stamp = dt.datetime.fromtimestamp(milliseconds / 1000, dt.timezone.utc)
        seconds = milliseconds // 1000
        return {
            "INPUT": "13 digits — read as milliseconds",
            "SECONDS": str(seconds),
            "ISO 8601": stamp.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "DISCORD": f"<t:{seconds}:F>",
            "AGE": f"{(utcnow() - stamp).days:,} days",
        }
    else:
        parsed = parse_dt(text)
        if parsed is None:
            raise UsageError("Give seconds, milliseconds or a date.")
        stamp = parsed
        seconds = int(parsed.timestamp())
    return {
        "SECONDS": str(seconds),
        "MILLIS": str(seconds * 1000),
        "NANOS": f"{seconds * 1_000_000_000}",
        "ISO 8601": dt.datetime.fromtimestamp(seconds, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "DISCORD": f"<t:{seconds}:F> · <t:{seconds}:R>",
        "AGE": f"{(utcnow() - dt.datetime.fromtimestamp(seconds, dt.timezone.utc)).days:,} days",
    }


# ── registry ───────────────────────────────────────────────────────────────

_ARSENAL: list[tuple[str, str, str, str, Handler, tuple[str, ...], tuple[str, ...]]] = [
    # phishing and lookalike defence
    ("phishmask", "web", "Show the gap between a link's label and its real destination.", "phishmask <url>", _phishmask, ("masklink",), ("local heuristics",)),
    ("phishlure", "web", "Score a lure message for social-engineering markers.", "phishlure <message text>", _phishlure, ("lurescore",), ("local heuristics",)),
    ("phishdork", "web", "Hunt dorks for lookalike infrastructure impersonating a brand.", "phishdork <brand>", _phishdork, ("luredork",), ("local heuristics",)),
    ("phishkit", "web", "Fingerprint a phishing kit from an HTML or source snippet.", "phishkit <html snippet>", _phishkit, ("kitcheck",), ("local heuristics",)),
    ("typosquat", "web", "Enumerate lookalike domains for defensive registration.", "typosquat <domain>", _typosquat, ("lookalike",), ("local heuristics",)),
    ("homoglyph", "web", "Render text with Unicode confusables.", "homoglyph <text>", _homoglyph, ("confuse",), ("local computation",)),
    ("dehomoglyph", "web", "Normalise lookalike characters back to ASCII.", "dehomoglyph <text>", _dehomoglyph, (), ("local computation",)),
    ("confusable", "web", "Detect mixed-script labels in a domain.", "confusable <domain>", _confusable, ("mixedscript",), ("local computation",)),
    ("urlentropy", "web", "Measure host and path entropy for generated-looking URLs.", "urlentropy <url>", _urlentropy, (), ("local heuristics",)),
    ("urlunwrap", "web", "Unwrap nested encodings and redirect parameters offline.", "urlunwrap <url>", _urlunwrap, ("unwrap",), ("local computation",)),
    ("redirparams", "web", "List redirect-style query parameters and their targets.", "redirparams <url>", _redirects, ("redir",), ("local computation",)),
    ("defang", "web", "Defang URLs and indicators for safe sharing.", "defang <text>", _defang, (), ("local computation",)),
    ("refang", "web", "Restore a defanged indicator.", "refang <text>", _refang, (), ("local computation",)),
    ("iocs", "web", "Extract indicators from pasted text.", "iocs <text>", _iocs, ("extractiocs",), ("local computation",)),
    # ciphers and encodings
    ("caesar", "craft", "Shift letters with a Caesar rotation.", "caesar <shift|text>", _caesar, (), ("local computation",)),
    ("uncaesar", "craft", "Print all 26 Caesar rotations.", "uncaesar <text>", _uncaesar, (), ("local computation",)),
    ("rot47", "craft", "Apply the self-inverse ROT47 rotation.", "rot47 <text>", _rot47, (), ("local computation",)),
    ("atbash", "craft", "Apply the Atbash letter reversal.", "atbash <text>", _atbash, (), ("local computation",)),
    ("a1z26", "craft", "Encode letters as 1–26 numbers.", "a1z26 <text>", _a1z26, (), ("local computation",)),
    ("una1z26", "craft", "Decode 1–26 numbers to letters.", "una1z26 <numbers>", _una1z26, (), ("local computation",)),
    ("vigenere", "craft", "Vigenère-encrypt with a keyword.", "vigenere <key|text>", lambda raw: _vigenere(raw), (), ("local computation",)),
    ("unvigenere", "craft", "Vigenère-decrypt with a keyword.", "unvigenere <key|text>", lambda raw: _vigenere(raw, decrypt=True), (), ("local computation",)),
    ("railfence", "craft", "Rail-fence encode with N rails.", "railfence <rails|text>", lambda raw: _railfence(raw), (), ("local computation",)),
    ("unrailfence", "craft", "Rail-fence decode with N rails.", "unrailfence <rails|text>", lambda raw: _railfence(raw, decrypt=True), (), ("local computation",)),
    ("bacon", "craft", "Encode letters as Bacon's A/B groups.", "bacon <text>", _bacon, (), ("local computation",)),
    ("unbacon", "craft", "Decode Bacon's A/B groups.", "unbacon <bits>", _unbacon, (), ("local computation",)),
    ("base58", "craft", "Encode text as base58 (Bitcoin alphabet).", "base58 <text>", _base58, (), ("local computation",)),
    ("unbase58", "craft", "Decode base58 text.", "unbase58 <text>", _unbase58, (), ("local computation",)),
    ("base36", "craft", "Encode text as base36.", "base36 <text>", _base36, (), ("local computation",)),
    ("unbase36", "craft", "Decode base36 text.", "unbase36 <text>", _unbase36, (), ("local computation",)),
    ("base85", "craft", "Encode text as base85.", "base85 <text>", _base85, (), ("local computation",)),
    ("unbase85", "craft", "Decode base85 text.", "unbase85 <text>", _unbase85, (), ("local computation",)),
    ("b64url", "craft", "Encode text as URL-safe base64.", "b64url <text>", _b64url, ("base64url",), ("local computation",)),
    ("unb64url", "craft", "Decode URL-safe base64.", "unb64url <text>", _unb64url, (), ("local computation",)),
    ("hexdump", "craft", "Show offset, hex and ASCII for any text.", "hexdump <text>", _hexdump, ("xxd",), ("local computation",)),
    ("fromhexdump", "craft", "Rebuild text from a hex dump.", "fromhexdump <dump>", _fromhexdump, ("unxxd",), ("local computation",)),
    ("xorhex", "craft", "XOR text with a hex key.", "xorhex <keyhex|text>", _xorhex, ("xor",), ("local computation",)),
    ("bitreverse", "craft", "Reverse the bit order of every byte.", "bitreverse <text>", _bitreverse, (), ("local computation",)),
    ("unicodeescape", "craft", "Escape text as \\uXXXX sequences.", "unicodeescape <text>", _unicodeescape, (), ("local computation",)),
    ("ununicode", "craft", "Decode escape sequences.", "ununicode <escaped>", _ununicode, (), ("local computation",)),
    ("zerowidth", "craft", "Reveal zero-width and invisible characters.", "zerowidth <text>", _zerowidth, ("invisible",), ("local computation",)),
    ("stripzero", "craft", "Remove zero-width characters.", "stripzero <text>", _stripzero, (), ("local computation",)),
    ("leet", "craft", "Convert text to leetspeak.", "leet <text>", _leet, ("1337",), ("local computation",)),
    ("unleet", "craft", "Approximate leetspeak decoding.", "unleet <text>", _unleet, (), ("local computation",)),
    ("nato", "craft", "Spell text with the NATO alphabet.", "nato <text>", _nato, ("phonetic",), ("local computation",)),
    ("unnato", "craft", "Decode NATO alphabet words.", "unnato <words>", _unnato, (), ("local computation",)),
    ("freq", "craft", "Character frequency table.", "freq <text>", _freq, ("frequency",), ("local computation",)),
    ("ngrams", "craft", "Top bigrams and trigrams.", "ngrams <text>", _ngrams, (), ("local computation",)),
    ("wordfreq", "craft", "Most common words with counts.", "wordfreq <text>", _wordfreq, (), ("local computation",)),
    ("acrostic", "craft", "Read the first letter of every line.", "acrostic <text>", _acrostic, (), ("local computation",)),
    ("palindrome", "craft", "Test whether text is a palindrome.", "palindrome <text>", _palindrome, (), ("local computation",)),
    ("anagram", "craft", "Compare two strings as anagrams.", "anagram <left|right>", _anagram, (), ("local computation",)),
    ("readability", "craft", "Flesch reading ease and grade level.", "readability <text>", _readability, (), ("local computation",)),
    # hashes and keys
    ("adler32", "toolkit", "Adler-32 checksum.", "adler32 <text>", _adler32, (), ("local computation",)),
    ("fnv1a", "toolkit", "FNV-1a 32- and 64-bit hashes.", "fnv1a <text>", _fnv1a, (), ("local computation",)),
    ("murmur3", "toolkit", "MurmurHash3 x86 32-bit — the favicon pivot hash.", "murmur3 <text>", _murmur3, (), ("local computation",)),
    ("hmacmd5", "toolkit", "HMAC-MD5 of `key|message`.", "hmacmd5 <key|message>", lambda raw: _hmac(raw, "md5"), (), ("local computation",)),
    ("hmacsha1", "toolkit", "HMAC-SHA1 of `key|message`.", "hmacsha1 <key|message>", lambda raw: _hmac(raw, "sha1"), (), ("local computation",)),
    ("hmacsha512", "toolkit", "HMAC-SHA512 of `key|message`.", "hmacsha512 <key|message>", lambda raw: _hmac(raw, "sha512"), (), ("local computation",)),
    ("pbkdf2", "toolkit", "Derive a key with PBKDF2-HMAC-SHA256.", "pbkdf2 <salt|password>", _pbkdf2, (), ("local computation",)),
    ("hashmode", "toolkit", "Suggest hashcat modes for a hash.", "hashmode <hash>", _hashmode, ("hashcat",), ("local computation",)),
    ("johnmode", "toolkit", "Suggest a John the Ripper format for a hash.", "johnmode <hash>", _johnmode, (), ("local computation",)),
    # network-local parsing
    ("subnetinfo", "network", "Full breakdown of a CIDR block.", "subnetinfo <cidr>", _subnet, ("subnetcalc",), ("local computation",)),
    ("supernet", "network", "Summarise a block into a parent prefix.", "supernet <cidr|prefix>", _supernet, (), ("local computation",)),
    ("ipv6type", "network", "Classify an IPv6 address (ULA, link-local, 6to4, Teredo).", "ipv6type <ipv6>", _ipv6type, (), ("local computation",)),
    ("portrange", "network", "Expand a port list or range.", "portrange <80,443,8000-8100>", _portrange, ("ports",), ("local computation",)),
    ("tcpflags", "network", "Decode a TCP flag byte or flag names.", "tcpflags <0x12|SYN,ACK>", _tcpflags, (), ("local computation",)),
    ("icmpcode", "network", "Explain an ICMP type and code.", "icmpcode <type|code>", _icmpcode, (), ("local computation",)),
    ("dnstype", "network", "Explain a DNS record type.", "dnstype <type>", _dnstype, ("rrttype",), ("local computation",)),
    ("httphdr", "web", "Explain an HTTP header.", "httphdr <header>", _httphdr, ("headerinfo",), ("local computation",)),
    ("ciphersuite", "network", "Decompose a TLS cipher suite name.", "ciphersuite <suite>", _ciphersuite, ("tlsname",), ("local computation",)),
    ("authresults", "domain", "Parse an Authentication-Results header.", "authresults <header value>", _emailauth, ("mailauth",), ("local computation",)),
    ("received", "domain", "Parse a Received header chain.", "received <headers>", _received, ("mailhops",), ("local computation",)),
    # synthetic generators
    ("fakecard", "generator", "Generate a Luhn-valid synthetic card number.", "fakecard [bin prefix]", _fakecard, ("testcard",), ("local computation",)),
    ("fakeiban", "generator", "Generate a MOD-97-valid synthetic IBAN.", "fakeiban [country]", _fakeiban, ("testiban",), ("local computation",)),
    ("fakeimei", "generator", "Generate a Luhn-valid synthetic IMEI.", "fakeimei [tac]", _fakeimei, ("testimei",), ("local computation",)),
    ("fakesnowflake", "discord", "Build a Discord snowflake for a timestamp.", "fakesnowflake [date]", _fakesnowflake, ("snowflakesynth",), ("local computation",)),
    ("fakehash", "generator", "Generate a hex hash of a chosen length.", "fakehash [length]", _fakehash, ("testhash",), ("local computation",)),
    ("fakejwt", "generator", "Build an unsigned demo JWT.", "fakejwt [subject]", _fakejwt, ("testjwt",), ("local computation",)),
    # discord-local helpers
    ("tokentype", "discord", "Classify a token's shape without echoing it.", "tokentype <token>", _tokentype, ("tokencheck",), ("local computation",)),
    ("snowflakerange", "discord", "Snowflake bounds for one UTC day.", "snowflakerange <date>", _snowflakerange, ("snowflakeday",), ("local computation",)),
    ("perms", "discord", "Decode a Discord permission bitfield.", "perms <integer>", _perms, ("permissions",), ("local computation",)),
    ("intents", "discord", "Decode a gateway intents bitfield.", "intents <integer>", _intents, (), ("local computation",)),
    ("oauthscopes", "discord", "Explain Discord OAuth2 scopes.", "oauthscopes [scope]", _oauthscopes, ("scopes",), ("local computation",)),
    # validation and misc
    ("passwordpolicy", "craft", "Evaluate a password against policy rules.", "passwordpolicy <password>", _passwordpolicy, ("passrules",), ("local computation",)),
    ("crondesc", "toolkit", "Explain a cron expression.", "crondesc <expression>", _crondesc, ("cron",), ("local computation",)),
    ("semver", "toolkit", "Validate and decompose a semantic version.", "semver <version>", _semver, (), ("local computation",)),
    ("regexplain", "toolkit", "Explain the constructs in a regular expression.", "regexplain <pattern>", _regexplain, ("regexdebug",), ("local computation",)),
    ("csvtable", "toolkit", "Convert CSV into a Markdown table.", "csvtable <csv>", _csvtable, ("csvmd",), ("local computation",)),
    ("colorblind", "toolkit", "Simulate a hex colour under colour-vision deficiencies.", "colorblind <#hex>", _colorblind, ("cvd",), ("local computation",)),
    ("ts", "toolkit", "Parse a timestamp into every useful format.", "ts <timestamp>", _ts, ("timestampinfo",), ("local computation",)),
    ("uuid7", "generator", "Generate a time-ordered UUIDv7.", "uuid7 [date]", _uuid7, (), ("local computation",)),
    ("nanoid", "generator", "Generate a URL-safe random identifier.", "nanoid [length]", _nanoid, (), ("local computation",)),
    ("offsettime", "toolkit", "Show one instant across time zones.", "offsettime <timestamp>", _offsettime, ("tz",), ("local computation",)),
    ("httpdate", "toolkit", "Parse an HTTP date header.", "httpdate <date>", _httpdate, (), ("local computation",)),
    ("caseconv", "toolkit", "Convert between naming styles.", "caseconv <style|text>", _caseconv, ("casing",), ("local computation",)),
    ("jsonflat", "toolkit", "Flatten JSON into dotted paths.", "jsonflat <json>", _jsonflat, ("jsonpaths",), ("local computation",)),
    ("idnlabels", "domain", "Break a domain into ASCII and Unicode labels.", "idnlabels <domain>", _idnlabels, ("idncheck",), ("local computation",)),
    ("rangeexpand", "network", "Expand an IPv4 range into addresses.", "rangeexpand <first|last>", _rangeexpand, (), ("local computation",)),
    ("epochtime", "toolkit", "Convert epoch seconds, millis or a date.", "epochtime <value>", _epoch, ("epochms",), ("local computation",)),
]


class Arsenal(commands.Cog, name="Arsenal"):
    """Local payload crafts, lure analysis and protocol decoding."""

    def __init__(self, bot: Any) -> None:
        self.bot = bot

    async def _render(
        self,
        ctx: commands.Context,
        name: str,
        category: str,
        raw: str,
        handler: Handler,
        sources: tuple[str, ...],
    ) -> None:
        await ack(ctx)
        value = (raw or "").strip()
        try:
            result = handler(value)
        except UsageError:
            raise
        except (ValueError, TypeError, IndexError, KeyError, binascii.Error, AttributeError) as exc:
            raise UsageError(str(exc) or "That input could not be processed.") from None
        embed = Intel(
            category=category,
            command=name,
            ctx=ctx,
            target=clip(value, 100) if value else None,
        )
        if value:
            embed.field("INPUT", _plain(value, 640), inline=False)
        if isinstance(result, dict):
            for label, item in list(result.items())[:18]:
                if item is None or item == "" or item == []:
                    continue
                text = item if isinstance(item, str) else json.dumps(item, ensure_ascii=False, default=str)
                if "\n" in text or len(text) > 90:
                    embed.field(str(label), _plain(text, 1200), inline=False)
                else:
                    embed.field(str(label), f"`{clip(text, 180).replace('`', 'ˋ')}`", inline=True)
        elif isinstance(result, (list, tuple)):
            embed.field("OUTPUT", _plain("\n".join(str(item) for item in result), 1200), inline=False)
        else:
            embed.field("OUTPUT", _plain(result, 1200), inline=False)
        embed.source(*sources)
        await embed.send(ctx)


def _callback_for(name: str, category: str, handler: Handler, sources: tuple[str, ...]) -> Callable[..., Any]:
    async def callback(self: Arsenal, ctx: commands.Context, target: str = None) -> None:
        await self._render(ctx, name, category, target or "", handler, sources)

    callback.__name__ = name
    return callback


def _install() -> None:
    for name, category, brief, usage, handler, aliases, sources in _ARSENAL:
        callback = _callback_for(name, category, handler, sources)
        callback.__doc__ = brief
        command = intel(
            category=category,
            brief=brief,
            usage=usage,
            aliases=aliases,
            examples=[usage],
            sources=sources,
            cooldown=(2, 6),
            name=name,
        )(callback)
        setattr(Arsenal, name, command)
        Arsenal.__cog_commands__.append(command)


_install()


async def setup(bot: Any) -> None:
    await bot.add_cog(Arsenal(bot))

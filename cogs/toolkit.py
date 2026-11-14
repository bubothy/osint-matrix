"""Local analysis tools: encoders, hashes, address arithmetic and text utilities.

Everything in this cog runs on the host. No target is sent to a third party,
which makes these commands useful when a source is unavailable or when a value
should not leave the instance.
"""

from __future__ import annotations

import base64
import binascii
import builtins
import codecs
import colorsys
import csv
import datetime as dt
import difflib
import hashlib
import hmac
import html
import ipaddress
import json
import math
import mimetypes
import re
import secrets
import statistics
import string
import textwrap
import unicodedata
import urllib.parse
import uuid
from collections import Counter
from http import HTTPStatus
from typing import Any, Callable

from discord.ext import commands

from core.command import intel
from core.embeds import Intel
from core.errors import UsageError
from core.signatures import COMMON_PORTS
from core.utils import (
    ack,
    base_domain,
    clip,
    is_domain,
    is_email,
    is_ip,
    is_url,
    normalize_host,
    parse_dt,
)

Handler = Callable[[str], Any]


def _plain(value: Any, limit: int = 1000) -> str:
    text = "" if value is None else str(value)
    return f"```text\n{clip(text, limit - 16)}\n```"


def _pair(raw: str) -> tuple[str, str]:
    if "|" not in raw:
        raise UsageError("Use `left|right` as the separator.")
    left, right = raw.split("|", 1)
    return left, right


def _decimal(raw: str) -> int:
    text = raw.strip().replace("_", "").replace(",", "")
    if not text:
        raise UsageError("Supply a number.")
    try:
        return int(text, 0)
    except ValueError:
        raise UsageError("Supply a whole number, optionally with a 0x prefix.") from None


def _b64e(raw: str) -> str:
    return base64.b64encode(raw.encode()).decode()


def _b64d(raw: str) -> str:
    try:
        return base64.b64decode(raw, validate=True).decode("utf-8", "replace")
    except (binascii.Error, ValueError):
        raise UsageError("That is not valid base64.") from None


def _b32e(raw: str) -> str:
    return base64.b32encode(raw.encode()).decode()


def _b32d(raw: str) -> str:
    try:
        return base64.b32decode(raw, casefold=True).decode("utf-8", "replace")
    except (binascii.Error, ValueError):
        raise UsageError("That is not valid base32.") from None


def _hexe(raw: str) -> str:
    return raw.encode().hex()


def _hexd(raw: str) -> str:
    cleaned = re.sub(r"\s+", "", raw)
    if len(cleaned) % 2:
        raise UsageError("Hex input needs an even number of digits.")
    try:
        return bytes.fromhex(cleaned).decode("utf-8", "replace")
    except ValueError:
        raise UsageError("That is not valid hexadecimal.") from None


def _urle(raw: str) -> str:
    return urllib.parse.quote(raw, safe="")


def _urld(raw: str) -> str:
    return urllib.parse.unquote(raw)


def _rot13(raw: str) -> str:
    return codecs.encode(raw, "rot_13")


def _binary(raw: str) -> str:
    return " ".join(f"{byte:08b}" for byte in raw.encode())


def _unbinary(raw: str) -> str:
    bits = re.sub(r"[^01]", "", raw)
    if not bits or len(bits) % 8:
        raise UsageError("Binary input must contain complete 8-bit groups.")
    return bytes(int(bits[index : index + 8], 2) for index in range(0, len(bits), 8)).decode(
        "utf-8", "replace"
    )


_MORSE = {
    "A": ".-",
    "B": "-...",
    "C": "-.-.",
    "D": "-..",
    "E": ".",
    "F": "..-.",
    "G": "--.",
    "H": "....",
    "I": "..",
    "J": ".---",
    "K": "-.-",
    "L": ".-..",
    "M": "--",
    "N": "-.",
    "O": "---",
    "P": ".--.",
    "Q": "--.-",
    "R": ".-.",
    "S": "...",
    "T": "-",
    "U": "..-",
    "V": "...-",
    "W": ".--",
    "X": "-..-",
    "Y": "-.--",
    "Z": "--..",
    "0": "-----",
    "1": ".----",
    "2": "..---",
    "3": "...--",
    "4": "....-",
    "5": ".....",
    "6": "-....",
    "7": "--...",
    "8": "---..",
    "9": "----.",
    ".": ".-.-.-",
    ",": "--..--",
    "?": "..--..",
    "/": "-..-.",
    "-": "-....-",
    "@": ".--.-.",
}
_MORSE_REVERSE = {value: key for key, value in _MORSE.items()}


def _morse(raw: str) -> str:
    words = []
    for word in raw.upper().split():
        words.append(" ".join(_MORSE.get(char, "") for char in word))
    return " / ".join(words)


def _unmorse(raw: str) -> str:
    words = []
    for word in raw.strip().split("/"):
        letters = []
        for token in word.split():
            if token not in _MORSE_REVERSE:
                raise UsageError(f"Unknown Morse token: `{clip(token, 20)}`")
            letters.append(_MORSE_REVERSE[token])
        words.append("".join(letters))
    return " ".join(words)


def _puny(raw: str) -> str:
    try:
        return raw.encode("idna").decode("ascii")
    except UnicodeError:
        raise UsageError("That label cannot be converted to IDNA.") from None


def _unpuny(raw: str) -> str:
    try:
        return raw.encode("ascii").decode("idna")
    except UnicodeError:
        raise UsageError("That is not a valid IDNA label.") from None


def _unicode(raw: str) -> str:
    return " ".join(f"U+{ord(char):04X}" for char in raw)


def _ununicode(raw: str) -> str:
    tokens = re.findall(r"(?:U\+|\\u|0x)?([0-9A-Fa-f]{2,6})", raw)
    if not tokens:
        raise UsageError("Supply code points such as `U+0041 U+0042`.")
    try:
        return "".join(chr(int(token, 16)) for token in tokens)
    except ValueError:
        raise UsageError("One of those code points is out of range.") from None


def _htmlenc(raw: str) -> str:
    return html.escape(raw, quote=True)


def _htmlunesc(raw: str) -> str:
    return html.unescape(raw)


def _hash(raw: str, algorithm: str) -> str:
    try:
        return hashlib.new(algorithm, raw.encode()).hexdigest()
    except ValueError:
        raise UsageError(f"Hash algorithm `{algorithm}` is not available.") from None


def _crc32(raw: str) -> str:
    return f"{binascii.crc32(raw.encode()) & 0xFFFFFFFF:08x}"


def _hmac(raw: str) -> str:
    key, message = _pair(raw)
    return hmac.new(key.encode(), message.encode(), hashlib.sha256).hexdigest()


def _hashid(raw: str) -> str:
    text = raw.strip()
    patterns = [
        ("MD5", r"^[a-f0-9]{32}$"),
        ("SHA-1", r"^[a-f0-9]{40}$"),
        ("SHA-256", r"^[a-f0-9]{64}$"),
        ("SHA-512", r"^[a-f0-9]{128}$"),
        ("bcrypt", r"^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$"),
        ("Argon2", r"^\$argon2(id|i|d)\$"),
    ]
    return ", ".join(name for name, pattern in patterns if re.match(pattern, text, re.I)) or "unrecognised"


def _entropy(raw: str) -> dict[str, Any]:
    if not raw:
        raise UsageError("Supply text to measure.")
    counts = Counter(raw)
    length = len(raw)
    value = -sum((count / length) * math.log2(count / length) for count in counts.values())
    return {
        "Length": length,
        "Unique characters": len(counts),
        "Shannon entropy": f"{value:.3f} bits/character",
        "Total entropy": f"{value * length:.1f} bits",
    }


def _passstrength(raw: str) -> dict[str, Any]:
    classes = sum(
        bool(re.search(pattern, raw))
        for pattern in (r"[a-z]", r"[A-Z]", r"\d", r"[^A-Za-z0-9]")
    )
    pool = 0
    if re.search(r"[a-z]", raw):
        pool += 26
    if re.search(r"[A-Z]", raw):
        pool += 26
    if re.search(r"\d", raw):
        pool += 10
    if re.search(r"[^A-Za-z0-9]", raw):
        pool += 33
    bits = len(raw) * math.log2(pool) if pool else 0
    verdict = "very weak" if bits < 28 else "weak" if bits < 40 else "reasonable" if bits < 60 else "strong"
    return {
        "Length": len(raw),
        "Character classes": classes,
        "Estimated entropy": f"{bits:.1f} bits",
        "Verdict": verdict,
    }


def _slug(raw: str) -> str:
    value = unicodedata.normalize("NFKD", raw).encode("ascii", "ignore").decode()
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-") or "—"


def _diff(raw: str) -> str:
    left, right = _pair(raw)
    lines = difflib.unified_diff(
        left.splitlines() or [""],
        right.splitlines() or [""],
        fromfile="left",
        tofile="right",
        lineterm="",
    )
    return "\n".join(lines) or "identical"


def _jsonfmt(raw: str, *, compact: bool = False) -> str:
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise UsageError(f"Invalid JSON: {exc.msg} at character {exc.pos}.") from None
    return json.dumps(value, indent=None if compact else 2, sort_keys=True, ensure_ascii=False)


def _jsonkeys(raw: str) -> str:
    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        raise UsageError("Invalid JSON.") from None
    found: list[str] = []

    def walk(item: Any, prefix: str = "") -> None:
        if isinstance(item, dict):
            for key, child in item.items():
                path = f"{prefix}.{key}" if prefix else key
                found.append(path)
                walk(child, path)
        elif isinstance(item, list):
            for index, child in enumerate(item[:5]):
                walk(child, f"{prefix}[{index}]")

    walk(value)
    return "\n".join(found[:100]) or "no keys"


def _jsonvals(raw: str) -> str:
    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        raise UsageError("Invalid JSON.") from None
    if not isinstance(value, dict):
        return _plain(value)
    return "\n".join(f"{key}: {clip(child, 80)}" for key, child in value.items())


def _urlinspect(raw: str) -> dict[str, Any]:
    if not is_url(raw):
        raise UsageError("Supply a URL with a host.")
    parsed = urllib.parse.urlsplit(raw if "://" in raw else f"https://{raw}")
    query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    return {
        "Scheme": parsed.scheme,
        "Host": parsed.hostname,
        "Port": parsed.port or "default",
        "Path": parsed.path or "/",
        "Query parameters": len(query),
        "Fragment": parsed.fragment or "—",
        "Normalised": urllib.parse.urlunsplit(
            (parsed.scheme, parsed.netloc.lower(), parsed.path or "/", parsed.query, "")
        ),
    }


def _queryparse(raw: str) -> str:
    query = raw.split("?", 1)[-1]
    pairs = urllib.parse.parse_qsl(query, keep_blank_values=True)
    return "\n".join(f"{key} = {value}" for key, value in pairs) or "no parameters"


def _querybuild(raw: str) -> str:
    pairs = urllib.parse.parse_qsl(raw, keep_blank_values=True)
    if not pairs and "=" in raw:
        pairs = [tuple(item.split("=", 1)) for item in raw.split("&") if "=" in item]
    if not pairs:
        raise UsageError("Use `key=value&key=value`.")
    return urllib.parse.urlencode(pairs)


def _jwtinspect(raw: str) -> dict[str, Any]:
    token = raw.strip()
    parts = token.split(".")
    if len(parts) != 3:
        raise UsageError("A JWT needs three dot-separated segments.")
    def decode(segment: str) -> Any:
        padded = segment + "=" * (-len(segment) % 4)
        try:
            return json.loads(base64.urlsafe_b64decode(padded).decode("utf-8"))
        except (ValueError, UnicodeError, binascii.Error):
            raise UsageError("A JWT segment is not valid base64 JSON.") from None
    header = decode(parts[0])
    payload = decode(parts[1])
    return {
        "Header": json.dumps(header, indent=2),
        "Payload": json.dumps(payload, indent=2),
        "Signature length": len(parts[2]),
    }


def _jwtpayload(raw: str) -> str:
    result = _jwtinspect(raw)
    return str(result["Payload"])


def _csvjson(raw: str) -> str:
    try:
        rows = list(csv.DictReader(raw.splitlines()))
    except csv.Error as exc:
        raise UsageError(f"CSV parse failed: {exc}") from None
    if not rows:
        raise UsageError("The first line must be a header row.")
    return json.dumps(rows, indent=2, ensure_ascii=False)


def _ip2int(raw: str) -> str:
    try:
        return str(int(ipaddress.IPv4Address(raw.strip())))
    except ValueError:
        raise UsageError("Supply one IPv4 address.") from None


def _int2ip(raw: str) -> str:
    value = _decimal(raw)
    if not 0 <= value <= 0xFFFFFFFF:
        raise UsageError("An IPv4 integer must be between 0 and 4294967295.")
    return str(ipaddress.IPv4Address(value))


def _ipv6expand(raw: str) -> str:
    try:
        return ipaddress.IPv6Address(raw.strip()).exploded
    except ValueError:
        raise UsageError("Supply one IPv6 address.") from None


def _ipv6compress(raw: str) -> str:
    try:
        return ipaddress.IPv6Address(raw.strip()).compressed
    except ValueError:
        raise UsageError("Supply one IPv6 address.") from None


def _ipclass(raw: str) -> dict[str, Any]:
    try:
        address = ipaddress.ip_address(raw.strip())
    except ValueError:
        raise UsageError("Supply one IPv4 or IPv6 address.") from None
    flags = {
        "Version": address.version,
        "Private": address.is_private,
        "Global": address.is_global,
        "Loopback": address.is_loopback,
        "Link-local": address.is_link_local,
        "Multicast": address.is_multicast,
        "Reserved": address.is_reserved,
        "Unspecified": address.is_unspecified,
        "Reverse DNS": address.reverse_pointer,
    }
    if address.version == 4:
        flags["Class"] = (
            "A" if address.packed[0] < 128 else "B" if address.packed[0] < 192 else "C" if address.packed[0] < 224 else "D/E"
        )
    return flags


def _ptrsuffix(raw: str) -> str:
    try:
        return ipaddress.ip_address(raw.strip()).reverse_pointer
    except ValueError:
        raise UsageError("Supply one IPv4 or IPv6 address.") from None


def _macfmt(raw: str) -> dict[str, Any]:
    digits = re.sub(r"[^0-9A-Fa-f]", "", raw).upper()
    if len(digits) != 12:
        raise UsageError("A MAC address needs 12 hexadecimal digits.")
    return {
        "Colon": ":".join(digits[index : index + 2] for index in range(0, 12, 2)),
        "Hyphen": "-".join(digits[index : index + 2] for index in range(0, 12, 2)),
        "Cisco": ".".join(digits[index : index + 4] for index in range(0, 12, 4)),
        "OUI": digits[:6],
        "Multicast": bool(int(digits[:2], 16) & 1),
        "Local": bool(int(digits[:2], 16) & 2),
    }


def _cidrsplit(raw: str) -> str:
    left, right = _pair(raw)
    try:
        network = ipaddress.ip_network(left.strip(), strict=False)
        bits = int(right.strip())
        return "\n".join(str(item) for item in network.subnets(new_prefix=bits))
    except (ValueError, TypeError):
        raise UsageError("Use `CIDR|new_prefix`, for example `192.0.2.0/24|26`.") from None


def _cidrmerge(raw: str) -> str:
    values = [item for item in re.split(r"[\s,]+", raw.strip()) if item]
    if not values:
        raise UsageError("Supply one or more CIDR blocks.")
    try:
        networks = [ipaddress.ip_network(item, strict=False) for item in values]
        merged = list(ipaddress.collapse_addresses(networks))
    except ValueError:
        raise UsageError("One of those blocks is invalid.") from None
    return "\n".join(str(item) for item in merged)


def _ipv4range(raw: str) -> dict[str, Any]:
    left, right = _pair(raw)
    try:
        first = ipaddress.IPv4Address(left.strip())
        last = ipaddress.IPv4Address(right.strip())
    except ValueError:
        raise UsageError("Use two IPv4 addresses separated by `|`.") from None
    if int(last) < int(first):
        first, last = last, first
    return {
        "First": first,
        "Last": last,
        "Count": f"{int(last) - int(first) + 1:,}",
        "Integer span": f"{int(first)} – {int(last)}",
    }


def _ipv6range(raw: str) -> dict[str, Any]:
    left, right = _pair(raw)
    try:
        first = ipaddress.IPv6Address(left.strip())
        last = ipaddress.IPv6Address(right.strip())
    except ValueError:
        raise UsageError("Use two IPv6 addresses separated by `|`.") from None
    if int(last) < int(first):
        first, last = last, first
    return {
        "First": first.compressed,
        "Last": last.compressed,
        "Count": f"{int(last) - int(first) + 1:,}",
        "Integer span": f"{int(first)} – {int(last)}",
    }


def _cidrcontains(raw: str) -> dict[str, Any]:
    left, right = _pair(raw)
    try:
        network = ipaddress.ip_network(left.strip(), strict=False)
        address = ipaddress.ip_address(right.strip())
    except ValueError:
        raise UsageError("Use `CIDR|address`.") from None
    return {
        "Network": network,
        "Address": address,
        "Contained": address in network,
        "Version match": network.version == address.version,
    }


def _wildcardmask(raw: str) -> dict[str, Any]:
    try:
        network = ipaddress.ip_network(raw.strip(), strict=False)
    except ValueError:
        raise UsageError("Supply a valid IPv4 network.") from None
    if network.version != 4:
        raise UsageError("Wildcard masks are an IPv4 convention.")
    return {
        "Network": network,
        "Netmask": network.netmask,
        "Wildcard": network.hostmask,
        "Cisco ACL": f"{network.network_address} {network.hostmask}",
    }


def _portmap(raw: str) -> dict[str, Any]:
    value = raw.strip().lower()
    if value.isdigit():
        port = int(value)
        if not 1 <= port <= 65535:
            raise UsageError("Ports run from 1 to 65535.")
        return {"Port": port, "Service": COMMON_PORTS.get(port, "unknown / custom")}
    matches = [port for port, name in COMMON_PORTS.items() if value in name.lower()]
    if not matches:
        raise UsageError("No common service matched that name.")
    return {"Service": value, "Ports": ", ".join(str(port) for port in matches[:20])}


def _protocol(raw: str) -> dict[str, Any]:
    table = {
        "1": "ICMP",
        "6": "TCP",
        "17": "UDP",
        "41": "IPv6",
        "47": "GRE",
        "50": "ESP",
        "51": "AH",
        "58": "ICMPv6",
        "89": "OSPF",
        "132": "SCTP",
    }
    value = raw.strip().upper()
    if value.isdigit():
        return {"Number": value, "Protocol": table.get(value, "unassigned / other")}
    found = [number for number, name in table.items() if value == name]
    return {"Protocol": value, "Number": found[0] if found else "unknown"}


def _statuscode(raw: str) -> dict[str, Any]:
    try:
        code = int(raw.strip())
        phrase = HTTPStatus(code).phrase
        category = f"{code // 100}xx"
    except ValueError:
        raise UsageError("Supply an HTTP status number.") from None
    return {"Status": code, "Phrase": phrase, "Class": category}


def _httpmethod(raw: str) -> dict[str, Any]:
    method = raw.strip().upper()
    allowed = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "CONNECT"}
    if method not in allowed:
        raise UsageError("Unknown HTTP method.")
    return {"Method": method, "Safe": method in {"GET", "HEAD", "OPTIONS", "TRACE"}, "Idempotent": method in {"GET", "HEAD", "PUT", "DELETE", "OPTIONS", "TRACE"}}


def _csp(raw: str) -> str:
    parts = [part.strip() for part in raw.split(";") if part.strip()]
    if not parts:
        raise UsageError("Supply a Content-Security-Policy value.")
    return "\n".join(f"{index:02d}  {clip(part, 180)}" for index, part in enumerate(parts, 1))


def _hsts(raw: str) -> dict[str, Any]:
    values = {}
    for part in raw.split(";"):
        if not part.strip():
            continue
        key, _, value = part.strip().partition("=")
        values[key.lower()] = value or True
    return {
        "max-age": values.get("max-age", "missing"),
        "includeSubDomains": "includeSubDomains" in values,
        "preload": "preload" in values,
        "directives": len(values),
    }


def _cookieparse(raw: str) -> str:
    values = []
    for part in raw.split(";"):
        if "=" in part:
            key, value = part.split("=", 1)
            values.append(f"{key.strip()} = {clip(value.strip(), 120)}")
    return "\n".join(values) or "no cookie pairs"


def _ua(raw: str) -> dict[str, Any]:
    text = raw.strip()
    browser = next(
        (name for name in ("Edg", "OPR", "Firefox", "Chrome", "Safari") if name in text),
        "unknown",
    )
    version = ""
    match = re.search(rf"{browser}/([0-9.]+)", text)
    if match:
        version = match.group(1)
    return {
        "Browser": browser,
        "Version": version or "—",
        "Mobile": "Mobile" in text,
        "Bot": bool(re.search(r"bot|crawler|spider", text, re.I)),
        "Length": len(text),
    }


def _uuidcheck(raw: str) -> dict[str, Any]:
    try:
        value = uuid.UUID(raw.strip())
    except ValueError:
        raise UsageError("That is not a valid UUID.") from None
    return {"Canonical": str(value), "Version": value.version, "Variant": value.variant, "Integer": value.int}


def _isbncheck(raw: str) -> dict[str, Any]:
    digits = re.sub(r"[^0-9Xx]", "", raw)
    if len(digits) == 10:
        total = sum((10 - index) * (10 if char in "Xx" else int(char)) for index, char in enumerate(digits))
        return {"Format": "ISBN-10", "Valid": total % 11 == 0, "Digits": digits}
    if len(digits) == 13:
        total = sum((1 if index % 2 == 0 else 3) * int(char) for index, char in enumerate(digits))
        return {"Format": "ISBN-13", "Valid": total % 10 == 0, "Digits": digits}
    raise UsageError("Supply an ISBN-10 or ISBN-13.")


def _luhn(raw: str) -> dict[str, Any]:
    digits = re.sub(r"\D", "", raw)
    if len(digits) < 2:
        raise UsageError("Supply a number with at least two digits.")
    total = 0
    for index, char in enumerate(reversed(digits)):
        value = int(char)
        if index % 2 == 1:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return {"Digits": len(digits), "Valid": total % 10 == 0, "Check digit": digits[-1]}


def _base64check(raw: str) -> dict[str, Any]:
    text = raw.strip()
    try:
        decoded = base64.b64decode(text, validate=True)
        return {"Valid": True, "Bytes": len(decoded), "Preview": decoded[:40].decode("utf-8", "replace")}
    except (binascii.Error, ValueError):
        return {"Valid": False, "Bytes": 0, "Preview": "—"}


def _domaincheck(raw: str) -> dict[str, Any]:
    host = normalize_host(raw)
    return {
        "Domain": host,
        "Valid syntax": is_domain(host),
        "Registrable": base_domain(host),
        "ASCII form": _puny(host) if host else "—",
        "Labels": host.count(".") + 1 if host else 0,
    }


def _emailcheck(raw: str) -> dict[str, Any]:
    text = raw.strip()
    local, _, domain = text.partition("@")
    return {
        "Address": text,
        "Valid syntax": is_email(text),
        "Local part": local or "—",
        "Domain": domain or "—",
        "Domain syntax": is_domain(domain) if domain else False,
    }


def _ipcheck(raw: str) -> dict[str, Any]:
    text = raw.strip()
    if not is_ip(text):
        raise UsageError("Supply one IPv4 or IPv6 address.")
    address = ipaddress.ip_address(text)
    return {
        "Address": address,
        "Version": address.version,
        "Private": address.is_private,
        "Global": address.is_global,
        "Reverse DNS": address.reverse_pointer,
    }


def _jsoncheck(raw: str) -> dict[str, Any]:
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        return {"Valid": False, "Error": f"{exc.msg} at character {exc.pos}"}
    return {"Valid": True, "Type": type(value).__name__, "Length": len(value) if hasattr(value, "__len__") else 1}


def _jwtcheck(raw: str) -> dict[str, Any]:
    try:
        parts = raw.strip().split(".")
        if len(parts) != 3:
            return {"Valid": False, "Segments": len(parts)}
        header = json.loads(base64.urlsafe_b64decode(parts[0] + "=" * (-len(parts[0]) % 4)))
        return {"Valid": True, "Segments": 3, "Algorithm": header.get("alg", "—"), "Type": header.get("typ", "—")}
    except (ValueError, json.JSONDecodeError, UnicodeError):
        return {"Valid": False, "Segments": 3}


def _mime(raw: str) -> dict[str, Any]:
    text = raw.strip().lower()
    if text.startswith("."):
        guessed = mimetypes.types_map.get(text, "unknown")
        return {"Extension": text, "MIME": guessed}
    extensions = sorted(ext for ext, mime in mimetypes.types_map.items() if mime == text)
    return {"MIME": text, "Extensions": ", ".join(extensions[:20]) or "unknown"}


def _baseconvert(raw: str) -> str:
    parts = [part.strip() for part in raw.replace("|", " ").split()]
    if len(parts) != 3:
        raise UsageError("Use `from|to|number`, for example `16 2 ff`.")
    try:
        source, target, value = int(parts[0]), int(parts[1]), parts[2]
        number = int(value, source)
        digits = "0123456789abcdefghijklmnopqrstuvwxyz"
        if not 2 <= target <= 36:
            raise ValueError
    except ValueError:
        raise UsageError("Bases must be between 2 and 36.") from None
    if number == 0:
        return "0"
    output = ""
    while number:
        number, remainder = divmod(number, target)
        output = digits[remainder] + output
    return output


def _roman(raw: str) -> str:
    value = _decimal(raw)
    if not 1 <= value <= 3999:
        raise UsageError("Roman numerals here cover 1–3999.")
    table = (
        (1000, "M"), (900, "CM"), (500, "D"), (400, "CD"), (100, "C"), (90, "XC"),
        (50, "L"), (40, "XL"), (10, "X"), (9, "IX"), (5, "V"), (4, "IV"), (1, "I"),
    )
    output = ""
    for amount, token in table:
        while value >= amount:
            output += token
            value -= amount
    return output


def _unroman(raw: str) -> str:
    text = raw.strip().upper()
    values = {"I": 1, "V": 5, "X": 10, "L": 50, "C": 100, "D": 500, "M": 1000}
    if not text or any(char not in values for char in text):
        raise UsageError("Supply a Roman numeral using I, V, X, L, C, D or M.")
    total = 0
    for index, char in enumerate(text):
        value = values[char]
        if index + 1 < len(text) and values[text[index + 1]] > value:
            total -= value
        else:
            total += value
    return str(total)


def _gcd(raw: str) -> str:
    values = [_decimal(part) for part in raw.replace(",", " ").split()]
    if len(values) < 2:
        raise UsageError("Supply at least two numbers.")
    return str(math.gcd(*values))


def _lcm(raw: str) -> str:
    values = [_decimal(part) for part in raw.replace(",", " ").split()]
    if len(values) < 2:
        raise UsageError("Supply at least two numbers.")
    result = values[0]
    for item in values[1:]:
        result = abs(result * item) // math.gcd(result, item) if result and item else 0
    return str(result)


def _prime(raw: str) -> str:
    value = _decimal(raw)
    if value < 2 or value > 10_000_000:
        raise UsageError("Use a number from 2 to 10,000,000.")
    if value % 2 == 0:
        return "prime" if value == 2 else "composite"
    limit = math.isqrt(value)
    factor = 3
    while factor <= limit:
        if value % factor == 0:
            return f"composite ({factor} × {value // factor})"
        factor += 2
    return "prime"


def _factors(raw: str) -> str:
    value = _decimal(raw)
    if not 1 <= value <= 10_000_000:
        raise UsageError("Use a positive number up to 10,000,000.")
    found = []
    for factor in range(1, math.isqrt(value) + 1):
        if value % factor == 0:
            found.append(factor)
            if factor != value // factor:
                found.append(value // factor)
    return " ".join(str(item) for item in sorted(found))


def _fib(raw: str) -> str:
    count = _decimal(raw)
    if not 1 <= count <= 500:
        raise UsageError("Choose 1–500 terms.")
    values = [0, 1]
    for _ in range(count):
        values.append(values[-1] + values[-2])
    return " ".join(str(item) for item in values[:count])


def _hexrgb(raw: str) -> dict[str, Any]:
    value = raw.strip().lstrip("#")
    if not re.fullmatch(r"[0-9A-Fa-f]{6}", value):
        raise UsageError("Supply a six-digit hex colour.")
    colour = tuple(int(value[index : index + 2], 16) for index in (0, 2, 4))
    return {"Hex": f"#{value.upper()}", "RGB": colour, "HSL": colorsys.rgb_to_hls(*(item / 255 for item in colour))}


def _rgbhex(raw: str) -> dict[str, Any]:
    values = [_decimal(part) for part in raw.replace(",", " ").split()]
    if len(values) != 3 or any(item < 0 or item > 255 for item in values):
        raise UsageError("Supply three channel values from 0 to 255.")
    return {"RGB": tuple(values), "Hex": "#" + "".join(f"{item:02X}" for item in values)}


def _contrast(raw: str) -> dict[str, Any]:
    parts = [part.strip().lstrip("#") for part in raw.replace(",", " ").split()]
    if len(parts) != 2 or any(not re.fullmatch(r"[0-9A-Fa-f]{6}", part) for part in parts):
        raise UsageError("Supply two six-digit hex colours.")

    def luminance(value: str) -> float:
        channels = [int(value[index : index + 2], 16) / 255 for index in (0, 2, 4)]
        adjusted = [item / 12.92 if item <= 0.03928 else ((item + 0.055) / 1.055) ** 2.4 for item in channels]
        return 0.2126 * adjusted[0] + 0.7152 * adjusted[1] + 0.0722 * adjusted[2]

    first, second = luminance(parts[0]), luminance(parts[1])
    ratio = (max(first, second) + 0.05) / (min(first, second) + 0.05)
    return {
        "Foreground": f"#{parts[0].upper()}",
        "Background": f"#{parts[1].upper()}",
        "Contrast ratio": f"{ratio:.2f}:1",
        "AA normal": ratio >= 4.5,
        "AAA normal": ratio >= 7.0,
    }


def _textstats(raw: str) -> dict[str, Any]:
    words = re.findall(r"\b\w+\b", raw)
    lines = raw.splitlines()
    return {
        "Characters": len(raw),
        "Words": len(words),
        "Lines": len(lines),
        "Unique words": len(set(word.lower() for word in words)),
        "Longest word": max(words, key=len) if words else "—",
    }


def _bytecount(raw: str) -> dict[str, Any]:
    encoded = raw.encode()
    return {
        "UTF-8 bytes": len(encoded),
        "Bits": len(encoded) * 8,
        "Base64 length": len(base64.b64encode(encoded)),
        "Hex length": len(encoded) * 2,
    }


def _percent(raw: str) -> str:
    parts = [part.strip() for part in raw.replace("|", " ").split()]
    if len(parts) != 2:
        raise UsageError("Use `part|whole`.")
    try:
        part, whole = float(parts[0]), float(parts[1])
    except ValueError:
        raise UsageError("Both values must be numbers.") from None
    if whole == 0:
        raise UsageError("The whole cannot be zero.")
    return f"{(part / whole) * 100:.4f}%"


def _sortnums(raw: str) -> str:
    values = [float(part) for part in re.split(r"[\s,]+", raw.strip()) if part]
    if not values:
        raise UsageError("Supply numbers separated by spaces or commas.")
    return " ".join(f"{item:g}" for item in sorted(values))


def _aggregate(raw: str, kind: str) -> str:
    values = [float(part) for part in re.split(r"[\s,]+", raw.strip()) if part]
    if not values:
        raise UsageError("Supply numbers separated by spaces or commas.")
    result = {
        "sum": builtins.sum(values),
        "mean": statistics.fmean(values),
        "median": statistics.median(values),
        "mode": statistics.mode(values),
        "min": builtins.min(values),
        "max": builtins.max(values),
    }[kind]
    return f"{result:g}"


def _numrange(raw: str) -> str:
    values = [float(part) for part in re.split(r"[\s,]+", raw.strip()) if part]
    if not values:
        raise UsageError("Supply numbers separated by spaces or commas.")
    return f"{max(values) - min(values):g}"


def _randomcolor(raw: str) -> str:
    count = _decimal(raw) if raw.strip() else 1
    if not 1 <= count <= 12:
        raise UsageError("Choose 1–12 colours.")
    return "\n".join(f"#{secrets.token_hex(3).upper()}" for _ in range(count))


def _unix(raw: str) -> dict[str, Any]:
    if raw.strip():
        stamp = _decimal(raw)
    else:
        stamp = int(dt.datetime.now(dt.timezone.utc).timestamp())
    parsed = dt.datetime.fromtimestamp(stamp, dt.timezone.utc)
    return {"Unix": stamp, "UTC": parsed.strftime("%Y-%m-%d %H:%M:%S"), "ISO 8601": parsed.isoformat(), "Relative": f"<t:{stamp}:R>"}


def _unixdate(raw: str) -> str:
    parsed = parse_dt(raw.strip())
    if parsed is None:
        raise UsageError("Supply a date such as `2025-01-31` or an ISO timestamp.")
    return str(int(parsed.timestamp()))


def _weekday(raw: str) -> dict[str, Any]:
    parsed = parse_dt(raw.strip())
    if parsed is None:
        raise UsageError("Supply a date such as `2025-01-31`.")
    return {"Date": parsed.date().isoformat(), "Weekday": parsed.strftime("%A"), "ISO week": parsed.isocalendar().week, "Day of year": parsed.timetuple().tm_yday}


def _duration(raw: str) -> str:
    seconds = _decimal(raw)
    sign = "-" if seconds < 0 else ""
    seconds = abs(seconds)
    days, seconds = divmod(seconds, 86400)
    hours, seconds = divmod(seconds, 3600)
    minutes, seconds = divmod(seconds, 60)
    return f"{sign}{days}d {hours:02d}h {minutes:02d}m {seconds:02d}s"


def _difftext(raw: str) -> str:
    return _diff(raw)


_TOOLS: list[tuple[str, str, str, Handler, tuple[str, ...]]] = [
    ("b64e", "Base64-encode a UTF-8 string.", "b64e <text>", _b64e, ("b64encode",)),
    ("b64d", "Decode a base64 string.", "b64d <text>", _b64d, ("b64decode",)),
    ("b32e", "Base32-encode a UTF-8 string.", "b32e <text>", _b32e, ()),
    ("b32d", "Decode a base32 string.", "b32d <text>", _b32d, ()),
    ("hexe", "Encode text as hexadecimal bytes.", "hexe <text>", _hexe, ()),
    ("hexd", "Decode hexadecimal bytes to text.", "hexd <hex>", _hexd, ()),
    ("urle", "Percent-encode text for a URL component.", "urle <text>", _urle, ("urlencode",)),
    ("urld", "Decode percent-encoded text.", "urld <text>", _urld, ("urldecode",)),
    ("rot13", "Apply the ROT13 substitution.", "rot13 <text>", _rot13, ()),
    ("tobin", "Render UTF-8 bytes as binary.", "tobin <text>", _binary, ("binary",)),
    ("frombin", "Decode binary bytes to UTF-8.", "frombin <bits>", _unbinary, ("unbinary",)),
    ("morse", "Encode text as International Morse.", "morse <text>", _morse, ()),
    ("unmorse", "Decode International Morse.", "unmorse <morse>", _unmorse, ()),
    ("puny", "Convert a domain to its IDNA form.", "puny <domain>", _puny, ("punycode",)),
    ("unpuny", "Decode an IDNA domain.", "unpuny <domain>", _unpuny, ()),
    ("codepoints", "Show the Unicode code point of each character.", "codepoints <text>", _unicode, ("unicode",)),
    ("fromcodepoints", "Build text from Unicode code points.", "fromcodepoints <points>", _ununicode, ("ununicode",)),
    ("htmlenc", "Escape text for HTML.", "htmlenc <text>", _htmlenc, ()),
    ("htmlunesc", "Unescape HTML entities.", "htmlunesc <text>", _htmlunesc, ()),
    ("md5", "MD5 digest of a string.", "md5 <text>", lambda raw: _hash(raw, "md5"), ()),
    ("sha1", "SHA-1 digest of a string.", "sha1 <text>", lambda raw: _hash(raw, "sha1"), ()),
    ("sha256", "SHA-256 digest of a string.", "sha256 <text>", lambda raw: _hash(raw, "sha256"), ()),
    ("sha512", "SHA-512 digest of a string.", "sha512 <text>", lambda raw: _hash(raw, "sha512"), ()),
    ("blake2b", "BLAKE2b digest of a string.", "blake2b <text>", lambda raw: _hash(raw, "blake2b"), ()),
    ("sha3", "SHA3-256 digest of a string.", "sha3 <text>", lambda raw: _hash(raw, "sha3_256"), ()),
    ("crc32", "CRC-32 checksum of a string.", "crc32 <text>", _crc32, ()),
    ("hmacsha256", "HMAC-SHA256 of `key|message`.", "hmacsha256 <key|message>", _hmac, ("hmac",)),
    ("hashident", "Identify a hash by length and prefix.", "hashident <hash>", _hashid, ()),
    ("entropy", "Measure Shannon entropy of text.", "entropy <text>", _entropy, ()),
    ("passwordbits", "Estimate password strength without storing it.", "passwordbits <password>", _passstrength, ()),
    ("slug", "Convert text to a URL-safe slug.", "slug <text>", _slug, ("slugify",)),
    ("uppercase", "Convert text to uppercase.", "uppercase <text>", str.upper, ("upper",)),
    ("lowercase", "Convert text to lowercase.", "lowercase <text>", str.lower, ("lower",)),
    ("titlecase", "Convert text to title case.", "titlecase <text>", str.title, ()),
    ("swapcase", "Swap the case of every character.", "swapcase <text>", str.swapcase, ()),
    ("reverse", "Reverse a string.", "reverse <text>", lambda raw: raw[::-1], ("reversetext",)),
    ("wordcount", "Count words in text.", "wordcount <text>", lambda raw: str(len(re.findall(r"\\b\\w+\\b", raw))), ()),
    ("charcount", "Count characters and lines.", "charcount <text>", lambda raw: f"characters {len(raw)} · lines {len(raw.splitlines())}", ()),
    ("dedupe", "Remove duplicate lines while preserving order.", "dedupe <text>", lambda raw: "\n".join(dict.fromkeys(raw.splitlines())), ()),
    ("sortlines", "Sort lines alphabetically.", "sortlines <text>", lambda raw: "\n".join(sorted(raw.splitlines())), ()),
    ("striphtml", "Remove HTML tags and decode entities.", "striphtml <html>", lambda raw: re.sub(r"<[^>]+>", "", html.unescape(raw)), ()),
    ("linenums", "Add line numbers to text.", "linenums <text>", lambda raw: "\n".join(f"{index:03d}  {line}" for index, line in enumerate(raw.splitlines(), 1)), ()),
    ("linewrap", "Wrap text at a chosen width: `width|text`.", "linewrap <width|text>", lambda raw: textwrap.fill(_pair(raw)[1], width=max(20, min(120, _decimal(_pair(raw)[0])))), ("wrap",)),
    ("difftext", "Unified diff between `left|right`.", "difftext <left|right>", _diff, ("diff",)),
    ("jsonfmt", "Pretty-print JSON.", "jsonfmt <json>", _jsonfmt, ()),
    ("jsonmin", "Minify JSON.", "jsonmin <json>", lambda raw: _jsonfmt(raw, compact=True), ()),
    ("jsonkeys", "List every key path in JSON.", "jsonkeys <json>", _jsonkeys, ()),
    ("jsonvals", "Show top-level JSON values.", "jsonvals <json>", _jsonvals, ()),
    ("jsoncheck", "Validate JSON and report its type.", "jsoncheck <json>", _jsoncheck, ()),
    ("urlinspect", "Break a URL into scheme, host, path and query.", "urlinspect <url>", _urlinspect, ("urlparse",)),
    ("queryparse", "Parse a query string.", "queryparse <query>", _queryparse, ()),
    ("querybuild", "Encode key/value pairs as a query string.", "querybuild <pairs>", _querybuild, ()),
    ("jwtinspect", "Decode JWT header and payload without verifying.", "jwtinspect <token>", _jwtinspect, ()),
    ("jwtpayload", "Show only a JWT payload.", "jwtpayload <token>", _jwtpayload, ()),
    ("jwtcheck", "Check JWT shape and algorithm.", "jwtcheck <token>", _jwtcheck, ()),
    ("csvjson", "Convert CSV with a header row to JSON.", "csvjson <csv>", _csvjson, ()),
    ("ip2int", "Convert IPv4 to its 32-bit integer.", "ip2int <ipv4>", _ip2int, ()),
    ("int2ip", "Convert a 32-bit integer to IPv4.", "int2ip <integer>", _int2ip, ()),
    ("ipv6expand", "Expand an IPv6 address.", "ipv6expand <ipv6>", _ipv6expand, ()),
    ("ipv6compress", "Compress an IPv6 address.", "ipv6compress <ipv6>", _ipv6compress, ()),
    ("ipclass", "Classify an address and its flags.", "ipclass <ip>", _ipclass, ()),
    ("ptrsuffix", "Build the reverse-DNS name for an address.", "ptrsuffix <ip>", _ptrsuffix, ()),
    ("macfmt", "Normalise a MAC address into three formats.", "macfmt <mac>", _macfmt, ()),
    ("cidrsplit", "Split a CIDR block: `cidr|prefix`.", "cidrsplit <cidr|prefix>", _cidrsplit, ()),
    ("cidrmerge", "Collapse overlapping CIDR blocks.", "cidrmerge <cidrs>", _cidrmerge, ()),
    ("ipv4range", "Describe an inclusive IPv4 range.", "ipv4range <first|last>", _ipv4range, ()),
    ("ipv6range", "Describe an inclusive IPv6 range.", "ipv6range <first|last>", _ipv6range, ()),
    ("cidrcontains", "Test whether an address is inside a block.", "cidrcontains <cidr|address>", _cidrcontains, ()),
    ("wildcardmask", "Show the Cisco wildcard mask for IPv4.", "wildcardmask <cidr>", _wildcardmask, ()),
    ("portmap", "Map a port number to a common service, or search by name.", "portmap <port|service>", _portmap, ("portservice",)),
    ("protocol", "Map an IP protocol number to its name.", "protocol <number|name>", _protocol, ()),
    ("statuscode", "Explain an HTTP status code.", "statuscode <code>", _statuscode, ("httpcode",)),
    ("httpmethod", "Describe an HTTP method.", "httpmethod <method>", _httpmethod, ()),
    ("csp", "List Content-Security-Policy directives.", "csp <policy>", _csp, ()),
    ("hsts", "Parse Strict-Transport-Security directives.", "hsts <header>", _hsts, ()),
    ("cookieparse", "Break a Set-Cookie value into pairs.", "cookieparse <cookie>", _cookieparse, ()),
    ("useragentparse", "Inspect a User-Agent string.", "useragentparse <user-agent>", _ua, ()),
    ("mime", "Look up a MIME type or extension.", "mime <mime|extension>", _mime, ()),
    ("uuidcheck", "Validate a UUID and report its variant.", "uuidcheck <uuid>", _uuidcheck, ()),
    ("isbncheck", "Validate an ISBN-10 or ISBN-13.", "isbncheck <isbn>", _isbncheck, ()),
    ("luhn", "Validate a number with the Luhn checksum.", "luhn <number>", _luhn, ()),
    ("base64check", "Check whether a string is valid base64.", "base64check <text>", _base64check, ()),
    ("domaincheck", "Validate a domain and show its registrable form.", "domaincheck <domain>", _domaincheck, ()),
    ("emailcheck", "Validate an email address structurally.", "emailcheck <email>", _emailcheck, ()),
    ("ipcheck", "Validate an IP address and show its flags.", "ipcheck <ip>", _ipcheck, ()),
    ("baseconvert", "Convert a number between bases: `from|to|number`.", "baseconvert <from|to|number>", _baseconvert, ()),
    ("roman", "Convert an integer to a Roman numeral.", "roman <1-3999>", _roman, ()),
    ("unroman", "Convert a Roman numeral to an integer.", "unroman <numeral>", _unroman, ()),
    ("gcd", "Greatest common divisor of two or more numbers.", "gcd <a> <b>", _gcd, ()),
    ("lcm", "Least common multiple of two or more numbers.", "lcm <a> <b>", _lcm, ()),
    ("prime", "Test whether a number is prime.", "prime <number>", _prime, ()),
    ("factors", "List every factor of a number.", "factors <number>", _factors, ()),
    ("fib", "Print Fibonacci terms.", "fib <count>", _fib, ("fibonacci",)),
    ("hexrgb", "Convert a hex colour to RGB and HSL.", "hexrgb <#hex>", _hexrgb, ()),
    ("rgbhex", "Convert RGB channels to hex.", "rgbhex <r> <g> <b>", _rgbhex, ()),
    ("contrast", "Calculate WCAG contrast between two colours.", "contrast <#hex> <#hex>", _contrast, ()),
    ("textstats", "Count characters, words, lines and unique words.", "textstats <text>", _textstats, ()),
    ("bytecount", "Show UTF-8, base64 and hex sizes.", "bytecount <text>", _bytecount, ("bytes",)),
    ("percent", "Calculate `part|whole` as a percentage.", "percent <part|whole>", _percent, ()),
    ("sortnums", "Sort numbers in ascending order.", "sortnums <numbers>", _sortnums, ()),
    ("sum", "Sum a list of numbers.", "sum <numbers>", lambda raw: _aggregate(raw, "sum"), ("addnums",)),
    ("mean", "Arithmetic mean of a list of numbers.", "mean <numbers>", lambda raw: _aggregate(raw, "mean"), ("average",)),
    ("median", "Median of a list of numbers.", "median <numbers>", lambda raw: _aggregate(raw, "median"), ()),
    ("mode", "Most common number in a list.", "mode <numbers>", lambda raw: _aggregate(raw, "mode"), ()),
    ("numrange", "Difference between the largest and smallest number.", "numrange <numbers>", _numrange, ("span",)),
    ("randomcolor", "Generate one or more random hex colours.", "randomcolor [count]", _randomcolor, ("randcolor",)),
    ("unix", "Convert a Unix timestamp, or show the current time.", "unix [timestamp]", _unix, ("timestamp",)),
    ("unixdate", "Convert a date to a Unix timestamp.", "unixdate <date>", _unixdate, ()),
    ("weekday", "Show the weekday and ISO week for a date.", "weekday <date>", _weekday, ()),
    ("duration", "Format a number of seconds as days and clock time.", "duration <seconds>", _duration, ()),
]


class Toolkit(commands.Cog, name="Toolkit"):
    """Local encoders, hashes, address arithmetic and text utilities."""

    def __init__(self, bot: Any) -> None:
        self.bot = bot

    async def _render(
        self,
        ctx: commands.Context,
        name: str,
        raw: str,
        handler: Handler,
    ) -> None:
        await ack(ctx)
        value = raw.strip()
        try:
            result = handler(value)
        except UsageError:
            raise
        except (ValueError, TypeError, IndexError, KeyError, binascii.Error) as exc:
            raise UsageError(str(exc) or "That input could not be processed.") from None
        embed = Intel(
            category="toolkit",
            command=name,
            ctx=ctx,
            target=clip(value, 100) if value else None,
        )
        if value:
            embed.field("INPUT", _plain(value, 700), inline=False)
        if isinstance(result, dict):
            for label, item in result.items():
                if item is None or item == "":
                    continue
                if isinstance(item, (dict, list, tuple)):
                    item = json.dumps(item, ensure_ascii=False, default=str)
                embed.field(str(label).upper(), _plain(item, 1000), inline=False)
        else:
            embed.field("OUTPUT", _plain(result, 1200), inline=False)
        embed.source("local computation")
        await embed.send(ctx)


def _callback_for(name: str, handler: Handler) -> Callable[..., Any]:
    async def callback(self: Toolkit, ctx: commands.Context, target: str = None) -> None:
        await self._render(ctx, name, target or "", handler)

    callback.__name__ = name
    return callback


def _install_tools() -> None:
    for name, brief, usage, handler, aliases in _TOOLS:
        callback = _callback_for(name, handler)
        callback.__doc__ = brief
        command = intel(
            category="toolkit",
            brief=brief,
            usage=usage,
            aliases=(),
            examples=[usage.replace("<", "value ").replace(">", "").strip()],
            sources=["local computation"],
            cooldown=(2, 6),
            name=name,
        )(callback)
        setattr(Toolkit, name, command)
        Toolkit.__cog_commands__.append(command)


_install_tools()


async def setup(bot: Any) -> None:
    await bot.add_cog(Toolkit(bot))

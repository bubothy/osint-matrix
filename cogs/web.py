"""Web surface intelligence: URLs, fingerprints, policy and phishing heuristics."""

from __future__ import annotations

import base64
import hashlib
import html as html_module
import re
from typing import Any
from urllib.parse import parse_qsl, quote, urlsplit

from discord.ext import commands

from core.command import intel
from core.embeds import Intel
from core.errors import IntelError, NotFound, SourceUnavailable, UsageError
from core.signatures import (
    DORKS,
    PHISH_KEYWORDS,
    RISKY_TLDS,
    SECURITY_HEADERS,
    TECH_SIGNATURES,
    WAF_SIGNATURES,
)
from core.utils import (
    ack,
    clip,
    ensure_url,
    human_bytes,
    normalize_host,
    num,
    require,
    strip_target,
)


def murmur3_32(data: bytes, seed: int = 0) -> int:
    """MurmurHash3 x86 32-bit — the hash Shodan uses for favicon pivoting."""
    c1, c2 = 0xCC9E2D51, 0x1B873593
    length = len(data)
    h1 = seed
    rounded = length & 0xFFFFFFFC
    for index in range(0, rounded, 4):
        k1 = (
            (data[index] & 0xFF)
            | ((data[index + 1] & 0xFF) << 8)
            | ((data[index + 2] & 0xFF) << 16)
            | (data[index + 3] << 24)
        )
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
        h1 = (h1 * 5 + 0xE6546B64) & 0xFFFFFFFF
    tail = length & 3
    k1 = 0
    if tail == 3:
        k1 ^= (data[rounded + 2] & 0xFF) << 16
    if tail >= 2:
        k1 ^= (data[rounded + 1] & 0xFF) << 8
    if tail >= 1:
        k1 ^= data[rounded] & 0xFF
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
    return h1


TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
META_RE = re.compile(r"<meta\s+([^>]+?)/?>", re.IGNORECASE | re.DOTALL)
ATTR_RE = re.compile(r'([a-zA-Z:_-]+)\s*=\s*["\']([^"\']*)["\']')
TAG_RE = re.compile(r"<[^>]+>")
GENERATOR_RE = re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', re.IGNORECASE)


class Web(commands.Cog, name="Web"):
    """HTTP surface, policy and content intelligence."""

    def __init__(self, bot: Any) -> None:
        self.bot = bot
        self.http = bot.http

    # ── helpers ──────────────────────────────────────────────────────────

    @staticmethod
    def _url(target: str | None, example: str) -> str:
        raw = require(target, "URL or host", example=example)
        url = ensure_url(strip_target(raw))
        parsed = urlsplit(url)
        if not parsed.hostname:
            raise UsageError("That URL has no hostname.")
        return url

    async def _page(self, url: str) -> Any:
        response = await self.http.get(url, cache_ttl=120, timeout=20, max_redirects=10)
        if not response.ok:
            raise SourceUnavailable(
                f"`{urlsplit(url).netloc}` answered HTTP {response.status}.",
                hint="The host may block non-browser clients. Try the bare host without a path.",
            )
        return response

    @staticmethod
    def _meta(html: str) -> dict[str, str]:
        out: dict[str, str] = {}
        for match in META_RE.finditer(html):
            attrs = dict(ATTR_RE.findall(match.group(1)))
            key = (attrs.get("name") or attrs.get("property") or "").strip().lower()
            if key:
                out[key] = attrs.get("content", "").strip()
        return out

    @staticmethod
    def _title(html: str) -> str:
        match = TITLE_RE.search(html)
        if not match:
            return ""
        return html_module.unescape(TAG_RE.sub("", match.group(1))).strip()

    async def _chain(self, url: str, *, limit: int = 10) -> list[tuple[int, str, str]]:
        hops: list[tuple[int, str, str]] = []
        current = url
        for _ in range(limit):
            response = await self.http.request(
                "GET", current, cache=False, allow_redirects=False, timeout=15
            )
            location = response.headers.get("location", "")
            hops.append((response.status, response.url, location))
            if response.status in {301, 302, 303, 307, 308} and location:
                from urllib.parse import urljoin

                current = urljoin(response.url, location)
                continue
            break
        return hops

    # ── URL intelligence ─────────────────────────────────────────────────

    @intel(
        category="web",
        brief="Full URL dossier: components, redirect chain, status, headers and a risk score.",
        usage="<url>",
        aliases=["urlinfo", "analyze"],
        examples=["url https://example.com/login?next=%2Fadmin"],
        sources=["direct HTTP"],
        cooldown=(3, 10),
    )
    async def url(self, ctx: commands.Context, target: str = None) -> None:
        await ack(ctx)
        url = self._url(target, ".url https://example.com/login")
        parsed = urlsplit(url)
        host = parsed.hostname or ""
        redirects = 0
        try:
            response = await self.http.get(url, cache=False, allow_redirects=True, timeout=20)
            status, final, headers = response.status, response.url, response.headers
            elapsed, payload = response.elapsed_ms, response.bytes_read
            redirects = len(response.history)
        except IntelError:
            status, final, headers, elapsed, payload = None, url, {}, 0, 0
        embed = Intel(
            category="web",
            command="url",
            ctx=ctx,
            target=clip(url, 120),
            summary="Structural decomposition plus live behaviour. The risk index is heuristic, not a verdict.",
        )
        embed.kv(
            "COMPONENTS",
            {
                "Scheme": parsed.scheme,
                "Host": host,
                "Port": parsed.port or ("443" if parsed.scheme == "https" else "80"),
                "Path": parsed.path or "/",
                "Query keys": [key for key, _ in parse_qsl(parsed.query)][:10] or "none",
                "Fragment": parsed.fragment or "none",
                "Userinfo": parsed.username or "none",
            },
            inline=True,
        )
        embed.kv(
            "LIVE",
            {
                "Status": status,
                "Final URL": clip(final, 90),
                "Redirects": redirects,
                "Elapsed": f"{elapsed:.0f} ms",
                "Payload": human_bytes(payload),
                "Server": headers.get("server"),
            },
            inline=True,
        )
        flags = self._url_flags(url)
        score = min(95, sum(weight for _, weight in flags))
        embed.checks("HEURISTICS", [(bool(weight), label, detail) for label, weight, detail in flags] or [(None, "No flags", "clean structure")])
        embed.risk(score, name="RISK INDEX")
        embed.steps(
            [
                "Parsed the URL according to RFC 3986",
                "Issued a live request and recorded the redirect chain",
                "Scored structural phishing indicators",
            ]
        )
        embed.source("direct HTTP")
        await embed.send(ctx)

    @staticmethod
    def _url_flags(url: str) -> list[tuple[str, float, str]]:
        parsed = urlsplit(url)
        host = (parsed.hostname or "").lower()
        flags: list[tuple[str, float, str]] = []
        if parsed.scheme == "http":
            flags.append(("Plain HTTP", 20, "traffic is unencrypted"))
        if parsed.username or parsed.password:
            flags.append(("Embedded credentials", 25, "`user:pass@host` is a classic obfuscation trick"))
        if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host):
            flags.append(("IP literal host", 25, "no domain name to attribute"))
        if host.startswith("xn--") or ".xn--" in host:
            flags.append(("Punycode host", 20, "possible homograph"))
        if len(host.split(".")) > 4:
            flags.append(("Deep subdomain chain", 15, f"{len(host.split('.'))} labels"))
        if host.split(".")[-1] in RISKY_TLDS:
            flags.append(("High-abuse TLD", 20, host.split(".")[-1]))
        if len(url) > 120:
            flags.append(("Very long URL", 10, f"{len(url)} characters"))
        if parsed.port and parsed.port not in {80, 443}:
            flags.append(("Non-standard port", 10, str(parsed.port)))
        lowered = url.lower()
        hits = [word for word in PHISH_KEYWORDS if word in lowered]
        if hits:
            flags.append(("Credential keywords", min(20, 5 * len(hits)), ", ".join(hits[:5])))
        if re.search(r"(?:redirect|url|next|return|continue|target)=https?%3A|(?:redirect|url|next|return)=https?:", lowered):
            flags.append(("Open redirect parameter", 15, "destination is supplied in the query string"))
        if "@" in parsed.path:
            flags.append(("At-sign in path", 10, "commonly used to confuse link previews"))
        return flags

    @intel(
        category="web",
        brief="Follow a short link or redirect chain hop by hop with status codes.",
        usage="<url>",
        aliases=["unshorten", "redirects"],
        examples=["expand https://bit.ly/example"],
        sources=["direct HTTP"],
        cooldown=(3, 10),
    )
    async def expand(self, ctx: commands.Context, target: str = None) -> None:
        await ack(ctx)
        url = self._url(target, ".expand https://bit.ly/example")
        hops = await self._chain(url)
        final = hops[-1][1] if hops else url
        embed = Intel(
            category="web",
            command="expand",
            ctx=ctx,
            target=clip(url, 110),
            summary="Every hop was requested manually with redirects disabled, so each status code is real.",
        )
        embed.steps(
            [f"`{status}` → {clip(location or destination, 110)}" for status, destination, location in hops],
            name="REDIRECT LADDER",
        )
        embed.kv(
            "OUTCOME",
            {
                "Hops": len(hops),
                "Final URL": clip(final, 200),
                "Destination host": urlsplit(final).hostname,
                "Cross-origin": urlsplit(final).hostname != urlsplit(url).hostname,
            },
            inline=True,
        )
        embed.checks(
            "SAFETY",
            [
                (urlsplit(final).scheme == "https", "HTTPS destination", urlsplit(final).scheme),
                (len(hops) <= 4, "Chain length", f"{len(hops)} requests"),
                (None, "Caution", "never authenticate after following an unsolicited short link"),
            ],
        )
        embed.source("direct HTTP")
        await embed.send(ctx)

    @intel(
        category="web",
        brief="Technology fingerprint from headers, cookies and markup with evidence.",
        usage="<url|host>",
        aliases=["whatweb", "stack"],
        examples=["tech example.com"],
        sources=["direct HTTP", "local signature tables"],
        cooldown=(3, 12),
    )
    async def tech(self, ctx: commands.Context, target: str = None) -> None:
        await ack(ctx)
        url = self._url(target, ".tech example.com")
        response = await self._page(url)
        html = response.text
        lowered = html.lower()
        cookie_header = " ".join(response.set_cookies).lower()
        matched: list[tuple[str, str, str]] = []
        for signature in TECH_SIGNATURES:
            evidence = ""
            for header, pattern in (signature.get("headers") or {}).items():
                value = response.headers.get(header.lower(), "")
                if value and (not pattern or re.search(pattern, value)):
                    evidence = f"header `{header}: {clip(value, 40)}`"
                    break
            if not evidence:
                for cookie in signature.get("cookies") or []:
                    if cookie.lower() in cookie_header:
                        evidence = f"cookie `{cookie}`"
                        break
            if not evidence:
                for pattern in signature.get("html") or []:
                    if re.search(pattern, html):
                        evidence = f"markup `{clip(pattern, 40)}`"
                        break
            if evidence:
                matched.append((signature["name"], signature.get("category", "other"), evidence))
        embed = Intel(
            category="web",
            command="tech",
            ctx=ctx,
            target=clip(response.url, 110),
            summary="Fingerprints are evidence-based inferences, not ground truth. Each match carries the artifact that triggered it.",
        )
        if not matched:
            embed.field("▸ RESULT", "No signature matched. The stack is custom, cloaked, or the page is a JS shell.", inline=False)
        else:
            grouped: dict[str, list[str]] = {}
            for name, category, evidence in matched:
                grouped.setdefault(category, []).append(f"**{name}** — {clip(evidence, 70)}")
            for category, lines in list(grouped.items())[:8]:
                embed.text(category.upper(), "\n".join(lines[:8]), inline=False)
        embed.kv(
            "PAGE",
            {
                "Title": clip(self._title(html), 90) or "none",
                "Bytes": human_bytes(len(html)),
                "Generator": (self._meta(html).get("generator") or "")[:80] or "not declared",
                "Server": response.headers.get("server"),
                "Powered by": response.headers.get("x-powered-by"),
            },
            inline=True,
        )
        embed.kv(
            "COUNTS",
            {"Technologies": len(matched), "Categories": len({category for _, category, _ in matched}), "Cookies": len(response.set_cookies)},
            inline=True,
        )
        embed.steps(
            [
                "Fetched the document and captured every response header",
                "Tested header, cookie and markup signatures in priority order",
                "Recorded the first matching artifact per technology",
            ]
        )
        embed.source("direct HTTP", "signature table")
        await embed.send(ctx)

    @intel(
        category="web",
        brief="Grade HTTP security headers A–F with per-header reasoning.",
        usage="<url|host>",
        aliases=["headersecurity", "grade"],
        examples=["secheaders example.com"],
        sources=["direct HTTP"],
        cooldown=(3, 12),
    )
    async def secheaders(self, ctx: commands.Context, target: str = None) -> None:
        await ack(ctx)
        url = self._url(target, ".secheaders example.com")
        response = await self.http.get(url, cache_ttl=60, timeout=20)
        headers = response.headers
        earned = 0.0
        total = sum(rule["weight"] for rule in SECURITY_HEADERS)
        results: list[tuple[bool | None, str, str]] = []
        missing: list[str] = []
        for rule in SECURITY_HEADERS:
            name = rule["header"]
            value = headers.get(name)
            state, detail = self._assess(rule, value)
            if state is True:
                earned += rule["weight"]
            elif value is None:
                missing.append(name)
            results.append((state, rule["label"], f"{clip(value, 70) if value else 'absent'} — {rule['expect']}"))
        score = earned / total * 100 if total else 0
        grade = "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 55 else "D" if score >= 35 else "F"
        embed = Intel(
            category="web",
            command="secheaders",
            ctx=ctx,
            target=clip(url, 110),
            summary="Weighted review of browser security controls. Absence is not automatically exploitable, but it removes defence in depth.",
        )
        embed.kv(
            "GRADE",
            {"Score": f"{score:.0f}/100", "Letter": grade, "Present": sum(1 for state, _, _ in results if state), "Rules": len(SECURITY_HEADERS)},
            inline=True,
        )
        embed.kv(
            "PRIORITY FIXES",
            {"Missing": missing[:8] or "none", "Guidance": [f"{rule['label']}: {rule['why']}" for rule in SECURITY_HEADERS if rule['header'] in missing][:4]},
            inline=False,
        )
        embed.checks("HEADER REVIEW", results)
        embed.risk(100 - score, name="EXPOSURE INDEX", verdict=grade)
        embed.source("direct HTTP")
        await embed.send(ctx)

    @staticmethod
    def _assess(rule: dict[str, Any], value: str | None) -> tuple[bool | None, str]:
        header = rule["header"]
        if value is None:
            if header == "x-powered-by":
                return True, "absent (good)"
            if header == "x-xss-protection":
                return True, "absent (modern guidance)"
            return False, "absent"
        lowered = value.lower()
        if header == "strict-transport-security":
            match = re.search(r"max-age=(\d+)", lowered)
            age = int(match.group(1)) if match else 0
            return age >= 15_552_000, f"max-age {age}s"
        if header == "content-security-policy":
            weak = "unsafe-inline" in lowered or "unsafe-eval" in lowered or re.search(r"\*(\s|;|$)", lowered)
            return not weak, "contains unsafe directives" if weak else "present"
        if header == "x-content-type-options":
            return lowered.strip() == "nosniff", value
        if header == "x-frame-options":
            return lowered.strip() in {"deny", "sameorigin"}, value
        if header == "referrer-policy":
            return lowered.strip() not in {"unsafe-url", "no-referrer-when-downgrade"}, value
        if header == "cross-origin-opener-policy":
            return lowered.startswith("same-origin"), value
        if header == "cross-origin-resource-policy":
            return lowered.startswith(("same-origin", "same-site")), value
        if header == "cross-origin-embedder-policy":
            return lowered.startswith("require-corp"), value
        if header == "x-xss-protection":
            return lowered.strip() in {"0", "1; mode=block"}, value
        if header == "server":
            return not re.search(r"\d+\.\d+", value), value
        return True, "present"

    @intel(
        category="web",
        brief="Fetch and interpret robots.txt: crawl rules, sitemaps and sensitive paths.",
        usage="<host>",
        name="robots",
        examples=["robots example.com"],
        sources=["direct HTTP"],
        cooldown=(3, 12),
    )
    async def robots_cmd(self, ctx: commands.Context, target: str = None) -> None:
        await ack(ctx)
        host = normalize_host(require(target, "host", example=".robots example.com"))
        response = await self.http.get(f"https://{host}/robots.txt", cache_ttl=300, timeout=15)
        if not response.ok:
            raise NotFound(f"`{host}` does not publish robots.txt (HTTP {response.status}).")
        text = response.text
        disallow: list[str] = []
        allow: list[str] = []
        sitemaps: list[str] = []
        agents: list[str] = []
        crawl_delay = ""
        for line in text.splitlines():
            cleaned = line.split("#", 1)[0].strip()
            if ":" not in cleaned:
                continue
            key, _, value = cleaned.partition(":")
            key, value = key.strip().lower(), value.strip()
            if key == "user-agent":
                agents.append(value)
            elif key == "disallow" and value:
                disallow.append(value)
            elif key == "allow" and value:
                allow.append(value)
            elif key == "sitemap":
                sitemaps.append(value)
            elif key == "crawl-delay":
                crawl_delay = value
        sensitive = [
            path
            for path in disallow
            if re.search(r"(?i)admin|backup|config|api|internal|private|db|sql|secret|dev|test|staging|phpinfo|\.git|cpanel", path)
        ]
        embed = Intel(
            category="web",
            command="robots",
            ctx=ctx,
            target=host,
            summary="robots.txt is a crawler convention, not an access control. Disallowed paths are a map of what the owner would rather you did not index.",
        )
        embed.kv(
            "CRAWL POLICY",
            {
                "Bytes": human_bytes(len(text)),
                "User-agent blocks": len(agents),
                "Disallow rules": len(disallow),
                "Allow rules": len(allow),
                "Crawl delay": crawl_delay or "not set",
            },
            inline=True,
        )
        embed.kv(
            "DISCOVERY",
            {
                "Sitemaps": sitemaps[:8] or "none declared",
                "Sensitive paths": sensitive[:12] or "none obvious",
                "Longest rule": max(disallow, key=len) if disallow else "none",
            },
            inline=False,
        )
        embed.code("RULES", "\n".join(disallow[:30]) or "no disallow rules", lang="yaml")
        embed.checks(
            "OBSERVATIONS",
            [
                (bool(sitemaps), "Sitemap declared", f"{len(sitemaps)} entry(ies)"),
                (bool(sensitive), "Sensitive paths hinted", f"{len(sensitive)} paths"),
                (None, "Note", "robots.txt is advisory: never treat it as a security boundary"),
            ],
        )
        embed.source("direct HTTP")
        await embed.send(ctx)

    @intel(
        category="web",
        brief="Parse sitemap.xml or a sitemap index for URL counts and samples.",
        usage="<host> [path]",
        name="sitemap",
        examples=["sitemap example.com"],
        sources=["direct HTTP"],
        cooldown=(3, 15),
    )
    async def sitemap_cmd(self, ctx: commands.Context, target: str = None, path: str = None) -> None:
        await ack(ctx)
        host = normalize_host(require(target, "host", example=".sitemap example.com"))
        location = path or "/sitemap.xml"
        if not location.startswith("/"):
            location = "/" + location
        response = await self.http.get(f"https://{host}{location}", cache_ttl=600, timeout=20)
        if not response.ok:
            raise NotFound(f"`{host}{location}` answered HTTP {response.status}.")
        locs = re.findall(r"<loc>\s*(.*?)\s*</loc>", response.text, re.IGNORECASE | re.DOTALL)
        index = "<sitemapindex" in response.text.lower()
        embed = Intel(
            category="web",
            command="sitemap",
            ctx=ctx,
            target=f"{host}{location}",
            summary="A sitemap index points at child sitemaps; a URL set lists content pages. Both leak site structure cheaply.",
        )
        embed.kv(
            "DOCUMENT",
            {
                "Type": "sitemap index" if index else "URL set",
                "Entries": len(locs),
                "Bytes": human_bytes(len(response.text)),
                "Unique hosts": len({urlsplit(url).hostname for url in locs if url.startswith("http")}),
            },
            inline=True,
        )
        embed.code("SAMPLE", "\n".join(clip(url, 100) for url in locs[:25]) or "no <loc> entries", lang="yaml")
        embed.steps(
            [
                "Fetched the sitemap document",
                "Detected index vs URL-set format",
                "Extracted every location entry and counted distinct hosts",
            ]
        )
        embed.source("direct HTTP")
        await embed.send(ctx)

    @intel(
        category="web",
        brief="Check RFC 9116 security.txt for contacts, policy and expiry.",
        usage="<host>",
        name="securitytxt",
        examples=["securitytxt example.com"],
        sources=["direct HTTP"],
        cooldown=(3, 12),
    )
    async def security_txt(self, ctx: commands.Context, target: str = None) -> None:
        await ack(ctx)
        host = normalize_host(require(target, "host", example=".securitytxt example.com"))
        found = None
        for path in ("/.well-known/security.txt", "/security.txt"):
            response = await self.http.get(f"https://{host}{path}", cache_ttl=600, timeout=15)
            if response.ok and "contact" in response.text.lower():
                found = (path, response)
                break
        if not found:
            raise NotFound(f"`{host}` does not publish a usable security.txt.")
        path, response = found
        fields: dict[str, list[str]] = {}
        for line in response.text.splitlines():
            cleaned = line.strip()
            if not cleaned or cleaned.startswith("#") or ":" not in cleaned:
                continue
            key, _, value = cleaned.partition(":")
            fields.setdefault(key.strip().lower(), []).append(value.strip())
        embed = Intel(
            category="web",
            command="securitytxt",
            ctx=ctx,
            target=f"{host}{path}",
            summary="security.txt is the machine-readable way to report a vulnerability to the right team.",
        )
        embed.kv(
            "DISCLOSURE",
            {
                "Contact": fields.get("contact", [])[:5] or "missing",
                "Expires": fields.get("expires", ["missing"])[0],
                "Canonical": fields.get("canonical", ["missing"])[0],
                "Policy": fields.get("policy", ["missing"])[0],
                "Encryption": fields.get("encryption", ["missing"])[0],
                "Languages": fields.get("preferred-languages", ["unspecified"])[0],
            },
            inline=False,
        )
        embed.checks(
            "COMPLETENESS",
            [
                (bool(fields.get("contact")), "Contact present", f"{len(fields.get('contact', []))} channel(s)"),
                (bool(fields.get("expires")), "Expiry declared", fields.get("expires", ["missing"])[0]),
                (bool(fields.get("policy")), "Policy linked", fields.get("policy", ["missing"])[0]),
                (bool(fields.get("encryption")), "Encryption key", fields.get("encryption", ["missing"])[0]),
            ],
        )
        embed.code("RAW", clip(response.text, 900), lang="yaml")
        embed.source("direct HTTP")
        await embed.send(ctx)

    @intel(
        category="web",
        brief="Audit Set-Cookie flags: Secure, HttpOnly, SameSite, prefixes and lifetimes.",
        usage="<url|host>",
        name="cookies",
        examples=["cookies example.com"],
        sources=["direct HTTP"],
        cooldown=(3, 12),
    )
    async def cookies_cmd(self, ctx: commands.Context, target: str = None) -> None:
        await ack(ctx)
        url = self._url(target, ".cookies example.com")
        response = await self.http.get(url, cache_ttl=60, timeout=20)
        if not response.set_cookies:
            raise NotFound("The response set no cookies (or the host rejects non-browser clients).")
        rows: list[tuple[bool | None, str, str]] = []
        for raw in response.set_cookies[:14]:
            parts = [part.strip() for part in raw.split(";")]
            name = parts[0].split("=")[0]
            flags = {part.split("=")[0].lower() for part in parts[1:]}
            lowered = raw.lower()
            issues = []
            if "secure" not in flags:
                issues.append("no Secure")
            if "httponly" not in flags:
                issues.append("no HttpOnly")
            if "samesite" not in lowered:
                issues.append("no SameSite")
            rows.append((not issues, name, ", ".join(issues) or "hardened"))
        embed = Intel(
            category="web",
            command="cookies",
            ctx=ctx,
            target=clip(response.url, 110),
            summary="Cookie flags decide whether a session survives XSS, CSRF and plaintext interception.",
        )
        embed.checks("COOKIE FLAGS", rows)
        embed.code("RAW", "\n".join(clip(cookie, 180) for cookie in response.set_cookies[:8]), lang="yaml")
        embed.kv(
            "SUMMARY",
            {"Cookies": len(response.set_cookies), "Hardened": sum(1 for state, _, _ in rows if state), "Weak": sum(1 for state, _, _ in rows if not state)},
            inline=True,
        )
        embed.source("direct HTTP")
        await embed.send(ctx)

    @intel(
        category="web",
        brief="Probe the CORS policy with an untrusted Origin and a null Origin.",
        usage="<url|host>",
        aliases=["corscheck"],
        examples=["cors https://api.example.com"],
        sources=["direct HTTP"],
        cooldown=(2, 20),
    )
    async def cors(self, ctx: commands.Context, target: str = None) -> None:
        await ack(ctx)
        url = self._url(target, ".cors https://api.example.com")
        probe_origin = "https://osint-matrix.invalid"
        evil = await self.http.request(
            "GET", url, headers={"Origin": probe_origin}, cache=False, timeout=15
        )
        null = await self.http.request(
            "GET", url, headers={"Origin": "null"}, cache=False, timeout=15
        )
        allow = evil.headers.get("access-control-allow-origin", "")
        credentials = evil.headers.get("access-control-allow-credentials", "")
        embed = Intel(
            category="web",
            command="cors",
            ctx=ctx,
            target=clip(url, 110),
            summary="Two read-only requests with attacker-controlled Origin headers reveal whether the API trusts arbitrary sites.",
        )
        embed.kv(
            "POLICY",
            {
                "ACAO (untrusted origin)": allow or "not returned",
                "ACAO (null origin)": null.headers.get("access-control-allow-origin", "not returned"),
                "Credentials": credentials or "not allowed",
                "Methods": evil.headers.get("access-control-allow-methods", "not declared"),
                "Headers": evil.headers.get("access-control-allow-headers", "not declared"),
                "Vary": evil.headers.get("vary", "not declared"),
            },
            inline=False,
        )
        wildcard = allow.strip() == "*"
        reflected = allow.strip().rstrip("/") == probe_origin
        dangerous = (wildcard or reflected) and credentials.lower() == "true"
        embed.checks(
            "VERDICT",
            [
                (not wildcard, "No wildcard ACAO", allow or "absent"),
                (not reflected, "Origin not reflected", allow or "absent"),
                (not dangerous, "No credentialed wildcard", "credentials with wildcard is critical" if dangerous else "safe pairing"),
                (null.headers.get("access-control-allow-origin", "") != "null", "Null origin rejected", null.headers.get("access-control-allow-origin", "absent")),
            ],
        )
        embed.risk(85 if dangerous else 55 if reflected else 30 if wildcard else 8, name="CORS RISK")
        embed.source("direct HTTP")
        await embed.send(ctx)

    @intel(
        category="web",
        brief="Allowed HTTP methods from an OPTIONS request.",
        usage="<url|host>",
        aliases=["options", "allow"],
        examples=["methods example.com"],
        sources=["direct HTTP"],
        cooldown=(3, 12),
    )
    async def methods(self, ctx: commands.Context, target: str = None) -> None:
        await ack(ctx)
        url = self._url(target, ".methods example.com")
        response = await self.http.options(url, cache_ttl=60, timeout=15)
        allowed = [method.strip().upper() for method in response.headers.get("allow", "").split(",") if method.strip()]
        if not allowed:
            allowed = [method.strip().upper() for method in response.headers.get("access-control-allow-methods", "").split(",") if method.strip()]
        risky = [method for method in allowed if method in {"PUT", "DELETE", "TRACE", "CONNECT", "PATCH"}]
        embed = Intel(
            category="web",
            command="methods",
            ctx=ctx,
            target=clip(response.url, 110),
            summary="Advertised methods only. A missing Allow header does not prove a method is rejected.",
        )
        embed.kv(
            "RESPONSE",
            {
                "Status": response.status,
                "Allow": allowed or "not advertised",
                "Risky verbs": risky or "none",
                "Server": response.headers.get("server"),
            },
            inline=True,
        )
        embed.checks(
            "POSTURE",
            [
                (bool(allowed), "Method list", f"{len(allowed)} verbs"),
                (not risky, "No risky verbs", ", ".join(risky) or "clean"),
                ("TRACE" not in allowed, "TRACE disabled", "present — cross-site tracing risk" if "TRACE" in allowed else "absent"),
            ],
        )
        embed.source("direct HTTP")
        await embed.send(ctx)

    @intel(
        category="web",
        brief="Favicon hashes for Shodan/Censys pivoting and origin clustering.",
        usage="<host>",
        aliases=["faviconhash"],
        examples=["favicon example.com"],
        sources=["direct HTTP"],
        cooldown=(3, 15),
    )
    async def favicon(self, ctx: commands.Context, target: str = None) -> None:
        await ack(ctx)
        host = normalize_host(require(target, "host", example=".favicon example.com"))
        response = await self.http.get(f"https://{host}/favicon.ico", cache_ttl=600, timeout=15)
        if not response.ok or not response.text:
            raise NotFound(f"`{host}` returned no usable favicon (HTTP {response.status}).")
        raw = response.body or response.text.encode("utf-8", "ignore")
        b64 = base64.encodebytes(raw)
        shodan_hash = murmur3_32(b64) & 0xFFFFFFFF
        if shodan_hash >= 2**31:
            shodan_hash -= 2**32
        embed = Intel(
            category="web",
            command="favicon",
            ctx=ctx,
            target=host,
            summary="The same favicon hash across unrelated hosts usually means one operator, one template or one shared origin.",
        )
        embed.kv(
            "ARTIFACT",
            {
                "Bytes": human_bytes(len(raw)),
                "Content type": response.headers.get("content-type"),
                "HTTP status": response.status,
                "MD5": hashlib.md5(raw).hexdigest(),
                "SHA-256": hashlib.sha256(raw).hexdigest(),
                "mmh3 (base64, Shodan)": shodan_hash,
                "mmh3 (raw)": murmur3_32(raw),
            },
            inline=False,
        )
        embed.code("PIVOT", f'shodan: http.favicon.hash:{shodan_hash}\ncensys: services.http.response.favicons.md5_hash="{hashlib.md5(raw).hexdigest()}"', lang="yaml")
        embed.steps(
            [
                "Downloaded the icon bytes",
                "Computed MD5 and SHA-256 for direct matching",
                "Computed MurmurHash3 over the base64 form used by Shodan",
                "Rendered copy-paste pivot queries",
            ]
        )
        embed.source("direct HTTP")
        await embed.send(ctx)

    @intel(
        category="web",
        brief="Passive WAF fingerprint with challenge-page indicators.",
        usage="<host>",
        aliases=["firewall"],
        examples=["waf example.com"],
        sources=["direct HTTP"],
        cooldown=(3, 15),
    )
    async def waf(self, ctx: commands.Context, target: str = None) -> None:
        await ack(ctx)
        host = normalize_host(require(target, "host", example=".waf example.com"))
        response = await self.http.get(f"https://{host}/", cache_ttl=60, timeout=20)
        headers = response.headers
        body = response.text.lower()
        hits: list[str] = []
        evidence: list[str] = []
        for signature in WAF_SIGNATURES:
            for header in signature.get("headers", []):
                if header in headers:
                    hits.append(signature["name"])
                    evidence.append(f"header `{header}` → {signature['name']}")
                    break
            cookie_header = " ".join(response.set_cookies).lower()
            for cookie in signature.get("cookies", []):
                if cookie.lower() in cookie_header:
                    hits.append(signature["name"])
                    evidence.append(f"cookie `{cookie}` → {signature['name']}")
                    break
        markers = {
            "Cloudflare challenge": "just a moment",
            "DataDome": "captcha-delivery",
            "PerimeterX": "_px",
            "Akamai reference": "reference&#32;#",
            "Incapsula block": "incapsula incident",
            "Sucuri block": "sucuri website firewall",
            "AWS WAF": "request blocked",
            "Generic challenge": "checking your browser",
        }
        for label, marker in markers.items():
            if marker in body:
                hits.append(label)
                evidence.append(f"body marker `{marker}`")
        embed = Intel(
            category="web",
            command="waf",
            ctx=ctx,
            target=host,
            summary="Passive only: one ordinary request, no attack payloads. Fingerprints come from the edge's own artefacts.",
        )
        embed.kv(
            "EDGE",
            {
                "Status": response.status,
                "Server": headers.get("server"),
                "Detected": sorted(set(hits)) or "no signature",
                "CDN headers": [name for name in ("cf-ray", "x-served-by", "x-akamai-request-id", "x-azure-ref", "x-amz-cf-id") if name in headers],
                "Cookies": len(response.set_cookies),
            },
            inline=True,
        )
        embed.steps(evidence[:8] or ["No WAF artefact found in this response"], name="EVIDENCE")
        embed.checks(
            "ASSESSMENT",
            [
                (bool(hits), "Filtering layer", ", ".join(sorted(set(hits))) or "none observed"),
                (None, "Caveat", "absence of a fingerprint does not mean absence of a WAF"),
            ],
        )
        embed.source("direct HTTP")
        await embed.send(ctx)

    @intel(
        category="web",
        brief="Heuristic phishing analysis of a URL without loading it.",
        usage="<url>",
        aliases=["phishing", "scam"],
        examples=["phish http://paypal-secure-login.example.tk/verify"],
        sources=["local heuristics"],
        cooldown=(3, 10),
    )
    async def phish(self, ctx: commands.Context, target: str = None) -> None:
        await ack(ctx)
        url = self._url(target, ".phish http://example.tk/login")
        parsed = urlsplit(url)
        host = (parsed.hostname or "").lower()
        labels = host.split(".")
        checks: list[tuple[bool | None, str, str]] = []
        score = 0.0

        def add(condition: bool, weight: float, label: str, detail: str) -> None:
            nonlocal score
            checks.append((condition, label, detail))
            if condition:
                score += weight

        add(parsed.scheme != "https", 15, "No TLS", parsed.scheme)
        add(bool(re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host)), 20, "IP literal", host)
        add(host.startswith("xn--") or ".xn--" in host, 18, "Punycode", host)
        add(len(labels) > 4, 12, "Subdomain depth", f"{len(labels)} labels")
        add(labels[-1] in RISKY_TLDS if labels else False, 18, "Risky TLD", labels[-1] if labels else "?")
        add(bool(parsed.username or parsed.password), 20, "Userinfo trick", "credentials before @")
        add(len(url) > 100, 8, "Long URL", f"{len(url)} chars")
        add(sum(char.isdigit() for char in host) >= 4, 8, "Digit stuffing", "many digits in host")
        add(host.count("-") >= 3, 10, "Hyphen stuffing", f"{host.count('-')} hyphens")
        keywords = [word for word in PHISH_KEYWORDS if word in f"{host}{parsed.path}".lower()]
        add(bool(keywords), min(24, 6 * len(keywords)), "Credential keywords", ", ".join(keywords[:6]))
        add(bool(parsed.port and parsed.port not in {80, 443}), 8, "Non-standard port", str(parsed.port))
        add("%" in parsed.path, 6, "Encoded path", "percent-encoding in path")
        add(any(param in parsed.query.lower() for param in ("redirect=", "url=", "next=", "return=")), 12, "Redirect parameter", parsed.query[:60])
        add(host.endswith((".zip", ".mov")), 10, "Archive TLD", "`.zip`/`.mov` confuse link detection")
        add(bool(re.search(r"[а-яА-Яα-ωΑ-Ω]", url)), 20, "Non-Latin characters", "possible homograph")
        label = "CRITICAL" if score >= 70 else "HIGH" if score >= 45 else "MEDIUM" if score >= 25 else "LOW"
        embed = Intel(
            category="web",
            command="phish",
            ctx=ctx,
            target=clip(url, 120),
            summary="Heuristics only — no page was loaded, so nothing here confirms malice. Treat it as a triage queue.",
        )
        embed.checks("SIGNALS", checks)
        embed.risk(score, name="PHISH RISK", verdict=label)
        embed.kv(
            "STRUCTURE",
            {
                "Host": host,
                "Registrable": ".".join(labels[-2:]) if len(labels) >= 2 else host,
                "Path": parsed.path or "/",
                "Query": parsed.query[:120] or "none",
                "Scheme": parsed.scheme,
            },
            inline=True,
        )
        embed.steps(
            [
                "Parsed the URL without contacting the host",
                "Applied 15 structural phishing indicators",
                "Summed weighted signals into a 0–100 index",
            ]
        )
        embed.source("local heuristics")
        await embed.send(ctx)

    @intel(
        category="web",
        brief="Generate targeted search dorks for a domain (templates only, no queries sent).",
        usage="<domain>",
        aliases=["dork", "googledorks"],
        examples=["dorks example.com"],
        sources=["local templates"],
        cooldown=(3, 10),
    )
    async def dorks(self, ctx: commands.Context, target: str = None) -> None:
        await ack(ctx)
        domain = normalize_host(require(target, "domain", example=".dorks example.com"))
        embed = Intel(
            category="web",
            command="dorks",
            ctx=ctx,
            target=domain,
            summary="Copy these into a search engine yourself. Nothing is queried by this bot, so the target sees no traffic from it.",
        )
        rendered = [dork.format(d=domain) for dork in DORKS]
        embed.code("DOCUMENT DISCOVERY", "\n".join(rendered[:10]), lang="yaml")
        embed.code("EXPOSURE HUNTING", "\n".join(rendered[10:]), lang="yaml")
        embed.checks(
            "SCOPE",
            [
                (True, "Passive", "no requests are made to the target"),
                (None, "Ethics", "only search infrastructure you are authorised to review"),
                (None, "Tip", "pair with `securitytxt` and `robots` for context"),
            ],
        )
        embed.source("local templates")
        await embed.send(ctx)

    @intel(
        category="web",
        brief="Extract page metadata: title, description, OpenGraph, canonical and JSON-LD.",
        usage="<url|host>",
        aliases=["meta", "opengraph"],
        examples=["metatags example.com"],
        sources=["direct HTTP"],
        cooldown=(3, 12),
    )
    async def metatags(self, ctx: commands.Context, target: str = None) -> None:
        await ack(ctx)
        url = self._url(target, ".metatags example.com")
        response = await self._page(url)
        html = response.text
        meta = self._meta(html)
        canonical = re.search(r'<link[^>]+rel=["\']canonical["\'][^>]+href=["\']([^"\']+)', html, re.IGNORECASE)
        alternates = len(re.findall(r'<link[^>]+hreflang=', html, re.IGNORECASE))
        jsonld = len(re.findall(r'application/ld\+json', html, re.IGNORECASE))
        embed = Intel(
            category="web",
            command="metatags",
            ctx=ctx,
            target=clip(response.url, 110),
            summary="Metadata tells you how the operator wants the page described — useful for attribution and clone detection.",
        )
        embed.kv(
            "CORE",
            {
                "Title": clip(self._title(html), 120) or "none",
                "Description": clip(meta.get("description", ""), 200) or "none",
                "Canonical": clip(canonical.group(1), 120) if canonical else "none",
                "Language": re.search(r'<html[^>]+lang=["\']([^"\']+)', html, re.IGNORECASE).group(1) if re.search(r'<html[^>]+lang=["\']([^"\']+)', html, re.IGNORECASE) else "undeclared",
                "Charset": re.search(r'charset=["\']?([\w-]+)', html[:2000], re.IGNORECASE).group(1) if re.search(r'charset=["\']?([\w-]+)', html[:2000], re.IGNORECASE) else "unknown",
            },
            inline=False,
        )
        social = {key: value for key, value in meta.items() if key.startswith(("og:", "twitter:"))}
        if social:
            embed.kv("SOCIAL CARDS", {key: clip(value, 90) for key, value in list(social.items())[:10]}, inline=False)
        embed.kv(
            "TECHNICAL",
            {
                "Generator": clip(meta.get("generator", ""), 80) or "not declared",
                "Robots meta": meta.get("robots", "not declared"),
                "JSON-LD blocks": jsonld,
                "hreflang links": alternates,
                "Viewport": meta.get("viewport", "not declared"),
            },
            inline=True,
        )
        embed.source("direct HTTP")
        await embed.send(ctx)


async def setup(bot: Any) -> None:
    await bot.add_cog(Web(bot))

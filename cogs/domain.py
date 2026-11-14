"""Domain intelligence: DNS, registration, certificates and mail posture."""

from __future__ import annotations

import asyncio
import re
import unicodedata
from typing import Any

from discord.ext import commands

from core import dns, whois
from core.command import intel
from core.embeds import Intel, notice, respond
from core.errors import IntelError, NotFound, SourceUnavailable, UsageError
from core.signatures import CONFUSABLE_LOOKALIKES, RISKY_TLDS
from core.ui import Paginator
from core.utils import (
    ack,
    as_int,
    base_domain,
    clip,
    fmt_dt,
    human_delta,
    is_domain,
    normalize_domain,
    num,
    require,
    unicode_domain,
    utcnow,
)

MAIL_PROVIDERS: list[tuple[str, str]] = [
    (r"google|googlemail|gmail", "Google Workspace"),
    (r"outlook|protection\.outlook|microsoft", "Microsoft 365"),
    (r"zoho", "Zoho Mail"),
    (r"protonmail|proton\.ch|pm\.me", "Proton Mail"),
    (r"mail\.ru|yandex", "Yandex Mail"),
    (r"qq\.com|tencent", "Tencent Exmail"),
    (r"icloud|apple", "iCloud Mail"),
    (r"fastmail", "Fastmail"),
    (r"mimecast", "Mimecast"),
    (r"barracuda", "Barracuda ESS"),
    (r"pphosted|proofpoint", "Proofpoint"),
    (r"mailgun", "Mailgun"),
    (r"sendgrid", "SendGrid"),
    (r"amazonses|amazonaws", "Amazon SES"),
    (r"secureserver", "GoDaddy"),
    (r"register\.it", "Register.it"),
    (r"improvmx", "ImprovMX"),
    (r"messagingengine", "Fastmail (Messaging Engine)"),
]

NAMESERVER_PROVIDERS: list[tuple[str, str]] = [
    (r"cloudflare", "Cloudflare"),
    (r"awsdns|route53", "AWS Route 53"),
    (r"azure-dns|azure", "Azure DNS"),
    (r"googledomains|google", "Google Cloud DNS"),
    (r"digitalocean", "DigitalOcean"),
    (r"namecheap|registrar-servers", "Namecheap"),
    (r"domaincontrol|godaddy", "GoDaddy"),
    (r"hetzner", "Hetzner"),
    (r"ovh", "OVH"),
    (r"nsone|ns1\.com", "NS1"),
    (r"dnsimple", "DNSimple"),
    (r"dynect|oracle", "Oracle Dyn"),
    (r"ultradns|vercara", "Vercara UltraDNS"),
    (r"gandi", "Gandi"),
    (r"porkbun", "Porkbun"),
]

ALGORITHMS = {
    "1": "RSAMD5 (deprecated)",
    "3": "DSA/SHA-1 (deprecated)",
    "5": "RSASHA1",
    "7": "RSASHA1-NSEC3",
    "8": "RSASHA256",
    "10": "RSASHA512",
    "12": "ECC-GOST",
    "13": "ECDSAP256SHA256",
    "14": "ECDSAP384SHA384",
    "15": "ED25519",
    "16": "ED448",
}

DIGESTS = {"1": "SHA-1", "2": "SHA-256", "3": "GOST R 34.11-94", "4": "SHA-384"}

DKIM_SELECTORS = ("default", "google", "selector1", "selector2", "s1", "s2", "k1", "mail", "dkim", "smtp", "mandrill", "everlytics")


def _vcard(entity: dict[str, Any]) -> dict[str, str]:
    out: dict[str, str] = {}
    card = entity.get("vcardArray")
    if not card or len(card) < 2 or not isinstance(card[1], list):
        return out
    for item in card[1]:
        if isinstance(item, list) and len(item) >= 4:
            value = item[3]
            if isinstance(value, list):
                value = ", ".join(str(part) for part in value)
            out[str(item[0]).lower()] = str(value)
    return out


def _provider(host: str, table: list[tuple[str, str]]) -> str:
    for pattern, name in table:
        if re.search(pattern, host, re.IGNORECASE):
            return name
    return "independent / self-hosted"


class Domain(commands.Cog, name="Domain"):
    """DNS, registration data, transparency logs and email authentication."""

    def __init__(self, bot: Any) -> None:
        self.bot = bot
        self.net = bot.net

    # ── helpers ──────────────────────────────────────────────────────────

    @staticmethod
    def _target(target: str | None, example: str) -> str:
        raw = require(target, "domain", example=example)
        domain = normalize_domain(raw)
        if not is_domain(domain):
            raise UsageError(f"`{clip(raw, 70)}` is not a valid domain name.")
        return domain

    async def _safe(self, name: str, rrtype: str) -> list[str]:
        try:
            return await dns.values(self.net, name, rrtype)
        except (NotFound, SourceUnavailable):
            return []

    async def _crtsh(self, domain: str) -> list[dict[str, Any]]:
        response = await self.net.request(
            "GET",
            "https://crt.sh/",
            params={"q": f"%.{domain}", "output": "json"},
            cache_ttl=900,
            timeout=45,
        )
        if not response.ok:
            raise SourceUnavailable(
                f"crt.sh answered HTTP {response.status}.",
                hint="The public instance throttles aggressively. Try again in a minute.",
            )
        if not response.text.strip():
            return []
        try:
            payload = response.json()
        except IntelError:
            raise SourceUnavailable("crt.sh returned a malformed body (usually rate limiting).") from None
        return payload if isinstance(payload, list) else []

    # ── record snapshots ─────────────────────────────────────────────────

    @intel(
        category="domain",
        brief="Complete DNS snapshot: A, AAAA, MX, NS, TXT, CNAME, CAA and SOA in one dossier.",
        usage="<domain>",
        aliases=["dnsall", "records"],
        examples=["dns example.com"],
        sources=["Cloudflare DoH"],
        cooldown=(3, 12),
    )
    async def dns(self, ctx: commands.Context, target: str = None) -> None:
        await ack(ctx)
        domain = self._target(target, ".dns example.com")
        types = ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "CAA")
        results = await asyncio.gather(
            *(self._safe(domain, rrtype) for rrtype in types), return_exceptions=True
        )
        table: dict[str, list[str]] = {}
        for rrtype, result in zip(types, results):
            table[rrtype] = [] if isinstance(result, BaseException) else result
        if not any(table.values()):
            raise NotFound(f"`{domain}` resolves to nothing (NXDOMAIN or empty zone).")
        soa = await dns.soa(self.net, domain)
        embed = Intel(
            category="domain",
            command="dns",
            ctx=ctx,
            target=domain,
            summary="Single-pass zone snapshot. Absent record types are shown explicitly so you can see what is *not* published.",
        )
        for rrtype in types:
            values = table.get(rrtype) or []
            embed.kv(
                rrtype,
                {
                    "Count": len(values),
                    "Records": values[:16] or "none published",
                },
                inline=True,
            )
        if soa:
            embed.kv(
                "SOA",
                {
                    "Primary NS": soa.get("primary_ns"),
                    "Hostmaster": soa.get("hostmaster"),
                    "Serial": soa.get("serial"),
                    "Refresh": human_delta(soa.get("refresh")),
                },
                inline=True,
            )
        embed.steps(
            [
                "Resolved the registrable domain and validated syntax",
                "Issued seven parallel DNS-over-HTTPS questions",
                "Collected negative answers instead of failing the whole lookup",
                "Fetched the SOA for the zone's serial and timing policy",
            ]
        )
        counts = ", ".join(f"{rrtype}:{len(table.get(rrtype) or [])}" for rrtype in types)
        embed.quote(f"Record census — {counts}")
        embed.source("Cloudflare DoH")
        await embed.send(ctx)

    @intel(
        category="domain",
        brief="IPv4 records with TTLs and reverse DNS for each address.",
        usage="<domain>",
        aliases=["arecord"],
        examples=["a example.com"],
        sources=["Cloudflare DoH"],
        cooldown=(4, 10),
    )
    async def a(self, ctx: commands.Context, target: str = None) -> None:
        await ack(ctx)
        domain = self._target(target, ".a example.com")
        try:
            answers = await dns.answers(self.net, domain, "A")
        except NotFound:
            raise NotFound(f"`{domain}` has no A record.") from None
        if not answers:
            raise NotFound(f"`{domain}` has no A record.")
        embed = Intel(
            category="domain",
            command="a",
            ctx=ctx,
            target=domain,
            summary="IPv4 answers in the order the resolver returned them, with reverse DNS for attribution.",
        )
        rows = []
        for answer in answers[:12]:
            address = answer.get("data", "").strip()
            rows.append(
                {
                    "Address": address,
                    "TTL": answer.get("TTL"),
                    "PTR": (await self._ptr(address)) or "none",
                }
            )
        embed.table(
            "ANSWERS",
            ["ADDRESS", "TTL", "PTR"],
            [[row["Address"], row["TTL"] or "—", row["PTR"]] for row in rows],
        )
        embed.kv(
            "SUMMARY",
            {
                "Records": len(answers),
                "Unique addresses": len({answer.get("data") for answer in answers}),
                "Lowest TTL": min((answer.get("TTL") or 0) for answer in answers),
                "Reverse zone": ".".join(reversed(str(answers[0].get("data", "")).split("."))) + ".in-addr.arpa",
            },
            inline=True,
        )
        embed.steps(
            [
                "Queried the A record set over DoH",
                "Preserved resolver order and per-record TTL",
                "Reverse-resolved each address for owner attribution",
            ]
        )
        embed.source("Cloudflare DoH")
        await embed.send(ctx)

    async def _ptr(self, address: str) -> str:
        try:
            from core.utils import parse_ip

            names = await dns.ptr(self.net, parse_ip(address).reverse_pointer)
            return ", ".join(names)
        except (ValueError, IntelError):
            return ""

    @intel(
        category="domain",
        brief="IPv6 records for a domain with TTL detail.",
        usage="<domain>",
        aliases=["aaaarecord"],
        examples=["aaaa example.com"],
        sources=["Cloudflare DoH"],
        cooldown=(4, 10),
    )
    async def aaaa(self, ctx: commands.Context, target: str = None) -> None:
        await ack(ctx)
        domain = self._target(target, ".aaaa example.com")
        try:
            answers = await dns.answers(self.net, domain, "AAAA")
        except NotFound:
            raise NotFound(f"`{domain}` has no AAAA record — it is IPv4-only.") from None
        if not answers:
            raise NotFound(f"`{domain}` has no AAAA record — it is IPv4-only.")
        embed = Intel(
            category="domain",
            command="aaaa",
            ctx=ctx,
            target=domain,
            summary="IPv6 reachability matters for mail reputation, CDN routing and modern client preference.",
        )
        embed.table(
            "ANSWERS",
            ["ADDRESS", "TTL"],
            [[answer.get("data", ""), answer.get("TTL") or "—"] for answer in answers[:16]],
        )
        embed.kv(
            "SUMMARY",
            {
                "Records": len(answers),
                "Unique": len({answer.get("data") for answer in answers}),
                "Dual stack": bool(await self._safe(domain, "A")),
                "Lowest TTL": min((answer.get("TTL") or 0) for answer in answers),
            },
            inline=True,
        )
        embed.steps(
            [
                "Queried AAAA over DNS-over-HTTPS",
                "Checked for an accompanying A record to establish dual-stack",
                "Reported TTLs for cache-behaviour analysis",
            ]
        )
        embed.source("Cloudflare DoH")
        await embed.send(ctx)

    @intel(
        category="domain",
        brief="Mail exchangers, priorities and the hosting provider behind them.",
        usage="<domain>",
        aliases=["mail", "mxrecords"],
        examples=["mx example.com"],
        sources=["Cloudflare DoH"],
        cooldown=(4, 10),
    )
    async def mx(self, ctx: commands.Context, target: str = None) -> None:
        await ack(ctx)
        domain = self._target(target, ".mx example.com")
        records = await dns.mx(self.net, domain)
        if not records:
            raise NotFound(f"`{domain}` publishes no MX records — it cannot receive mail.")
        embed = Intel(
            category="domain",
            command="mx",
            ctx=ctx,
            target=domain,
            summary="MX priority decides delivery order: lower numbers are tried first.",
        )
        embed.code(
            "EXCHANGERS",
            "\n".join(f"{priority:>3}  {host}" for priority, host in records),
            lang="yaml",
        )
        providers = sorted({_provider(host, MAIL_PROVIDERS) for _, host in records})
        embed.kv(
            "PROVIDER",
            {
                "Detected": providers,
                "Exchangers": len(records),
                "Backup only": len(records) > 1,
                "SPF present": any(record.lower().startswith("v=spf1") for record in await dns.txt(self.net, domain)),
            },
            inline=True,
        )
        embed.kv(
            "PRIORITY MAP",
            {"Primary": records[0][1], "Failover": [host for _, host in records[1:]] or "none"},
            inline=True,
        )
        embed.steps(
            [
                "Resolved MX records and parsed priority / host pairs",
                "Matched hosting patterns to a known mail provider",
                "Checked for an accompanying SPF policy",
            ]
        )
        embed.source("Cloudflare DoH")
        await embed.send(ctx)

    @intel(
        category="domain",
        brief="Every TXT record, classified by purpose (SPF, verification, policy).",
        usage="<domain>",
        aliases=["txtrecords"],
        examples=["txt example.com"],
        sources=["Cloudflare DoH"],
        cooldown=(4, 10),
    )
    async def txt(self, ctx: commands.Context, target: str = None) -> None:
        await ack(ctx)
        domain = self._target(target, ".txt example.com")
        records = await dns.txt(self.net, domain)
        if not records:
            raise NotFound(f"`{domain}` publishes no TXT records.")
        buckets: dict[str, list[str]] = {}
        for record in records:
            lowered = record.lower()
            if lowered.startswith("v=spf1"):
                key = "spf"
            elif "verification" in lowered or lowered.startswith(("ms=", "google-site", "facebook-domain", "apple-domain", "atlassian", "zoom", "docusign", "adobe-idp")):
                key = "verification"
            elif lowered.startswith("v=dmarc1"):
                key = "dmarc"
            elif lowered.startswith("v=dkim1") or "k=rsa" in lowered:
                key = "dkim"
            else:
                key = "other"
            buckets.setdefault(key, []).append(record)
        embed = Intel(
            category="domain",
            command="txt",
            ctx=ctx,
            target=domain,
            summary="TXT is the DNS Swiss-army knife: mail policy, domain ownership proofs and third-party attestations all live here.",
        )
        embed.kv("CENSUS", {key: len(value) for key, value in buckets.items()} | {"total": len(records)}, inline=True)
        for key in ("spf", "verification", "dmarc", "dkim", "other"):
            if buckets.get(key):
                embed.code(key.upper(), "\n".join(buckets[key][:8]), lang="yaml")
        embed.steps(
            [
                "Collected every TXT string, joining split character-strings",
                "Classified each record by leading token",
                "Rendered each family separately so anomalies stand out",
            ]
        )
        embed.source("Cloudflare DoH")
        await embed.send(ctx)

    @intel(
        category="domain",
        brief="Authoritative nameservers, their providers and resolved glue addresses.",
        usage="<domain>",
        aliases=["nameservers"],
        examples=["ns example.com"],
        sources=["Cloudflare DoH"],
        cooldown=(4, 12),
    )
    async def ns(self, ctx: commands.Context, target: str = None) -> None:
        await ack(ctx)
        domain = self._target(target, ".ns example.com")
        servers = await dns.ns(self.net, domain)
        if not servers:
            raise NotFound(f"`{domain}` publishes no NS records.")
        glue: list[str] = []
        for server in servers[:8]:
            records = await dns.address_records(self.net, server)
            addresses = (records.get("A") or []) + (records.get("AAAA") or [])
            glue.append(f"{server} → {', '.join(addresses) or 'no glue visible'}")
        embed = Intel(
            category="domain",
            command="ns",
            ctx=ctx,
            target=domain,
            summary="Nameservers are the delegation target for the zone — whoever controls them controls every record.",
        )
        embed.code("DELEGATION", "\n".join(servers), lang="yaml")
        embed.kv(
            "PROVIDERS",
            {"Detected": sorted({_provider(server, NAMESERVER_PROVIDERS) for server in servers}), "Count": len(servers)},
            inline=True,
        )
        embed.kv(
            "GLUE",
            {"Resolved": glue},
            inline=False,
        )
        embed.steps(
            [
                "Read the NS RRset from the child zone",
                "Matched each hostname against hosting provider patterns",
                "Resolved glue addresses for the first eight servers",
            ]
        )
        embed.source("Cloudflare DoH")
        await embed.send(ctx)

    @intel(
        category="domain",
        brief="CNAME chain with the final address set and CDN detection.",
        usage="<domain>",
        aliases=["alias"],
        examples=["cname www.example.com"],
        sources=["Cloudflare DoH"],
        cooldown=(4, 10),
    )
    async def cname(self, ctx: commands.Context, target: str = None) -> None:
        await ack(ctx)
        domain = self._target(target, ".cname www.example.com")
        chain = [domain]
        current = domain
        for _ in range(6):
            records = await self._safe(current, "CNAME")
            if not records:
                break
            current = records[0].rstrip(".")
            if current in chain:
                break
            chain.append(current)
        if len(chain) == 1:
            raise NotFound(f"`{domain}` has no CNAME record.")
        addresses = await dns.address_records(self.net, current)
        embed = Intel(
            category="domain",
            command="cname",
            ctx=ctx,
            target=domain,
            summary="A CNAME delegates the name to another host. Long chains cost latency and can hide a third-party dependency.",
        )
        embed.steps([f"`{name}`" for name in chain], name="CNAME CHAIN")
        embed.kv(
            "TERMINUS",
            {
                "Final host": current,
                "IPv4": addresses.get("A"),
                "IPv6": addresses.get("AAAA"),
                "Hops": len(chain) - 1,
                "Provider": _provider(current, NAMESERVER_PROVIDERS + MAIL_PROVIDERS),
            },
            inline=True,
        )
        embed.checks(
            "HEALTH",
            [
                (len(chain) <= 3, "Chain length", f"{len(chain) - 1} redirects"),
                (bool(addresses), "Resolvable terminus", "yes" if addresses else "terminus has no A/AAAA"),
                (None, "Note", "CNAMEs cannot coexist with other record types on the same name"),
            ],
        )
        embed.source("Cloudflare DoH")
        await embed.send(ctx)

    @intel(
        category="domain",
        brief="Start of authority: primary server, serial and refresh/retry/expire timers.",
        usage="<domain>",
        aliases=["authority"],
        examples=["soa example.com"],
        sources=["Cloudflare DoH"],
        cooldown=(4, 10),
    )
    async def soa(self, ctx: commands.Context, target: str = None) -> None:
        await ack(ctx)
        domain = self._target(target, ".soa example.com")
        data = await dns.soa(self.net, domain)
        if not data:
            raise NotFound(f"`{domain}` returned no SOA record.")
        embed = Intel(
            category="domain",
            command="soa",
            ctx=ctx,
            target=domain,
            summary="The SOA is the zone's control record: it identifies the primary server and sets how secondaries behave.",
        )
        embed.kv(
            "AUTHORITY",
            {
                "Primary NS": data.get("primary_ns"),
                "Hostmaster": data.get("hostmaster"),
                "Serial": data.get("serial"),
                "Serial age": "increment on every zone change",
            },
            inline=True,
        )
        embed.kv(
            "TIMERS",
            {
                "Refresh": human_delta(data.get("refresh")),
                "Retry": human_delta(data.get("retry")),
                "Expire": human_delta(data.get("expire")),
                "Negative TTL": human_delta(data.get("minimum")),
            },
            inline=True,
        )
        embed.checks(
            "SANITY",
            [
                (data.get("refresh", 0) > 0, "Refresh positive", f"{data.get('refresh')}s"),
                (data.get("retry", 0) > 0, "Retry positive", f"{data.get('retry')}s"),
                (data.get("expire", 0) > data.get("refresh", 0), "Expire > refresh", "healthy ordering" if data.get("expire", 0) > data.get("refresh", 0) else "misconfigured"),
                (data.get("minimum", 999999) <= 3600, "Negative caching", f"{data.get('minimum')}s"),
            ],
        )
        embed.source("Cloudflare DoH")
        await embed.send(ctx)

    @intel(
        category="domain",
        brief="Certificate Authority Authorization: which CAs may issue for this name.",
        usage="<domain>",
        aliases=["caarecord"],
        examples=["caa example.com"],
        sources=["Cloudflare DoH"],
        cooldown=(4, 10),
    )
    async def caa(self, ctx: commands.Context, target: str = None) -> None:
        await ack(ctx)
        domain = self._target(target, ".caa example.com")
        records = await dns.caa(self.net, domain)
        embed = Intel(
            category="domain",
            command="caa",
            ctx=ctx,
            target=domain,
            summary="CAA restricts which certificate authorities may issue for the name. Absence means any CA may issue.",
        )
        if not records:
            embed.checks(
                "POLICY",
                [
                    (False, "CAA present", "no record — any public CA may issue"),
                    (None, "Recommendation", "publish `0 issue \"letsencrypt.org\"` to narrow the blast radius of mis-issuance"),
                ],
            )
        else:
            parsed = []
            for record in records:
                parts = record.split()
                flags = parts[0] if parts else "0"
                tag = parts[1] if len(parts) > 1 else "?"
                value = " ".join(parts[2:]) if len(parts) > 2 else ""
                parsed.append((flags, tag, value))
            embed.table("RECORDS", ["FLAGS", "TAG", "VALUE"], parsed)
            tags = {tag for _, tag, _ in parsed}
            embed.checks(
                "POLICY",
                [
                    (True, "CAA present", f"{len(records)} record(s)"),
                    ("issue" in tags, "Issuance restricted", "issue tag found" if "issue" in tags else "only wildcard/iodef tags"),
                    ("iodef" in tags, "Incident reporting", "iodef present" if "iodef" in tags else "no iodef contact"),
                ],
            )
        embed.source("Cloudflare DoH")
        await embed.send(ctx)

    @intel(
        category="domain",
        brief="SRV records: service, protocol, priority, weight and target host.",
        usage="<_service._proto.domain>",
        aliases=["srvrecord"],
        examples=["srv _sip._tcp.example.com", "srv _xmpp-server._tcp.example.com"],
        sources=["Cloudflare DoH"],
        cooldown=(4, 10),
    )
    async def srv(self, ctx: commands.Context, target: str = None) -> None:
        await ack(ctx)
        name = normalize_domain(require(target, "service record", example=".srv _sip._tcp.example.com"))
        records = await dns.srv(self.net, name)
        if not records:
            raise NotFound(f"`{name}` has no SRV record.")
        embed = Intel(
            category="domain",
            command="srv",
            ctx=ctx,
            target=name,
            summary="SRV records let one domain advertise where a service actually lives, with priority and weight for load spreading.",
        )
        rows = []
        for record in records:
            parts = record.split()
            if len(parts) >= 4:
                rows.append((parts[0], parts[1], parts[2], parts[3].rstrip(".")))
            else:
                rows.append((record, "", "", ""))
        embed.table("RECORDS", ["PRIORITY", "WEIGHT", "PORT", "TARGET"], rows)
        embed.kv(
            "ROUTING",
            {
                "Service": name.split(".")[0],
                "Protocol": name.split(".")[1] if len(name.split(".")) > 1 else "?",
                "Targets": len(rows),
                "Weighting": "randomised by weight among lowest priority" if len(rows) > 1 else "single target",
            },
            inline=True,
        )
        embed.source("Cloudflare DoH")
        await embed.send(ctx)

    # ── mail authentication ──────────────────────────────────────────────

    @intel(
        category="domain",
        brief="Parse and grade an SPF policy, including the 10-lookup budget.",
        usage="<domain>",
        aliases=["senderpolicy"],
        examples=["spf example.com"],
        sources=["Cloudflare DoH"],
        cooldown=(4, 12),
    )
    async def spf(self, ctx: commands.Context, target: str = None) -> None:
        await ack(ctx)
        domain = self._target(target, ".spf example.com")
        records = [record for record in await dns.txt(self.net, domain) if record.lower().startswith("v=spf1")]
        if not records:
            raise NotFound(f"`{domain}` publishes no SPF record — anyone can spoof its sender domain.")
        if len(records) > 1:
            embed_extra = "Multiple SPF records exist. Per RFC 7208 this is a permanent error and receivers must ignore all of them."
        else:
            embed_extra = ""
        record = records[0]
        tokens = record.split()[1:]
        lookup_mechanisms = {"include", "a", "mx", "ptr", "exists", "redirect"}
        lookups = sum(1 for token in tokens if token.split(":")[0].lstrip("+-~?") in lookup_mechanisms)
        qualifier = next((token[0] for token in tokens if token and token[0] in "+-~?"), "+")
        all_qualifier = next((token[0] for token in tokens if token.lstrip("+-~?") == "all"), None)
        embed = Intel(
            category="domain",
            command="spf",
            ctx=ctx,
            target=domain,
            summary="SPF authorises sending hosts. It breaks silently when the policy exceeds ten DNS lookups or ends in a permissive qualifier.",
        )
        embed.code("RAW POLICY", record, lang="yaml")
        embed.kv(
            "MECHANISMS",
            {
                "Includes": [token for token in tokens if token.lstrip("+-~?").startswith("include:")][:8],
                "IPv4": sum(1 for token in tokens if token.lstrip("+-~?").startswith("ip4:")),
                "IPv6": sum(1 for token in tokens if token.lstrip("+-~?").startswith("ip6:")),
                "A / MX": [token for token in tokens if token.lstrip("+-~?").startswith(("a", "mx"))][:6],
                "Redirect": next((token for token in tokens if token.lstrip("+-~?").startswith("redirect=")), "none"),
                "PTR": "present (deprecated)" if any(token.lstrip("+-~?").startswith("ptr") for token in tokens) else "absent",
            },
            inline=True,
        )
        embed.kv(
            "BUDGET",
            {
                "DNS lookups": f"{lookups}/10",
                "Headroom": max(0, 10 - lookups),
                "All qualifier": all_qualifier or "none (defaults to ?all)",
                "Default qualifier": qualifier,
            },
            inline=True,
        )
        verdicts = [
            (len(records) == 1, "Single record", f"{len(records)} found"),
            (lookups <= 10, "Lookup budget", f"{lookups} DNS-costing mechanisms"),
            (all_qualifier in {"-", "~"}, "Terminal all", {None: "missing", "+": "permissive (+all)", "-": "hard fail (-all)", "~": "soft fail (~all)", "?": "neutral (?all)"}.get(all_qualifier, "unknown")),
            (not any(token.lstrip("+-~?").startswith("ptr") for token in tokens), "No ptr mechanism", "ptr is deprecated and unreliable"),
        ]
        score = sum(1 for state, _, _ in verdicts if state) / len(verdicts) * 100
        embed.checks("GRADE", verdicts)
        embed.risk(100 - score, name="SPOOF RISK", verdict="LOW" if score >= 75 else "ELEVATED" if score >= 50 else "HIGH")
        if embed_extra:
            embed.quote(embed_extra)
        embed.steps(
            [
                "Located the v=spf1 TXT record",
                "Tokenised mechanisms and counted DNS-costing terms against RFC 7208's limit of 10",
                "Identified the terminal qualifier for unlisted senders",
                "Cross-checked for the deprecated ptr mechanism",
            ]
        )
        embed.source("Cloudflare DoH")
        await embed.send(ctx)

    @intel(
        category="domain",
        brief="DMARC policy analysis: enforcement, alignment, reporting addresses and coverage.",
        usage="<domain>",
        aliases=["dmarcpolicy"],
        examples=["dmarc example.com"],
        sources=["Cloudflare DoH"],
        cooldown=(4, 12),
    )
    async def dmarc(self, ctx: commands.Context, target: str = None) -> None:
        await ack(ctx)
        domain = self._target(target, ".dmarc example.com")
        records = [record for record in await self._safe(f"_dmarc.{domain}", "TXT") if record.lower().startswith("v=dmarc1")]
        if not records:
            raise NotFound(f"No DMARC record at `_dmarc.{domain}`.")
        tags: dict[str, str] = {}
        for part in records[0].split(";"):
            if "=" in part:
                key, _, value = part.partition("=")
                tags[key.strip().lower()] = value.strip()
        policy = tags.get("p", "none").lower()
        sub_policy = tags.get("sp", "inherit").lower()
        pct = int(tags.get("pct", "100")) if tags.get("pct", "100").isdigit() else 100
        embed = Intel(
            category="domain",
            command="dmarc",
            ctx=ctx,
            target=domain,
            summary="DMARC tells receivers what to do when SPF and DKIM fail, and where to send reports.",
        )
        embed.code("RAW POLICY", records[0], lang="yaml")
        embed.kv(
            "POLICY",
            {
                "p": policy,
                "sp": sub_policy,
                "pct": f"{pct}%",
                "adkim": tags.get("adkim", "r (relaxed)"),
                "aspf": tags.get("aspf", "r (relaxed)"),
                "fo": tags.get("fo"),
                "rf": tags.get("rf"),
                "ri": tags.get("ri"),
            },
            inline=True,
        )
        embed.kv(
            "REPORTING",
            {
                "Aggregate (rua)": [address.strip() for address in tags.get("rua", "").split(",") if address.strip()] or "none",
                "Forensic (ruf)": [address.strip() for address in tags.get("ruf", "").split(",") if address.strip()] or "none",
            },
            inline=False,
        )
        enforced = policy in {"quarantine", "reject"}
        embed.checks(
            "ENFORCEMENT",
            [
                (policy == "reject", "Reject policy", f"p={policy}"),
                (enforced, "Active enforcement", "quarantine or reject" if enforced else "monitor only — spoofed mail still lands"),
                (pct == 100, "Full coverage", f"pct={pct}"),
                (bool(tags.get("rua")), "Aggregate reporting", "configured" if tags.get("rua") else "no rua address"),
                (sub_policy in {"quarantine", "reject"}, "Subdomain policy", f"sp={sub_policy}"),
            ],
        )
        risk = 85 if policy == "none" else 45 if policy == "quarantine" else 12
        if pct < 100:
            risk += 10
        embed.risk(risk, name="SPOOF RISK")
        embed.steps(
            [
                "Read the _dmarc TXT record",
                "Parsed the tag=value policy language",
                "Evaluated enforcement strength and reporting coverage",
            ]
        )
        embed.source("Cloudflare DoH")
        await embed.send(ctx)

    @intel(
        category="domain",
        brief="Hunt for DKIM selectors and estimate the signing key size.",
        usage="<domain> [selector]",
        aliases=["dkimkey"],
        examples=["dkim example.com", "dkim example.com google"],
        sources=["Cloudflare DoH"],
        cooldown=(3, 15),
    )
    async def dkim(self, ctx: commands.Context, target: str = None, selector: str = None) -> None:
        await ack(ctx)
        domain = self._target(target, ".dkim example.com")
        selectors = [selector.strip().lower()] if selector else list(DKIM_SELECTORS)

        async def probe(name: str) -> tuple[str, list[str]]:
            return name, await self._safe(f"{name}._domainkey.{domain}", "TXT")

        results = await asyncio.gather(*(probe(name) for name in selectors))
        found = [(name, records) for name, records in results if records]
        embed = Intel(
            category="domain",
            command="dkim",
            ctx=ctx,
            target=domain,
            summary="DKIM selectors are not enumerable by design. This checks the conventional names; a custom selector must be supplied explicitly.",
        )
        embed.kv(
            "SEARCH",
            {
                "Selectors tried": len(selectors),
                "Found": len(found),
                "Present": [name for name, _ in found] or "none of the common selectors",
            },
            inline=True,
        )
        for name, records in found[:4]:
            record = records[0]
            key_blob = ""
            tags: dict[str, str] = {}
            for part in record.replace(" ", "").split(";"):
                if "=" in part:
                    key, _, value = part.partition("=")
                    tags[key.strip().lower()] = value.strip()
            key_blob = tags.get("p", "")
            bits = len(key_blob) * 6
            embed.code(
                f"SELECTOR {name.upper()}",
                f"v={tags.get('v', 'DKIM1')}  k={tags.get('k', 'rsa')}  h={tags.get('h', 'unspecified')}\n"
                f"key material: {len(key_blob)} base64 chars ≈ {bits} bits\n"
                f"flags: {tags.get('t', 'none')}",
                lang="yaml",
            )
        if not found:
            embed.checks(
                "RESULT",
                [
                    (False, "Conventional selectors", "no key published under default names"),
                    (None, "Interpretation", "the domain may sign with a custom selector, or not sign at all"),
                ],
            )
        else:
            embed.checks(
                "RESULT",
                [
                    (True, "Key published", f"{len(found)} selector(s) answered"),
                    (None, "Interpretation", "DKIM alone does not enforce anything — DMARC must reference it"),
                ],
            )
        embed.source("Cloudflare DoH")
        await embed.send(ctx)

    @intel(
        category="domain",
        brief="DNSSEC chain: DS at the parent and DNSKEY at the zone, with algorithm detail.",
        usage="<domain>",
        aliases=["ds"],
        examples=["dnssec example.com"],
        sources=["Cloudflare DoH"],
        cooldown=(4, 12),
    )
    async def dnssec(self, ctx: commands.Context, target: str = None) -> None:
        await ack(ctx)
        domain = self._target(target, ".dnssec example.com")
        ds_records = await dns.ds(self.net, domain)
        keys = await dns.dnskey(self.net, domain)
        embed = Intel(
            category="domain",
            command="dnssec",
            ctx=ctx,
            target=domain,
            summary="DNSSEC proves a DNS answer was not tampered with. The DS record at the parent is what actually anchors the trust chain.",
        )
        signed = bool(ds_records)
        embed.checks(
            "STATUS",
            [
                (signed, "DS at parent", "published" if ds_records else "not signed or validation not enabled"),
                (bool(keys), "DNSKEY at zone", f"{len(keys)} key records" if keys else "no keys returned"),
            ],
        )
        parsed = []
        for record in ds_records[:6]:
            parts = record.split()
            if len(parts) >= 4:
                parsed.append(
                    f"keytag={parts[0]} algorithm={ALGORITHMS.get(parts[1], parts[1])} digest={DIGESTS.get(parts[2], parts[2])}"
                )
        if parsed:
            embed.code("DS RECORDS", "\n".join(parsed), lang="yaml")
        if keys:
            embed.code("DNSKEY SAMPLE", "\n".join(clip(key, 120) for key in keys[:3]), lang="yaml")
        if signed:
            embed.kv(
                "ASSESSMENT",
                {
                    "Zone signed": "yes",
                    "Algorithms": sorted({ALGORITHMS.get(record.split()[1], record.split()[1]) for record in ds_records if len(record.split()) > 1}),
                    "Digest types": sorted({DIGESTS.get(record.split()[2], record.split()[2]) for record in ds_records if len(record.split()) > 2}),
                },
                inline=True,
            )
        embed.steps(
            [
                "Queried DS records from the parent side of the delegation",
                "Queried DNSKEY records from the zone itself",
                "Mapped algorithm and digest identifiers to their names",
            ]
        )
        embed.source("Cloudflare DoH")
        await embed.send(ctx)

    # ── registration ─────────────────────────────────────────────────────

    @intel(
        category="domain",
        brief="Raw WHOIS with parsed registrar, dates, status flags and nameservers.",
        usage="<domain>",
        aliases=["whoisdomain"],
        examples=["whois example.com"],
        sources=["port-43 WHOIS via IANA referral"],
        cooldown=(3, 20),
    )
    async def whois(self, ctx: commands.Context, target: str = None) -> None:
        await ack(ctx)
        domain = self._target(target, ".whois example.com")
        raw, server = await whois.lookup(domain)
        parsed = whois.parse(raw)
        age = whois.age_days(parsed.get("created"))
        embed = Intel(
            category="domain",
            command="whois",
            ctx=ctx,
            target=domain,
            summary=f"Registry answer served by `{server}`. Registrant details are commonly redacted for privacy, which is expected.",
        )
        embed.kv(
            "REGISTRAR",
            {
                "Name": parsed.get("registrar"),
                "URL": parsed.get("registrar_url"),
                "IANA id": parsed.get("id"),
                "Abuse contact": parsed.get("abuse") or parsed.get("email"),
            },
            inline=True,
        )
        embed.kv(
            "LIFECYCLE",
            {
                "Created": fmt_dt(parsed.get("created")),
                "Updated": fmt_dt(parsed.get("updated")),
                "Expires": fmt_dt(parsed.get("expires")),
                "Age": f"{num(age)} days" if age is not None else "unknown",
            },
            inline=True,
        )
        embed.kv(
            "TECHNICAL",
            {
                "Nameservers": parsed.get("nameservers"),
                "DNSSEC": parsed.get("dnssec"),
                "Status": parsed.get("status"),
                "Country": parsed.get("country"),
                "Org": parsed.get("org"),
            },
            inline=False,
        )
        embed.code("RAW EXCERPT", clip(raw, 900), lang="yaml")
        if age is not None and age < 30:
            embed.quote("This domain is less than 30 days old. Young domains are disproportionately associated with phishing campaigns.")
        embed.steps(
            [
                "Asked IANA for the authoritative WHOIS server",
                "Followed the referral and captured the full response",
                "Parsed registrar, lifecycle and technical fields",
                "Normalised dates and computed age in days",
            ]
        )
        embed.source(f"WHOIS {server}")
        await embed.send(ctx)

    @intel(
        category="domain",
        brief="Structured RDAP registration record with entities and events.",
        usage="<domain>",
        aliases=["registration"],
        examples=["rdap example.com"],
        sources=["rdap.org"],
        cooldown=(4, 15),
    )
    async def rdap(self, ctx: commands.Context, target: str = None) -> None:
        await ack(ctx)
        domain = self._target(target, ".rdap example.com")
        payload = await self.net.get_json(f"https://rdap.org/domain/{domain}", cache_ttl=3600)
        events = {event.get("eventAction"): event.get("eventDate") for event in payload.get("events") or []}
        embed = Intel(
            category="domain",
            command="rdap",
            ctx=ctx,
            target=domain,
            summary="RDAP is the JSON successor to WHOIS: stable schema, explicit events and a machine-readable entity graph.",
        )
        embed.kv(
            "REGISTRATION",
            {
                "Handle": payload.get("handle"),
                "LDH name": payload.get("ldhName"),
                "Status": payload.get("status"),
                "Registered": events.get("registration"),
                "Expires": events.get("expiration"),
                "Last changed": events.get("last changed") or events.get("last-modified"),
            },
            inline=True,
        )
        nameservers = [server.get("ldhName") for server in payload.get("nameservers") or [] if server.get("ldhName")]
        embed.kv(
            "DELEGATION",
            {
                "Nameservers": nameservers or "none",
                "Secure DNS": (payload.get("secureDNS") or {}).get("delegationSigned"),
                "DNSSEC keys": len((payload.get("secureDNS") or {}).get("dsData") or []),
            },
            inline=True,
        )
        entities = []
        for entity in payload.get("entities") or []:
            card = _vcard(entity)
            roles = ", ".join(entity.get("roles") or []) or "entity"
            label = card.get("fn") or card.get("org") or entity.get("handle") or "unnamed"
            email = card.get("email")
            entities.append(f"**{roles}** — {clip(label, 60)}" + (f" · `{email}`" if email else ""))
        if entities:
            embed.text("ENTITIES", "\n".join(entities[:10]), inline=False)
        embed.steps(
            [
                "Followed the RDAP bootstrap to the authoritative registry",
                "Read the event log for registration and expiry",
                "Walked entities for registrar, abuse and technical roles",
            ]
        )
        embed.source("rdap.org")
        await embed.send(ctx)

    @intel(
        category="domain",
        brief="Domain age, expiry runway and registrar from the registration record.",
        usage="<domain>",
        aliases=["age", "expiry"],
        examples=["domainage example.com"],
        sources=["port-43 WHOIS"],
        cooldown=(3, 20),
    )
    async def domainage(self, ctx: commands.Context, target: str = None) -> None:
        await ack(ctx)
        domain = self._target(target, ".domainage example.com")
        raw, server = await whois.lookup(domain)
        parsed = whois.parse(raw)
        created = whois.age_days(parsed.get("created"))
        from core.utils import parse_dt

        expires_at = parse_dt(parsed.get("expires"))
        now = utcnow()
        days_left = (expires_at - now).days if expires_at else None
        embed = Intel(
            category="domain",
            command="domainage",
            ctx=ctx,
            target=domain,
            summary="Domain age is a cheap trust signal: phishing infrastructure rarely survives its first month.",
        )
        embed.kv(
            "AGE",
            {
                "Created": parsed.get("created") or "unknown",
                "Age": f"{num(created)} days" if created is not None else "unknown",
                "Years": f"{created / 365:.1f}" if created is not None else "unknown",
                "Expires": parsed.get("expires") or "unknown",
                "Days remaining": num(days_left) if days_left is not None else "unknown",
            },
            inline=True,
        )
        embed.kv(
            "REGISTRAR",
            {
                "Name": parsed.get("registrar"),
                "Status": parsed.get("status"),
                "Nameservers": parsed.get("nameservers"),
                "Registry": server,
            },
            inline=True,
        )
        risk = 15
        if created is not None:
            if created < 30:
                risk = 88
            elif created < 180:
                risk = 60
            elif created < 365:
                risk = 38
        if days_left is not None and days_left < 30:
            risk = max(risk, 65)
        embed.risk(risk, name="TRUST INDEX", verdict="YOUNG DOMAIN" if risk >= 60 else "ESTABLISHED" if risk < 40 else "CAUTION")
        embed.checks(
            "SIGNALS",
            [
                (created is not None and created > 365, "Older than a year", f"{num(created)} days"),
                (days_left is None or days_left > 30, "Expiry runway", f"{num(days_left)} days" if days_left is not None else "unknown"),
                (bool(parsed.get("nameservers")), "Delegation visible", f"{len(parsed.get('nameservers') or [])} nameservers"),
            ],
        )
        embed.source(f"WHOIS {server}")
        await embed.send(ctx)

    # ── transparency ─────────────────────────────────────────────────────

    @intel(
        category="domain",
        brief="Certificate Transparency search: issuers, validity window and covered names.",
        usage="<domain>",
        aliases=["ct", "certs"],
        examples=["crtsh example.com"],
        sources=["crt.sh"],
        cooldown=(2, 25),
    )
    async def crtsh(self, ctx: commands.Context, target: str = None) -> None:
        await ack(ctx)
        domain = self._target(target, ".crtsh example.com")
        entries = await self._crtsh(domain)
        if not entries:
            raise NotFound(f"Certificate Transparency holds no certificate for `{domain}`.")
        names: set[str] = set()
        issuers: dict[str, int] = {}
        for entry in entries:
            for name in str(entry.get("name_value", "")).splitlines():
                cleaned = name.strip().lower().lstrip("*.")
                if cleaned:
                    names.add(cleaned)
            issuer = str(entry.get("issuer_name") or "unknown")
            issuers[issuer] = issuers.get(issuer, 0) + 1
        dates = sorted(str(entry.get("not_before", "")) for entry in entries if entry.get("not_before"))
        embed = Intel(
            category="domain",
            command="crtsh",
            ctx=ctx,
            target=domain,
            summary="Every publicly trusted certificate is logged. CT is the best passive source for historical hostnames.",
        )
        embed.kv(
            "CORPUS",
            {
                "Certificates": len(entries),
                "Unique names": len(names),
                "First entry": dates[0][:10] if dates else "unknown",
                "Latest entry": dates[-1][:10] if dates else "unknown",
            },
            inline=True,
        )
        top_issuers = sorted(issuers.items(), key=lambda item: item[1], reverse=True)[:6]
        embed.text(
            "ISSUERS",
            "\n".join(f"`{count:>4}` {clip(issuer, 90)}" for issuer, count in top_issuers),
            inline=True,
        )
        embed.code("NAME SAMPLE", "\n".join(sorted(names)[:22]), lang="yaml")
        embed.steps(
            [
                "Queried the public crt.sh transparency index",
                "Deduplicated wildcard and SAN-derived names",
                "Aggregated issuing authorities",
            ]
        )
        embed.source("crt.sh")
        await embed.send(ctx)

    @intel(
        category="domain",
        brief="Passive subdomain enumeration from Certificate Transparency, paginated.",
        usage="<domain>",
        aliases=["subs", "enum"],
        examples=["subdomains example.com"],
        sources=["crt.sh"],
        cooldown=(2, 30),
    )
    async def subdomains(self, ctx: commands.Context, target: str = None) -> None:
        await ack(ctx)
        domain = self._target(target, ".subdomains example.com")
        entries = await self._crtsh(domain)
        if not entries:
            raise NotFound(f"No certificates logged for `{domain}`.")
        names: set[str] = set()
        for entry in entries:
            for name in str(entry.get("name_value", "")).splitlines():
                cleaned = name.strip().lower()
                if cleaned and "*" not in cleaned:
                    names.add(cleaned)
        scoped = sorted(name for name in names if name == domain or name.endswith("." + domain))
        if not scoped:
            raise NotFound("No in-scope names were found in the transparency logs.")
        base = notice(
            "PASSIVE SUBDOMAIN ENUMERATION",
            f"`{len(scoped)}` unique in-scope names recovered from Certificate Transparency. "
            "Nothing was actively scanned.",
            category="domain",
            footer=f"source: crt.sh  •  {len(entries)} certificates parsed",
        )
        pages: list[Any] = []
        page_size = 45
        for index in range(0, len(scoped), page_size):
            page = base.copy()
            chunk = scoped[index : index + page_size]
            page.add_field(
                name=f"▸ NAMES {index + 1}–{index + len(chunk)}",
                value=f"```yaml\n" + "\n".join(clip(name, 90) for name in chunk) + "```",
                inline=False,
            )
            pages.append(page)
        if len(pages) == 1:
            await respond(ctx, pages[0])
        else:
            await respond(ctx, pages[0], view=Paginator(pages, author_id=ctx.author.id))

    # ── operations ───────────────────────────────────────────────────────

    @intel(
        category="domain",
        brief="Compare one record across four independent public resolvers.",
        usage="<domain> [type]",
        aliases=["prop"],
        examples=["propagation example.com", "propagation example.com MX"],
        sources=["Cloudflare", "Google", "Quad9", "AdGuard"],
        cooldown=(3, 15),
    )
    async def propagation(self, ctx: commands.Context, target: str = None, rrtype: str = None) -> None:
        await ack(ctx)
        domain = self._target(target, ".propagation example.com")
        record_type = (rrtype or "A").upper()
        results = await dns.propagation(self.net, domain, record_type)
        unique = {value for value in results.values() if value not in {"unreachable"}}
        embed = Intel(
            category="domain",
            command="propagation",
            ctx=ctx,
            target=f"{domain} {record_type}",
            summary="Different resolvers cache independently. Divergence here implies a recent change or a split-horizon setup.",
        )
        embed.kv(rrtype or "A", results, inline=False)
        embed.checks(
            "CONSISTENCY",
            [
                (len(unique) == 1, "Resolvers agree", f"{len(unique)} distinct answer set(s)"),
                (len(results) == 4, "Resolver coverage", f"{len(results)}/4 answered"),
                (None, "Caveat", "authoritative TTL determines how long divergence can persist"),
            ],
        )
        embed.steps(
            [
                "Issued the same question to four independent DoH resolvers",
                "Compared their answer sets",
                "Flagged divergence and unreachable resolvers separately",
            ]
        )
        embed.source("Cloudflare", "Google", "Quad9", "AdGuard")
        await embed.send(ctx)

    @intel(
        category="domain",
        brief="IDN / homograph analysis: punycode form, scripts and confusable characters.",
        usage="<domain>",
        aliases=["idn", "homograph"],
        examples=["punycode xn--80ak6aa92e.com", "punycode аpple.com"],
        sources=["local Unicode analysis"],
        cooldown=(4, 10),
    )
    async def punycode(self, ctx: commands.Context, target: str = None) -> None:
        await ack(ctx)
        raw = require(target, "domain", example=".punycode xn--80ak6aa92e.com").strip()
        ascii_form = normalize_domain(raw)
        unicode_form = unicode_domain(ascii_form)
        if not is_domain(ascii_form):
            raise UsageError("That is not a valid domain in either form.")
        scripts: set[str] = set()
        confusables = []
        for char in unicode_form:
            if ord(char) < 128:
                continue
            try:
                name = unicodedata.name(char)
            except ValueError:
                name = "UNKNOWN"
            scripts.add(name.split()[0].title())
            mapped = CONFUSABLE_LOOKALIKES.get(char)
            if mapped:
                confusables.append(f"`{char}` (U+{ord(char):04X}) looks like `{mapped}`")
        labels = ascii_form.split(".")
        risky_tld = labels[-1] in RISKY_TLDS
        risk = 8
        if confusables:
            risk = 82
        elif scripts:
            risk = 45
        if len(scripts) > 1:
            risk = min(95, risk + 20)
        if risky_tld:
            risk = min(95, risk + 15)
        embed = Intel(
            category="domain",
            command="punycode",
            ctx=ctx,
            target=ascii_form,
            summary="Homographs abuse characters that render identically across scripts. Always compare the ASCII form before trusting a link.",
        )
        embed.kv(
            "FORMS",
            {
                "Unicode": unicode_form,
                "ASCII / punycode": ascii_form,
                "Labels": labels,
                "TLD": labels[-1],
                "Length": len(ascii_form),
            },
            inline=True,
        )
        embed.kv(
            "SCRIPT",
            {
                "Scripts": sorted(scripts) or ["Latin only"],
                "Mixed script": len(scripts) > 1,
                "Confusables": confusables[:8] or "none detected",
                "Hyphens": labels[-2].count("-") if len(labels) > 1 else 0,
            },
            inline=True,
        )
        embed.checks(
            "RED FLAGS",
            [
                (bool(confusables), "Confusable characters", f"{len(confusables)} mapping(s)"),
                (len(scripts) > 1, "Mixed scripts", ", ".join(sorted(scripts)) or "latin only"),
                (ascii_form.startswith("xn--") or ".xn--" in ascii_form, "Punycode label", "encoded label present"),
                (risky_tld, "High-abuse TLD", labels[-1]),
            ],
        )
        embed.risk(risk, name="HOMOGRAPH RISK")
        embed.steps(
            [
                "Decoded the IDNA form into its Unicode presentation",
                "Enumerated every non-ASCII codepoint and its script",
                "Mapped confusable glyphs to Latin lookalikes",
                "Scored the name against mixed-script and TLD heuristics",
            ]
        )
        embed.source("local Unicode analysis")
        await embed.send(ctx)

    @intel(
        category="domain",
        brief="TLD facts: IANA registration, class, root nameservers.",
        usage="<domain|tld>",
        aliases=["tld"],
        examples=["tldinfo example.co.uk", "tldinfo xyz"],
        sources=["data.iana.org", "Cloudflare DoH"],
        cooldown=(3, 20),
    )
    async def tldinfo(self, ctx: commands.Context, target: str = None) -> None:
        await ack(ctx)
        raw = normalize_domain(require(target, "domain or TLD", example=".tldinfo example.com"))
        tld = raw.split(".")[-1]
        listing = await self.net.get_text("https://data.iana.org/TLD/tlds-alpha-by-domain.txt", cache_ttl=86_400)
        known = {line.strip().lower() for line in listing.splitlines() if line and not line.startswith("#")}
        registered = tld in known
        ascii_tld = tld.encode("idna").decode("ascii") if tld else tld
        registered = registered or ascii_tld in known
        servers = await dns.ns(self.net, ascii_tld) if registered else []
        kind = "country-code (ccTLD)" if len(ascii_tld) == 2 else "generic (gTLD)"
        if ascii_tld.startswith("xn--"):
            kind = "internationalised (IDN TLD)"
        embed = Intel(
            category="domain",
            command="tldinfo",
            ctx=ctx,
            target=tld,
            summary="The TLD determines the registry, the RDAP endpoint and often the abuse-handling process.",
        )
        embed.kv(
            "CLASSIFICATION",
            {
                "TLD": ascii_tld,
                "Unicode": unicode_domain(ascii_tld),
                "Class": kind,
                "IANA registered": registered,
                "Registrable domain": base_domain(raw),
            },
            inline=True,
        )
        embed.kv(
            "ROOT DELEGATION",
            {
                "Nameservers": servers[:8] or "not resolvable",
                "Server count": len(servers),
                "RDAP": "https://rdap.org/domain/" + base_domain(raw),
            },
            inline=False,
        )
        embed.checks(
            "SIGNALS",
            [
                (registered, "In the IANA root", "yes" if registered else "not present in tlds-alpha-by-domain.txt"),
                (len(servers) >= 2, "Root redundancy", f"{len(servers)} nameservers"),
                (ascii_tld not in RISKY_TLDS, "Abuse reputation", "commonly abused TLD" if ascii_tld in RISKY_TLDS else "no flag"),
            ],
        )
        embed.source("data.iana.org", "Cloudflare DoH")
        await embed.send(ctx)

    @intel(
        category="domain",
        brief="End-to-end email authentication posture score across SPF, DMARC, DKIM, DNSSEC and MTA-STS.",
        usage="<domain>",
        aliases=["mailposture", "emailauth"],
        examples=["emailposture example.com"],
        sources=["Cloudflare DoH", "direct HTTPS"],
        cooldown=(2, 25),
    )
    async def emailposture(self, ctx: commands.Context, target: str = None) -> None:
        await ack(ctx)
        domain = self._target(target, ".emailposture example.com")
        mx = await dns.mx(self.net, domain)
        txt = await dns.txt(self.net, domain)
        spf = next((record for record in txt if record.lower().startswith("v=spf1")), None)
        dmarc_records = [record for record in await self._safe(f"_dmarc.{domain}", "TXT") if record.lower().startswith("v=dmarc1")]
        dmarc_tags: dict[str, str] = {}
        if dmarc_records:
            for part in dmarc_records[0].split(";"):
                if "=" in part:
                    key, _, value = part.partition("=")
                    dmarc_tags[key.strip().lower()] = value.strip()
        dkim_found = []
        for selector in ("default", "google", "selector1", "selector2"):
            records = await self._safe(f"{selector}._domainkey.{domain}", "TXT")
            if records:
                dkim_found.append(selector)
        ds = await dns.ds(self.net, domain)
        mta_sts = [record for record in await self._safe(f"_mta-sts.{domain}", "TXT") if record.lower().startswith("v=stsv1")]
        tls_rpt = [record for record in await self._safe(f"_smtp._tls.{domain}", "TXT") if record.lower().startswith("v=tlsrptv1")]
        bimi = await self._safe(f"default._bimi.{domain}", "TXT")
        policy_text = ""
        if mta_sts:
            try:
                policy_text = await self.net.get_text(f"https://mta-sts.{domain}/.well-known/mta-sts.txt", cache_ttl=1800, timeout=10)
            except IntelError:
                policy_text = ""

        lookup_mechanisms = {"include", "a", "mx", "ptr", "exists", "redirect"}
        spf_lookups = 0
        spf_all = None
        if spf:
            for token in spf.split()[1:]:
                if token.split(":")[0].lstrip("+-~?") in lookup_mechanisms:
                    spf_lookups += 1
                if token.lstrip("+-~?") == "all":
                    spf_all = token[0]

        dmarc_policy = dmarc_tags.get("p", "none").lower()
        checklist = [
            (bool(mx), "MX records", f"{len(mx)} exchanger(s)" if mx else "domain cannot receive mail"),
            (bool(spf), "SPF policy", f"{spf_lookups} DNS lookups, terminal {spf_all or '?'}all" if spf else "not published"),
            (spf is not None and spf_all in {"-", "~"} and spf_lookups <= 10, "SPF strength", "strict with budget headroom" if spf else "n/a"),
            (bool(dmarc_records), "DMARC policy", f"p={dmarc_policy}" if dmarc_records else "not published"),
            (dmarc_policy in {"quarantine", "reject"}, "DMARC enforcement", dmarc_policy),
            (bool(dkim_found), "DKIM selectors", ", ".join(dkim_found) or "none of the common selectors"),
            (bool(ds), "DNSSEC", "signed" if ds else "unsigned"),
            (bool(mta_sts), "MTA-STS", "published" if mta_sts else "absent"),
            (bool(tls_rpt), "TLS-RPT", "published" if tls_rpt else "absent"),
            (bool(bimi), "BIMI", "published" if bimi else "absent"),
        ]
        weights = [8, 14, 14, 16, 10, 10, 8, 8, 6, 6]
        score = sum(weight for (state, _, _), weight in zip(checklist, weights) if state)
        embed = Intel(
            category="domain",
            command="emailposture",
            ctx=ctx,
            target=domain,
            summary="One score across the whole mail authentication stack. Each layer is independently useful, but only together do they stop spoofing.",
        )
        embed.checks("CONTROLS", checklist)
        embed.kv(
            "DETAIL",
            {
                "Mail provider": sorted({_provider(host, MAIL_PROVIDERS) for _, host in mx}) or "no MX",
                "DMARC rua": dmarc_tags.get("rua", "none"),
                "DMARC pct": dmarc_tags.get("pct", "100"),
                "MTA-STS mode": re.search(r"mode:\s*(\w+)", policy_text).group(1) if re.search(r"mode:\s*(\w+)", policy_text) else "n/a",
                "MTA-STS max_age": re.search(r"max_age:\s*(\d+)", policy_text).group(1) if re.search(r"max_age:\s*(\d+)", policy_text) else "n/a",
            },
            inline=True,
        )
        embed.risk(100 - score, name="SPOOF RISK", verdict="HARDENED" if score >= 90 else "PARTIAL" if score >= 55 else "EXPOSED")
        embed.steps(
            [
                "Collected MX, SPF and DMARC records",
                "Probed the conventional DKIM selectors",
                "Checked DNSSEC, MTA-STS, TLS-RPT and BIMI attestations",
                "Fetched the MTA-STS policy document over HTTPS",
                "Weighted each control into a single posture score",
            ]
        )
        embed.source("Cloudflare DoH", "direct HTTPS")
        await embed.send(ctx)


async def setup(bot: Any) -> None:
    await bot.add_cog(Domain(bot))

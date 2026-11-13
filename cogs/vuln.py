"""Vulnerability intelligence: CVEs, KEV, EPSS, CWE, malware and reputation."""

from __future__ import annotations

import base64
from datetime import timedelta
from typing import Any
from urllib.parse import quote

from discord.ext import commands

from config import settings
from core.command import intel
from core.cvss import base_score, describe, normalise
from core.embeds import Intel
from core.errors import IntelError, NotFound, NotConfigured, SourceUnavailable, UsageError
from core.utils import ack, clip, fmt_dt, num, require, utcnow

CVE_RE = r"CVE-\d{4}-\d{4,7}"


class Vulnerability(commands.Cog, name="Vulnerability"):
    """CVE, exploit and reputation intelligence from primary sources."""

    def __init__(self, bot: Any) -> None:
        self.bot = bot
        self.net = bot.net

    # ── helpers ──────────────────────────────────────────────────────────

    def _nvd_headers(self) -> dict[str, str]:
        headers = {"User-Agent": "OSINT-MATRIX/1.0", "Accept": "application/json"}
        if settings.has("NVD_API_KEY"):
            headers["apiKey"] = settings.key("NVD_API_KEY")
        return headers

    async def _nvd(self, params: dict[str, Any]) -> dict[str, Any]:
        return await self.net.get_json(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params=params,
            headers=self._nvd_headers(),
            cache_ttl=900,
            timeout=35,
        )

    @staticmethod
    def _metrics(vuln: dict[str, Any]) -> dict[str, Any]:
        metrics = vuln.get("metrics") or {}
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key) or []
            if entries:
                entry = entries[0]
                data = entry.get("cvssData") or {}
                return {
                    "version": data.get("version", key[-3:]),
                    "score": data.get("baseScore"),
                    "severity": data.get("baseSeverity") or entry.get("baseSeverity"),
                    "vector": data.get("vectorString"),
                    "attack_vector": data.get("attackVector") or data.get("accessVector"),
                    "attack_complexity": data.get("attackComplexity") or data.get("accessComplexity"),
                    "privileges": data.get("privilegesRequired") or data.get("authentication"),
                    "interaction": data.get("userInteraction"),
                    "scope": data.get("scope"),
                    "confidentiality": data.get("confidentialityImpact"),
                    "integrity": data.get("integrityImpact"),
                    "availability": data.get("availabilityImpact"),
                    "exploitability": entry.get("exploitabilityScore"),
                    "impact": entry.get("impactScore"),
                }
        return {}

    async def _epss(self, cve: str) -> dict[str, Any] | None:
        try:
            payload = await self.net.get_json(
                "https://api.first.org/data/v1/epss", params={"cve": cve}, cache_ttl=3600, timeout=15
            )
        except IntelError:
            return None
        data = payload.get("data") or []
        return data[0] if data else None

    async def _kev(self) -> dict[str, dict[str, Any]]:
        payload = await self.net.get_json(
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            cache_ttl=21_600,
            timeout=35,
        )
        return {item.get("cveID"): item for item in payload.get("vulnerabilities") or []}

    # ── CVE ──────────────────────────────────────────────────────────────

    @intel(
        category="vuln",
        brief="Full CVE dossier: description, CVSS, CWE, CPE exposure, EPSS and KEV status.",
        usage="<cve id>",
        aliases=["cveinfo", "vuln"],
        examples=["cve CVE-2021-44228"],
        sources=["NIST NVD", "FIRST EPSS", "CISA KEV"],
        cooldown=(2, 15),
    )
    async def cve(self, ctx: commands.Context, target: str = None) -> None:
        await ack(ctx)
        raw = require(target, "CVE ID", example=".cve CVE-2021-44228").strip().upper()
        if not __import__("re").fullmatch(CVE_RE, raw):
            raise UsageError("CVE IDs look like `CVE-2021-44228`.")
        payload = await self._nvd({"cveId": raw})
        items = payload.get("vulnerabilities") or []
        if not items:
            raise NotFound(f"NVD has no record for `{raw}`.")
        vuln = items[0].get("cve") or {}
        description = next(
            (entry.get("value") for entry in vuln.get("descriptions") or [] if entry.get("lang") == "en"),
            "no description",
        )
        metrics = self._metrics(vuln)
        epss = await self._epss(raw)
        kev_entry = None
        try:
            kev_entry = (await self._kev()).get(raw)
        except IntelError:
            kev_entry = None
        weaknesses = sorted(
            {
                entry.get("value")
                for weakness in vuln.get("weaknesses") or []
                for entry in weakness.get("description") or []
                if entry.get("value", "").startswith("CWE")
            }
        )
        configurations = vuln.get("configurations") or []
        cpe_count = sum(
            len(node.get("cpeMatch") or [])
            for config in configurations
            for node in config.get("nodes") or []
        )
        references = vuln.get("references") or []
        embed = Intel(
            category="vuln",
            command="cve",
            ctx=ctx,
            target=raw,
            summary=clip(description, 700),
        )
        embed.kv(
            "RECORD",
            {
                "ID": vuln.get("id", raw),
                "Status": vuln.get("vulnStatus"),
                "Published": fmt_dt(vuln.get("published")),
                "Modified": fmt_dt(vuln.get("lastModified")),
                "Source": vuln.get("sourceIdentifier"),
                "CWE": weaknesses or "not assigned",
                "CPE matches": cpe_count,
                "References": len(references),
            },
            inline=True,
        )
        if metrics:
            embed.kv(
                "CVSS",
                {
                    "Version": metrics.get("version"),
                    "Base score": metrics.get("score"),
                    "Severity": metrics.get("severity"),
                    "Vector": metrics.get("vector"),
                    "Attack vector": metrics.get("attack_vector"),
                    "Complexity": metrics.get("attack_complexity"),
                    "Privileges": metrics.get("privileges"),
                    "User interaction": metrics.get("interaction"),
                    "Scope": metrics.get("scope"),
                    "C / I / A": f"{metrics.get('confidentiality')} / {metrics.get('integrity')} / {metrics.get('availability')}",
                },
                inline=True,
            )
        embed.kv(
            "EXPLOITATION",
            {
                "EPSS score": f"{float(epss['epss']) * 100:.2f}%" if epss else "unavailable",
                "EPSS percentile": f"{float(epss['percentile']) * 100:.1f}%" if epss else "unavailable",
                "EPSS date": epss.get("date") if epss else None,
                "CISA KEV": "listed" if kev_entry else "not listed",
                "Ransomware use": kev_entry.get("knownRansomwareCampaignUse") if kev_entry else None,
                "KEV due date": kev_entry.get("dueDate") if kev_entry else None,
            },
            inline=True,
        )
        if kev_entry:
            embed.text(
                "KEV REQUIRED ACTION",
                f"**{kev_entry.get('vulnerabilityName')}**\n{clip(kev_entry.get('requiredAction') or '', 500)}",
                inline=False,
            )
        if references:
            embed.code(
                "REFERENCES",
                "\n".join(clip(reference.get("url", ""), 110) for reference in references[:10]),
                lang="yaml",
            )
        score = float(metrics.get("score") or 0)
        if epss:
            score = max(score, float(epss.get("epss") or 0) * 10)
        embed.risk(min(100, score * 10), name="PRIORITY INDEX", verdict=(metrics.get("severity") or "UNSCORED"))
        embed.checks(
            "TRIAGE",
            [
                (kev_entry is not None, "Known exploited", "CISA KEV" if kev_entry else "not in KEV"),
                (bool(epss and float(epss.get("epss") or 0) > 0.1), "High exploitation probability", f"EPSS {float(epss['epss']) * 100:.1f}%" if epss else "no EPSS"),
                (bool(configurations), "Product coverage", f"{cpe_count} CPE matches"),
                (None, "Note", "CVSS measures severity, EPSS measures likelihood — triage needs both"),
            ],
        )
        embed.source("NVD", "FIRST EPSS", "CISA KEV")
        await embed.send(ctx)

    @intel(
        category="vuln",
        brief="Keyword search across the NVD CVE corpus.",
        usage="<keyword>",
        aliases=["searchcve"],
        examples=["cves earch apache struts"],
        sources=["NIST NVD"],
        cooldown=(2, 20),
    )
    async def cvesearch(self, ctx: commands.Context, *, target: str = None) -> None:
        await ack(ctx)
        keyword = require(target, "keyword", example=".cvesearch apache struts")
        payload = await self._nvd({"keywordSearch": keyword, "resultsPerPage": 20})
        items = payload.get("vulnerabilities") or []
        if not items:
            raise NotFound(f"NVD returned no CVE matching `{clip(keyword, 60)}`.")
        rows = []
        for item in items:
            vuln = item.get("cve") or {}
            metrics = self._metrics(vuln)
            description = next(
                (entry.get("value") for entry in vuln.get("descriptions") or [] if entry.get("lang") == "en"), ""
            )
            rows.append(
                f"{vuln.get('id', '?')}  {str(metrics.get('score') or '-'):>4}  "
                f"{str(metrics.get('severity') or '-'):8}  {str(vuln.get('published') or '')[:10]}  {clip(description, 90)}"
            )
        embed = Intel(
            category="vuln",
            command="cvesearch",
            ctx=ctx,
            target=clip(keyword, 80),
            summary=f"NVD reports {num(payload.get('totalResults'))} matches. The newest page is shown; refine the keyword for precision.",
        )
        embed.code("RESULTS", "\n".join(rows), lang="yaml")
        embed.kv(
            "QUERY",
            {
                "Keyword": keyword,
                "Total results": num(payload.get("totalResults")),
                "Returned": len(items),
                "Rate limit": "50 req/30 s with NVD_API_KEY" if settings.has("NVD_API_KEY") else "5 req/30 s unauthenticated",
            },
            inline=True,
        )
        embed.source("NVD")
        await embed.send(ctx)

    @intel(
        category="vuln",
        brief="CVEs published in the last seven days, ranked by CVSS.",
        usage="",
        aliases=["recentcves", "latest"],
        sources=["NIST NVD"],
        cooldown=(1, 30),
    )
    async def nvdrecent(self, ctx: commands.Context) -> None:
        await ack(ctx)
        end = utcnow()
        start = end - timedelta(days=7)
        payload = await self._nvd(
            {
                "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
                "pubEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000"),
                "noRejected": "",
                "resultsPerPage": 40,
            }
        )
        items = payload.get("vulnerabilities") or []
        if not items:
            raise NotFound("NVD returned no CVEs for the last seven days.")
        ranked = []
        for item in items:
            vuln = item.get("cve") or {}
            metrics = self._metrics(vuln)
            ranked.append((float(metrics.get("score") or 0), vuln.get("id", "?"), metrics.get("severity"), vuln.get("published")))
        ranked.sort(reverse=True)
        embed = Intel(
            category="vuln",
            command="nvdrecent",
            ctx=ctx,
            target=f"{start:%Y-%m-%d} → {end:%Y-%m-%d}",
            summary="A weekly pulse on newly published vulnerabilities. High CVSS in a fresh CVE is where patching effort usually pays off first.",
        )
        embed.code(
            "RANKED",
            "\n".join(
                f"{score:>4.1f}  {cve:18}  {str(severity or '-'):9}  {str(published or '')[:10]}"
                for score, cve, severity, published in ranked[:20]
            ),
            lang="yaml",
        )
        embed.kv(
            "WINDOW",
            {
                "From": f"{start:%Y-%m-%d %H:%M} UTC",
                "To": f"{end:%Y-%m-%d %H:%M} UTC",
                "Total returned": len(items),
                "Critical": sum(1 for score, _, _, _ in ranked if score >= 9),
                "High": sum(1 for score, _, _, _ in ranked if 7 <= score < 9),
            },
            inline=True,
        )
        embed.source("NVD")
        await embed.send(ctx)

    @intel(
        category="vuln",
        brief="Search the CISA Known Exploited Vulnerabilities catalogue.",
        usage="<cve|product>",
        aliases=["known-exploited"],
        examples=["kev CVE-2021-44228", "kev log4j"],
        sources=["CISA KEV"],
        cooldown=(2, 20),
    )
    async def kev(self, ctx: commands.Context, target: str = None) -> None:
        await ack(ctx)
        query = require(target, "CVE or product keyword", example=".kev CVE-2021-44228")
        catalogue = await self._kev()
        upper = query.strip().upper()
        if upper.startswith("CVE-"):
            matches = [catalogue[upper]] if upper in catalogue else []
        else:
            lowered = query.lower()
            matches = [
                item
                for item in catalogue.values()
                if lowered in str(item.get("vendorProject", "")).lower()
                or lowered in str(item.get("product", "")).lower()
                or lowered in str(item.get("vulnerabilityName", "")).lower()
            ]
        if not matches:
            raise NotFound(f"No KEV entry matches `{clip(query, 60)}`.")
        embed = Intel(
            category="vuln",
            command="kev",
            ctx=ctx,
            target=clip(query, 60),
            summary=f"{len(matches)} catalogue match(es). KEV means exploitation has been observed in the wild — it is not a severity score.",
        )
        rows = []
        for item in matches[:10]:
            rows.append(
                f"{item.get('cveID')}  {str(item.get('dateAdded')):10}  due {str(item.get('dueDate')):10}  "
                f"{clip(item.get('vendorProject') + ' ' + item.get('product'), 34)}  "
                f"ransomware={item.get('knownRansomwareCampaignUse')}"
            )
        embed.code("CATALOGUE MATCHES", "\n".join(rows), lang="yaml")
        embed.kv(
            "CATALOGUE",
            {
                "Total entries": num(len(catalogue)),
                "Matches": len(matches),
                "Ransomware-linked": sum(1 for item in matches if item.get("knownRansomwareCampaignUse") == "Known"),
                "Oldest match": min((str(item.get("dateAdded")) for item in matches), default="n/a"),
            },
            inline=True,
        )
        first = matches[0]
        embed.text(
            "REQUIRED ACTION",
            f"**{first.get('vulnerabilityName')}**\n{clip(first.get('requiredAction') or '', 500)}",
            inline=False,
        )
        embed.source("CISA KEV")
        await embed.send(ctx)

    @intel(
        category="vuln",
        brief="EPSS exploitation probability for a CVE with percentile context.",
        usage="<cve>",
        aliases=["exploitprob"],
        examples=["epss CVE-2021-44228"],
        sources=["FIRST EPSS"],
        cooldown=(3, 15),
    )
    async def epss(self, ctx: commands.Context, target: str = None) -> None:
        await ack(ctx)
        cve = require(target, "CVE ID", example=".epss CVE-2021-44228").strip().upper()
        if not __import__("re").fullmatch(CVE_RE, cve):
            raise UsageError("CVE IDs look like `CVE-2021-44228`.")
        payload = await self.net.get_json(
            "https://api.first.org/data/v1/epss", params={"cve": cve}, cache_ttl=3600, expect=False
        )
        data = payload.get("data") or []
        if not data:
            raise NotFound(f"EPSS has no score for `{cve}` yet.")
        entry = data[0]
        score = float(entry.get("epss") or 0) * 100
        percentile = float(entry.get("percentile") or 0) * 100
        embed = Intel(
            category="vuln",
            command="epss",
            ctx=ctx,
            target=cve,
            summary="EPSS estimates the probability that this CVE is exploited in the next 30 days. It complements, never replaces, CVSS.",
        )
        embed.kv(
            "PROBABILITY",
            {
                "EPSS score": f"{score:.3f}%",
                "Percentile": f"{percentile:.1f}%",
                "Score date": entry.get("date"),
                "Model": payload.get("status") or "EPSS v3",
                "Interpretation": "higher than most CVEs" if percentile > 80 else "typical" if percentile > 40 else "lower than most",
            },
            inline=True,
        )
        embed.risk(score * 10 if score < 10 else 100, name="EXPLOITATION LIKELIHOOD", verdict=f"{score:.2f}%")
        embed.checks(
            "TRIAGE",
            [
                (percentile > 90, "Top decile", f"{percentile:.1f}th percentile"),
                (score > 10, "Meaningful probability", f"{score:.2f}% in 30 days"),
                (None, "Pair with", "KEV membership and asset exposure decide actual priority"),
            ],
        )
        embed.source("FIRST EPSS")
        await embed.send(ctx)

    @intel(
        category="vuln",
        brief="CWE weakness definition, consequences and mitigations.",
        usage="<cwe id>",
        aliases=["weakness"],
        examples=["cwe 79"],
        sources=["cwe-api.mitre.org"],
        cooldown=(3, 12),
    )
    async def cwe(self, ctx: commands.Context, target: str = None) -> None:
        await ack(ctx)
        raw = require(target, "CWE number", example=".cwe 79").strip().upper().replace("CWE-", "")
        if not raw.isdigit():
            raise UsageError("Supply a numeric CWE, e.g. `79`.")
        payload = await self.net.get_json(
            f"https://cwe-api.mitre.org/api/v1/cwe/weakness/{raw}", cache_ttl=86_400, expect=False
        )
        if not payload or not payload.get("WeaknessID"):
            raise NotFound(f"MITRE has no weakness numbered `{raw}`.")
        consequences = []
        for entry in payload.get("CommonConsequences") or []:
            scopes = ", ".join(scope.get("Scope", "") for scope in entry.get("Scope") or [])
            impacts = ", ".join(impact.get("Impact", "") for impact in entry.get("Impact") or [])
            if scopes or impacts:
                consequences.append(f"{scopes}: {impacts}")
        mitigations = [
            f"{entry.get('Phase')}: {clip(entry.get('Description') or '', 160)}"
            for entry in payload.get("PotentialMitigations") or []
        ]
        embed = Intel(
            category="vuln",
            command="cwe",
            ctx=ctx,
            target=f"CWE-{payload.get('WeaknessID')}",
            summary=f"**{payload.get('Name')}**\n{clip(payload.get('Description') or '', 600)}",
        )
        embed.kv(
            "TAXONOMY",
            {
                "ID": f"CWE-{payload.get('WeaknessID')}",
                "Name": payload.get("Name"),
                "Abstraction": payload.get("WeaknessAbstraction"),
                "Status": payload.get("Status"),
                "Structure": payload.get("Structure"),
                "Related": [
                    f"{item.get('Nature')}: CWE-{item.get('CWE_ID')}"
                    for item in (payload.get("RelatedWeaknesses") or [])[:8]
                ] or "none",
            },
            inline=True,
        )
        if payload.get("ExtendedDescription"):
            embed.text("EXTENDED DESCRIPTION", clip(payload["ExtendedDescription"], 700), inline=False)
        if consequences:
            embed.text("CONSEQUENCES", "\n".join(f"• {clip(item, 180)}" for item in consequences[:6]), inline=False)
        if mitigations:
            embed.text("MITIGATIONS", "\n".join(f"• {clip(item, 200)}" for item in mitigations[:6]), inline=False)
        platforms = [
            f"{entry.get('Type')}: {', '.join(entry.get('Class') or [])}"
            for entry in payload.get("Platforms") or []
        ]
        embed.kv("PLATFORMS", {"Applies to": platforms[:5] or "technology-agnostic"}, inline=True)
        embed.source("MITRE CWE")
        await embed.send(ctx)

    @intel(
        category="vuln",
        brief="Calculate a CVSS v3 base score from a vector string.",
        usage="<vector>",
        aliases=["cvsscalc"],
        examples=["cvss CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"],
        sources=["local computation"],
        cooldown=(4, 10),
    )
    async def cvss(self, ctx: commands.Context, target: str = None) -> None:
        await ack(ctx)
        raw = require(target, "CVSS vector", example=".cvss CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        try:
            vector = normalise(raw)
            score, severity, _ = base_score(vector)
            rows = describe(vector)
        except ValueError as exc:
            raise UsageError(str(exc)) from None
        embed = Intel(
            category="vuln",
            command="cvss",
            ctx=ctx,
            target=clip(vector, 120),
            summary="Deterministic implementation of the CVSS v3.1 base metric equations.",
        )
        embed.kv(
            "SCORE",
            {"Base score": f"{score:.1f}", "Severity": severity, "Vector": vector},
            inline=True,
        )
        embed.checks("METRICS", [(None, f"{key} = {value}", label) for key, value, label in rows])
        embed.risk(score * 10, name="SEVERITY", verdict=severity)
        embed.code(
            "INTERPRETATION",
            f"Attack vector      {rows[0][2]}\n"
            f"Complexity         {rows[1][2]}\n"
            f"Privileges needed  {rows[2][2]}\n"
            f"User interaction   {rows[3][2]}\n"
            f"Scope              {rows[4][2]}\n"
            f"Impact C/I/A       {rows[5][2]} / {rows[6][2]} / {rows[7][2]}",
            lang="yaml",
        )
        embed.source("local computation")
        await embed.send(ctx)

    # ── reputation / malware ─────────────────────────────────────────────

    @intel(
        category="vuln",
        brief="MalwareBazaar sample metadata for a file hash.",
        usage="<hash>",
        aliases=["malwarebazaar", "sample"],
        examples=["bazaar 094fd325049b8a9cf6d1640cc527bc1e"],
        sources=["abuse.ch MalwareBazaar"],
        cooldown=(2, 20),
    )
    async def bazaar(self, ctx: commands.Context, target: str = None) -> None:
        await ack(ctx)
        digest = require(target, "file hash", example=".bazaar 094fd325049b8a9cf6d1640cc527bc1e").strip().lower()
        key = settings.key("ABUSECH_AUTH_KEY")
        if not key:
            raise NotConfigured(
                "ABUSECH_AUTH_KEY",
                "abuse.ch",
                "MalwareBazaar sample metadata and ThreatFox IOC correlation.",
                "https://auth.abuse.ch/",
            )
        response = await self.net.request(
            "POST",
            "https://mb-api.abuse.ch/api/v1/",
            data={"query": "get_info", "hash": digest},
            headers={"Auth-Key": key},
            cache_ttl=3600,
            timeout=25,
        )
        if not response.ok:
            raise SourceUnavailable(f"MalwareBazaar answered HTTP {response.status}.")
        payload = response.json()
        status = payload.get("query_status")
        if status == "hash_not_found":
            raise NotFound(f"MalwareBazaar has no sample with hash `{digest}`.")
        if status != "ok":
            raise IntelError(f"MalwareBazaar rejected the query (`{status}`).")
        sample = (payload.get("data") or [{}])[0]
        intelligence = sample.get("intelligence") or {}
        embed = Intel(
            category="vuln",
            command="bazaar",
            ctx=ctx,
            target=digest[:24] + ("…" if len(digest) > 24 else ""),
            summary="Community-submitted malware metadata. A match confirms the file's existence in the corpus, not that it is malicious in your context.",
        )
        embed.kv(
            "SAMPLE",
            {
                "Signature": sample.get("signature"),
                "File name": sample.get("file_name"),
                "File type": sample.get("file_type"),
                "MIME": sample.get("file_type_mime"),
                "Size": f"{num(sample.get('file_size'))} bytes",
                "First seen": fmt_dt(sample.get("first_seen")),
                "Last seen": fmt_dt(sample.get("last_seen")),
                "Reporter": sample.get("reporter"),
                "Origin": sample.get("origin_country"),
                "Delivery": sample.get("delivery_method"),
                "Tags": sample.get("tags") or "none",
            },
            inline=True,
        )
        embed.kv(
            "HASHES",
            {
                "SHA-256": sample.get("sha256_hash"),
                "SHA-1": sample.get("sha1_hash"),
                "MD5": sample.get("md5_hash"),
                "imphash": sample.get("imphash"),
                "TLSH": sample.get("tlsh"),
            },
            inline=False,
        )
        embed.kv(
            "INTELLIGENCE",
            {
                "Downloads": intelligence.get("downloads"),
                "Uploads": intelligence.get("uploads"),
                "Mail reports": intelligence.get("mail"),
                "Vendor intel": intelligence.get("vendor_intel") and list(intelligence["vendor_intel"])[:5] or None,
            },
            inline=True,
        )
        embed.checks(
            "TRIAGE",
            [
                (bool(intelligence.get("downloads")), "Downloaded elsewhere", num(intelligence.get("downloads"))),
                (None, "Handling", "never execute a sample outside an isolated analysis environment"),
                (None, "Pivot", f"search other hashes with `.bazaar {sample.get('sha1_hash') or '<sha1>'}`"),
            ],
        )
        embed.source("MalwareBazaar")
        await embed.send(ctx)

    @intel(
        category="vuln",
        brief="Passive urlscan.io search for scans touching a domain, IP or hash.",
        usage="<indicator>",
        name="urlscan",
        examples=["urlscan example.com"],
        sources=["urlscan.io API"],
        cooldown=(2, 20),
    )
    async def urlscan_cmd(self, ctx: commands.Context, target: str = None) -> None:
        await ack(ctx)
        indicator = require(target, "domain, IP or hash", example=".urlscan example.com").strip()
        if "." not in indicator and not indicator.isalnum():
            raise UsageError("That does not look like a domain, IP or hash.")
        if __import__("re").fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", indicator):
            query = f"ip:{indicator}"
        elif __import__("re").fullmatch(r"[a-fA-F0-9]{32,64}", indicator):
            query = f"hash:{indicator}"
        else:
            query = f"domain:{indicator}"
        headers = {"User-Agent": "OSINT-MATRIX/1.0"}
        if settings.has("URLSCAN_API_KEY"):
            headers["api-key"] = settings.key("URLSCAN_API_KEY")
        payload = await self.net.get_json(
            "https://urlscan.io/api/v1/search/",
            params={"q": query, "size": 20},
            headers=headers,
            cache_ttl=900,
            timeout=25,
            expect=False,
        )
        results = payload.get("results") or []
        total = int(payload.get("total") or 0)
        if not results:
            raise NotFound(f"urlscan.io has no scan matching `{query}`.")
        rows = []
        for result in results[:12]:
            page = result.get("page") or {}
            verdict = ((result.get("verdicts") or {}).get("overall") or {})
            rows.append(
                f"{str((result.get('task') or {}).get('time') or '')[:10]:10}  "
                f"score={str(verdict.get('score', '-')):>3}  malicious={str(verdict.get('malicious', '-')):5}  "
                f"{clip(page.get('domain') or page.get('url') or '?', 40)}"
            )
        embed = Intel(
            category="vuln",
            command="urlscan",
            ctx=ctx,
            target=indicator,
            summary="urlscan.io scans pages in a real browser and records every request. Search is passive; only submitting is an action.",
        )
        embed.code("RECENT SCANS", "\n".join(rows), lang="yaml")
        embed.kv(
            "CORPUS",
            {
                "Query": query,
                "Total scans": num(total),
                "Returned": len(results),
                "Malicious verdicts": sum(
                    1 for result in results if ((result.get("verdicts") or {}).get("overall") or {}).get("malicious")
                ),
                "Key": "configured" if settings.has("URLSCAN_API_KEY") else "unauthenticated (search only)",
            },
            inline=True,
        )
        first = results[0]
        embed.kv(
            "LATEST",
            {
                "Page": (first.get("page") or {}).get("url"),
                "Screenshot": (first.get("screenshot") or "") or "none",
                "Result": (first.get("result") or "") or "none",
                "Task": (first.get("task") or {}).get("url"),
            },
            inline=False,
        )
        embed.thumbnail((first.get("screenshot") or None))
        embed.source("urlscan.io")
        await embed.send(ctx)

    @intel(
        category="vuln",
        brief="VirusTotal multi-engine reputation for an IP, domain, URL or hash.",
        usage="<indicator>",
        aliases=["vt"],
        examples=["virustotal example.com", "virustotal 8.8.8.8"],
        sources=["VirusTotal API v3"],
        cooldown=(2, 20),
    )
    async def virustotal(self, ctx: commands.Context, target: str = None) -> None:
        await ack(ctx)
        indicator = require(target, "IP, domain, URL or hash", example=".virustotal example.com").strip()
        key = settings.key("VIRUSTOTAL_API_KEY")
        if not key:
            raise NotConfigured(
                "VIRUSTOTAL_API_KEY",
                "VirusTotal",
                "Multi-engine reputation for domains, URLs, IPs and file hashes.",
                "https://www.virustotal.com/gui/my-apikey",
            )
        if __import__("re").fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", indicator):
            kind, value = "ip_addresses", indicator
        elif __import__("re").fullmatch(r"[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}", indicator):
            kind, value = "files", indicator
        elif indicator.startswith(("http://", "https://")):
            kind, value = "urls", base64.urlsafe_b64encode(indicator.encode()).decode().rstrip("=")
        else:
            kind, value = "domains", indicator
        payload = await self.net.get_json(
            f"https://www.virustotal.com/api/v3/{kind}/{quote(value, safe='')}",
            headers={"x-apikey": key, "Accept": "application/json"},
            cache_ttl=1800,
            timeout=25,
        )
        attributes = payload.get("data", {}).get("attributes") or {}
        stats = attributes.get("last_analysis_stats") or {}
        total_engines = sum(int(value) for value in stats.values() if isinstance(value, (int, float)))
        embed = Intel(
            category="vuln",
            command="virustotal",
            ctx=ctx,
            target=clip(indicator, 80),
            summary="Aggregated verdicts from dozens of engines. A low detection count is not proof of safety; a high one is strong evidence of malice.",
        )
        embed.kv(
            "VERDICTS",
            {
                "Malicious": stats.get("malicious"),
                "Suspicious": stats.get("suspicious"),
                "Harmless": stats.get("harmless"),
                "Undetected": stats.get("undetected"),
                "Timeout": stats.get("timeout"),
                "Engines": total_engines,
                "Reputation": attributes.get("reputation"),
            },
            inline=True,
        )
        embed.kv(
            "OBJECT",
            {
                "Type": kind,
                "Meaningful name": attributes.get("meaningful_name") or attributes.get("id"),
                "First submission": fmt_dt(attributes.get("first_submission_date")),
                "Last analysis": fmt_dt(attributes.get("last_analysis_date")),
                "Creation": fmt_dt(attributes.get("creation_date")),
                "Tags": attributes.get("tags") or [],
                "Categories": list((attributes.get("categories") or {}).items())[:6] or [],
            },
            inline=True,
        )
        ratio = (stats.get("malicious") or 0) / total_engines * 100 if total_engines else 0
        embed.risk(min(100, ratio * 1.6), name="DETECTION RATIO", verdict=f"{ratio:.0f}% of engines")
        embed.source("VirusTotal")
        await embed.send(ctx)

    @intel(
        category="vuln",
        brief="Shodan host exposure: open ports, banners, hostnames and known vulnerabilities.",
        usage="<ip>",
        name="shodan",
        aliases=["shodanhost"],
        examples=["shodan 8.8.8.8"],
        sources=["Shodan API"],
        cooldown=(2, 20),
    )
    async def shodan_cmd(self, ctx: commands.Context, target: str = None) -> None:
        await ack(ctx)
        address = require(target, "IP address", example=".shodan 8.8.8.8").strip()
        key = settings.key("SHODAN_API_KEY")
        if not key:
            raise NotConfigured(
                "SHODAN_API_KEY",
                "Shodan",
                "Exposed-service and banner intelligence for a host.",
                "https://account.shodan.io",
            )
        payload = await self.net.get_json(
            f"https://api.shodan.io/shodan/host/{quote(address)}",
            params={"key": key},
            cache_ttl=1800,
            timeout=25,
        )
        embed = Intel(
            category="vuln",
            command="shodan",
            ctx=ctx,
            target=address,
            summary="Shodan records what a scanner saw. Open ports are exposure, not automatically a vulnerability.",
        )
        embed.kv(
            "HOST",
            {
                "Organisation": payload.get("org"),
                "ISP": payload.get("isp"),
                "ASN": payload.get("asn"),
                "Country": payload.get("country_name"),
                "City": payload.get("city"),
                "OS": payload.get("os"),
                "Hostnames": payload.get("hostnames") or [],
                "Domains": payload.get("domains") or [],
                "Tags": payload.get("tags") or [],
                "Last update": payload.get("last_update"),
            },
            inline=True,
        )
        embed.kv(
            "EXPOSURE",
            {
                "Open ports": payload.get("ports") or [],
                "Port count": len(payload.get("ports") or []),
                "Vulnerabilities": list((payload.get("vulns") or {}).keys())[:10] or "none reported",
                "Vuln count": len(payload.get("vulns") or {}),
            },
            inline=True,
        )
        services = []
        for banner in (payload.get("data") or [])[:8]:
            services.append(
                f"{banner.get('port'):>5}  {clip(str(banner.get('transport', '?')), 4):4}  "
                f"{clip(str(banner.get('product') or banner.get('module') or '?'), 20):20}  "
                f"{clip(str(banner.get('version') or ''), 12)}"
            )
        if services:
            embed.code("SERVICES", "\n".join(services), lang="yaml")
        embed.risk(min(100, len(payload.get("vulns") or {}) * 12), name="EXPOSURE INDEX")
        embed.source("Shodan")
        await embed.send(ctx)

    @intel(
        category="vuln",
        brief="AbuseIPDB reputation score and report breakdown for an IP.",
        usage="<ip>",
        aliases=["abuseip"],
        examples=["abuseipdb 1.1.1.1"],
        sources=["AbuseIPDB API"],
        cooldown=(2, 20),
    )
    async def abuseipdb(self, ctx: commands.Context, target: str = None) -> None:
        await ack(ctx)
        address = require(target, "IP address", example=".abuseipdb 1.1.1.1").strip()
        key = settings.key("ABUSEIPDB_API_KEY")
        if not key:
            raise NotConfigured(
                "ABUSEIPDB_API_KEY",
                "AbuseIPDB",
                "Abuse confidence score and report history for an IP address.",
                "https://www.abuseipdb.com/account/api",
            )
        payload = await self.net.get_json(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": address, "maxAgeInDays": 365},
            headers={"Key": key, "Accept": "application/json"},
            cache_ttl=3600,
            timeout=20,
        )
        data = payload.get("data") or {}
        score = int(data.get("abuseConfidenceScore") or 0)
        embed = Intel(
            category="vuln",
            command="abuseipdb",
            ctx=ctx,
            target=address,
            summary="Crowd-sourced abuse reports. A high score means many independent reporters flagged the address recently.",
        )
        embed.kv(
            "REPUTATION",
            {
                "Abuse confidence": f"{score}%",
                "Reports": num(data.get("totalReports")),
                "Distinct reporters": num(data.get("numDistinctUsers")),
                "Last reported": data.get("lastReportedAt"),
                "Whitelisted": data.get("isWhitelisted"),
            },
            inline=True,
        )
        embed.kv(
            "NETWORK",
            {
                "ISP": data.get("isp"),
                "Domain": data.get("domain"),
                "Usage type": data.get("usageType"),
                "Country": data.get("countryCode"),
                "Hostnames": data.get("hostnames") or [],
            },
            inline=True,
        )
        embed.risk(score, name="ABUSE INDEX", verdict="LOW" if score < 25 else "ELEVATED" if score < 75 else "HIGH")
        embed.checks(
            "TRIAGE",
            [
                (score == 0, "No abuse reports", f"{score}% confidence"),
                (bool(data.get("isWhitelisted")), "Whitelisted", "yes" if data.get("isWhitelisted") else "no"),
                (None, "Caveat", "shared hosting and NAT can implicate innocent neighbours"),
            ],
        )
        embed.source("AbuseIPDB")
        await embed.send(ctx)


async def setup(bot: Any) -> None:
    await bot.add_cog(Vulnerability(bot))

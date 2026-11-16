"""Anonymity detection for an IP address: VPN, proxy, Tor and datacenter.

Three layers, each best-effort and independently useful:

1. ``ipapi.is`` — the richest source, but the free tier without a key returns a
   short response without the flags. Used when ``IPAPI_IS_KEY`` is configured,
   which also gives the VPN provider name.
2. ``ipquery.io`` — keyless risk flags (VPN, proxy, Tor, datacenter) plus an
   aggregate risk score.
3. ``ip-api.com`` — keyless fallback that classifies proxy, hosting and mobile.

The layers are merged with OR semantics: a positive flag from any source is
kept, so a provider that misses one category cannot erase the others. Only
public addresses are classified; private and reserved space is reported
separately so a NAT address is never labelled a VPN.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Any

FLAG_WEIGHTS: tuple[tuple[str, int], ...] = (
    ("tor", 100),
    ("vpn", 88),
    ("proxy", 80),
    ("abuser", 70),
    ("datacenter", 55),
    ("mobile", 22),
)

LABELS: tuple[tuple[str, str], ...] = (
    ("tor", "Tor exit node"),
    ("vpn", "VPN egress"),
    ("proxy", "Proxy or relay"),
    ("abuser", "Flagged for abuse"),
    ("datacenter", "Datacenter or cloud"),
    ("mobile", "Mobile carrier"),
)


@dataclass
class Verdict:
    """Merged classification for one address."""

    address: str
    vpn: bool = False
    proxy: bool = False
    tor: bool = False
    datacenter: bool = False
    abuser: bool = False
    mobile: bool = False
    provider: str | None = None
    asn: str | None = None
    org: str | None = None
    country: str | None = None
    risk_score: int | None = None
    public: bool = True
    sources: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    # ── derived values ───────────────────────────────────────────────────

    def flags(self) -> list[str]:
        return [label for key, label in LABELS if getattr(self, key)]

    @property
    def flagged(self) -> bool:
        return bool(self.flags())

    @property
    def score(self) -> int:
        score = 5
        for key, weight in FLAG_WEIGHTS:
            if getattr(self, key):
                score = max(score, weight)
        if self.risk_score is not None:
            score = max(score, min(100, int(self.risk_score)))
        return score

    @property
    def label(self) -> str:
        if not self.public:
            return "Private or reserved address"
        for key, label in LABELS:
            if getattr(self, key):
                return label
        return "Residential or unclassified"

    @property
    def confidence(self) -> int:
        """How much the layered answer can be trusted as a single verdict."""
        if not self.sources:
            return 0
        if "ipapi.is" in self.sources:
            return 95
        if len([source for source in self.sources if source != "ipwho.is"]) >= 2:
            return 88
        return 72

    @property
    def headline(self) -> str:
        if not self.sources:
            return "No classification available"
        if self.flagged:
            return f"{self.label} · {self.confidence}% confidence"
        return f"Not anonymised · {self.confidence}% confidence"

    def detail(self) -> dict[str, Any]:
        """Key/value pairs for a report panel."""
        return {
            "Verdict": self.label,
            "Confidence": f"{self.confidence}%",
            "VPN": self.vpn,
            "Proxy": self.proxy,
            "Tor exit": self.tor,
            "Hosting / DC": self.datacenter,
            "Abuse history": self.abuser,
            "Mobile carrier": self.mobile,
        }

    def network(self) -> dict[str, Any]:
        return {
            "Provider": self.provider,
            "ASN": self.asn,
            "Organisation": self.org,
            "Country": self.country,
        }


def _clean(value: Any) -> str | None:
    text = str(value).strip() if value not in (None, "") else ""
    return text or None


async def _from_ipapi_is(http: Any, address: str, key: str) -> Verdict | None:
    """Full response only with a key; the anonymous tier has no flags."""
    if not key:
        return None
    payload = await http.get_json(
        "https://api.ipapi.is",
        params={"q": address, "key": key},
        cache_ttl=1800,
    )
    if not isinstance(payload, dict) or not payload.get("ip"):
        return None
    vpn_info = payload.get("vpn") if isinstance(payload.get("vpn"), dict) else {}
    company = payload.get("company") if isinstance(payload.get("company"), dict) else {}
    asn = payload.get("asn") if isinstance(payload.get("asn"), dict) else {}
    verdict = Verdict(
        address=address,
        vpn=bool(payload.get("is_vpn")),
        proxy=bool(payload.get("is_proxy")),
        tor=bool(payload.get("is_tor")),
        datacenter=bool(payload.get("is_datacenter")),
        abuser=bool(payload.get("is_abuser")),
        mobile=bool(payload.get("is_mobile")),
        provider=_clean(vpn_info.get("provider") or vpn_info.get("name") or company.get("name")),
        asn=f"AS{asn.get('asn')}" if asn.get("asn") else None,
        org=_clean(asn.get("org") or company.get("name")),
        country=_clean((payload.get("location") or {}).get("country") or payload.get("country")),
        sources=["ipapi.is"],
    )
    if verdict.flagged and not verdict.provider:
        verdict.provider = verdict.org
    return verdict


async def _from_ipquery(http: Any, address: str) -> Verdict | None:
    payload = await http.get_json(f"https://api.ipquery.io/{address}", cache_ttl=1800)
    if not isinstance(payload, dict) or not payload.get("ip"):
        return None
    risk = payload.get("risk") if isinstance(payload.get("risk"), dict) else {}
    isp = payload.get("isp") if isinstance(payload.get("isp"), dict) else {}
    location = payload.get("location") if isinstance(payload.get("location"), dict) else {}
    verdict = Verdict(
        address=address,
        vpn=bool(risk.get("is_vpn")),
        proxy=bool(risk.get("is_proxy")),
        tor=bool(risk.get("is_tor")),
        datacenter=bool(risk.get("is_datacenter")),
        mobile=bool(risk.get("is_mobile")),
        risk_score=int(risk["risk_score"]) if isinstance(risk.get("risk_score"), (int, float)) else None,
        asn=_clean(isp.get("asn")),
        org=_clean(isp.get("org") or isp.get("isp")),
        country=_clean(location.get("country") or location.get("country_code")),
        sources=["ipquery.io"],
    )
    if verdict.flagged and not verdict.provider:
        verdict.provider = verdict.org
    return verdict


async def _from_ip_api(http: Any, address: str) -> Verdict | None:
    payload = await http.get_json(
        f"http://ip-api.com/json/{address}",
        params={"fields": "status,country,countryCode,isp,org,as,proxy,hosting,mobile,query"},
        cache_ttl=1800,
    )
    if not isinstance(payload, dict) or payload.get("status") != "success":
        return None
    hosting = bool(payload.get("hosting"))
    proxy = bool(payload.get("proxy")) and not hosting
    verdict = Verdict(
        address=address,
        proxy=proxy,
        datacenter=hosting,
        mobile=bool(payload.get("mobile")),
        asn=_clean(payload.get("as")),
        org=_clean(payload.get("org") or payload.get("isp")),
        country=_clean(payload.get("country")),
        sources=["ip-api.com"],
    )
    if payload.get("proxy") and hosting:
        # ip-api marks public DNS and cloud ranges as proxies; that is hosting.
        verdict.notes.append("ip-api flagged this cloud range as a proxy; counted as hosting instead.")
    return verdict


def _merge(base: Verdict, extra: Verdict) -> Verdict:
    """Fold an additional source into the accumulated verdict."""
    base.vpn = base.vpn or extra.vpn
    base.proxy = base.proxy or extra.proxy
    base.tor = base.tor or extra.tor
    base.datacenter = base.datacenter or extra.datacenter
    base.abuser = base.abuser or extra.abuser
    base.mobile = base.mobile or extra.mobile
    base.provider = base.provider or extra.provider
    base.asn = base.asn or extra.asn
    base.org = base.org or extra.org
    base.country = base.country or extra.country
    if extra.risk_score is not None:
        base.risk_score = max(base.risk_score or 0, extra.risk_score)
    for source in extra.sources:
        if source not in base.sources:
            base.sources.append(source)
    base.notes.extend(extra.notes)
    return base


def is_public(address: str) -> bool:
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return False
    return not (
        parsed.is_private
        or parsed.is_loopback
        or parsed.is_link_local
        or parsed.is_reserved
        or parsed.is_multicast
        or parsed.is_unspecified
    )


async def detect(http: Any, address: str, *, key: str = "") -> Verdict:
    """Classify one address, merging every source that answers.

    A failed source is skipped rather than raised: the caller always gets a
    verdict object, and ``sources`` tells the report which layers replied.
    """
    verdict = Verdict(address=address, public=is_public(address))

    if not verdict.public:
        verdict.notes.append("Not globally routable; anonymity flags do not apply.")
        return verdict

    layers: list[tuple[str, Any]] = []
    if key:
        layers.append(("ipapi.is", _from_ipapi_is(http, address, key)))
    layers.append(("ipquery.io", _from_ipquery(http, address)))
    layers.append(("ip-api.com", _from_ip_api(http, address)))

    for name, awaited in layers:
        try:
            answer = await awaited
        except Exception:  # noqa: BLE001 - one provider must not sink the report
            verdict.notes.append(f"{name} did not answer.")
            continue
        if answer is not None:
            _merge(verdict, answer)

    if verdict.tor:
        verdict.notes.append("Tor exit nodes rotate; the same visitor may appear from another address next time.")
    if verdict.proxy and not verdict.vpn:
        verdict.notes.append("Open proxies are unstable and often shared; treat the address as a relay, not a person.")
    if verdict.datacenter and not (verdict.vpn or verdict.proxy or verdict.tor):
        verdict.notes.append("Datacenter ranges are normal for cloud hosts and crawlers; this alone is not evidence of evasion.")
    if verdict.vpn and not verdict.tor:
        verdict.notes.append("Commercial VPN egress is shared by many customers, so the address is not attributable to one person.")
    if not verdict.sources:
        verdict.notes.append("No anonymity provider replied; the classification is unknown rather than clean.")

    return verdict

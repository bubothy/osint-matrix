"""Network intelligence: addresses, routing, transport, TLS and edge."""

from __future__ import annotations

import asyncio
import ipaddress
import time
from http import HTTPStatus
from typing import Any

from discord.ext import commands

from core import dns
from core.command import intel
from core.embeds import Intel
from core.errors import IntelError, NotFound, SourceUnavailable, UsageError
from core.signatures import CDN_CNAME, COMMON_PORTS, DNSBL_ZONES, WAF_SIGNATURES
from core.tls import inspect as inspect_tls
from core.utils import (
    ack,
    as_int,
    base_domain,
    clip,
    ensure_url,
    fmt_dt,
    human_bytes,
    is_ip,
    is_private_ip,
    normalize_host,
    num,
    parse_ip,
    require,
    strip_target,
)


def _vcard(entity: dict[str, Any]) -> dict[str, str]:
    out: dict[str, str] = {}
    card = entity.get("vcardArray")
    if not card or len(card) < 2 or not isinstance(card[1], list):
        return out
    for item in card[1]:
        if isinstance(item, list) and len(item) >= 4:
            key = str(item[0]).lower()
            value = item[3]
            if isinstance(value, list):
                value = ", ".join(str(part) for part in value)
            out[key] = str(value)
    return out


def _entities(payload: dict[str, Any]) -> list[str]:
    lines: list[str] = []
    for entity in payload.get("entities") or []:
        card = _vcard(entity)
        roles = ", ".join(entity.get("roles") or []) or "entity"
        label = card.get("fn") or card.get("org") or entity.get("handle") or "unnamed"
        contact = card.get("email") or ""
        line = f"**{roles}** — {clip(label, 70)}"
        if contact:
            line += f" · `{clip(contact, 60)}`"
        lines.append(line)
    return lines


class Network(commands.Cog, name="Network"):
    """IP, ASN, routing, port, TLS and CDN intelligence."""

    def __init__(self, bot: Any) -> None:
        self.bot = bot
        self.net = bot.net

    # ── shared panels ────────────────────────────────────────────────────

    async def _ip_intel(self, target: str) -> dict[str, Any]:
        data = await self.net.get_json(f"https://ipwho.is/{target}", cache_ttl=1800)
        if not isinstance(data, dict) or data.get("success") is False:
            raise NotFound(f"`{target}` has no public geolocation record.")
        return data

    @staticmethod
    def _address_panel(embed: Intel, data: dict[str, Any]) -> None:
        conn = data.get("connection") or {}
        tz = data.get("timezone") or {}
        currency = data.get("currency") or {}
        embed.kv(
            "GEOLOCATION",
            {
                "Country": f"{data.get('country') or '—'} ({data.get('country_code') or '—'})",
                "Region": data.get("region"),
                "City": data.get("city"),
                "Postal": data.get("postal"),
                "Continent": data.get("continent"),
                "Coordinates": f"{data.get('latitude')}, {data.get('longitude')}",
                "EU member": data.get("is_eu"),
            },
            inline=True,
        )
        embed.kv(
            "OWNING NETWORK",
            {
                "ASN": f"AS{conn.get('asn')}" if conn.get("asn") else None,
                "Organisation": conn.get("org"),
                "ISP": conn.get("isp"),
                "Domain": conn.get("domain"),
                "Address type": data.get("type"),
            },
            inline=True,
        )
        embed.kv(
            "LOCALE",
            {
                "Timezone": tz.get("id"),
                "UTC offset": tz.get("utc"),
                "Local time": tz.get("current_time"),
                "Calling code": f"+{data.get('calling_code')}" if data.get("calling_code") else None,
                "Currency": f"{currency.get('name')} ({currency.get('code')})" if currency else None,
                "Capital": data.get("capital"),
                "Borders": ", ".join(data.get("borders") or []) or None,
            },
            inline=True,
        )
        security = data.get("security") or {}
        if security:
            embed.kv(
                "SECURITY POSTURE",
                {
                    "Proxy": security.get("proxy"),
                    "VPN": security.get("vpn"),
                    "Tor exit": security.get("tor"),
                    "Hosting / DC": security.get("hosting"),
                    "Anonymous": security.get("anonymous"),
                },
                inline=True,
            )
            score = 10
            if security.get("hosting"):
                score = 45
            if security.get("proxy"):
                score = 65
            if security.get("vpn"):
                score = 70
            if security.get("tor"):
                score = 95
            embed.risk(score, name="EXPOSURE INDEX", inline=True)

    async def _ptr_panel(self, embed: Intel, address: str) -> None:
        try:
            parsed = parse_ip(address)
            names = await dns.ptr(self.net, parsed.reverse_pointer)
        except (ValueError, IntelError):
            names = []
        if not names:
            embed.kv("REVERSE DNS", {"PTR": "none published"}, inline=False)
            return
        confirmed = []
        for name in names[:3]:
            try:
                resolved = await dns.address_records(self.net, name)
            except IntelError:
                resolved = {}
            values = (resolved.get("A") or []) + (resolved.get("AAAA") or [])
            confirmed.append(f"{name} → {', '.join(values) if values else 'no forward record'}")
        match = "yes" if any(address in line for line in confirmed) else "no (forward mismatch)"
        embed.kv(
            "REVERSE DNS",
            {"PTR": ", ".join(names), "Forward-confirmed": match, "Checks": confirmed},
            inline=False,
        )

    async def _ripestat(self, call: str, resource: str) -> dict[str, Any]:
        payload = await self.net.get_json(
            f"https://stat.ripe.net/data/{call}/data.json",
            params={"resource": resource},
            cache_ttl=3600,
            timeout=25,
        )
        if payload.get("status") != "ok":
            raise SourceUnavailable(
                f"RIPEstat returned status `{payload.get('status')}` for {resource}.",
                hint="The ASN may not be announced, or the service is briefly unavailable.",
            )
        return payload.get("data") or {}

    async def _cname_chain(self, host: str) -> list[str]:
        chain = [host]
        current = host
        for _ in range(6):
            try:
                records = await dns.values(self.net, current, "CNAME")
            except (NotFound, SourceUnavailable):
                break
            if not records:
                break
            current = records[0].rstrip(".")
            if current in chain:
                break
            chain.append(current)
        return chain

    # ── addresses ────────────────────────────────────────────────────────

    @intel(
        category="network",
        brief="Full address dossier: geography, owning network, security flags and reverse DNS.",
        usage="<ipv4|ipv6>",
        aliases=["ipinfo"],
        examples=["ip 1.1.1.1", "ip 2606:4700:4700::1111"],
        sources=["ipwho.is", "Cloudflare DoH"],
        cooldown=(4, 10),
    )
    async def ip(self, ctx: commands.Context, target: str = None) -> None:
        await ack(ctx)
        raw = require(target, "IP address", example=".ip 1.1.1.1")
        if not is_ip(raw):
            raise UsageError(f"`{clip(raw, 60)}` is not a valid IPv4 or IPv6 address.")
        data = await self._ip_intel(raw)
        embed = Intel(
            category="network",
            command="ip",
            ctx=ctx,
            target=raw,
            summary=(
                f"Address-level dossier for `{raw}`. Combines registry geography, the announcing network, "
                "anonymity signals and forward-confirmed reverse DNS."
            ),
        )
        self._address_panel(embed, data)
        await self._ptr_panel(embed, raw)
        embed.steps(
            [
                "Resolved the address family and validated it with Python's ipaddress module",
                "Queried ipwho.is for registry-backed geolocation and connection metadata",
                "Classified anonymity signals: proxy, VPN, Tor exit, hosting",
                "Built the in-addr.arpa / ip6.arpa name and requested the PTR record over DoH",
                "Forward-resolved each PTR target to confirm the loop closes",
            ]
        )
        if is_private_ip(raw):
            embed.quote("RFC 1918 / loopback / link-local space — this address is not globally routable, so geolocation will be empty or misleading.")
        embed.source("ipwho.is", "Cloudflare DoH")
        await embed.send(ctx)

    @intel(
        category="network",
        brief="Geolocation-first view of an address with map coordinates and locale detail.",
        usage="<ipv4|ipv6>",
        aliases=["geolocate", "loc"],
        examples=["geo 8.8.8.8"],
        sources=["ipwho.is"],
        cooldown=(4, 10),
    )
    async def geo(self, ctx: commands.Context, target: str = None) -> None:
        await ack(ctx)
        raw = require(target, "IP address", example=".geo 8.8.8.8")
        if not is_ip(raw):
            raise UsageError("Supply a literal IPv4 or IPv6 address.")
        data = await self._ip_intel(raw)
        lat, lon = data.get("latitude"), data.get("longitude")
        embed = Intel(
            category="network",
            command="geo",
            ctx=ctx,
            target=raw,
            summary="Registry-level location estimate. City accuracy varies by ISP and should be treated as a region, not a street address.",
        )
        embed.kv(
            "COORDINATES",
            {
                "Latitude": lat,
                "Longitude": lon,
                "Accuracy": "city / region (registry data)",
                "Map": f"https://www.google.com/maps?q={lat},{lon}" if lat is not None else None,
            },
            inline=True,
        )
        embed.kv(
            "PLACE",
            {
                "Country": data.get("country"),
                "Country code": data.get("country_code"),
                "Region": data.get("region"),
                "City": data.get("city"),
                "Postal": data.get("postal"),
                "Continent": data.get("continent"),
            },
            inline=True,
        )
        embed.kv(
            "LOCALE",
            {
                "Timezone": (data.get("timezone") or {}).get("id"),
                "UTC": (data.get("timezone") or {}).get("utc"),
                "Calling code": f"+{data.get('calling_code')}",
                "Currency": (data.get("currency") or {}).get("code"),
            },
            inline=True,
        )
        embed.steps(
            [
                "Validated the address literal",
                "Requested registry geolocation with the network block attached",
                "Separated country / region / city confidence",
                "Rendered coordinates for manual corroboration",
            ]
        )
        embed.source("ipwho.is")
        await embed.send(ctx)

    @intel(
        category="network",
        brief="Egress address of this bot instance, fully enriched.",
        usage="",
        aliases=["egress"],
        sources=["api.ipify.org", "ipwho.is"],
        cooldown=(3, 15),
    )
    async def myip(self, ctx: commands.Context) -> None:
        await ack(ctx)
        payload = await self.net.get_json("https://api.ipify.org?format=json", cache_ttl=60)
        address = payload.get("ip")
        if not address:
            raise IntelError("The egress resolver returned no address.")
        data = await self._ip_intel(address)
        embed = Intel(
            category="network",
            command="myip",
            ctx=ctx,
            target=address,
            summary="The public address this host presents to the internet. Useful for allow-listing the bot or verifying a VPN egress.",
        )
        self._address_panel(embed, data)
        embed.steps(
            [
                "Asked api.ipify.org which source address it observed",
                "Enriched that address through the same registry pipeline as `ip`",
                "Compared the result against the hosting/ASN flags to detect proxying",
            ]
        )
        embed.source("api.ipify.org", "ipwho.is")
        await embed.send(ctx)

    @intel(
        category="network",
        brief="Network block arithmetic for an address or CIDR: range, hosts, masks and reverse zone.",
        usage="<cidr|ip>",
        aliases=["cidr", "subnet"],
        examples=["netblock 192.0.2.0/24", "netblock 2001:db8::/32"],
        sources=["local computation"],
        cooldown=(4, 10),
    )
    async def netblock(self, ctx: commands.Context, target: str = None) -> None:
        await ack(ctx)
        raw = require(target, "CIDR or IP", example=".netblock 192.0.2.0/24")
        try:
            if "/" in raw:
                network = ipaddress.ip_network(raw, strict=False)
            else:
                address = ipaddress.ip_address(raw)
                network = ipaddress.ip_network(
                    f"{address}/24" if address.version == 4 else f"{address}/64", strict=False
                )
        except ValueError as exc:
            raise UsageError(f"`{clip(raw, 60)}` is not a valid network: {exc}") from None

        total = network.num_addresses
        usable = max(0, total - 2) if network.version == 4 and network.prefixlen <= 30 else total
        first = network.network_address
        last = network.broadcast_address if network.version == 4 else network[-1]
        embed = Intel(
            category="network",
            command="netblock",
            ctx=ctx,
            target=str(network),
            summary="Pure address arithmetic: exactly what this block contains, without contacting any registry.",
        )
        embed.kv(
            "BLOCK",
            {
                "Network": str(network),
                "Version": f"IPv{network.version}",
                "Prefix length": f"/{network.prefixlen}",
                "Netmask": str(network.netmask) if network.version == 4 else "n/a",
                "Wildcard": str(network.hostmask) if network.version == 4 else "n/a",
            },
            inline=True,
        )
        embed.kv(
            "RANGE",
            {
                "First address": str(first),
                "Last address": str(last),
                "Total addresses": num(total),
                "Usable hosts": num(usable),
                "Integer span": f"{int(first)} – {int(last)}",
            },
            inline=True,
        )
        embed.kv(
            "CLASSIFICATION",
            {
                "Private": network.is_private,
                "Global": network.is_global,
                "Loopback": network.is_loopback,
                "Link-local": network.is_link_local,
                "Multicast": network.is_multicast,
                "Reserved": network.is_reserved,
            },
            inline=True,
        )
        embed.kv(
            "DNS",
            {
                "Reverse zone": first.reverse_pointer.split(".", 1)[-1] if network.version == 4 else "ip6.arpa nibble zone",
                "PTR sample": first.reverse_pointer,
                "Base domain hint": base_domain(str(first)) if network.version == 4 else None,
            },
            inline=False,
        )
        embed.steps(
            [
                "Parsed the target as a strict network (host bits are masked, not rejected)",
                "Computed first, last, size and usable host counts",
                "Evaluated special-use flags from the ipaddress module",
                "Derived the reverse DNS zone for PTR enumeration",
            ]
        )
        if network.prefixlen <= 16 and network.version == 4:
            embed.quote("This is a very large block. Registry lookups against a whole /16 or wider will be truncated by the upstream API.")
        embed.source("local computation")
        await embed.send(ctx)

    @intel(
        category="network",
        brief="IPv6 structural analysis: scope, embedded IPv4, reverse nibble zone and RFC 5952 form.",
        usage="<ipv6>",
        aliases=["v6"],
        examples=["ipv6 2001:4860:4860::8888"],
        sources=["local computation", "ipwho.is"],
        cooldown=(4, 10),
    )
    async def ipv6(self, ctx: commands.Context, target: str = None) -> None:
        await ack(ctx)
        raw = require(target, "IPv6 address", example=".ipv6 2001:4860:4860::8888")
        try:
            address = ipaddress.IPv6Address(raw.strip().strip("[]"))
        except ValueError:
            raise UsageError("That is not a valid IPv6 address.") from None

        embedded = None
        if address.ipv4_mapped:
            embedded = f"IPv4-mapped → {address.ipv4_mapped}"
        elif address.sixtofour:
            embedded = f"6to4 → {address.sixtofour}"
        elif address.teredo:
            embedded = f"Teredo → server {address.teredo[0]}, client {address.teredo[1]}"

        scope = "global unicast"
        if address.is_private:
            scope = "unique local (fc00::/7)"
        elif address.is_link_local:
            scope = "link-local (fe80::/10)"
        elif address.is_multicast:
            scope = "multicast"
        elif address.is_loopback:
            scope = "loopback"
        elif address.is_reserved:
            scope = "reserved / special"

        embed = Intel(
            category="network",
            command="ipv6",
            ctx=ctx,
            target=address.compressed,
            summary="Structural decomposition of a 128-bit address, including the reverse nibble zone used for PTR records.",
        )
        embed.kv(
            "REPRESENTATION",
            {
                "Compressed (RFC 5952)": address.compressed,
                "Exploded": address.exploded,
                "Uppercase": address.exploded.upper(),
                "Integer": num(int(address)),
                "Hex": hex(int(address)),
            },
            inline=False,
        )
        embed.kv(
            "STRUCTURE",
            {
                "Scope": scope,
                "Prefix /64": f"{address}/64",
                "Interface ID": address.exploded.split(":")[-4:],
                "Embedded IPv4": embedded,
                "Global": address.is_global,
                "Multicast": address.is_multicast,
                "Link-local": address.is_link_local,
            },
            inline=True,
        )
        embed.kv(
            "REVERSE DNS",
            {
                "Nibble zone": ".".join(reversed(address.exploded.replace(":", ""))) + ".ip6.arpa",
                "PTR length": f"{len(address.exploded.replace(':', ''))} nibbles",
            },
            inline=True,
        )
        try:
            data = await self._ip_intel(address.compressed)
        except IntelError:
            data = None
        if data:
            embed.kv(
                "REGISTRY",
                {
                    "ASN": f"AS{(data.get('connection') or {}).get('asn')}",
                    "Organisation": (data.get("connection") or {}).get("org"),
                    "Country": data.get("country"),
                    "City": data.get("city"),
                },
                inline=False,
            )
        embed.steps(
            [
                "Parsed the address into a 128-bit integer",
                "Detected embedded transition formats (mapped, 6to4, Teredo)",
                "Classified scope against IANA special-purpose registries",
                "Built the ip6.arpa nibble zone for reverse lookups",
            ]
        )
        embed.source("local computation", "ipwho.is")
        await embed.send(ctx)

    @intel(
        category="network",
        brief="MAC address anatomy and IEEE OUI vendor resolution.",
        usage="<mac>",
        aliases=["oui"],
        examples=["mac 00:1A:2B:3C:4D:5E"],
        sources=["api.macvendors.com"],
        cooldown=(4, 10),
    )
    async def mac(self, ctx: commands.Context, target: str = None) -> None:
        await ack(ctx)
        raw = require(target, "MAC address", example=".mac 00:1A:2B:3C:4D:5E")
        digits = "".join(char for char in raw if char.isalnum()).upper()
        if len(digits) != 12 or any(char not in "0123456789ABCDEF" for char in digits):
            raise UsageError("A MAC address needs exactly 12 hexadecimal digits.")
        oui = digits[:6]
        nic = digits[6:]
        first_octet = int(digits[:2], 16)
        vendor = "unknown"
        try:
            vendor = (await self.net.get_text(f"https://api.macvendors.com/{':'.join(digits[i:i+2] for i in range(0, 12, 2))}", cache_ttl=86_400)).strip()
        except IntelError:
            vendor = "not present in the public OUI registry"

        embed = Intel(
            category="network",
            command="mac",
            ctx=ctx,
            target=raw,
            summary="MAC addresses identify a network interface, not a person. OUI data resolves the manufacturer block only.",
        )
        embed.kv(
            "ADDRESS",
            {
                "Normalised": ":".join(digits[i : i + 2] for i in range(0, 12, 2)),
                "Windows form": "-".join(digits[i : i + 2] for i in range(0, 12, 2)),
                "Cisco form": ".".join(digits[i : i + 4] for i in range(0, 12, 4)),
                "OUI": oui,
                "NIC": nic,
                "Vendor": vendor,
            },
            inline=False,
        )
        embed.kv(
            "BITS",
            {
                "First octet": f"0x{digits[:2]} ({first_octet:08b})",
                "Multicast bit": bool(first_octet & 0x01),
                "Locally administered": bool(first_octet & 0x02),
                "Address type": "group/multicast" if first_octet & 0x01 else "unicast",
            },
            inline=True,
        )
        embed.steps(
            [
                "Stripped separators and validated the 48-bit length",
                "Split the vendor OUI from the interface identifier",
                "Decoded the multicast and local-administration bits",
                "Resolved the OUI against the IEEE registry",
            ]
        )
        embed.source("api.macvendors.com")
        await embed.send(ctx)

    # ── routing ──────────────────────────────────────────────────────────

    @intel(
        category="network",
        brief="Autonomous system dossier: holder, registry, website, prefix and peer counts.",
        usage="<asn>",
        aliases=["whois-as"],
        examples=["asn 13335", "asn AS15169"],
        sources=["RIPEstat"],
        cooldown=(4, 10),
    )
    async def asn(self, ctx: commands.Context, target: str = None) -> None:
        await ack(ctx)
        asn = require(target, "ASN", example=".asn 13335").upper().replace("AS", "").strip()
        if not asn.isdigit():
            raise UsageError("ASN must be digits, e.g. `13335` or `AS13335`.")
        overview = await self._ripestat("as-overview", f"AS{asn}")
        prefix_data = await self._ripestat("announced-prefixes", f"AS{asn}")
        neighbour_data = await self._ripestat("asn-neighbours", f"AS{asn}")
        prefixes = [item.get("prefix") for item in prefix_data.get("prefixes") or [] if item.get("prefix")]
        neighbours = [
            item for item in neighbour_data.get("neighbours") or [] if item.get("asn") != int(asn)
        ]
        kinds: dict[str, int] = {}
        for item in neighbours:
            kinds[str(item.get("type") or "uncertain")] = kinds.get(str(item.get("type") or "uncertain"), 0) + 1
        block = overview.get("block") or {}
        embed = Intel(
            category="network",
            command="asn",
            ctx=ctx,
            target=f"AS{asn}",
            summary="Public routing identity: the holder, its registry block, announced address space and neighbour count.",
        )
        embed.kv(
            "ENTITY",
            {
                "ASN": f"AS{overview.get('resource', asn)}",
                "Holder": overview.get("holder"),
                "Type": overview.get("type"),
                "Announced": overview.get("announced"),
                "Registry": "RIPEstat / RIS",
            },
            inline=True,
        )
        embed.kv(
            "REGISTRY BLOCK",
            {
                "Range": block.get("resource"),
                "Description": block.get("desc"),
                "Registry name": block.get("name"),
            },
            inline=True,
        )
        embed.kv(
            "FOOTPRINT",
            {
                "Prefixes": len(prefixes),
                "IPv4": sum(1 for prefix in prefixes if ":" not in prefix),
                "IPv6": sum(1 for prefix in prefixes if ":" in prefix),
                "Neighbours": len(neighbours),
                "Upstream": kinds.get("left", 0),
                "Downstream": kinds.get("right", 0),
            },
            inline=True,
        )
        embed.code("PREFIX SAMPLE", "\n".join(prefixes[:12]) or "none announced", lang="yaml")
        embed.steps(
            [
                "Normalised the AS number",
                "Fetched the RIPEstat overview and registry block",
                "Collected announced prefixes from the RIS full feed",
                "Counted upstream/downstream neighbours",
            ]
        )
        embed.source("RIPEstat")
        await embed.send(ctx)

    @intel(
        category="network",
        brief="Every IPv4 and IPv6 prefix announced by an autonomous system.",
        usage="<asn>",
        aliases=["prefixes"],
        examples=["asnprefixes 15169"],
        sources=["RIPEstat"],
        cooldown=(4, 12),
    )
    async def asnprefixes(self, ctx: commands.Context, target: str = None) -> None:
        await ack(ctx)
        asn = require(target, "ASN", example=".asnprefixes 15169").upper().replace("AS", "").strip()
        if not asn.isdigit():
            raise UsageError("ASN must be numeric.")
        data = await self._ripestat("announced-prefixes", f"AS{asn}")
        prefixes = [item.get("prefix") for item in data.get("prefixes") or [] if item.get("prefix")]
        if not prefixes:
            raise NotFound(f"RIPEstat has no announced prefixes for AS{asn}.")
        v4 = sorted(
            [prefix for prefix in prefixes if ":" not in prefix],
            key=lambda prefix: int(prefix.split("/")[-1]) if "/" in prefix else 0,
        )
        v6 = sorted(
            [prefix for prefix in prefixes if ":" in prefix],
            key=lambda prefix: int(prefix.split("/")[-1]) if "/" in prefix else 0,
        )
        embed = Intel(
            category="network",
            command="asnprefixes",
            ctx=ctx,
            target=f"AS{asn}",
            summary=f"Address space advertised in BGP by AS{asn}: {len(v4)} IPv4 and {len(v6)} IPv6 announcements.",
        )
        embed.kv(
            "SUMMARY",
            {
                "IPv4 prefixes": len(v4),
                "IPv6 prefixes": len(v6),
                "Total": len(v4) + len(v6),
                "Widest IPv4": v4[:4] or "none",
                "Window": f"{str(data.get('earliest_time'))[:16]} → {str(data.get('latest_time'))[:16]}",
            },
            inline=True,
        )
        embed.code("IPv4 SAMPLE", "\n".join(v4[:18]) or "none", lang="yaml")
        if v6:
            embed.code("IPv6 SAMPLE", "\n".join(v6[:12]), lang="yaml")
        embed.steps(
            [
                "Requested announced prefixes from RIPEstat",
                "Separated IPv4 and IPv6 announcements",
                "Sorted by prefix length to surface the widest blocks",
                "Rendered the first page of each family",
            ]
        )
        embed.source("RIPEstat")
        await embed.send(ctx)

    @intel(
        category="network",
        brief="BGP peer relationships for an autonomous system.",
        usage="<asn>",
        aliases=["peers"],
        examples=["bgppeers 13335"],
        sources=["RIPEstat"],
        cooldown=(4, 12),
    )
    async def bgppeers(self, ctx: commands.Context, target: str = None) -> None:
        await ack(ctx)
        asn = require(target, "ASN", example=".bgppeers 13335").upper().replace("AS", "").strip()
        if not asn.isdigit():
            raise UsageError("ASN must be numeric.")
        data = await self._ripestat("asn-neighbours", f"AS{asn}")
        neighbours = [
            item for item in data.get("neighbours") or [] if item.get("asn") != int(asn)
        ]
        if not neighbours:
            raise NotFound(f"RIPEstat has no neighbour data for AS{asn}.")
        kinds: dict[str, int] = {}
        for item in neighbours:
            kinds[str(item.get("type") or "uncertain")] = kinds.get(str(item.get("type") or "uncertain"), 0) + 1
        top = sorted(neighbours, key=lambda item: int(item.get("power") or 0), reverse=True)[:10]

        async def holder(neighbour_asn: int) -> tuple[int, str]:
            try:
                overview = await self._ripestat("as-overview", f"AS{neighbour_asn}")
                return neighbour_asn, str(overview.get("holder") or "unknown")
            except IntelError:
                return neighbour_asn, "unknown"

        enriched = await asyncio.gather(*(holder(int(item["asn"])) for item in top))
        names = dict(enriched)
        embed = Intel(
            category="network",
            command="bgppeers",
            ctx=ctx,
            target=f"AS{asn}",
            summary="Neighbour relationships reveal transit providers, customers and settlement-free interconnects.",
        )
        embed.kv(
            "COUNTS",
            {
                "Neighbours": len(neighbours),
                "Upstream (left)": kinds.get("left", 0),
                "Downstream (right)": kinds.get("right", 0),
                "Uncertain": kinds.get("uncertain", 0),
                "Window": f"{str(data.get('earliest_time'))[:16]} → {str(data.get('latest_time'))[:16]}",
            },
            inline=True,
        )
        embed.code(
            "TOP BY VISIBILITY",
            "\n".join(
                f"AS{int(item['asn']):<7} {str(item.get('type') or '?'):9} power={int(item.get('power') or 0):<5} "
                f"v4={int(item.get('v4_peers') or 0):<4} v6={int(item.get('v6_peers') or 0):<3} {clip(names.get(int(item['asn']), 'unknown'), 34)}"
                for item in top
            ),
            lang="yaml",
        )
        embed.steps(
            [
                "Fetched the neighbour table from RIPEstat",
                "Classified each relationship as upstream, downstream or uncertain",
                "Ranked by visibility power and enriched the top ten with holder names",
            ]
        )
        embed.source("RIPEstat")
        await embed.send(ctx)

    @intel(
        category="network",
        brief="Reverse DNS with forward-confirmation of the pointer target.",
        usage="<ip>",
        aliases=["ptr", "reversedns"],
        examples=["rdns 8.8.8.8"],
        sources=["Cloudflare DoH"],
        cooldown=(4, 10),
    )
    async def rdns(self, ctx: commands.Context, target: str = None) -> None:
        await ack(ctx)
        raw = require(target, "IP address", example=".rdns 8.8.8.8")
        if not is_ip(raw):
            raise UsageError("Supply a literal IP address.")
        address = parse_ip(raw)
        names = await dns.ptr(self.net, address.reverse_pointer)
        embed = Intel(
            category="network",
            command="rdns",
            ctx=ctx,
            target=raw,
            summary="PTR records are published by the network owner and are not authoritative for identity. Forward confirmation is the only reliable check.",
        )
        if not names:
            embed.kv("PTR", {"Result": "no pointer published", "Zone": address.reverse_pointer}, inline=False)
        else:
            checks = []
            for name in names[:5]:
                try:
                    records = await dns.address_records(self.net, name)
                except IntelError:
                    records = {}
                values = (records.get("A") or []) + (records.get("AAAA") or [])
                checks.append(f"{name} → {', '.join(values) or 'unresolvable'}")
            embed.kv("PTR", {"Names": names, "Zone": address.reverse_pointer}, inline=False)
            embed.kv("FORWARD CONFIRMATION", {"Checks": checks}, inline=False)
            confirmed = any(raw in line for line in checks)
            embed.checks(
                "VERDICT",
                [
                    (confirmed, "Forward-confirmed", "the name resolves back to the same address" if confirmed else "the name resolves elsewhere — treat as stale"),
                    (None, "Zone", address.reverse_pointer),
                ],
            )
        embed.steps(
            [
                "Converted the address into its reverse DNS name",
                "Queried PTR over DNS-over-HTTPS",
                "Forward-resolved every returned name",
                "Compared the forward answer with the original address",
            ]
        )
        embed.source("Cloudflare DoH")
        await embed.send(ctx)

    # ── transport ────────────────────────────────────────────────────────

    @intel(
        category="network",
        brief="TCP reachability, handshake latency and service banner for a single port.",
        usage="<host> [port]",
        aliases=["port"],
        examples=["portcheck example.com 443", "portcheck 1.1.1.1 22"],
        sources=["direct TCP"],
        cooldown=(3, 10),
    )
    async def portcheck(self, ctx: commands.Context, target: str = None, port: str = None) -> None:
        await ack(ctx)
        host = normalize_host(require(target, "host", example=".portcheck example.com 443"))
        port_num = as_int(port, default=443, low=1, high=65535, label="port")
        started = time.perf_counter()
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port_num), timeout=7)
        except (OSError, asyncio.TimeoutError) as exc:
            raise SourceUnavailable(
                f"TCP connect to `{host}:{port_num}` failed ({type(exc).__name__}).",
                hint="Filtered ports usually time out; refused ports answer immediately with RST.",
            ) from exc
        latency = (time.perf_counter() - started) * 1000
        banner = ""
        try:
            chunk = await asyncio.wait_for(reader.read(256), timeout=1.5)
            banner = chunk.decode("utf-8", "replace").strip()
        except (asyncio.TimeoutError, OSError):
            banner = ""
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:  # noqa: BLE001 - teardown only
            pass
        service = COMMON_PORTS.get(port_num, "unknown / custom")
        embed = Intel(
            category="network",
            command="portcheck",
            ctx=ctx,
            target=f"{host}:{port_num}",
            summary="A single TCP handshake, not a scan. Only test hosts you own or have written authorisation to assess.",
        )
        embed.kv(
            "CONNECTION",
            {
                "Host": host,
                "Port": port_num,
                "Service": service,
                "State": "open",
                "Handshake": f"{latency:.1f} ms",
            },
            inline=True,
        )
        embed.kv(
            "BANNER",
            {"Length": human_bytes(len(banner)), "Preview": banner[:180] or "no banner sent before timeout"},
            inline=False,
        )
        embed.steps(
            [
                "Resolved the hostname through the system resolver",
                "Opened a single TCP connection with a 7 s ceiling",
                "Waited 1.5 s for a service banner on the raw socket",
                "Closed the connection without sending protocol payloads",
            ]
        )
        embed.quote("Authorisation reminder: probing systems you do not control may violate computer-misuse law and the target's terms of service.")
        embed.source("direct TCP")
        await embed.send(ctx)

    @intel(
        category="network",
        brief="Response headers, redirect chain and a security-header coverage count.",
        usage="<url|host>",
        aliases=["responseheaders"],
        examples=["headers example.com"],
        sources=["direct HTTP"],
        cooldown=(3, 10),
    )
    async def headers(self, ctx: commands.Context, target: str = None) -> None:
        await ack(ctx)
        url = ensure_url(require(target, "URL or host", example=".headers example.com"))
        response = await self.net.request("GET", url, cache=False, allow_redirects=True, timeout=20)
        embed = Intel(
            category="network",
            command="headers",
            ctx=ctx,
            target=clip(response.url, 120),
            summary="Raw HTTP response metadata exactly as the edge presented it.",
        )
        embed.kv(
            "RESPONSE",
            {
                "Status": f"{response.status} {self._phrase(response.status)}",
                "Protocol": response.http_version,
                "Content type": response.content_type or "—",
                "Bytes": human_bytes(response.bytes_read),
                "Elapsed": f"{response.elapsed_ms:.0f} ms",
                "Redirects": len(response.history),
            },
            inline=True,
        )
        security = ["strict-transport-security", "content-security-policy", "x-content-type-options", "x-frame-options", "referrer-policy", "permissions-policy"]
        present = [name for name in security if name in response.headers]
        embed.kv(
            "SECURITY HEADERS",
            {"Present": f"{len(present)}/{len(security)}", "Found": present, "Missing": [name for name in security if name not in response.headers]},
            inline=True,
        )
        if response.history:
            embed.steps(response.history + [response.url], name="REDIRECT CHAIN")
        embed.code("HEADERS", "\n".join(f"{key}: {value}" for key, value in sorted(response.headers.items())), lang="yaml")
        embed.source("direct HTTP")
        await embed.send(ctx)

    @staticmethod
    def _phrase(status: int) -> str:
        try:
            return HTTPStatus(status).phrase
        except ValueError:
            return ""

    @intel(
        category="network",
        brief="Status code, redirect hops, protocol and transfer timing for a URL.",
        usage="<url>",
        aliases=["http"],
        examples=["httpstatus https://example.com"],
        sources=["direct HTTP"],
        cooldown=(3, 10),
    )
    async def httpstatus(self, ctx: commands.Context, target: str = None) -> None:
        await ack(ctx)
        url = ensure_url(require(target, "URL", example=".httpstatus https://example.com"))
        response = await self.net.request("GET", url, cache=False, allow_redirects=True, timeout=20)
        embed = Intel(
            category="network",
            command="httpstatus",
            ctx=ctx,
            target=clip(url, 120),
            summary="Transport-level health check with the full redirect ladder.",
        )
        embed.kv(
            "OUTCOME",
            {
                "Status": f"{response.status} {self._phrase(response.status)}",
                "OK": response.ok,
                "Protocol": response.http_version,
                "Final URL": clip(response.url, 90),
                "TTFB + body": f"{response.elapsed_ms:.0f} ms",
                "Payload": human_bytes(response.bytes_read),
            },
            inline=True,
        )
        embed.kv(
            "HEADERS OF INTEREST",
            {
                "Server": response.headers.get("server"),
                "Cache": response.headers.get("cache-control"),
                "CDN": response.headers.get("cf-ray") or response.headers.get("x-vercel-id") or response.headers.get("x-amz-cf-id"),
                "Content type": response.content_type,
                "Encoding": response.headers.get("content-encoding"),
            },
            inline=True,
        )
        if response.history:
            embed.steps(
                [f"`{status}` final → {clip(url, 100)}" for status in [response.status] for url in [response.url]]
                + [f"hop → {clip(hop, 100)}" for hop in response.history],
                name="REDIRECT LADDER",
            )
        else:
            embed.field("▸ REDIRECT LADDER", "`00` direct response — no redirects", inline=False)
        embed.steps(
            [
                "Issued a plain GET with redirects enabled",
                "Recorded each hop and the final destination",
                "Captured protocol, encoding and payload size",
            ]
        )
        embed.source("direct HTTP")
        await embed.send(ctx)

    @intel(
        category="network",
        brief="TLS certificate and protocol inspection: issuer, SANs, expiry, ciphers, fingerprints.",
        usage="<host> [port]",
        aliases=["cert", "ssl"],
        examples=["tls example.com", "tls example.com 8443"],
        sources=["direct TLS handshake"],
        cooldown=(3, 10),
    )
    async def tls(self, ctx: commands.Context, target: str = None, port: str = None) -> None:
        await ack(ctx)
        host = normalize_host(require(target, "host", example=".tls example.com"))
        port_num = as_int(port, default=443, low=1, high=65535, label="port")
        cert = await inspect_tls(host, port_num, timeout=12)
        embed = Intel(
            category="network",
            command="tls",
            ctx=ctx,
            target=f"{host}:{port_num}",
            summary="Live handshake inspection. Everything below was read from the certificate the server actually presented.",
        )
        embed.kv(
            "SUBJECT",
            {
                "Common name": cert.get("common_name"),
                "Distinguished name": cert.get("subject"),
                "SANs": len(cert.get("sans") or []),
                "SAN sample": (cert.get("sans") or [])[:12],
            },
            inline=False,
        )
        embed.kv(
            "ISSUER",
            {"Authority": cert.get("issuer"), "Serial": cert.get("serial")},
            inline=True,
        )
        embed.kv(
            "VALIDITY",
            {
                "Not before": fmt_dt(cert.get("valid_from")),
                "Not after": fmt_dt(cert.get("valid_to")),
                "Days left": cert.get("days_left"),
                "Expired": cert.get("expired"),
            },
            inline=True,
        )
        embed.kv(
            "PROTOCOL",
            {
                "Negotiated": cert.get("version"),
                "Cipher": cert.get("cipher"),
                "Key bits": cert.get("cipher_bits"),
                "TLS 1.2": cert.get("tls12"),
                "TLS 1.3": cert.get("tls13"),
                "Handshake": f"{cert.get('handshake_ms', 0):.0f} ms",
            },
            inline=True,
        )
        embed.code(
            "FINGERPRINTS",
            f"SHA-256  {cert.get('sha256')}\nSHA-1    {cert.get('sha1')}",
            lang="yaml",
            inline=False,
        )
        if cert.get("ocsp"):
            embed.field("▸ OCSP", str(cert["ocsp"])[:1024], inline=False)
        warnings = []
        if cert.get("expired"):
            warnings.append("Certificate has expired")
        elif (cert.get("days_left") or 0) < 30:
            warnings.append(f"Certificate expires in {cert.get('days_left')} days")
        if not cert.get("tls13"):
            warnings.append("TLS 1.3 is not offered")
        if "TLSv1.2" in str(cert.get("version")) and "TLSv1.3" not in str(cert.get("version")):
            warnings.append("Connection negotiated TLS 1.2 — check whether 1.3 is intentionally disabled")
        embed.checks(
            "POSTURE",
            [
                (not cert.get("expired"), "Validity window", f"{cert.get('days_left')} days remaining"),
                (bool(cert.get("tls13")), "TLS 1.3", "offered" if cert.get("tls13") else "not offered"),
                (bool(cert.get("tls12")), "TLS 1.2", "offered" if cert.get("tls12") else "not offered"),
                (None, "Warnings", "; ".join(warnings) if warnings else "none"),
            ],
        )
        embed.source("direct TLS handshake")
        await embed.send(ctx)

    @intel(
        category="network",
        brief="CDN and WAF fingerprinting from CNAME chains, headers and cookies.",
        usage="<host>",
        aliases=["edge"],
        examples=["cdn example.com"],
        sources=["Cloudflare DoH", "direct HTTP"],
        cooldown=(4, 12),
    )
    async def cdn(self, ctx: commands.Context, target: str = None) -> None:
        await ack(ctx)
        host = normalize_host(require(target, "host", example=".cdn example.com"))
        chain = await self._cname_chain(host)
        providers: list[str] = []
        evidence: list[str] = []
        for name in chain:
            for suffix, provider in CDN_CNAME:
                if name.endswith(suffix):
                    providers.append(provider)
                    evidence.append(f"CNAME `{clip(name, 50)}` matches {provider}")
        headers: dict[str, str] = {}
        waf_hits: list[str] = []
        status = None
        try:
            response = await self.net.get(f"https://{host}", cache=False, allow_redirects=True, timeout=15)
            headers = response.headers
            status = response.status
            for signature in WAF_SIGNATURES:
                if any(name in headers for name in signature.get("headers", [])):
                    waf_hits.append(signature["name"])
                    evidence.append(f"header marker for {signature['name']}")
                cookie_header = headers.get("set-cookie", "")
                if any(cookie.lower() in cookie_header.lower() for cookie in signature.get("cookies", [])):
                    waf_hits.append(signature["name"])
                    evidence.append(f"cookie marker for {signature['name']}")
        except IntelError:
            evidence.append("HTTP probe failed — edge verdict relies on DNS only")
        embed = Intel(
            category="network",
            command="cdn",
            ctx=ctx,
            target=host,
            summary="Edge fingerprints tell you who terminates TLS and filters traffic before your request reaches the origin.",
        )
        embed.kv(
            "DNS CHAIN",
            {"Hops": len(chain), "Chain": chain, "Providers": sorted(set(providers)) or "none matched"},
            inline=False,
        )
        embed.kv(
            "HTTP EDGE",
            {
                "Probe status": status,
                "Server": headers.get("server"),
                "CDN headers": [name for name in ("cf-ray", "x-amz-cf-id", "x-vercel-id", "x-fastly-request-id", "x-akamai-request-id") if name in headers],
                "WAF markers": sorted(set(waf_hits)) or "none",
            },
            inline=True,
        )
        embed.steps(evidence[:6] or ["No CDN or WAF fingerprint matched"], name="EVIDENCE")
        embed.checks(
            "VERDICT",
            [
                (bool(providers), "CDN fronted", ", ".join(sorted(set(providers))) or "no known CDN CNAME"),
                (bool(waf_hits), "WAF detected", ", ".join(sorted(set(waf_hits))) or "no WAF signature"),
                (None, "Origin exposure", "resolve historical DNS before assuming the origin is hidden"),
            ],
        )
        embed.source("Cloudflare DoH", "direct HTTP")
        await embed.send(ctx)

    @intel(
        category="network",
        brief="Check an address against fourteen DNS blocklists.",
        usage="<ip>",
        aliases=["blacklist", "dnsbl"],
        examples=["rbl 127.0.0.2"],
        sources=["14 DNSBL zones over DoH"],
        cooldown=(2, 20),
    )
    async def rbl(self, ctx: commands.Context, target: str = None) -> None:
        await ack(ctx)
        raw = require(target, "IPv4 address", example=".rbl 127.0.0.2")
        try:
            address = ipaddress.IPv4Address(raw)
        except ValueError:
            raise UsageError("DNSBL checks need a literal IPv4 address.") from None
        if address.is_private or address.is_loopback:
            raise UsageError("Private and loopback addresses are not listed on public blocklists.")
        reversed_ip = ".".join(reversed(str(address).split(".")))
        results: list[tuple[bool | None, str, str]] = []
        listed = 0
        for zone, name, note in DNSBL_ZONES:
            query_name = f"{reversed_ip}.{zone}"
            try:
                records = await dns.values(self.net, query_name, "A")
            except NotFound:
                results.append((False, name, "not listed"))
                continue
            except IntelError:
                results.append((None, name, "query failed"))
                continue
            if not records:
                results.append((False, name, "not listed"))
                continue
            codes = [record for record in records if record.startswith("127.")]
            if any(code.startswith("127.255.255.") for code in codes):
                results.append((None, name, "query refused — public resolver blocked"))
                continue
            listed += 1
            results.append((True, name, f"listed as {', '.join(codes)} · {note}"))
        embed = Intel(
            category="network",
            command="rbl",
            ctx=ctx,
            target=str(address),
            summary="DNS blocklists are reputation signals run by third parties. A listing is not proof of compromise.",
        )
        embed.kv(
            "SUMMARY",
            {"Zones queried": len(DNSBL_ZONES), "Listed": listed, "Clean": sum(1 for state, _, _ in results if state is False)},
            inline=True,
        )
        embed.checks("RESULTS", results)
        embed.steps(
            [
                "Reversed the octets into the DNSBL query format",
                "Queried every zone over DNS-over-HTTPS",
                "Interpreted 127.255.255.x as a refusal, not a listing",
                "Aggregated the verdict",
            ]
        )
        embed.source("14 DNSBL zones")
        await embed.send(ctx)

    @intel(
        category="network",
        brief="RDAP registration record for an IP: network block, holder, abuse contacts.",
        usage="<ip>",
        aliases=["ipwhois", "rdapip"],
        examples=["whoisip 1.1.1.1"],
        sources=["rdap.org"],
        cooldown=(4, 15),
    )
    async def whoisip(self, ctx: commands.Context, target: str = None) -> None:
        await ack(ctx)
        raw = require(target, "IP address", example=".whoisip 1.1.1.1")
        if not is_ip(raw):
            raise UsageError("Supply a literal IP address.")
        payload = await self.net.get_json(f"https://rdap.org/ip/{raw}", cache_ttl=3600)
        events = {event.get("eventAction"): event.get("eventDate") for event in payload.get("events") or []}
        embed = Intel(
            category="network",
            command="whoisip",
            ctx=ctx,
            target=raw,
            summary="Structured registration data (RDAP) — the modern, machine-readable replacement for port-43 WHOIS.",
        )
        embed.kv(
            "NETWORK",
            {
                "Handle": payload.get("handle"),
                "Name": payload.get("name"),
                "Start": payload.get("startAddress"),
                "End": payload.get("endAddress"),
                "Version": f"IPv{payload.get('ipVersion')}",
                "Type": payload.get("type"),
                "Country": payload.get("country"),
                "Parent": payload.get("parentHandle"),
            },
            inline=True,
        )
        embed.kv(
            "STATUS",
            {"Status": payload.get("status"), "Registered": events.get("registration"), "Last changed": events.get("last changed") or events.get("last-modified")},
            inline=True,
        )
        entities = _entities(payload)
        if entities:
            embed.text("ENTITIES", "\n".join(entities[:10]), inline=False)
        remarks = payload.get("remarks") or []
        if remarks:
            embed.text(
                "REMARKS",
                "\n\n".join(clip(" ".join(str(line) for line in remark.get("description") or []), 300) for remark in remarks[:3]),
                inline=False,
            )
        embed.steps(
            [
                "Resolved the address through the RDAP bootstrap service",
                "Extracted the network range and registration events",
                "Walked the entity graph for abuse and administrative contacts",
            ]
        )
        embed.source("rdap.org")
        await embed.send(ctx)


async def setup(bot: Any) -> None:
    await bot.add_cog(Network(bot))

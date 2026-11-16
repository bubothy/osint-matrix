"""TLS inspection over a plain socket.

Collects the leaf certificate, SANs, fingerprints, validity window, negotiated
cipher and whether TLS 1.2 / 1.3 are accepted.
"""

from __future__ import annotations

import asyncio
import hashlib
import socket
import ssl
import time
from datetime import datetime, timezone
from typing import Any

from core.errors import SourceUnavailable


def _flatten(name: Any) -> str:
    parts: list[str] = []
    if not name:
        return ""
    for rdn in name:
        for key, value in rdn:
            if key in {"commonName", "organizationName", "organizationalUnitName", "countryName"}:
                parts.append(f"{key}={value}")
    return ", ".join(parts)


def _sans(cert: dict[str, Any]) -> list[str]:
    out: list[str] = []
    for key, value in cert.get("subjectAltName", ()):  # type: ignore[union-attr]
        if key.lower() in {"dns", "ip address", "ip"}:
            out.append(value)
    return sorted(set(out))


def _supports(host: str, port: int, version: ssl.TLSVersion, timeout: float) -> bool:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        context.minimum_version = version
        context.maximum_version = version
    except (ValueError, ssl.SSLError):
        return False
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host):
                return True
    except (ssl.SSLError, OSError, ValueError):
        return False


def _inspect_blocking(host: str, port: int, timeout: float) -> dict[str, Any]:
    context = ssl.create_default_context()
    started = time.perf_counter()
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=host) as tls:
            cert = tls.getpeercert() or {}
            der = tls.getpeercert(binary_form=True) or b""
            negotiated = {
                "host": host,
                "port": port,
                "subject": _flatten(cert.get("subject")),
                "issuer": _flatten(cert.get("issuer")),
                "sans": _sans(cert),
                "serial": cert.get("serialNumber", "—"),
                "not_before": cert.get("notBefore"),
                "not_after": cert.get("notAfter"),
                "version": tls.version(),
                "cipher": (tls.cipher() or ("unknown",))[0],
                "cipher_bits": (tls.cipher() or ("", "", 0))[2],
                "sha256": hashlib.sha256(der).hexdigest(),
                "sha1": hashlib.sha1(der).hexdigest(),
                "ocsp": cert.get("OCSP", ()),
                "ca_issuers": cert.get("caIssuers", ()),
                "crl": cert.get("crlDistributionPoints", ()),
                "handshake_ms": (time.perf_counter() - started) * 1000,
            }
    return negotiated


def _cert_dates(cert: dict[str, Any]) -> tuple[datetime | None, datetime | None]:
    def parse(value: Any) -> datetime | None:
        if not value:
            return None
        try:
            stamp = ssl.cert_time_to_seconds(value)
            return datetime.fromtimestamp(stamp, timezone.utc)
        except (ValueError, TypeError):
            return None

    return parse(cert.get("not_before")), parse(cert.get("not_after"))


async def inspect(host: str, port: int = 443, *, timeout: float = 10.0) -> dict[str, Any]:
    """Inspect a TLS endpoint, returning a flat dictionary."""
    host = host.strip().strip("[]").rstrip(".")

    def blocking() -> dict[str, Any]:
        try:
            data = _inspect_blocking(host, port, timeout)
        except ssl.SSLCertVerificationError as exc:
            raise SourceUnavailable(
                f"TLS certificate verification failed for `{host}`.",
                hint=str(exc.verify_message or exc),
            ) from exc
        except ssl.SSLError as exc:
            raise SourceUnavailable(f"TLS handshake with `{host}:{port}` failed ({exc.reason or exc}).") from exc
        except (OSError, socket.timeout) as exc:
            raise SourceUnavailable(f"Could not open `{host}:{port}` ({type(exc).__name__}).") from exc
        data["tls12"] = _supports(host, port, ssl.TLSVersion.TLSv1_2, timeout)
        data["tls13"] = _supports(host, port, ssl.TLSVersion.TLSv1_3, timeout)
        return data

    data = await asyncio.to_thread(blocking)
    before, after = _cert_dates(data)
    now = datetime.now(timezone.utc)
    data["valid_from"] = before
    data["valid_to"] = after
    data["days_left"] = (after - now).days if after else None
    data["expired"] = bool(after and after < now)
    data["common_name"] = ""
    for part in data["subject"].split(", "):
        if part.startswith("commonName="):
            data["common_name"] = part.split("=", 1)[1]
            break
    return data

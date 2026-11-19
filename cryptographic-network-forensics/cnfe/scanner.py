import ipaddress
import socket
import ssl
import uuid
from datetime import datetime, timezone
from typing import Any

from .config import Settings, target_is_authorized


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _name_to_dict(name: tuple) -> dict:
    output: dict[str, list[str]] = {}
    for rdn in name:
        for key, value in rdn:
            output.setdefault(key, []).append(value)
    return output


def scan_tls_target(target: str, port: int, settings: Settings) -> dict[str, Any]:
    host = target.strip().lower().rstrip(".")
    if (
        not host or "/" in host or "://" in host
        or any(char in host for char in (" ", "@", "#"))
    ):
        raise ValueError("Target must be a hostname or IP address, not a URL or path")
    if not target_is_authorized(host, settings):
        raise PermissionError("Target is not in AUTHORIZED_TARGETS")
    if port not in settings.allowed_ports:
        raise PermissionError("Port is not in ALLOWED_PORTS")

    addresses = sorted({
        item[4][0]
        for item in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    })
    if not addresses:
        raise OSError("Target did not resolve to an IP address")

    # Stage 1: one bounded TCP connection and certificate-verified TLS handshake.
    # No application payload, fuzzing, record manipulation, or exploitation.
    resolved_ip = addresses[0]
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED

    started = datetime.now(timezone.utc)
    raw = socket.create_connection(
        (resolved_ip, port), timeout=settings.connect_timeout
    )
    try:
        raw.settimeout(settings.tls_timeout)
        with context.wrap_socket(raw, server_hostname=host) as tls:
            certificate = tls.getpeercert()
            cipher = tls.cipher()
            result = {
                "id": str(uuid.uuid4()),
                "created_at": started.isoformat(),
                "target": host,
                "resolved_ip": resolved_ip,
                "all_resolved_ips": addresses,
                "port": port,
                "status": "completed",
                "protocol": "TLS",
                "tls_version": tls.version(),
                "cipher": cipher[0] if cipher else None,
                "cipher_protocol": cipher[1] if cipher else None,
                "cipher_bits": cipher[2] if cipher else None,
                "alpn": tls.selected_alpn_protocol(),
                "certificate": {
                    "subject": _name_to_dict(certificate.get("subject", ())),
                    "issuer": _name_to_dict(certificate.get("issuer", ())),
                    "not_after": certificate.get("notAfter"),
                    "subject_alt_names": [
                        {"type": kind, "value": value}
                        for kind, value in certificate.get("subjectAltName", ())
                    ],
                },
                "duration_ms": round(
                    (datetime.now(timezone.utc) - started).total_seconds() * 1000, 2
                ),
                "findings": [
                    {
                        "id": "TLS-HANDSHAKE-OBSERVED",
                        "severity": "info",
                        "status": "observed",
                        "description": (
                            "A certificate-verified TLS handshake completed. "
                            "This inventories one negotiated connection; it is not "
                            "a complete security certification."
                        ),
                    },
                    {
                        "id": "GCM-NONCE-REUSE",
                        "severity": "unknown",
                        "status": "unverified",
                        "description": (
                            "External handshake data alone cannot prove nonce reuse. "
                            "Authorized endpoint telemetry identifying the key epoch "
                            "and nonce is required."
                        ),
                    },
                ],
                "limitations": [
                    "Only one TLS handshake was performed.",
                    "No application data, credentials, cookies, or session tokens were collected.",
                    "No nonce-reuse exploit, GHASH-key recovery, padding-oracle probe, or timing exploit was attempted.",
                    "Negotiated parameters describe this connection, not every server-supported configuration.",
                ],
            }
            return result
    except Exception:
        raw.close()
        raise

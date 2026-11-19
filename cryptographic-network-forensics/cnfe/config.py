import ipaddress
import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    authorized_targets: tuple[str, ...]
    allowed_ports: tuple[int, ...]
    database_path: str
    connect_timeout: float
    tls_timeout: float


def load_settings() -> Settings:
    targets = tuple(
        item.strip().lower().rstrip(".")
        for item in os.getenv("AUTHORIZED_TARGETS", "").split(",")
        if item.strip()
    )
    ports = tuple(
        int(item.strip())
        for item in os.getenv("ALLOWED_PORTS", "443").split(",")
        if item.strip()
    )
    if any(port < 1 or port > 65535 for port in ports):
        raise ValueError("ALLOWED_PORTS must contain valid TCP ports")
    return Settings(
        authorized_targets=targets,
        allowed_ports=ports,
        database_path=os.getenv("DATABASE_PATH", "./data/scans.sqlite3"),
        connect_timeout=float(os.getenv("CONNECT_TIMEOUT_SECONDS", "4")),
        tls_timeout=float(os.getenv("TLS_TIMEOUT_SECONDS", "5")),
    )


def target_is_authorized(host: str, settings: Settings) -> bool:
    normalized = host.strip().lower().rstrip(".")
    try:
        address = ipaddress.ip_address(normalized)
    except ValueError:
        address = None

    for entry in settings.authorized_targets:
        try:
            network = ipaddress.ip_network(entry, strict=False)
            if address is not None and address in network:
                return True
        except ValueError:
            if address is None and normalized == entry:
                return True
    return False

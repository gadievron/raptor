"""Validate explicit web transport hosts without widening scan scope."""

from __future__ import annotations

import ipaddress
import re


_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")


def required_host(value: str) -> str:
    """Return one exact public DNS name; reject proxy wildcard syntax."""
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError("required host must be an exact public DNS name")
    host = value.lower()
    if len(host) > 253 or "." not in host or any(
        not _LABEL.fullmatch(label) for label in host.split(".")
    ):
        raise ValueError("required host must be an exact public DNS name (no URL, port, or wildcard)")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise ValueError("required host must be a DNS name, not an IP address")
    if host == "localhost" or host.endswith(".localhost"):
        raise ValueError("required host cannot be localhost")
    return host

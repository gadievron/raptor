"""SAGE configuration for RAPTOR."""

import logging
import os
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

_DEFAULT_TIMEOUT = 30.0


def ensure_loopback_no_proxy() -> None:
    """Exempt loopback from proxy env vars for this process.

    httpx honours HTTP_PROXY/HTTPS_PROXY but — unlike browsers — does
    not special-case loopback: with a proxy set and no NO_PROXY entry,
    every call to the localhost SAGE/Ollama sidecars is routed to a
    proxy that cannot reach this machine's loopback, and SAGE silently
    degrades to unavailable. Corporate NO_PROXY values rarely include
    loopback, so append it ourselves. Additive and idempotent —
    non-loopback SAGE hosts still use the configured proxy chain.

    Lives here (not client.py) so hooks.py can call it without a
    hooks↔client import cycle; every SAGE consumer already imports
    this module.
    """
    if not any(
        os.environ.get(k)
        for k in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
                  "http_proxy", "https_proxy", "all_proxy")
    ):
        return
    for var in ("NO_PROXY", "no_proxy"):
        entries = [e.strip() for e in os.environ.get(var, "").split(",") if e.strip()]
        for host in ("localhost", "127.0.0.1", "::1"):
            if host not in entries:
                entries.append(host)
        os.environ[var] = ",".join(entries)


def _read_timeout() -> float:
    """Parse SAGE_TIMEOUT, falling back to the default on bad input.

    `float(os.getenv("SAGE_TIMEOUT", "30.0"))` raised ValueError on
    non-numeric values (e.g., `SAGE_TIMEOUT=15s`, a typo, or an
    accidentally-quoted shell variable). The exception propagated
    out of dataclass `field(default_factory=...)` at the FIRST
    construction of SageConfig anywhere in the program — every
    SAGE consumer (hooks, client, scripts) crashed with a confusing
    "could not convert string to float" traceback rather than the
    self-explanatory "operator typo'd SAGE_TIMEOUT". Now: warn,
    fall back to default, keep the run going.
    """
    raw = os.getenv("SAGE_TIMEOUT")
    if raw is None or raw == "":
        return _DEFAULT_TIMEOUT
    try:
        value = float(raw)
    except (TypeError, ValueError):
        logger.warning(
            "SAGE_TIMEOUT=%r is not a valid float — using default %s",
            raw, _DEFAULT_TIMEOUT,
        )
        return _DEFAULT_TIMEOUT
    if value <= 0:
        logger.warning(
            "SAGE_TIMEOUT=%s must be positive — using default %s",
            value, _DEFAULT_TIMEOUT,
        )
        return _DEFAULT_TIMEOUT
    return value


@dataclass
class SageConfig:
    """
    Configuration for SAGE persistent memory.

    All settings can be overridden via environment variables.
    """

    enabled: bool = field(
        default_factory=lambda: os.getenv("SAGE_ENABLED", "false").lower() in ("true", "1", "yes")
    )
    url: str = field(
        default_factory=lambda: os.getenv("SAGE_URL", "http://localhost:8090")
    )
    identity_path: str | None = field(
        default_factory=lambda: os.getenv("SAGE_IDENTITY_PATH")
    )
    timeout: float = field(default_factory=_read_timeout)

    @staticmethod
    def from_env() -> "SageConfig":
        """Create config from environment variables."""
        return SageConfig()

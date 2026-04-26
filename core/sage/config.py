"""SAGE configuration for RAPTOR."""

import os
from dataclasses import dataclass, field
from typing import Optional


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
    identity_path: Optional[str] = field(
        default_factory=lambda: os.getenv("SAGE_IDENTITY_PATH")
    )
    timeout: float = field(
        default_factory=lambda: float(os.getenv("SAGE_TIMEOUT", "15.0"))
    )

    @staticmethod
    def from_env() -> "SageConfig":
        """Create config from environment variables."""
        return SageConfig()

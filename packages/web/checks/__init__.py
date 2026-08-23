"""Web security checks package.

Import order matters -- all modules must be imported here so their
@registry.register() decorators fire before any scanner phase runs.
"""

from packages.web.checks.base import (
    Check,
    CheckCategory,
    CheckResult,
    CheckRegistry,
    registry,
)

# Import all check modules to populate the registry
from packages.web.checks import (
    api,
    authentication,
    cache,
    cors,
    headers,
    host_header,
    information,
    oauth,
    prototype_pollution,
    session,
    ssrf,
    tls,
)

__all__ = [
    "Check",
    "CheckCategory",
    "CheckRegistry",
    "CheckResult",
    "api",
    "authentication",
    "cache",
    "cors",
    "headers",
    "host_header",
    "information",
    "oauth",
    "prototype_pollution",
    "registry",
    "session",
    "ssrf",
    "tls",
]

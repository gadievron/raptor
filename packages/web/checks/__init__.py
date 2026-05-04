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
    headers,
    cors,
    session,
    tls,
    information,
    authentication,
    api,
    host_header,
    ssrf,
    cache,
    prototype_pollution,
    oauth,
)

__all__ = [
    "Check",
    "CheckCategory",
    "CheckResult",
    "CheckRegistry",
    "registry",
]

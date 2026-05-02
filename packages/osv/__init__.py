"""OSV.dev shared client + parser.

Used by both ``cve_diff`` (commit-SHA discovery for CVE patch hunting)
and ``sca`` (per-dependency advisory lookup for the security gate).

Each consumer maps :class:`OsvRecord` to its own domain type — this
package owns wire-format parsing only, no domain logic.
"""

from .client import OSV_BASE_URL, DEFAULT_TTL_SECONDS, OsvClient
from .parser import parse_record
from .types import (
    OsvAffected,
    OsvRange,
    OsvRecord,
    OsvReference,
    OsvSeverity,
)

__all__ = [
    "DEFAULT_TTL_SECONDS",
    "OSV_BASE_URL",
    "OsvAffected",
    "OsvClient",
    "OsvRange",
    "OsvRecord",
    "OsvReference",
    "OsvSeverity",
    "parse_record",
]

"""OSV.dev shared client, parser, and oracle verdict types.

Used by ``cve_diff`` (commit-SHA discovery and ground-truth verification),
``sca`` (per-dependency advisory lookup for the security gate), and other
RAPTOR pipelines that need OSV vulnerability data.

Each consumer maps :class:`OsvRecord` to its own domain types — this
package owns wire-format parsing, verdict classification, and
verification logic.
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
from .verdicts import OracleVerdict, Verdict

__all__ = [
    "DEFAULT_TTL_SECONDS",
    "OSV_BASE_URL",
    "OracleVerdict",
    "OsvAffected",
    "OsvClient",
    "OsvRange",
    "OsvRecord",
    "OsvReference",
    "OsvSeverity",
    "Verdict",
    "parse_record",
]

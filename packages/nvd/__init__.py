"""NVD API v2.0 shared client + parser.

Used by ``cve_diff`` (CVE patch discovery via Patch-tagged references)
and other RAPTOR pipelines that need NVD vulnerability data.

Each consumer maps raw NVD payloads to its own domain types — this
package owns API fetch, caching, and reference extraction only.
"""

from .client import BASE_URL, DEFAULT_CACHE_DIR, DEFAULT_TIMEOUT_S, NvdClient
from .parser import extract_patch_refs
from .verify import verify as verify_against_nvd

__all__ = [
    "BASE_URL",
    "DEFAULT_CACHE_DIR",
    "DEFAULT_TIMEOUT_S",
    "NvdClient",
    "extract_patch_refs",
    "verify_against_nvd",
]

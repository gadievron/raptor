"""Defensive input-validation library for cve-diff.

The CVE pipeline takes ONE externally-supplied input directly: the
``cve_id`` argument to ``cve-diff run``. That input is validated by
``validate_cve_id`` in ``cli/main.py`` before it flows into filename
construction or the agent loop.

The other validators in this module — ``validate_url``, ``validate_path``,
``validate_commit_sha``, ``validate_cvss_score`` — are a defense-in-depth
library, not currently invoked from the CLI. They exist because:

  * Future callers (web frontend, batch ingestion) will receive
    URLs / paths / SHAs from untrusted sources and need a tested
    validator at the boundary.
  * Their tests live alongside the implementation in
    ``tests/unit/security/test_validators.py``; deleting them would
    forfeit that test coverage on already-written security code.
  * The audit pipeline (``audit/phases/04_security.py``) flags them
    as "0 callsites" — that's a deliberate alert, not a bug.

When wiring a new external entry point, prefer these validators
over inline regex / string checks: the existing tests already cover
the SSRF / path-traversal / injection cases.
"""
from cve_diff.security.exceptions import (
    SecurityError,
    SSRFError,
    ValidationError,
)
from cve_diff.security.validators import (
    validate_commit_sha,
    validate_cve_id,
    validate_cvss_score,
    validate_path,
    validate_url,
)

__all__ = [
    "SSRFError",
    "SecurityError",
    "ValidationError",
    "validate_commit_sha",
    "validate_cve_id",
    "validate_cvss_score",
    "validate_path",
    "validate_url",
]

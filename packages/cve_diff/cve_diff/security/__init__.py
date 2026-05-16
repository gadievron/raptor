"""Defensive input-validation library for cve-diff.

The CVE pipeline takes ONE externally-supplied input directly: the
``cve_id`` argument to ``cve-diff run``. That input is validated by
``validate_cve_id`` in ``cli/main.py`` before it flows into filename
construction or the agent loop.
"""
from cve_diff.security.exceptions import (
    SecurityError,
    ValidationError,
)
from cve_diff.security.validators import validate_cve_id

__all__ = [
    "SecurityError",
    "ValidationError",
    "validate_cve_id",
]

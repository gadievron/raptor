"""Input validators for the patch analysis pipeline.

The CVE pipeline takes ONE externally-supplied input directly: the
``cve_id`` argument to ``cve-diff run``. ``validate_cve_id`` is wired
into ``cli/main.py`` before that input flows into filename construction
or the agent loop. No other adversarial inputs cross a boundary in
cve-diff today, so the previously-shipped URL / path / SHA / CVSS
validators were trimmed (they had zero callsites in this project and
duplicated checks in ``cve_diff/agent/invariants.py`` for SHAs). If a
future surface (web frontend, batch ingestion) needs them, restore
from git history rather than carrying them dormant.
"""

from __future__ import annotations

import re
from datetime import datetime

from cve_diff.security.exceptions import ValidationError

_CVE_ID_RE = re.compile(r"^CVE-(\d{4})-(\d{4,})$")
_SQL_INJECT_TOKENS = ("'", '"', ";", "--", "/*", "*/", "DROP", "SELECT")


def validate_cve_id(cve_id: str) -> str:
    """Validate `CVE-YYYY-NNNN+` with CRLF / SQLi / path-traversal guards."""
    if cve_id is None:
        raise ValidationError("CVE ID cannot be None, must be string")
    if not isinstance(cve_id, str):
        raise ValidationError(f"CVE ID must be string, not {type(cve_id).__name__}")
    if not cve_id or not cve_id.strip():
        raise ValidationError("CVE ID cannot be empty")
    if cve_id != cve_id.strip():
        raise ValidationError("CVE ID cannot contain leading/trailing whitespace")

    for token in _SQL_INJECT_TOKENS:
        if token in cve_id:
            raise ValidationError("CVE ID contains invalid characters (possible SQL injection attempt)")

    if ".." in cve_id or "/" in cve_id or "\\" in cve_id:
        raise ValidationError("CVE ID contains invalid characters (possible path traversal attempt)")

    match = _CVE_ID_RE.match(cve_id)
    if not match:
        if not cve_id.startswith("CVE-"):
            if cve_id.lower().startswith("cve-"):
                raise ValidationError("CVE ID must use uppercase 'CVE-', not lowercase")
            raise ValidationError("CVE ID must start with 'CVE-' prefix (uppercase)")
        if cve_id.count("-") > 2:
            raise ValidationError("CVE ID format invalid (too many hyphens)")
        parts = cve_id.split("-")
        if len(parts) >= 2:
            year_part = parts[1]
            if not year_part.isdigit():
                raise ValidationError("CVE ID year must be numeric (YYYY format)")
            if len(year_part) != 4:
                raise ValidationError("CVE ID year must be 4 digits (YYYY format)")
        if len(parts) >= 3:
            id_part = parts[2]
            if not id_part.isdigit():
                raise ValidationError("CVE ID number must be numeric (no letters)")
            if len(id_part) < 4:
                raise ValidationError("CVE ID number must be at least 4 digits")
        raise ValidationError("CVE ID format invalid (expected: CVE-YYYY-NNNN)")

    year_str, id_str = match.group(1), match.group(2)
    if not year_str.isascii() or not id_str.isascii():
        raise ValidationError("CVE ID must contain only ASCII characters (no unicode)")

    year = int(year_str)
    current_year = datetime.now().year
    if year < 1999:
        raise ValidationError("CVE ID year must be 1999 or later (CVE program started in 1999)")
    if year > current_year + 1:
        raise ValidationError(f"CVE ID year cannot be in distant future (max: {current_year + 1})")
    if len(id_str) > 10:
        raise ValidationError("CVE ID number too long (max 10 digits)")

    return cve_id

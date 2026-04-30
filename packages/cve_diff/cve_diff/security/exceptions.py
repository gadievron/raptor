"""Security-domain exceptions.

Raised by the validators in ``cve_diff/security/validators.py`` when
input fails defensive checks (CVE id format, URL shape, path
traversal, SSRF, SHA format, CVSS score).
"""


class SecurityError(Exception):
    """Base exception for security-related errors."""


class ValidationError(SecurityError):
    """Raised when input validation fails."""


class SSRFError(SecurityError):
    """Raised when an SSRF bypass attempt is detected."""

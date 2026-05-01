"""Security-domain exceptions.

Raised by the CVE-id validator in ``cve_diff/security/validators.py``
when input fails the format / injection / path-traversal checks.
"""


class SecurityError(Exception):
    """Base exception for security-related errors."""


class ValidationError(SecurityError):
    """Raised when input validation fails."""

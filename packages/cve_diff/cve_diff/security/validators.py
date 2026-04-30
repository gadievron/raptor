"""
Input validators for the patch analysis pipeline.

Ported from code-differ/packages/security/validators.py. Kept verbatim in
behavior because the suite is defense-in-depth: each rule blocks a class of
attack (CRLF, SSRF, path traversal, SHA injection, CVSS DOS) that cannot be
re-derived from higher-level types.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from datetime import datetime
from urllib.parse import urlparse

from cve_diff.security.exceptions import SSRFError, ValidationError

_CVE_ID_RE = re.compile(r"^CVE-(\d{4})-(\d{4,})$")
_OCTAL_IP_RE = re.compile(r"^0\d+\.\d+\.\d+\.\d+$")
_HEX_IP_RE = re.compile(r"^0x[0-9a-fA-F]+")
_CVSS_RE = re.compile(r"^\d{1,2}\.\d$")

_SQL_INJECT_TOKENS = ("'", '"', ";", "--", "/*", "*/", "DROP", "SELECT")
_SHA_FORBIDDEN = ("'", '"', ";", "--", "/*", "*/", "/", "\\", ".", "-")
_CVSS_FORBIDDEN = ("'", '"', ";", "--", "/*", "*/", " ", "e", "E")


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


def validate_url(url: str) -> str:
    """Validate HTTP/HTTPS URL with SSRF protection against private / loopback / link-local ranges."""
    if url is None:
        raise ValidationError("URL cannot be None, must be string")
    if not isinstance(url, str):
        raise ValidationError(f"URL must be string, not {type(url).__name__}")
    if not url or not url.strip():
        raise ValidationError("URL cannot be empty")

    try:
        parsed = urlparse(url)
    except Exception as e:
        raise ValidationError(f"URL parsing failed: {e}") from e

    if not parsed.scheme:
        raise ValidationError("URL must include scheme (http:// or https://)")
    if parsed.scheme.lower() not in ("http", "https"):
        raise ValidationError(f"URL scheme must be HTTP or HTTPS, not {parsed.scheme}")
    if not parsed.netloc:
        raise ValidationError("URL invalid or malformed (missing hostname)")

    hostname = parsed.hostname
    if not hostname:
        raise ValidationError("URL hostname invalid or malformed")

    if _OCTAL_IP_RE.match(hostname):
        raise SSRFError("Cannot access IP in octal notation (SSRF bypass attempt)")
    if _HEX_IP_RE.match(hostname):
        raise SSRFError("Cannot access IP in hex notation (SSRF bypass attempt)")
    if "%" in hostname:
        raise ValidationError("URL-encoded hostnames not allowed (possible SSRF bypass)")

    if hostname.lower() in ("localhost", "127.0.0.1"):
        raise SSRFError("Cannot access localhost (SSRF protection)")

    try:
        ip = ipaddress.ip_address(hostname)
    except ValueError:
        try:
            ip = ipaddress.ip_address(socket.gethostbyname(hostname))
        except (socket.gaierror, socket.herror):
            return url

    if ip.is_private or ip.is_loopback or ip.is_link_local:
        raise SSRFError(f"Cannot access private IP address {ip} (SSRF protection)")

    return url


def validate_path(path: str) -> str:
    """Validate a relative path; reject traversal, absolute, null-byte, unicode-dot and encoded-dot bypasses."""
    if path is None:
        raise ValidationError("Path cannot be None, must be string")
    if not isinstance(path, str):
        raise ValidationError(f"Path must be string, not {type(path).__name__}")
    if not path or not path.strip():
        raise ValidationError("Path cannot be empty")
    if "\x00" in path:
        raise ValidationError("Path contains null byte (possible injection attempt)")
    if len(path) > 1024:
        raise ValidationError("Path too long (max 1024 characters, possible DOS attack)")
    if ".." in path:
        raise ValidationError("Path traversal attempt detected (.. not allowed)")
    if path.startswith("/"):
        raise ValidationError("Absolute paths not allowed (must be relative path)")
    if len(path) >= 3 and path[1] == ":" and path[2] == "\\":
        raise ValidationError("Absolute paths not allowed (Windows drive letters not allowed)")
    if "%" in path:
        raise ValidationError("URL-encoded characters not allowed (possible bypass attempt)")
    if "\u2024" in path:
        raise ValidationError("Unicode dots not allowed (possible bypass attempt)")
    if "\\" in path:
        raise ValidationError("Backslashes not allowed (possible Windows traversal attempt)")
    return path


def validate_commit_sha(sha: str) -> str:
    """Validate a Git SHA-1 (7–40 hex chars, ASCII, no injection tokens)."""
    if sha is None:
        raise ValidationError("Commit SHA cannot be None, must be string")
    if not isinstance(sha, str):
        raise ValidationError(f"Commit SHA must be string, not {type(sha).__name__}")
    if not sha or not sha.strip():
        raise ValidationError("Commit SHA cannot be empty")
    if sha != sha.strip():
        raise ValidationError("Commit SHA cannot contain leading/trailing whitespace")
    if " " in sha:
        raise ValidationError("Commit SHA cannot contain spaces")
    if len(sha) < 7:
        raise ValidationError("Commit SHA too short (minimum 7 characters for abbreviated SHA)")
    if len(sha) > 40:
        raise ValidationError("Commit SHA too long (maximum 40 characters for full SHA)")
    if not sha.isascii():
        raise ValidationError("Commit SHA must contain only ASCII characters (no unicode)")

    for token in _SHA_FORBIDDEN:
        if token in sha:
            raise ValidationError("Commit SHA contains invalid characters (possible injection attempt)")

    try:
        int(sha, 16)
    except ValueError as e:
        raise ValidationError(
            "Commit SHA must contain only hexadecimal characters (0-9, a-f, A-F)"
        ) from e

    return sha


def validate_cvss_score(score: str) -> float:
    """Validate CVSS score string `X.Y` in [0.0, 10.0]; reject sci-notation, negatives, and injections."""
    if score is None:
        raise ValidationError("CVSS score cannot be None, must be string")
    if not isinstance(score, str):
        raise ValidationError(f"CVSS score must be string, not {type(score).__name__}")
    if not score or not score.strip():
        raise ValidationError("CVSS score cannot be empty")
    if score != score.strip():
        raise ValidationError("CVSS score cannot contain leading/trailing whitespace")
    if len(score) > 10:
        raise ValidationError("CVSS score string too long (max 10 characters, possible DOS attack)")
    if not score.isascii():
        raise ValidationError("CVSS score must contain only ASCII characters (no unicode)")
    if score.startswith("-"):
        raise ValidationError("CVSS score must be in range 0.0-10.0 (cannot be negative)")

    if score.count(".") != 1:
        if "." not in score:
            raise ValidationError("CVSS score must include decimal point (format: X.Y)")
        raise ValidationError("CVSS score must have exactly one decimal point")

    if not _CVSS_RE.match(score):
        raise ValidationError("CVSS score format invalid (expected: X.Y with one decimal place)")

    for token in _CVSS_FORBIDDEN:
        if token in score:
            raise ValidationError("CVSS score contains invalid characters (possible injection attempt)")

    score_float = float(score)
    if score_float < 0.0:
        raise ValidationError("CVSS score must be in range 0.0-10.0 (cannot be negative)")
    if score_float > 10.0:
        raise ValidationError("CVSS score must be in range 0.0-10.0 (maximum is 10.0)")

    return score_float

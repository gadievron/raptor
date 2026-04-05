"""Shared formatting utilities for report rendering."""

from typing import Any, Dict


def get_display_status(finding: Dict[str, Any]) -> str:
    """Derive human-readable display status from a finding dict.

    Handles all field formats across pipelines:
    - Validate: ruling.status, final_status
    - Agentic: is_true_positive, is_exploitable, error
    """
    # Check for error first (agentic)
    if "error" in finding:
        return f"Error ({finding.get('error_type', 'unknown')})"

    # Boolean fields (agentic pipeline) are the actual verdict — check first.
    # These take priority over the string 'ruling' field, which may describe
    # code provenance (test_code, dead_code) rather than exploitability.
    if "is_true_positive" in finding or "is_exploitable" in finding:
        if finding.get("is_true_positive") is False:
            return "False Positive"
        if finding.get("is_exploitable"):
            return "Exploitable"
        if finding.get("is_true_positive"):
            return "Confirmed"

    # Check ruling dict (validate pipeline)
    ruling = finding.get("ruling", {})
    if isinstance(ruling, dict):
        status = ruling.get("status", "")
    else:
        status = str(ruling) if ruling else ""

    # Fall through to flat fields
    status = status or finding.get("final_status", "") or finding.get("status", "")

    status_map = {
        "exploitable": "Exploitable",
        "confirmed": "Confirmed",
        "confirmed_constrained": "Confirmed (Constrained)",
        "confirmed_blocked": "Confirmed (Blocked)",
        "ruled_out": "Ruled Out",
        "false_positive": "False Positive",
        "disproven": "Ruled Out",
        "validated": "Confirmed",
        "test_code": "Ruled Out",
        "dead_code": "Ruled Out",
        "mitigated": "Ruled Out",
        "unreachable": "Ruled Out",
    }
    return status_map.get(status, status.replace("_", " ").title() if status else "Unknown")


_DISPLAY_NAMES = {
    "null_deref": "Null Pointer Dereference",
    "xss": "Cross-Site Scripting",
    "ssrf": "Server-Side Request Forgery",
    "csrf": "Cross-Site Request Forgery",
    "xxe": "XML External Entity",
    "rce": "Remote Code Execution",
    "lfi": "Local File Inclusion",
    "rfi": "Remote File Inclusion",
    "idor": "Insecure Direct Object Reference",
    "sca": "Software Composition Analysis",
    "weak_crypto": "Weak Cryptography",
    "sql_injection": "SQL Injection",
    "out_of_bounds_read": "Out-of-Bounds Read",
    "out_of_bounds_write": "Out-of-Bounds Write",
}


def title_case_type(vuln_type: str) -> str:
    """Convert snake_case vuln_type to human-readable display name."""
    if not vuln_type:
        return "—"
    return _DISPLAY_NAMES.get(vuln_type, vuln_type.replace("_", " ").title())


def truncate_path(path: str, max_len: int = 40) -> str:
    """Truncate long paths with ... prefix."""
    if len(path) > max_len:
        return "..." + path[-(max_len - 3):]
    return path


def format_elapsed(seconds: float) -> str:
    """Format seconds as human-readable duration."""
    if seconds < 60:
        return f"{seconds:.0f}s"
    minutes = int(seconds // 60)
    secs = int(seconds % 60)
    if minutes < 60:
        return f"{minutes}m {secs}s"
    hours = int(minutes // 60)
    mins = minutes % 60
    return f"{hours}h {mins}m"

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
    #
    # Pre-fix the truthy checks below were `if finding.get(field):` which
    # fires on the STRING `"false"` (truthy because non-empty) — so a
    # finding with `{"is_exploitable": "false"}` produced from a tool
    # that stringified the bool got marked "Exploitable", the opposite
    # of its intent. Also `is_true_positive is False` only matched the
    # literal Python False, not the string `"false"` — so the same
    # input ALSO failed the False-positive branch and silently passed
    # through to the next check.
    #
    # Coerce string-encoded booleans up-front so all three branches
    # see Python booleans. Unknown strings stay None (treated as
    # absent — falls through to status-string handling).
    def _coerce_bool(v):
        if v is None or isinstance(v, bool):
            return v
        if isinstance(v, str):
            sl = v.strip().lower()
            if sl in ("true", "1", "yes"):
                return True
            if sl in ("false", "0", "no"):
                return False
        return None
    has_tp = "is_true_positive" in finding
    has_ex = "is_exploitable" in finding
    if has_tp or has_ex:
        tp = _coerce_bool(finding.get("is_true_positive"))
        ex = _coerce_bool(finding.get("is_exploitable"))
        if tp is False:
            return "False Positive"
        if ex is True:
            return "Exploitable"
        if tp is True:
            return "Confirmed"

    # final_status is authoritative (set after Stage E feasibility adjustment)
    status = finding.get("final_status", "")

    # Fall back to ruling.status (Stage D), then top-level status
    if not status:
        ruling = finding.get("ruling", {})
        if isinstance(ruling, dict):
            status = ruling.get("status", "")
        else:
            status = str(ruling) if ruling else ""
    status = status or finding.get("status", "")

    status_map = {
        "exploitable": "Exploitable",
        "confirmed": "Confirmed",
        "confirmed_constrained": "Confirmed (Constrained)",
        "confirmed_blocked": "Confirmed (Blocked)",
        "ruled_out": "Ruled Out",
        "false_positive": "False Positive",
        "poc_success": "Exploitable",
        "not_disproven": "Unconfirmed",
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

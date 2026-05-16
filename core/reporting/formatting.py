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
    """Truncate long paths with ``...`` prefix.

    For ASCII-only paths (the common case), code-point length and
    display width agree — use a fast slice path. For paths containing
    non-ASCII bytes (CJK file names, emoji folder names — they exist
    in real codebases), the naive `path[-(max_len - 3):]` slice can:
      * cut mid-grapheme on combining-character sequences,
      * count wide chars (CJK ideographs, fullwidth glyphs, most
        emoji) as 1 column when they actually take 2 — so the
        truncated path overflows the column the caller sized for it.

    Slow-path uses ``_display_width`` (from `core.reporting.console`)
    to walk back from the path tail until the visible width fits.
    Walks character by character — costs O(N) per call only on
    non-ASCII paths; ASCII is O(1).
    """
    # Fast ASCII path.
    if path.isascii():
        if len(path) > max_len:
            return "..." + path[-(max_len - 3):]
        return path

    # Slow path: build the suffix from the right edge, accumulating
    # display width until adding the next char would exceed
    # max_len - 3. `_display_width` belongs to console module — local
    # import to avoid an unconditional dependency.
    from core.reporting.console import _display_width
    if _display_width(path) <= max_len:
        return path
    target = max_len - 3
    suffix_chars: list[str] = []
    width = 0
    for ch in reversed(path):
        w = _display_width(ch)
        if w < 0:
            w = 1
        if width + w > target:
            break
        suffix_chars.append(ch)
        width += w
    return "..." + "".join(reversed(suffix_chars))


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

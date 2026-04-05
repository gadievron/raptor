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

    # Check ruling dict (validate pipeline)
    ruling = finding.get("ruling", {})
    if isinstance(ruling, dict):
        status = ruling.get("status", "")
    else:
        status = str(ruling) if ruling else ""

    # Fall through to flat fields
    status = status or finding.get("final_status", "") or finding.get("status", "")

    # If still empty, derive from boolean fields (agentic)
    if not status:
        if finding.get("is_true_positive") is False:
            return "False Positive"
        if finding.get("is_exploitable"):
            return "Exploitable"
        if finding.get("is_true_positive"):
            return "Confirmed"

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


def title_case_type(vuln_type: str) -> str:
    """Convert snake_case vuln_type to Title Case display."""
    if not vuln_type:
        return "—"
    return vuln_type.replace("_", " ").title()


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

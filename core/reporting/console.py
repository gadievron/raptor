"""Console table renderer — box-drawing terminal output."""

from typing import Dict, List, Optional, Tuple

from core.security.log_sanitisation import escape_nonprintable

try:
    from wcwidth import wcswidth as _wcswidth
except ImportError:  # pragma: no cover
    # Fall back to len() — under-reports CJK / emoji widths but
    # never raises. Acceptable degradation.
    _wcswidth = None


def _display_width(s: str) -> int:
    """Visual cell width of `s` in terminal columns. Wide chars
    (CJK ideographs, fullwidth, most emoji) count as 2 rather
    than 1; combining characters count as 0. Falls back to
    `len()` if `wcwidth` isn't installed.

    Negative result from `wcswidth` (control char snuck through
    despite our escaping) → treat as len() to avoid arithmetic
    surprises later."""
    if _wcswidth is None:
        return len(s)
    width = _wcswidth(s)
    if width < 0:
        return len(s)
    return width


def _pad_to_width(s: str, target_width: int) -> str:
    """Right-pad `s` with spaces so its display width reaches
    `target_width`. Used in place of `str.ljust` because ljust
    pads to a code-point count, not a display-column count —
    wide chars in the cell content would otherwise leave the
    pipe-separator column misaligned."""
    pad = target_width - _display_width(s)
    if pad <= 0:
        return s
    return s + " " * pad


def render_console_table(
    columns: List[str],
    rows: List[Tuple],
    title: str = "Results at a Glance",
    footer: Optional[str] = None,
    max_widths: Optional[Dict[int, int]] = None,
) -> str:
    """Render a box-drawing table for terminal display.

    Args:
        columns: Column headers
        rows: Data rows as tuples of strings
        title: Title printed above the table
        footer: Text printed below the table
        max_widths: Optional {column_index: max_width} to cap column widths

    Returns:
        Formatted string with box-drawing characters
    """
    max_widths = max_widths or {}

    # Sanitise cells up-front so width calculation, truncation, and
    # row formatting all operate on display-safe strings.
    # `escape_nonprintable` handles ANSI escapes (terminal hijack),
    # null bytes, control bytes, and bidi-overrides that would
    # otherwise corrupt the box-drawing render and mislead the
    # operator about table contents.
    safe_columns = [escape_nonprintable(str(h)) for h in columns]
    safe_rows = [
        tuple(escape_nonprintable(str(cell)) for cell in row)
        for row in rows
    ]

    # Calculate column widths using DISPLAY width (CJK and emoji
    # take two columns) rather than `len()` (code-point count).
    # Pre-fix `len()` produced a width too small for any wide-char
    # cell — the box-drawing pipe column landed mid-character on
    # the next row.
    widths = [_display_width(h) for h in safe_columns]
    for row in safe_rows:
        for j, cell in enumerate(row):
            widths[j] = max(widths[j], _display_width(cell))

    # Apply caps
    for j, cap in max_widths.items():
        widths[j] = min(widths[j], cap)

    def fmt_row(cols):
        return "  │ " + " │ ".join(
            _pad_to_width(str(c), widths[j])[:widths[j]]
            for j, c in enumerate(cols)
        ) + " │"

    def separator(left, mid, right):
        return "  " + left + mid.join("─" * (w + 2) for w in widths) + right

    lines = []
    lines.append(f"\n{title}\n")
    lines.append(separator("┌", "┬", "┐"))
    lines.append(fmt_row(safe_columns))
    lines.append(separator("├", "┼", "┤"))
    for idx, row in enumerate(safe_rows):
        lines.append(fmt_row(row))
        if idx < len(safe_rows) - 1:
            lines.append(separator("├", "┼", "┤"))
    lines.append(separator("└", "┴", "┘"))

    if footer:
        lines.append(f"\n  {footer}")

    return "\n".join(lines)

"""Console table renderer — box-drawing terminal output."""

from typing import Dict, List, Optional, Tuple


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

    # Calculate column widths
    widths = [len(h) for h in columns]
    for row in rows:
        for j, cell in enumerate(row):
            widths[j] = max(widths[j], len(str(cell)))

    # Apply caps
    for j, cap in max_widths.items():
        widths[j] = min(widths[j], cap)

    def fmt_row(cols):
        return "  │ " + " │ ".join(
            str(c).ljust(widths[j])[:widths[j]] for j, c in enumerate(cols)
        ) + " │"

    def separator(left, mid, right):
        return "  " + left + mid.join("─" * (w + 2) for w in widths) + right

    lines = []
    lines.append(f"\n{title}\n")
    lines.append(separator("┌", "┬", "┐"))
    lines.append(fmt_row(columns))
    lines.append(separator("├", "┼", "┤"))
    for idx, row in enumerate(rows):
        lines.append(fmt_row(row))
        if idx < len(rows) - 1:
            lines.append(separator("├", "┼", "┤"))
    lines.append(separator("└", "┴", "┘"))

    if footer:
        lines.append(f"\n  {footer}")

    return "\n".join(lines)

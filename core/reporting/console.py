"""Console table renderer — box-drawing terminal output."""


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


#: Default per-column display-width ceiling (see the cap loop in
#: render_console_table for the trade-off note).
_DEFAULT_MAX_WIDTH = 256

#: Code-point ceiling for the title and footer lines. They carry
#: the same finding-derived text class as cells, and escaping alone
#: does not bound LENGTH — without a ceiling one hostile slot could
#: dictate the whole render's size. Generous: real titles are one
#: line, real footers a few lines of counts.
_TITLE_FOOTER_MAX_CHARS = 4096


def _cell_code_point_cap(w: int) -> int:
    """Code-point ceiling for a cell truncated to display width *w*.

    Display width alone cannot bound a cell's LENGTH: combining marks
    are printable (escaping keeps them) and zero display columns wide,
    so a flood of them never trips the width check. Four code points
    per display column plus slack is far beyond any legitimate
    combining-mark density; the ceiling turns a flood cell into a cut
    cell instead of an unbounded one."""
    return 4 * w + 8


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
    columns: list[str],
    rows: list[tuple],
    title: str = "Results at a Glance",
    footer: str | None = None,
    max_widths: dict[int, int] | None = None,
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
    # operator about table contents. The title and footer lines reach
    # the terminal through the same return value, so they get the
    # same treatment (newlines kept — footers are legitimately
    # multi-line prose): pre-fix only cells and headers were escaped,
    # and a finding-derived title/footer carried raw ANSI/BEL through.
    title = escape_nonprintable(str(title), preserve_newlines=True)
    if len(title) > _TITLE_FOOTER_MAX_CHARS:
        title = title[:_TITLE_FOOTER_MAX_CHARS] + " [elided]"
    if footer is not None:
        footer = escape_nonprintable(str(footer), preserve_newlines=True)
        if len(footer) > _TITLE_FOOTER_MAX_CHARS:
            footer = footer[:_TITLE_FOOTER_MAX_CHARS] + " [elided]"
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

    # Apply caps. Every column gets a ceiling: an explicit per-column
    # cap when the caller set one, else the default. Pre-fix columns
    # without an explicit cap sized to their longest cell unbounded,
    # so one hostile-influenceable cell (LLM-emitted vuln_type,
    # imported-SARIF field) made EVERY row of the table that wide.
    # Trade-off, both directions: a lower default starts truncating
    # legitimate long cells the caller expected to render whole (the
    # widest real cells — messages, paths — sit well under 200
    # columns); an unbounded default hands row width to the least
    # trusted cell in the table. Callers with a genuinely wider cell
    # class pass their own larger cap.
    for j in range(len(widths)):
        widths[j] = min(widths[j], max_widths.get(j, _DEFAULT_MAX_WIDTH))

    def _truncate_to_width(s: str, w: int) -> str:
        # Incremental accumulation — one per-character width each
        # step. The previous form recomputed _display_width(s[:i+1])
        # per character, O(N²) for EVERY cell (capped or not): a
        # 100k-character finding-derived cell cost ~14 s, and cells
        # carry hostile-influenceable text (LLM output over a hostile
        # target, imported SARIF, scanned-repo paths). Per-character
        # wcwidth loses wcswidth's sequence-level treatment of a few
        # rare grapheme clusters, which can only OVER-count width —
        # truncating a flood cell slightly early, never overflowing
        # the column.
        hard_cap = _cell_code_point_cap(w)
        if len(s) > hard_cap:
            # Zero-width code points (combining marks are printable,
            # so escaping keeps them) accumulate no display width:
            # without a code-point ceiling a cell of one base char +
            # 100k combining marks never trips the width check and
            # sails through the column cap whole. No legitimate cell
            # text approaches 4 code points per display column.
            s = s[:hard_cap]
        cur = 0
        for i, ch in enumerate(s):
            cur += _display_width(ch)
            if cur > w:
                return s[:i]
        return s

    def fmt_row(cols):
        return "  │ " + " │ ".join(
            _pad_to_width(_truncate_to_width(str(c), widths[j]), widths[j])
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

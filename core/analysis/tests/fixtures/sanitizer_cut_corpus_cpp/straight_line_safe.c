/* Straight-line safe: x → g_markup_escape_text → y → render.
 *
 * Phase 11 verdict: suppress.
 *
 * Single CFG path from entry; one catalog sanitizer; cleaned value
 * reaches sink. The same shape as the Python ``straight_line_safe.py``
 * — the value-bound gate's "TP" baseline.
 */
extern char *g_markup_escape_text(const char *, long);
extern void render(const char *);

void handle(const char *x) {
    const char *y = g_markup_escape_text(x, -1);
    render(y);
}

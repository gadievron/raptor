/* may_escape downgrade — indirection on the source→sink path.
 *
 * Phase 11 verdict: candidate_only.
 *
 * The value-bound vertex-cut would otherwise SUPPRESS (every path
 * from the entry to render crosses g_markup_escape_text and y is
 * the cleaned symbol that reaches the sink), but the call to
 * snprintf — in _BULK_COPY_FUNCS — stamps the line with
 * may_escape. The on-path scan in evaluate_finding catches it and
 * downgrades. Documents Phase 10 + Phase 11 working in tandem.
 */
extern char *g_markup_escape_text(const char *, long);
extern int snprintf(char *, unsigned long, const char *, ...);
extern void render(const char *);

void handle(const char *x) {
    char buf[256];
    const char *y = g_markup_escape_text(x, -1);
    snprintf(buf, sizeof(buf), "<p>%s</p>", y);
    render(y);
}

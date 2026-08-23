/* Real bypass — a path reaches the sink without sanitizing.
 *
 * Phase 11 verdict: no_suppress.
 *
 * The else branch passes ``x`` through to render unchanged. Neither
 * lexical nor value-bound should suppress this — it's a real
 * finding.
 */
extern char *g_markup_escape_text(const char *, long);
extern void render(const char *);

void handle(const char *x, int trusted) {
    const char *safe;
    if (trusted) {
        safe = g_markup_escape_text(x, -1);
    } else {
        safe = x;
    }
    render(safe);
}

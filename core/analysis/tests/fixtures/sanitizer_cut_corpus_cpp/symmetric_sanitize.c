/* Symmetric sanitize across if-branches.
 *
 * Phase 11 verdict: suppress.
 *
 * Both branches produce the cleaned value into ``out``; control-flow
 * cut holds and value-bound conditions 2 and 3 fire on both branch's
 * binding. Lexical-only would miss this (no single sanitizer
 * dominates both branches in the legacy regex check). The value-
 * bound gate is the design's motivating case.
 */
extern char *g_markup_escape_text(const char *, long);
extern void render(const char *);

void handle(const char *x, int trusted) {
    const char *out;
    if (trusted) {
        out = g_markup_escape_text(x, -1);
    } else {
        out = g_markup_escape_text(x, -1);
    }
    render(out);
}

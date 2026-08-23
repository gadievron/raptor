/* Wrong-variable case — the sanitizer cleans the wrong symbol.
 *
 * Phase 11 verdict: candidate_only.
 *
 * Control-flow cut still holds (every CFG path crosses
 * g_markup_escape_text), but the cleaned value ``safe_other`` never
 * reaches the sink — render reads ``user`` instead. The shipped
 * pre-Phase-11 lexical check would falsely suppress; the value-
 * bound gate (condition 3: sink_arg in binding.output_symbols)
 * refuses. The soundness witness for C/C++.
 */
extern char *g_markup_escape_text(const char *, long);
extern void render(const char *);

void handle(const char *user, const char *other) {
    const char *safe_other = g_markup_escape_text(other, -1);
    render(user);
    (void)safe_other;
}

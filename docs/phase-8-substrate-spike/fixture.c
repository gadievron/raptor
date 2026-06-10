/* Phase 8 substrate spike — 50-line C fixture pinning the canonical
 * shapes the value-bound gate has to recognise in C.
 *
 * Picked from the design doc's enumeration:
 *   - straight-line sanitize -> render (the easy TP)
 *   - sanitizer in if-branch (the symmetric-sanitize shape)
 *   - sanitizer cleans the WRONG variable (soundness witness)
 *   - sanitizer in helper / nested call (Phase 14 sub-arc C analogue)
 *   - sanitizer on a multi-argument source
 *   - switch + fallthrough (Phase 9 control-flow coverage)
 *
 * No #includes — the spike walks pre-preprocessor source; the
 * functions referenced (escape_html, render, validate) are decls
 * that don't need bodies for the AST walk.
 */

extern char *escape_html(const char *s);
extern void render(const char *s);
extern int validate(const char *s);

/* 1. straight-line safe: y is bound to escape_html(x); sink reads y. */
void handle_straight(const char *x) {
    const char *y = escape_html(x);
    render(y);
}

/* 2. if-branch sanitize: both arms produce a clean value into out. */
void handle_branch(const char *x, int trusted) {
    const char *out;
    if (trusted) {
        out = x;
    } else {
        out = escape_html(x);
    }
    render(out);
}

/* 3. wrong-variable: escape_html cleans `other`, but the sink reads `user`. */
void handle_wrong(const char *user, const char *other) {
    const char *safe_other = escape_html(other);
    render(user);                          /* unsafe — soundness witness */
    (void)safe_other;
}

/* 4. sanitizer in helper: clean happens through a callee. */
static const char *_sanitize(const char *s) { return escape_html(s); }
void handle_helper(const char *x) {
    const char *y = _sanitize(x);
    render(y);
}

/* 5. switch with fallthrough: sanitize only in one arm. */
void handle_switch(const char *x, int kind) {
    const char *out = x;
    switch (kind) {
        case 1: out = escape_html(x); /* fallthrough */
        case 2: render(out); break;
        default: render(x);    break;  /* no sanitize on this path */
    }
}

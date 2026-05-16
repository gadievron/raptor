/*
 * axis3_negative_distant_check.c — axis-3 FP-leak detection fixture.
 *
 * Surface shape: `p = kstrdup(...)` followed by use of `p` — the
 * shape axis-3 unchecked_alloc_local.cocci matches. BUT: the NULL
 * check IS present, just at a distance the cocci `when !=` clauses
 * may or may not catch.
 *
 * Here the check is in a HELPER function `validate()` that p is
 * passed to BEFORE the deref. Cocci's intra-procedural `when !=`
 * constraints can't see across function boundaries — so this CAN
 * leak as a FP.
 *
 * Verdict label: false_positive — axis-3 SHOULD NOT mark this as
 * EXPLOITABLE. If the corpus measurement shows it leaks (i.e.,
 * axis-3 emits EXPLOITABLE but label is false_positive), we have
 * the over-eager FP we're testing for.
 *
 * Crafted; this is precisely the "interprocedural NULL check" gap
 * that axis-3-expansion would need to address (call-site escape
 * analysis or harness-level taint forwarding).
 */

#include <stddef.h>

extern char *kstrdup(const char *s, int gfp);
extern void use_string(const char *s);

static int validate(const char *p)
{
	if (!p)
		return -1;
	return 0;
}

void op_distant_check(const char *s)
{
	char *p;
	p = kstrdup(s, 0);
	if (validate(p) < 0)
		return;
	use_string(p);
}

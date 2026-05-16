/*
 * axis3_negative_loop_check.c — axis-3 FP-leak detection fixture
 * (loop / continue pattern).
 *
 * Surface shape: `p = kstrdup(...)` in a loop, followed by use of
 * `p`. The check `if (!p) continue;` IS present, but cocci's
 * `when !=` matches the absence of the EXPLICIT comparison terms
 * within the same straight-line region. With a continue, the alloc
 * and the deref form a path-segment that cocci CAN recognize as
 * having the check — but the path operator's handling of `continue`
 * loops is fragile.
 *
 * Verdict label: false_positive. If axis-3 leaks → known gap with
 * the loop pattern. If axis-3 correctly suppresses → confirms the
 * `when !=` clauses handle the loop case adequately.
 *
 * Crafted; documents the loop-pattern edge.
 */

#include <stddef.h>

extern char *kstrdup(const char *s, int gfp);
extern void use_string(const char *s);

void op_loop_check(const char *const *items, int n)
{
	int i;
	for (i = 0; i < n; i++) {
		char *p;
		p = kstrdup(items[i], 0);
		if (!p)
			continue;
		use_string(p);
	}
}

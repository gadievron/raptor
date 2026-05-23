/*
 * fp_bug_on_dominates.c — crafted FP fixture for source_intel corpus.
 *
 * Surface shape: classic CWE-476 unchecked-alloc-then-deref pattern.
 * A naive analyser would flag this as a NULL-deref TP.
 *
 * Actual semantics: BUG_ON(!p) immediately after the kmalloc dominates
 * the path to the dereference. At runtime BUG_ON triggers a kernel
 * panic / oops before reaching p->field = 42 — DoS only, no
 * memory-corruption primitive. This is the canonical infeasible_branch
 * FP class.
 *
 * Source_intel evidence expected:
 *   - Axis 2 (proximity) emits "abort_proximate: BUG_ON at line 27 with
 *     grade=dominates (no intervening reassignment of `p`)"
 *   - Stage D LLM consults the evidence and rules the finding
 *     false_positive / fp_category=infeasible_branch
 *
 * Not a real CVE — this fixture exercises the FP-suppression path,
 * not a real bug.
 */

#include <stddef.h>

struct ctx { int field; };

void *kmalloc(size_t sz, int gfp);
void BUG_ON(int cond);

void example_bug_on_dominates(int gfp)
{
	struct ctx *p = kmalloc(sizeof(*p), gfp);
	BUG_ON(!p);
	p->field = 42;
}

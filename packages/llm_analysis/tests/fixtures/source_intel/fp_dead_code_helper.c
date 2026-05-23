/*
 * fp_dead_code_helper.c — crafted FP fixture for source_intel corpus.
 *
 * Surface shape: classic CWE-120 unbounded strcpy into fixed-size
 * stack buffer. A naive analyser would flag this as a stack
 * buffer-overflow TP.
 *
 * Actual semantics: `unsafe_helper` is `static` and has no callers
 * anywhere in the codebase — orphan dead code. The bug is structurally
 * unreachable; it cannot be triggered.
 *
 * Source_intel evidence expected:
 *   - Composes with PR-4 `engine/coccinelle/prereqs/function_inventory.cocci`:
 *     `unsafe_helper` appears in `def` records but NOT in any `call`
 *     record (the orphan-static-helper signal already shipped on main).
 *   - Source_intel renders this as fp_category=dead_code evidence.
 *   - Stage D LLM consults the evidence and rules the finding
 *     false_positive / fp_category=dead_code.
 *
 * Not a real CVE — this fixture exercises the dead-code FP path.
 */

#include <string.h>

static int unsafe_helper(const char *s)
{
	char buf[16];
	strcpy(buf, s);
	return 0;
}

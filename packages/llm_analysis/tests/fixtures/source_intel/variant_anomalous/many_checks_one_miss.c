/*
 * many_checks_one_miss.c — axis-5 anomaly fixture.
 *
 * 10 sites of `kstrdup`; 9 are followed by `if (!p)` checks, the
 * 10th is not. The 1 unchecked site is the bug. Axis-5
 * variant_ratio(kstrdup) returns (9, 1) — strong asymmetry,
 * informational signal that the unchecked site is anomalous
 * relative to the project's idiom.
 *
 * Axis-3 (unchecked_alloc) AND axis-5 (variant_ratio) both fire.
 * Axis-3 alone already verdicts EXPLOITABLE for the unchecked site.
 * Axis-5 is INFORMATIONAL in Phase 9 — exposes the (9, 1) ratio
 * via SourceIntelResult.variant_ratio() but doesn't change verdict
 * yet. Crafted, not a real CVE.
 */

#include <stddef.h>

extern char *kstrdup(const char *s, int gfp);
extern void use_string(const char *s);

void op_a(const char *s) {
	char *p;
	p = kstrdup(s, 0);
	if (!p) return;
	use_string(p);
}

void op_b(const char *s) {
	char *p;
	p = kstrdup(s, 0);
	if (!p) return;
	use_string(p);
}

void op_c(const char *s) {
	char *p;
	p = kstrdup(s, 0);
	if (!p) return;
	use_string(p);
}

void op_d(const char *s) {
	char *p;
	p = kstrdup(s, 0);
	if (!p) return;
	use_string(p);
}

void op_e(const char *s) {
	char *p;
	p = kstrdup(s, 0);
	if (!p) return;
	use_string(p);
}

void op_f(const char *s) {
	char *p;
	p = kstrdup(s, 0);
	if (!p) return;
	use_string(p);
}

void op_g(const char *s) {
	char *p;
	p = kstrdup(s, 0);
	if (!p) return;
	use_string(p);
}

void op_h(const char *s) {
	char *p;
	p = kstrdup(s, 0);
	if (!p) return;
	use_string(p);
}

void op_i(const char *s) {
	char *p;
	p = kstrdup(s, 0);
	if (!p) return;
	use_string(p);
}

/* The bug: this is the 1 of 10 sites that doesn't check. */
void op_j_buggy(const char *s) {
	char *p;
	p = kstrdup(s, 0);
	use_string(p);
}

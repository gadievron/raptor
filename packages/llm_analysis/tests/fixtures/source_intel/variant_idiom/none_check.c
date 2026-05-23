/*
 * none_check.c — axis-5 idiom fixture.
 *
 * 5 sites of `kstrdup`; 0 of them check the return. The project's
 * idiom is to never check (perhaps it relies on an upstream
 * GFP_NOFAIL guarantee, or the project's policy is "we don't
 * support OOM"). Axis-5 variant_ratio(kstrdup) returns (0, 5) —
 * uniform pattern, NOT an asymmetric anomaly.
 *
 * The finding labelled here is on one of the 5 sites. Verdict:
 * still TP under axis-3 (any unchecked kstrdup is a real bug), but
 * axis-5 should NOT contribute extra confidence — the asymmetry is
 * zero. This fixture tests that axis-5 doesn't fabricate signal
 * from uniform patterns.
 *
 * Crafted, not a real CVE.
 */

#include <stddef.h>

extern char *kstrdup(const char *s, int gfp);
extern void use_string(const char *s);

void op_1(const char *s) {
	char *p;
	p = kstrdup(s, 0);
	use_string(p);
}

void op_2(const char *s) {
	char *p;
	p = kstrdup(s, 0);
	use_string(p);
}

void op_3(const char *s) {
	char *p;
	p = kstrdup(s, 0);
	use_string(p);
}

void op_4(const char *s) {
	char *p;
	p = kstrdup(s, 0);
	use_string(p);
}

void op_5(const char *s) {
	char *p;
	p = kstrdup(s, 0);
	use_string(p);
}

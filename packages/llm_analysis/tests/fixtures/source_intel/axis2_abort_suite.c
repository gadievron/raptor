/*
 * axis2_abort_suite.c — axis-2 verdict coverage fixture.
 *
 * One function per abort-class macro/call. Each is a memory-corruption
 * shape (cpp/null-dereference) gated by an abort that runs before
 * the deref, so axis-2 abort-dominance must emit NOT_EXPLOITABLE.
 *
 * Macros covered: panic, abort, _Exit, __builtin_trap, assert.
 * (BUG_ON is covered by the existing fp_bug_on_dominates.c fixture.)
 *
 * Plus a cross-function negative — abort exists in a sibling
 * function, NOT in the finding's enclosing function.
 */

#include <stddef.h>

extern void panic(const char *msg);
extern void abort(void);
extern void _Exit(int);
extern void assert(int);


/* 1. panic dominance */
void op_with_panic(int *p)
{
	if (!p)
		panic("p was NULL");
	*p = 1;
}


/* 2. abort dominance */
void op_with_abort(int *p)
{
	if (!p)
		abort();
	*p = 1;
}


/* 3. _Exit dominance */
void op_with_exit(int *p)
{
	if (!p)
		_Exit(1);
	*p = 1;
}


/* 4. __builtin_trap dominance */
void op_with_trap(int *p)
{
	if (!p)
		__builtin_trap();
	*p = 1;
}


/* 5. assert dominance */
void op_with_assert(int *p)
{
	assert(p);
	*p = 1;
}


/* 6. cross-function negative — abort in SIBLING, not finding's
 *    enclosing function. Must NOT suppress. Note: include a caller
 *    of op_no_abort so dead-code doesn't fire either. */
void sibling_op_with_abort(int *p)
{
	if (!p)
		abort();
}

void op_no_abort(int *p)
{
	*p = 1;
}

int main(void)
{
	int x = 0;
	op_no_abort(&x);
	op_conditional_panic(&x);
	op_nested_abort(&x);
	op_distant_panic(&x);
	return 0;
}


/* 7. Conditional abort — panic wrapped in #ifdef CONFIG_PARANOID.
 *    Axis-2 cocci matches the call site; conditional capture records
 *    the surrounding macro. Verdict still emits NOT_EXPLOITABLE
 *    based on the call presence (Stage D LLM is expected to
 *    attenuate based on build context). */
void op_conditional_panic(int *p)
{
#ifdef CONFIG_PARANOID
	if (!p)
		panic("paranoid: null p");
#endif
	*p = 1;
}


/* 8. Abort in nested if/else — panic is in a nested branch, not
 *    the outer if. Same-function attribution + ±50 line proximity
 *    should still hold. */
void op_nested_abort(int *p)
{
	int mode = 0;
	if (mode == 0) {
		if (p == 0) {
			panic("nested null");
		}
	} else {
		/* other branch */
	}
	*p = 1;
}


/* 9. Distant abort — panic far from sink (beyond ±50 line proximity
 *    gate). Axis-2 must NOT dominate because the proximity gate
 *    rejects same_function matches > 50 lines away.
 *
 *    Padding to push abort >50 lines from sink. */
void op_distant_panic(int *p)
{
	if (!p) {
		panic("far away");
	}
	/* Pad with comments to push next deref >50 lines below abort */
	/* l1 */ int a = 0;
	/* l2 */ int b = 0;
	/* l3 */ int c = 0;
	/* l4 */ int d = 0;
	/* l5 */ int e = 0;
	/* l6 */ int f = 0;
	/* l7 */ int g = 0;
	/* l8 */ int h = 0;
	/* l9 */ int i = 0;
	/* l10 */ int j = 0;
	/* l11 */ int k = 0;
	/* l12 */ int l = 0;
	/* l13 */ int m = 0;
	/* l14 */ int n = 0;
	/* l15 */ int o = 0;
	/* l16 */ int q = 0;
	/* l17 */ int r = 0;
	/* l18 */ int s = 0;
	/* l19 */ int t = 0;
	/* l20 */ int u = 0;
	/* l21 */ int v = 0;
	/* l22 */ int w = 0;
	/* l23 */ int x = 0;
	/* l24 */ int y = 0;
	/* l25 */ int z = 0;
	/* l26 */ int aa = 0;
	/* l27 */ int bb = 0;
	/* l28 */ int cc = 0;
	/* l29 */ int dd = 0;
	/* l30 */ int ee = 0;
	/* l31 */ int ff = 0;
	/* l32 */ int gg = 0;
	/* l33 */ int hh = 0;
	/* l34 */ int ii = 0;
	/* l35 */ int jj = 0;
	/* l36 */ int kk = 0;
	/* l37 */ int ll = 0;
	/* l38 */ int mm = 0;
	/* l39 */ int nn = 0;
	/* l40 */ int oo = 0;
	/* l41 */ int pp = 0;
	/* l42 */ int qq = 0;
	/* l43 */ int rr = 0;
	/* l44 */ int ss = 0;
	/* l45 */ int tt = 0;
	/* l46 */ int uu = 0;
	/* l47 */ int vv = 0;
	/* l48 */ int ww = 0;
	/* l49 */ int xx = 0;
	/* l50 */ int yy = 0;
	/* l51 */ int zz = 0;
	/* l52 */ int aaa = 0;
	(void)a; (void)b; (void)c; (void)d; (void)e; (void)f; (void)g;
	(void)h; (void)i; (void)j; (void)k; (void)l; (void)m; (void)n;
	(void)o; (void)q; (void)r; (void)s; (void)t; (void)u; (void)v;
	(void)w; (void)x; (void)y; (void)z; (void)aa; (void)bb; (void)cc;
	(void)dd; (void)ee; (void)ff; (void)gg; (void)hh; (void)ii; (void)jj;
	(void)kk; (void)ll; (void)mm; (void)nn; (void)oo; (void)pp; (void)qq;
	(void)rr; (void)ss; (void)tt; (void)uu; (void)vv; (void)ww; (void)xx;
	(void)yy; (void)zz; (void)aaa;
	*p = 1;  /* >50 lines from the panic — proximity gate must reject */
}

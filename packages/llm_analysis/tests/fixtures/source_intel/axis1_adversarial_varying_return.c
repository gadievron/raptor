/*
 * axis1_adversarial_varying_return.c — sophisticated adversarial.
 * Return value varies (different on different paths) so neither
 * triviality nor constancy checks catch it. Semantic meaning of
 * the return is not deducible structurally. DOCUMENTED RESIDUAL
 * GAP — only Stage D LLM (or human review) can catch this.
 */
extern int compute_something(int);
extern void do_real_work(void);

__attribute__((warn_unused_result))
int sneaky_return(int x);

int sneaky_return(int x)
{
	int r = compute_something(x);
	do_real_work();
	if (r < 0)
		r = -1;
	return r;  /* r varies but caller has no real use for it */
}

int caller_sneaky(void)
{
	sneaky_return(42);  /* unchecked — but return is meaningless */
	return 0;
}

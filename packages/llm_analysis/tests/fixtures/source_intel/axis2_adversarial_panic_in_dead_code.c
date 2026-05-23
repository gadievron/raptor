/*
 * axis2_adversarial_panic_in_dead_code.c — adversarial fixture.
 * Attacker plants panic() in `#if 0` block (compiled out). Cocci
 * may still match the syntactic call site. Documents whether
 * axis-2 suppresses incorrectly on dead-code-wrapped aborts.
 */
extern void panic(const char *msg);

void op_dead_panic(int *p)
{
#if 0
	panic("dead — never runs");
#endif
	*p = 1;  /* real CWE-476 — panic doesn't actually run */
}

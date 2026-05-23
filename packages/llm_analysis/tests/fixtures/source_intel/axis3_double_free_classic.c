/*
 * axis3_double_free_classic.c — classic double-free TP.
 * Two kfree on same local var, no reassignment between.
 */
extern void *kmalloc(unsigned long, int);
extern void kfree(void *);

void op(void)
{
	void *p = kmalloc(16, 0);
	if (!p) return;
	kfree(p);
	/* forgot to set p = NULL */
	kfree(p);  /* DOUBLE FREE */
}

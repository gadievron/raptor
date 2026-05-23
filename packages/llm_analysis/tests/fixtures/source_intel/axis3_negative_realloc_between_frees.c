/*
 * axis3_negative_realloc_between_frees.c — alloc, free, alloc
 * again, free. NOT a double-free. CodeQL false-positive shape.
 */
extern void *kmalloc(unsigned long, int);
extern void kfree(void *);

void op(void)
{
	void *p = kmalloc(16, 0);
	if (!p) return;
	kfree(p);
	p = kmalloc(32, 0);  /* re-alloc */
	if (!p) return;
	kfree(p);  /* freeing the NEW alloc — not a double-free */
}

/* Patched variant: the last use happens before the free, and the pointer
 * is cleared to prevent a later dangling dereference. */
void cleanup(struct conn *c)
{
	log_bytes(c->buf, c->len);
	kfree(c->buf);
	c->buf = NULL;
}

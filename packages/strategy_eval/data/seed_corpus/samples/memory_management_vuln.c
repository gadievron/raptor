/* Synthetic minimal repro: object is used after it has been freed. */
void cleanup(struct conn *c)
{
	kfree(c->buf);
	/* BUG: c->buf is dereferenced after the free above (use-after-free).
	 * c->buf is also left dangling for any later caller. */
	log_bytes(c->buf, c->len);
}

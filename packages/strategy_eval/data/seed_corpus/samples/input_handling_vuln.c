/* Synthetic minimal repro: a caller-controlled length is used to size a
 * copy into a fixed buffer with no bounds check (length-confusion). */
void handle(struct packet *p)
{
	char buf[64];

	/* BUG: p->len is attacker-controlled and never validated against
	 * sizeof(buf) before the copy — a stack overflow. */
	memcpy(buf, p->data, p->len);
	process(buf);
}

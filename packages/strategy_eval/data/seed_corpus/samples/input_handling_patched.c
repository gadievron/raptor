/* Patched variant: the caller-controlled length is validated against the
 * destination buffer before the copy. */
void handle(struct packet *p)
{
	char buf[64];

	if (p->len > sizeof(buf))
		return;		/* reject oversized input */
	memcpy(buf, p->data, p->len);
	process(buf);
}

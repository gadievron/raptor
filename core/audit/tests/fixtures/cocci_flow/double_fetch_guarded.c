/* Fixture: single fetch — the header is fetched once and reused from
 * kernel memory. Must NOT match. */
struct hdr { unsigned int len; };
unsigned long copy_from_user(void *to, const void *from, unsigned long n);
void *memcpy(void *d, const void *s, unsigned long n);

void single_fetch(const void *uptr, char *kbuf) {
    struct hdr h;
    copy_from_user(&h, uptr, sizeof(h));
    if (h.len > 64)
        return;
    memcpy(kbuf, &h, sizeof(h));
}

/* Fixture: double-fetch — two copy_from_user reads from the same
 * user pointer uptr with no re-binding. Must MATCH. */
struct hdr { unsigned int len; };
unsigned long copy_from_user(void *to, const void *from, unsigned long n);

void double_fetch(const void *uptr, char *kbuf) {
    struct hdr h;
    copy_from_user(&h, uptr, sizeof(h));
    if (h.len > 64)
        return;
    copy_from_user(kbuf, uptr, h.len);
}

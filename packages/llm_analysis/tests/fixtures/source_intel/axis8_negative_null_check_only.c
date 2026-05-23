/*
 * axis8_negative_null_check_only.c — `if (!ptr) return;` is an
 * allocator-success check, NOT a size-overflow validation. Axis 8
 * must NOT suppress — that's axis 3 / 5 territory. Real-world:
 * hid-core.c:164.
 */
#include <stddef.h>
extern void *krealloc(void *, size_t, int);
extern void use(void *);

int op(void *old, int new_size) {
    void *p = krealloc(old, new_size * sizeof(int), 0);
    if (!p)
        return -1;
    use(p);
    return 0;
}

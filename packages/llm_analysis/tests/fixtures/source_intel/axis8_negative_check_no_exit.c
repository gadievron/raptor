/*
 * axis8_negative_check_no_exit.c — `if (size > MAX) warn();` only
 * warns, doesn't return. Doesn't mitigate the overflow. Axis 8
 * must NOT suppress.
 */
#include <stddef.h>
extern void warn(const char *);
extern void *memcpy(void *, const void *, size_t);

int op(int n, void *src) {
    char buf[4096];
    int size = n * sizeof(int);
    if (size > 4096) {
        warn("big size");
        /* no return — falls through to memcpy */
    }
    memcpy(buf, src, size);
    return 0;
}

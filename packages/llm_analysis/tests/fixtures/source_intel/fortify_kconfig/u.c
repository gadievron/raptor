#include <stddef.h>
extern void *memcpy(void *dst, const void *src, size_t n);

int op(const char *user, size_t n) {
    char buf[128];
    memcpy(buf, user, n);
    return 0;
}

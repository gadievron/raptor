#include <stddef.h>
extern void *malloc(size_t n);
extern char *strcpy(char *dst, const char *src);

int op(const char *user, size_t want) {
    char *buf = (char *)malloc(want);
    strcpy(buf, user);  /* FORTIFY can't intercept — dest size unknown at compile */
    return 0;
}

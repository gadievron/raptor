#include <stddef.h>
extern char *strcpy(char *dst, const char *src);

int op(const char *user) {
    char buf[64];
    strcpy(buf, user);  /* FORTIFY intercepts: __strcpy_chk */
    return 0;
}

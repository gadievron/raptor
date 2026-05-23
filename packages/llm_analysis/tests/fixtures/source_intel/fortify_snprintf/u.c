#include <stddef.h>
extern int snprintf(char *dst, size_t sz, const char *fmt, ...);

int op(const char *user) {
    char buf[64];
    snprintf(buf, 256, "%s", user);  /* FORTIFY catches sz > obj_size */
    return 0;
}

#include <string.h>

void copy_fixed(const char *src) {
    char dst[8];
    memcpy(dst, src, 32);
    (void)dst;
}

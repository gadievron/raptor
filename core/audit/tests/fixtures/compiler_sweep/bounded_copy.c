#include <string.h>

/* GUARDED pattern: length clamped to the destination size before the
 * copy.  Negative control — must NOT confirm an overflow hypothesis. */
void copy_bounded(const char *src, unsigned long len) {
    char dst[8];
    if (len > sizeof(dst)) {
        len = sizeof(dst);
    }
    memcpy(dst, src, len);
    (void)dst;
}

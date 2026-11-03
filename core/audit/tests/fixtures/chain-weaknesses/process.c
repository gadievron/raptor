#include <string.h>

/* Weakness: copies into a fixed-size stack buffer using
   caller-provided length.  Not a vulnerability alone — the caller
   might pass safe values. */
int process_body(const char *data, size_t len) {
    char buf[256];
    if (len == 0)
        return -1;
    memcpy(buf, data, len);
    return 0;
}

#include <stdlib.h>
#include <string.h>

/* A real UAF on `p`, plus an unrelated healthy buffer `other_buf`.
 * A hypothesis naming only `other_buf` must NOT be confirmed by the
 * diagnostic implicating `p`. */
int mixed_buffers(void) {
    char other_buf[16];
    memset(other_buf, 0, sizeof(other_buf));
    int *p = malloc(sizeof(int));
    if (!p) return -1;
    *p = 7;
    free(p);
    return *p;
}

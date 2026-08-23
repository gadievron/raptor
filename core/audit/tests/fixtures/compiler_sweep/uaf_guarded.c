#include <stdlib.h>

/* GUARDED pattern: null-out after free, guard before reuse.
 * Negative control — must NOT confirm a use-after-free hypothesis. */
int guarded_free(void) {
    int *p = malloc(sizeof(int));
    if (!p) return -1;
    *p = 42;
    free(p);
    p = NULL;
    if (p) return *p;
    return 0;
}

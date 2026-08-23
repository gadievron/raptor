/* Fixture: guarded re-free — buf is reassigned between the two
 * frees. Must NOT match. */
#include <stdlib.h>

void refree_after_realloc(char *buf, int n) {
    free(buf);
    buf = malloc(n);
    free(buf);
}

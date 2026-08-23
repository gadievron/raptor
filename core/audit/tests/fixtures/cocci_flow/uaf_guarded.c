/* Fixture: correctly-guarded frees — every deref is preceded by a
 * reassignment of buf on the path. Must NOT match. */
#include <stdlib.h>

void guarded_realloc(char *buf, int n) {
    free(buf);
    buf = malloc(n);
    buf[0] = 'a';
}

void guarded_null_then_no_use(char *buf) {
    free(buf);
    buf = 0;
}

void free_only(char *buf) {
    free(buf);
}

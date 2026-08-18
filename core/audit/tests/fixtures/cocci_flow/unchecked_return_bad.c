/* Fixture: unchecked return — malloc result dereferenced with no
 * if-test on the path. Must MATCH. */
#include <stdlib.h>

void unchecked_decl_init(int n) {
    char *q = malloc(n);
    q[0] = 'a';
}

void unchecked_assign(int n) {
    char *q;
    q = malloc(n);
    *q = 'b';
}

/* Fixture: checked return — every deref is dominated by an if-test
 * involving q, or q is rebound first. Must NOT match. */
#include <stdlib.h>

char *fallback(int n);

void checked_bang(int n) {
    char *q = malloc(n);
    if (!q)
        return;
    q[0] = 'a';
}

void checked_null_cmp(int n) {
    char *q = malloc(n);
    if (q == 0)
        return;
    *q = 'b';
}

void rebound(int n) {
    char *q = malloc(n);
    q = fallback(n);
    q[0] = 'c';
}

/* Fixture: use-after-free — deref of buf after free with no
 * intervening reassignment on the path. Must MATCH. */
#include <stdlib.h>

void uaf_index(char *buf) {
    free(buf);
    buf[0] = 'a';
}

void uaf_star(char *buf) {
    free(buf);
    *buf = 'b';
}

struct conn { char *data; };

void uaf_field(struct conn *buf) {
    free(buf);
    buf->data = 0;
}

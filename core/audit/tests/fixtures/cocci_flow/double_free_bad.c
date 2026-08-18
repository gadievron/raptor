/* Fixture: double-free — second free(buf) reachable with no
 * intervening reassignment. Must MATCH. */
#include <stdlib.h>

void double_free(char *buf, int err) {
    free(buf);
    if (err)
        free(buf);
}

#include <stdlib.h>

void release_twice(void) {
    int *buf = malloc(4);
    if (!buf) return;
    free(buf);
    free(buf);
}

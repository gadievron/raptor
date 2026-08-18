#include <stdlib.h>

int use_after_free(void) {
    int *p = malloc(sizeof(int));
    if (!p) return -1;
    *p = 42;
    free(p);
    return *p;
}

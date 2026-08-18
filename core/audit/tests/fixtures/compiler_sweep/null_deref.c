#include <stdlib.h>

int read_maybe_null(int cond) {
    int *ptr = cond ? malloc(sizeof(int)) : NULL;
    return *ptr;
}

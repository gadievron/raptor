#include <stdlib.h>

void forget_buffer(void) {
    int *scratch = malloc(64);
    if (scratch) {
        scratch[0] = 1;
    }
}

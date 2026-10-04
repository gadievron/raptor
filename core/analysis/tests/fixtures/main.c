#include <stdio.h>
#include "lib.h"

int main(int argc, char **argv) {
    (void)argv;
    int n = argc;
    n += live_called(n);
    n += inlined_only_user(n);
    n += folded_a(n);
    n += folded_b(n);
    n += indirect_caller(n);
    /* Touch the address-taken table so the linker can't elide it. */
    n += GLOBAL_TABLE[0](n);
    n += GLOBAL_TABLE2[0](n);
    printf("%d\n", n);
    return 0;
}

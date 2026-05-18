#include <stdio.h>
#include "internal.h"

static int helper(int x) {
    return x + 1;
}

int main(int argc, char **argv) {
    asm volatile ("nop");
    if (helper(argc) > 0) {
        printf("positive");
        return 0;
    }
    return 1;
}

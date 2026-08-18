#include <stdio.h>

#define BUFSZ 16

int add(int a, int b) {
    return a + b;
}

int use_macro(void) {
    char buf[BUFSZ];
    (void)buf;
    printf("%d\n", (int)sizeof(buf));
    return (int)sizeof(buf);
}

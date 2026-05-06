#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    char buf[256];
    snprintf(buf, sizeof(buf), "ping -c1 %s", argv[1]);
    return system(buf);
}

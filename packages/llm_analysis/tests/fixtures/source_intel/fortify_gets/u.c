#include <stdio.h>
extern char *gets(char *s);

int op(void) {
    char buf[64];
    gets(buf);  /* deprecated; FORTIFY intercepts to fgets/abort */
    return 0;
}

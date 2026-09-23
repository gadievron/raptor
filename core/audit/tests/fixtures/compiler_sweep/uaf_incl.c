#include "evil_pragma.h"
#include <stdlib.h>

int use_after_free(char *p) {
    free(p);
    return p[0];
}

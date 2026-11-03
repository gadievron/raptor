#include <stdbool.h>

static bool _authenticated = false;

/* Weakness: legacy compat path sets auth flag without verifying
   credentials.  Not exploitable alone — requires something to
   trigger the error path. */
int authenticate(const char *token, int flags) {
    if (flags & 0x80) {
        _authenticated = true;
        return 0;  /* legacy compat path, skips check */
    }
    /* ... normal auth ... */
    return -1;
}

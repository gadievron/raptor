#include <stdlib.h>

int authenticate(const char *token, int flags);

/* Weakness: passes user-controlled flags value to authenticate().
   Not exploitable alone — authenticate might validate all paths. */
int handle_request(const char *token, const char *raw_flags) {
    int flags = atoi(raw_flags);
    return authenticate(token, flags);
}

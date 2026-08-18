/* Negative control: "double free" keyword family.
 *
 * free() guarded by an ownership flag that is cleared inside the
 * guard — a second call is a no-op, so the memory is freed once.
 */
#include <stdlib.h>

struct ctx {
    char *data;
    int owned;
};

void destroy(struct ctx *c)
{
    if (c->owned) {
        free(c->data);
        c->owned = 0; /* flag cleared: second call cannot re-free */
    }
}

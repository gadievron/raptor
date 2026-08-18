/* Negative control: "use after free" keyword family.
 *
 * free() immediately followed by nulling the pointer — later code
 * cannot dereference the stale allocation.
 */
#include <stdlib.h>

struct ctx {
    char *buf;
};

void release_buf(struct ctx *c)
{
    free(c->buf);
    c->buf = 0; /* null-out prevents any later use */
}

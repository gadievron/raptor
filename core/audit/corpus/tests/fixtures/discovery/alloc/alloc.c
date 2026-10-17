/* Pool allocator — callee side.
 *
 * pool_alloc() with raw=true skips the memset, leaving .size and
 * .data uninitialised.  This is the producer half of contract seam 1
 * (see consumer.c for the consumer half). */

#include "alloc.h"
#include <stdlib.h>
#include <string.h>

struct pool_hdr *pool_alloc(size_t nbytes, int raw)
{
    struct pool_hdr *h = malloc(sizeof(*h) + nbytes);
    if (!h)
        return NULL;
    if (!raw) {
        memset(h, 0, sizeof(*h) + nbytes);
        h->size = nbytes;
        h->data = (char *)h + sizeof(*h);
    }
    /* raw=true: h->size and h->data are uninitialised */
    h->flags = raw ? 1 : 0;
    return h;
}

struct pool_hdr *pool_alloc_zeroed(size_t nbytes)
{
    return pool_alloc(nbytes, 0);
}

void pool_free(struct pool_hdr *h)
{
    if (h)
        free(h);
}

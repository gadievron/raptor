/* Consumer — caller side of three contract seams.
 *
 * SEAM 1 (uninitialised .size): process_raw() calls pool_alloc with
 * raw=true, then reads h->size.  The callee leaves .size uninitialised
 * in that path — a cross-module assumption mismatch.
 *
 * SEAM 2 (missing NULL check): fast_copy() calls pool_alloc but does
 * not check for NULL return before dereferencing.
 *
 * SEAM 3 (u32→u16 truncation): summarise() casts h->size (size_t) to
 * unsigned short for the header wire format — silent truncation when
 * size > 65535. */

#include "alloc.h"
#include <string.h>

int process_raw(const char *src, size_t len)
{
    struct pool_hdr *h = pool_alloc(len, 1);
    if (!h)
        return -1;
    /* BUG: h->size is uninitialised when raw=true */
    memcpy(h->data, src, h->size);
    pool_free(h);
    return 0;
}

int fast_copy(const char *src, size_t len)
{
    /* BUG: no NULL check — pool_alloc can return NULL on OOM */
    struct pool_hdr *h = pool_alloc(len, 0);
    memcpy(h->data, src, h->size);
    pool_free(h);
    return 0;
}

struct wire_hdr {
    unsigned short size;
    unsigned short flags;
};

int summarise(struct pool_hdr *h, struct wire_hdr *out)
{
    if (!h || !out)
        return -1;
    /* BUG: size_t → unsigned short truncation */
    out->size  = (unsigned short)h->size;
    out->flags = (unsigned short)h->flags;
    return 0;
}

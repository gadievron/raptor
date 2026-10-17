/* Allocator interface — callee side of the contract seam.
 *
 * pool_alloc() returns NULL on OOM.  pool_alloc_zeroed() additionally
 * zeroes the buffer.  The .size field of the returned header is set
 * only by pool_alloc_zeroed(); pool_alloc() leaves it uninitialised
 * when called with raw=true.
 *
 * Discovery fixture: contract perspective should detect that callers
 * in consumer.c assume .size is always valid. */

#ifndef ALLOC_H
#define ALLOC_H

#include <stddef.h>

struct pool_hdr {
    size_t size;
    int    flags;
    void  *data;
};

struct pool_hdr *pool_alloc(size_t nbytes, int raw);
struct pool_hdr *pool_alloc_zeroed(size_t nbytes);
void pool_free(struct pool_hdr *h);

#endif

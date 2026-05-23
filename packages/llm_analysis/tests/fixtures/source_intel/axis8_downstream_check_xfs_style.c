/*
 * axis8_downstream_check_xfs_style.c — TP-mitigated by downstream
 * `if (size < 0 || size > MAX) return -ERR;` after an arithmetic
 * size computation. Real-world shape: xfs_inode_fork.c:117/127.
 */
#include <stddef.h>
extern void *memcpy(void *, const void *, size_t);

int op(int nex, void *src) {
    char buf[4096];
    int size = nex * sizeof(int);
    /* warning + side effects between if and return — common kernel pattern */
    if (size < 0 || size > 4096) {
        /* error reporting */
        memcpy(buf, "err", 3);
        return -1;
    }
    memcpy(buf, src, size);
    return 0;
}

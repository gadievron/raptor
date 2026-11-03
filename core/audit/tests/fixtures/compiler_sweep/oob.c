extern void *memcpy(void *, const void *, __SIZE_TYPE__); /* No SDK fortify macro. */

void copy_fixed(const char *src) {
    char dst[8];
    memcpy(dst, src, 32);
    (void)dst;
}

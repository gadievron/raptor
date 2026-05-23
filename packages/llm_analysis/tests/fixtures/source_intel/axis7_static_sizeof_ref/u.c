extern int strcpy(char *d, const char *s);
extern void *malloc(unsigned long n);

static int hook(const char *user) {
    char buf[16];
    strcpy(buf, user);
    return 0;
}

void setup(void) {
    /* sizeof on the function name takes the function-pointer size;
     * unusual but seen in hook-table sizing. */
    void *p = malloc(sizeof(&hook) * 16);
    (void)p;
}

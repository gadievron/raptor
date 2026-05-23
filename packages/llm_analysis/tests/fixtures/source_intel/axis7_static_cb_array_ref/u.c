extern int strcpy(char *d, const char *s);

static int op_a(const char *user) {
    char buf[16];
    strcpy(buf, user);
    return 0;
}

static int op_b(const char *user) {
    char buf[16];
    strcpy(buf, user);
    return 0;
}

typedef int (*op_fn_t)(const char *);
static op_fn_t ops[] = {
    op_a,
    op_b,
};

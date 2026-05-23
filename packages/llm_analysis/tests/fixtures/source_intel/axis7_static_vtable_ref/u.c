extern int strcpy(char *d, const char *s);

static int my_handler(const char *user) {
    char buf[16];
    strcpy(buf, user);
    return 0;
}

struct ops_t {
    int (*handler)(const char *);
};

struct ops_t my_ops = {
    .handler = my_handler,
};

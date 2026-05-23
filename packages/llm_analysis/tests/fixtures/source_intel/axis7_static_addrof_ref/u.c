extern int strcpy(char *d, const char *s);
extern int register_cb(int (*)(const char *));

static int callback(const char *user) {
    char buf[16];
    strcpy(buf, user);
    return 0;
}

void register_at_init(void) {
    register_cb(&callback);
}

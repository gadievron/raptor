extern int strcpy(char *d, const char *s);

int exported_handler(const char *user) {
    char buf[16];
    strcpy(buf, user);
    return 0;
}

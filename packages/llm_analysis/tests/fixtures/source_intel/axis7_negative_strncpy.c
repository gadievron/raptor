extern char *strncpy(char *, const char *, unsigned long);
int op(const char *user) {
    char buf[16];
    strncpy(buf, user, sizeof(buf));
    return 0;
}

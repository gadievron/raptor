extern int sprintf(char *, const char *, ...);
int op(const char *user) {
    char buf[64];
    sprintf(buf, "%s/%s/%s", user, user, user);
    return 0;
}

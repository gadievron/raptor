extern int strcpy(char *d, const char *s);
int public_handler(const char *user) {
    char buf[16];
    strcpy(buf, user);
    return 0;
}

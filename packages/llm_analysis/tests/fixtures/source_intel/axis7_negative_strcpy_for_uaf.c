extern int strcpy(char *, const char *);
extern void *malloc(unsigned long);
extern void free(void *);
int op(const char *user) {
    char *buf = malloc(16);
    strcpy(buf, user);
    free(buf);
    free(buf);
    return 0;
}

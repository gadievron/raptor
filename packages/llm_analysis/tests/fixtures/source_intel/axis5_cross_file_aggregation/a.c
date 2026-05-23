extern char *kstrdup(const char *s, int gfp);
extern void use_string(const char *s);

void op_a_1(const char *s) {
    char *p;
    p = kstrdup(s, 0);
    if (!p) return;
    use_string(p);
}

void op_a_2(const char *s) {
    char *p;
    p = kstrdup(s, 0);
    if (!p) return;
    use_string(p);
}

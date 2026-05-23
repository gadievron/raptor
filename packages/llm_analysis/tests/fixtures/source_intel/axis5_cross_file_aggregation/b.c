extern char *kstrdup(const char *s, int gfp);
extern void use_string(const char *s);

void op_b_1(const char *s) {
    char *p;
    p = kstrdup(s, 0);
    if (!p) return;
    use_string(p);
}

/* finding's bug site — unchecked */
void op_b_2_buggy(const char *s) {
    char *p;
    p = kstrdup(s, 0);
    use_string(p);
}

extern char *kstrdup(const char *s, int gfp);
extern void use_string(const char *s);

void check_0(const char *s) {
    char *p;
    p = kstrdup(s, 0);
    if (!p) return;
    use_string(p);
}

void check_1(const char *s) {
    char *p;
    p = kstrdup(s, 0);
    if (!p) return;
    use_string(p);
}

void check_2(const char *s) {
    char *p;
    p = kstrdup(s, 0);
    if (!p) return;
    use_string(p);
}

void check_3(const char *s) {
    char *p;
    p = kstrdup(s, 0);
    if (!p) return;
    use_string(p);
}

void check_4(const char *s) {
    char *p;
    p = kstrdup(s, 0);
    if (!p) return;
    use_string(p);
}

void check_5(const char *s) {
    char *p;
    p = kstrdup(s, 0);
    if (!p) return;
    use_string(p);
}

void check_6(const char *s) {
    char *p;
    p = kstrdup(s, 0);
    if (!p) return;
    use_string(p);
}

void check_7(const char *s) {
    char *p;
    p = kstrdup(s, 0);
    if (!p) return;
    use_string(p);
}

void miss_0(const char *s) {
    char *p;
    p = kstrdup(s, 0);
    use_string(p);
}

void miss_1(const char *s) {
    char *p;
    p = kstrdup(s, 0);
    use_string(p);
}


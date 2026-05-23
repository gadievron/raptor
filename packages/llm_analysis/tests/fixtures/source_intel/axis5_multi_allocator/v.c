extern char *kstrdup(const char *s, int gfp);
extern void *kmalloc(unsigned long n, int gfp);
extern void use_string(const char *s);
extern void use_buf(void *p);

/* kstrdup section: 3 checked + 1 unchecked → (3, 1) */
void kstrdup_a(const char *s) {
    char *p;
    p = kstrdup(s, 0);
    if (!p) return;
    use_string(p);
}

void kstrdup_b(const char *s) {
    char *p;
    p = kstrdup(s, 0);
    if (!p) return;
    use_string(p);
}

void kstrdup_c(const char *s) {
    char *p;
    p = kstrdup(s, 0);
    if (!p) return;
    use_string(p);
}

void kstrdup_miss(const char *s) {
    char *p;
    p = kstrdup(s, 0);
    use_string(p);
}

/* kmalloc section: 1 checked + 2 unchecked → (1, 2) */
void kmalloc_a(int n) {
    void *p;
    p = kmalloc(n, 0);
    if (!p) return;
    use_buf(p);
}

void kmalloc_miss_1(int n) {
    void *p;
    p = kmalloc(n, 0);
    use_buf(p);
}

void kmalloc_miss_2(int n) {
    void *p;
    p = kmalloc(n, 0);
    use_buf(p);
}

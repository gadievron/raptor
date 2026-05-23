extern void *kmalloc(unsigned long n, int gfp);
extern void use_buf(void *p);

void op_check_1(int n) {
    void *p;
    p = kmalloc(n, 0);
    if (!p) return;
    use_buf(p);
}

void op_check_2(int n) {
    void *p;
    p = kmalloc(n, 0);
    if (!p) return;
    use_buf(p);
}

void op_check_3(int n) {
    void *p;
    p = kmalloc(n, 0);
    if (!p) return;
    use_buf(p);
}

void op_miss(int n) {
    void *p;
    p = kmalloc(n, 0);
    use_buf(p);
}

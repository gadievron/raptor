extern void *kmalloc(unsigned long n, int gfp);
extern void use_buf(void *p);
struct rec { void *buf; };

void op_field_check_1(struct rec *r, int n) {
    r->buf = kmalloc(n, 0);
    if (!r->buf) return;
    use_buf(r->buf);
}

void op_field_check_2(struct rec *r, int n) {
    r->buf = kmalloc(n, 0);
    if (!r->buf) return;
    use_buf(r->buf);
}

/* unchecked field assignment */
void op_field_miss(struct rec *r, int n) {
    r->buf = kmalloc(n, 0);
    use_buf(r->buf);
}

extern void *kmalloc(unsigned long, int);
extern int recv_count(void);
void *op(void) {
    int n = recv_count();
    return kmalloc(n * sizeof(int), 0);
}

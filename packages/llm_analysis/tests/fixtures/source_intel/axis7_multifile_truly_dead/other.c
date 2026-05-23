/* Unrelated work — doesn't reference dead_helper anywhere */
extern int printf(const char *fmt, ...);

void unrelated_init(void) {
    printf("init\n");
}

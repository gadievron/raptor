/*
 * axis8_downstream_check_radeon_style.c — single-line `if (size >
 * limit) return -ERR;` after multiplication. Real-world: r100.c:2284/2286.
 */
extern int report_too_small(int);

int op(int pitch, int cpp, int maxy, int max_buf_size) {
    int size = pitch * cpp * maxy;
    if (size > max_buf_size)
        return -1;
    return 0;
}

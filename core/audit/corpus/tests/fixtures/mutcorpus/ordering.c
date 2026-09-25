/* Ordering family: four sibling functions call lock_take() before
 * buf_flush().  The swap-order mutant reverses one pair, leaving a
 * 3/4 majority on the consensus order. */

void op_a(int fd)
{
    lock_take(fd);
    buf_flush(fd);
}

void op_b(int fd)
{
    lock_take(fd);
    buf_flush(fd);
}

void op_c(int fd)
{
    lock_take(fd);
    buf_flush(fd);
}

void op_d(int fd)
{
    lock_take(fd);
    buf_flush(fd);
}

/* Return-usage census family: ten sibling sites all check
 * dev_read()'s return.  The drop-return-check mutant discards one
 * check, leaving a 9/10 checked majority over the deviant — exactly
 * the census verdict layer's majority floor. */

int reader_a(int fd)
{
    if (dev_read(fd) < 0) return -1;
    return 0;
}

int reader_b(int fd)
{
    if (dev_read(fd) < 0) return -2;
    return 0;
}

int reader_c(int fd)
{
    if (dev_read(fd) < 0) return -3;
    return 0;
}

int reader_d(int fd)
{
    if (dev_read(fd) < 0) return -4;
    return 0;
}

int reader_e(int fd)
{
    if (dev_read(fd) < 0) return -5;
    return 0;
}

int reader_f(int fd)
{
    if (dev_read(fd) < 0) return -6;
    return 0;
}

int reader_g(int fd)
{
    if (dev_read(fd) < 0) return -7;
    return 0;
}

int reader_h(int fd)
{
    if (dev_read(fd) < 0) return -8;
    return 0;
}

int reader_i(int fd)
{
    if (dev_read(fd) < 0) return -9;
    return 0;
}

int reader_j(int fd)
{
    if (dev_read(fd) < 0) return -10;
    return 0;
}

/* Cleanup family (learned dev_open/dev_close pair): four sibling
 * callers acquire and release.  The remove-pair-release mutant
 * deletes one release, leaving a 3/4 releasing majority over the
 * leaking sibling. */

int job_a(int k)
{
    int h = dev_open(k);
    work(h);
    dev_close(h);
    return 0;
}

int job_b(int k)
{
    int h = dev_open(k);
    work(h);
    dev_close(h);
    return 0;
}

int job_c(int k)
{
    int h = dev_open(k);
    work(h);
    dev_close(h);
    return 0;
}

int job_d(int k)
{
    int h = dev_open(k);
    work(h);
    dev_close(h);
    return 0;
}

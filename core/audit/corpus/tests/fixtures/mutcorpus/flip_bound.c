/* Flip-bound family: sibling loops share the same bound idiom, and
 * the flip-bound mutant turns one `<` into `<=`.  The operator's
 * current baseline floor is pinned in tests/test_mutation_floors.py;
 * update the expected value there when a consuming dimension
 * lands. */

int sum_a(int *a, int n)
{
    int i, t = 0;
    for (i = 0; i < n; i++)
        t += a[i];
    return t;
}

int sum_b(int *a, int n)
{
    int i, t = 0;
    for (i = 0; i < n; i++)
        t += a[i];
    return t;
}

int sum_c(int *a, int n)
{
    int i, t = 0;
    for (i = 0; i < n; i++)
        t += a[i];
    return t;
}

int sum_d(int *a, int n)
{
    int i, t = 0;
    for (i = 0; i < n; i++)
        t += a[i];
    return t;
}

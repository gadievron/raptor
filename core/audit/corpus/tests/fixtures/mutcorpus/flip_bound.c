/* Flip-bound family: sibling loops share the same bound idiom.
 * Two operators mutate sum_d along orthogonal axes: flip-bound
 * turns one `<` into `<=` (guard-predicate dimension) and
 * shift-bound turns one bound `n` into `n + 1` (boundary/unit
 * dimension).  Floors are pinned in tests/test_mutation_floors.py. */

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

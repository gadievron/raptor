/* Guard-presence (null leg) family: four sibling sites capture
 * node_lookup()'s result, null-guard it, then dereference.  The
 * drop-guard mutant removes one guard, leaving a 3/4 guarded
 * majority over the unguarded dereference. */

struct node { int val; };

int use_a(int k)
{
    struct node *p = node_lookup(k);
    if (!p)
        return -1;
    p->val = 1;
    return 0;
}

int use_b(int k)
{
    struct node *p = node_lookup(k);
    if (!p)
        return -1;
    p->val = 2;
    return 0;
}

int use_c(int k)
{
    struct node *p = node_lookup(k);
    if (!p)
        return -1;
    p->val = 3;
    return 0;
}

int use_d(int k)
{
    struct node *p = node_lookup(k);
    if (!p)
        return -1;
    p->val = 4;
    return 0;
}

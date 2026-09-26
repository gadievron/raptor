/* Guard-predicate (deref leg) family: four sibling guards test the
 * pointer AND the dereferenced field.  The drop-null-arm mutant
 * removes one guard's null arm, leaving a 3/4 null-armed majority
 * over the bare dereference comparison. */

struct pkt { int len; };

int h_a(struct pkt *p, int max)
{
    if (p && p->len < max)
        return consume(p);
    return -1;
}

int h_b(struct pkt *p, int max)
{
    if (p && p->len < max)
        return consume(p);
    return -1;
}

int h_c(struct pkt *p, int max)
{
    if (p && p->len < max)
        return consume(p);
    return -1;
}

int h_d(struct pkt *p, int max)
{
    if (p && p->len < max)
        return consume(p);
    return -1;
}

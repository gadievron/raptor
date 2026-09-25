/* Interface-slot family: four implementations installed into the
 * same ops-struct slot, each null-guarding its argument.  The
 * drop-slot-guard mutant removes one guard, leaving a 3/4 guarded
 * majority the interface parity dimension votes over (family formed
 * by the L7 interface-slot census, not by naming). */

struct pkt { char *data; int len; };

int tcp_send(struct pkt *p)
{
    if (!p)
        return -1;
    return emit(p->data, p->len);
}

int udp_send(struct pkt *p)
{
    if (!p)
        return -1;
    return emit(p->data, p->len);
}

int raw_send(struct pkt *p)
{
    if (!p)
        return -1;
    return emit(p->data, p->len);
}

int icmp_send(struct pkt *p)
{
    if (!p)
        return -1;
    return emit(p->data, p->len);
}

static const struct pkt_ops tcp_ops = { .send = tcp_send };
static const struct pkt_ops udp_ops = { .send = udp_send };
static const struct pkt_ops raw_ops = { .send = raw_send };
static const struct pkt_ops icmp_ops = { .send = icmp_send };

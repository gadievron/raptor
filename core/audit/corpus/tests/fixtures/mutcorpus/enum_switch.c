/* Enum-by-switch family: four switches over the same enum, each
 * handling every member with no default arm.  The drop-case-arm
 * mutant removes one arm from one switch, leaving a 3/4 handled
 * majority for the missing member — the enum-switch completeness
 * census flags the deviant switch. */

enum pkt_kind { PKT_DATA, PKT_ACK, PKT_RESET };

int handle_a(enum pkt_kind k)
{
    switch (k) {
    case PKT_DATA: return 1;
    case PKT_ACK: return 2;
    case PKT_RESET: return 3;
    }
    return 0;
}

int handle_b(enum pkt_kind k)
{
    switch (k) {
    case PKT_DATA: return 1;
    case PKT_ACK: return 2;
    case PKT_RESET: return 3;
    }
    return 0;
}

int handle_c(enum pkt_kind k)
{
    switch (k) {
    case PKT_DATA: return 1;
    case PKT_ACK: return 2;
    case PKT_RESET: return 3;
    }
    return 0;
}

int handle_d(enum pkt_kind k)
{
    switch (k) {
    case PKT_DATA: return 1;
    case PKT_ACK: return 2;
    case PKT_RESET: return 3;
    }
    return 0;
}

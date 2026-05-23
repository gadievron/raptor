/*
 * axis8_negative_field_check.c — `if (var->field == 0)` checks a
 * FIELD of var (the underlying memory at the pointer), NOT the
 * pointer itself or the size that overflowed. Axis 8 must NOT
 * suppress — the check doesn't actually mitigate the overflow.
 *
 * Real-world shape: s390/kvm/interrupt.c:3337/3339.
 */
#include <stddef.h>
struct gaite_s { int count; };
extern struct gaite_s *gait_base;

int op(int si) {
    struct gaite_s *gaite = gait_base + (si * sizeof(struct gaite_s));
    if (gaite->count == 0)
        return -1;
    gaite->count++;
    return 0;
}

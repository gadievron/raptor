/*
 * axis4_backwalk_bounded_caller.c — caller has BOUNDED cap
 * (CAP_NET_ADMIN), so back-walk must NOT suppress.
 */
#include <stddef.h>
extern int capable(int);
#define CAP_NET_ADMIN 12
#define EPERM 1
void *memcpy(void *, const void *, unsigned long);

static int net_inner(const char *user, unsigned long len)
{
	char buf[64];
	memcpy(buf, user, len);
	return 0;
}

int net_entry(const char *user, unsigned long len)
{
	if (!capable(CAP_NET_ADMIN))
		return -EPERM;
	return net_inner(user, len);
}

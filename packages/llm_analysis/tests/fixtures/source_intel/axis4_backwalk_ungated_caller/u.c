/*
 * axis4_backwalk_ungated_caller.c — caller has NO capable() gate
 * at all. Back-walk finds an ungated path → must NOT suppress.
 */
#include <stddef.h>
void *memcpy(void *, const void *, unsigned long);

static int unrestricted_inner(const char *user, unsigned long len)
{
	char buf[64];
	memcpy(buf, user, len);
	return 0;
}

int unrestricted_entry(const char *user, unsigned long len)
{
	return unrestricted_inner(user, len);
}

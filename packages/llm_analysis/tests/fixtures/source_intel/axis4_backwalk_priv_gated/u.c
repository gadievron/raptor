/*
 * axis4_backwalk_priv_gated.c — axis-4 1-hop privilege back-walk.
 *
 * Caller `ioctl_entry` checks CAP_SYS_ADMIN. Callee `inner_work`
 * has the CWE-787 bug. Without back-walk, axis-4 only sees the
 * bug function (no capable in same function). With back-walk,
 * axis-4 sees inner_work's only caller IS gated → suppress.
 */
#include <stddef.h>
extern int capable(int);
#define CAP_SYS_ADMIN 21
#define EPERM 1
void *memcpy(void *, const void *, unsigned long);

static int inner_work(const char *user, unsigned long len)
{
	char buf[64];
	memcpy(buf, user, len);  /* CWE-787 — but caller is gated */
	return 0;
}

int ioctl_entry(const char *user, unsigned long len)
{
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	return inner_work(user, len);
}

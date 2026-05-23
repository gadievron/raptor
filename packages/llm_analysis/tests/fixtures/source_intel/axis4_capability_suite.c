/*
 * axis4_capability_suite.c — axis-4 verdict coverage fixture.
 *
 * One function per (cap_function, cap_constant) combination we need
 * to verify. Each fixture creates a finding against a specific
 * function whose privilege gate should/shouldn't suppress.
 *
 * Privileged caps (must suppress):
 *   CAP_SYS_MODULE, CAP_SYS_RAWIO, CAP_SYS_BOOT,
 *   CAP_DAC_OVERRIDE, CAP_DAC_READ_SEARCH
 *   (CAP_SYS_ADMIN already covered in cap_sys_admin_gated.c)
 *
 * Bounded caps (must NOT suppress):
 *   CAP_SYS_NICE (CAP_NET_ADMIN already covered)
 *
 * Cap function variants:
 *   ns_capable, has_capability (cocci matches both; verdict must
 *   exclude both since they're ns-scoped or non-current-task)
 *
 * Cross-function negative:
 *   capable() in a SIBLING function, not the finding's enclosing
 *   function — must NOT dominate.
 */

#include <stddef.h>

extern int capable(int cap);
extern int ns_capable(struct user_namespace *ns, int cap);
extern int has_capability(struct task_struct *t, int cap);

#define CAP_SYS_MODULE 16
#define CAP_SYS_RAWIO 17
#define CAP_SYS_BOOT 22
#define CAP_DAC_OVERRIDE 1
#define CAP_DAC_READ_SEARCH 2
#define CAP_SYS_NICE 23
#define CAP_SYS_ADMIN 21
#define EPERM 1

void *memcpy(void *dst, const void *src, size_t n);


/* 1. capable(CAP_SYS_MODULE) — root-equivalent (module load) */
int privileged_module_op(const char *user, size_t len)
{
	char buf[128];
	if (!capable(CAP_SYS_MODULE))
		return -EPERM;
	memcpy(buf, user, len);
	return 0;
}


/* 2. capable(CAP_SYS_RAWIO) — root-equivalent (raw I/O) */
int privileged_rawio_op(const char *user, size_t len)
{
	char buf[128];
	if (!capable(CAP_SYS_RAWIO))
		return -EPERM;
	memcpy(buf, user, len);
	return 0;
}


/* 3. capable(CAP_SYS_BOOT) — root-equivalent (kexec) */
int privileged_boot_op(const char *user, size_t len)
{
	char buf[128];
	if (!capable(CAP_SYS_BOOT))
		return -EPERM;
	memcpy(buf, user, len);
	return 0;
}


/* 4. capable(CAP_DAC_OVERRIDE) — root-equivalent (file DAC bypass) */
int privileged_dac_override_op(const char *user, size_t len)
{
	char buf[128];
	if (!capable(CAP_DAC_OVERRIDE))
		return -EPERM;
	memcpy(buf, user, len);
	return 0;
}


/* 5. capable(CAP_DAC_READ_SEARCH) — root-equivalent reads */
int privileged_dac_read_op(const char *user, size_t len)
{
	char buf[128];
	if (!capable(CAP_DAC_READ_SEARCH))
		return -EPERM;
	memcpy(buf, user, len);
	return 0;
}


/* 6. capable(CAP_SYS_NICE) — bounded (scheduling priority only) */
int bounded_nice_op(const char *user, size_t len)
{
	char buf[128];
	if (!capable(CAP_SYS_NICE))
		return -EPERM;
	memcpy(buf, user, len);
	return 0;
}


/* 7. ns_capable(ns, CAP_SYS_ADMIN) — userns-scoped (unprivileged
 *    userns admin can self-grant inside their own ns) */
int userns_admin_op(struct user_namespace *ns,
		    const char *user, size_t len)
{
	char buf[128];
	if (!ns_capable(ns, CAP_SYS_ADMIN))
		return -EPERM;
	memcpy(buf, user, len);
	return 0;
}


/* 8. Cross-function negative — capable check in SIBLING, not
 *    finding's enclosing function. */
int cap_check_sibling(void)
{
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	return 0;
}

int finding_target_no_gate(const char *user, size_t len)
{
	char buf[128];
	memcpy(buf, user, len);  /* no capability gate in this function */
	return 0;
}

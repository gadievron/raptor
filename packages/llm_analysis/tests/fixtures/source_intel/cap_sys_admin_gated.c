/*
 * cap_sys_admin_gated.c — axis-4 verdict fixture.
 *
 * Surface shape: CWE-787 unbounded-write into a fixed-size kernel
 * buffer (overflow if `len` is attacker-controlled). A naive
 * analyser flags this as TP-exploitable.
 *
 * Actual semantics: the function is gated by capable(CAP_SYS_ADMIN)
 * — only an already-root attacker can reach the bug primitive.
 * Such an attacker already holds power that subsumes the
 * memory-corruption capability, so the finding contributes no
 * additional adversary capability. Classified as framework_mitigation
 * (privilege gate).
 *
 * Source_intel evidence expected:
 *   - Axis 4 (capability_check) emits "capability:capable" at line 18
 *     with grade=dominates (same_function, ±50 line proximity)
 *   - Verdict policy: NOT_EXPLOITABLE because cap_function="capable"
 *     and the line carries CAP_SYS_ADMIN (in _PRIVILEGED_CAP_CONSTANTS)
 *
 * Inspired by the shape of CVE-2022-0185 (legacy_parse_param) and
 * other CAP_SYS_ADMIN-gated fs/mount-path bugs. Crafted, not the
 * actual CVE code.
 */

#include <stddef.h>

extern int capable(int cap);
#define CAP_SYS_ADMIN 21
#define EPERM 1

void *memcpy(void *dst, const void *src, size_t n);

int privileged_fs_setup(const char *user_data, size_t len)
{
	char setup_buf[128];

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	memcpy(setup_buf, user_data, len);
	return 0;
}

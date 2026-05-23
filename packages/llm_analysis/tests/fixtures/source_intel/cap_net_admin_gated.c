/*
 * cap_net_admin_gated.c — axis-4 negative fixture (privilege gate
 * exists but is BOUNDED — verdict policy must NOT suppress).
 *
 * Surface shape: CWE-787 unbounded-write into a fixed-size buffer
 * — same as cap_sys_admin_gated.c.
 *
 * Actual semantics: gated by capable(CAP_NET_ADMIN). CAP_NET_ADMIN
 * grants network-stack admin power (interface configuration, packet
 * filters, etc.) — bounded. It does NOT grant root-equivalent
 * arbitrary memory write. So a memory-corruption primitive in a
 * CAP_NET_ADMIN-gated path IS a privilege escalation: from
 * CAP_NET_ADMIN → arbitrary kernel memory. The finding stands.
 *
 * Source_intel evidence expected:
 *   - Axis 4 (capability_check) emits "capability:capable" at line 17
 *     with grade=dominates
 *   - Verdict policy: NOT suppressed. CAP_NET_ADMIN is NOT in
 *     _PRIVILEGED_CAP_CONSTANTS, so _line_uses_privileged_cap()
 *     returns False, and _privileged_capability_dominates() returns
 *     False. Verdict falls through to UNCERTAIN (no other axis
 *     fires for this fixture).
 *
 * Inspired by netfilter/nft-class bugs (e.g. CVE-2022-32250, which
 * is CAP_NET_ADMIN-gated for some attack paths). Crafted, not the
 * actual CVE code.
 */

#include <stddef.h>

extern int capable(int cap);
#define CAP_NET_ADMIN 12
#define EPERM 1

void *memcpy(void *dst, const void *src, size_t n);

int net_admin_op(const char *user_data, size_t len)
{
	char setup_buf[128];

	if (!capable(CAP_NET_ADMIN))
		return -EPERM;

	memcpy(setup_buf, user_data, len);
	return 0;
}

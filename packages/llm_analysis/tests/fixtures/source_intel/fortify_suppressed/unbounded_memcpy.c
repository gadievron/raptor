/*
 * unbounded_memcpy.c — axis-6 verdict fixture (FORTIFY_SOURCE
 * intercepts the call → NOT_EXPLOITABLE).
 *
 * Surface shape: CWE-787 unbounded write of attacker-controlled
 * length into a fixed-size stack buffer via memcpy().
 *
 * Actual semantics: with -D_FORTIFY_SOURCE=2 in the build
 * (compile_commands.json sibling), glibc rewrites this memcpy() to
 * __memcpy_chk(setup_buf, user_data, len, __builtin_object_size(setup_buf, 0)),
 * which aborts at runtime if len > 128. The bug primitive is gated
 * by FORTIFY — exploitation reduced to abort()/SIGABRT.
 *
 * Source_intel evidence expected:
 *   - Axis 6 consumer reads build_flags.fortify_source_level=2
 *   - Sink line names `memcpy` which is in _FORTIFIED_WRITE_CALLS
 *   - _fortify_source_blocks_finding() returns True
 *   - Verdict policy: NOT_EXPLOITABLE
 *
 * Crafted fixture, not a real CVE.
 */

#include <stddef.h>

void *memcpy(void *dst, const void *src, size_t n);

int fortified_op(const char *user_data, size_t len)
{
	char setup_buf[128];
	memcpy(setup_buf, user_data, len);
	return 0;
}

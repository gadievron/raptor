/*
 * unbounded_mymemcpy.c — axis-6 negative fixture.
 *
 * Surface shape: CWE-787 unbounded write through a CUSTOM helper
 * `my_memcpy()`. The build IS FORTIFY_SOURCE=2 (sibling
 * compile_commands.json), but FORTIFY only intercepts glibc names
 * (memcpy / strcpy / sprintf / etc.) — not user-defined wrappers.
 *
 * Source_intel evidence expected:
 *   - Axis 6 consumer reads build_flags.fortify_source_level=2
 *   - Sink line names `my_memcpy` which is NOT in _FORTIFIED_WRITE_CALLS
 *   - Token-boundary scan in _fortify_source_blocks_finding() rejects
 *     `my_memcpy` (substring match suppressed)
 *   - Verdict policy: NOT suppressed (falls through to UNCERTAIN)
 *
 * This is the false-positive boundary test for axis 6: presence of
 * FORTIFY in the build does not blanket-suppress unbounded-write
 * findings — only fortified-call findings.
 */

#include <stddef.h>

static void my_memcpy(void *dst, const void *src, size_t n)
{
	char *d = (char *)dst;
	const char *s = (const char *)src;
	for (size_t i = 0; i < n; i++)
		d[i] = s[i];
}

int custom_op(const char *user_data, size_t len)
{
	char setup_buf[128];
	my_memcpy(setup_buf, user_data, len);
	return 0;
}

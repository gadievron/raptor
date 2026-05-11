/*
 * Phase 1.6 target #2: classic off-by-one — freestanding form.
 *
 * Distinct bug shape from target #1's "no bound check at all":
 *   target #1: for (i = 0; i < n; i++) buf[i] = input[i];          // ignores buf_size entirely
 *   target #2: for (i = 0; i <= buf_size && i < n; i++) ...;       // <= instead of < — writes ONE byte past
 *
 * On any witness with n >= buf_size + 1, the bug writes a single byte
 * at offset buf_size (just past the valid buffer). For n in (0, buf_size]
 * the bug doesn't fire — the loop terminates on `i < n` before reaching
 * the off-by-one boundary.
 *
 * Behaviourally the same gadget (memory-safety::oob-write) catches this,
 * but the corpus has a sharper signal: every crash witness has
 * exactly oob_count == 1, regardless of witness length. That's a
 * structural-output test the redzone+pattern primitive should pass.
 */

#include <stddef.h>

char zkpox_target_02_victim(
    char *buf,
    size_t buf_size,
    const char *input,
    size_t n)
{
    /* Bug: `i <= buf_size`. Standard textbook off-by-one. */
    for (size_t i = 0; i <= buf_size && i < n; i++) {
        buf[i] = input[i];
    }
    return buf[0];
}

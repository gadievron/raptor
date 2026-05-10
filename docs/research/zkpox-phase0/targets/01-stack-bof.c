/*
 * Phase 0 target #1: classic stack buffer overflow — freestanding form.
 *
 * Originally a small standalone process. Refactored so the buggy primitive
 * is a single freestanding function (no syscalls, no libc) — the same C
 * source can therefore be (a) compiled to a native binary for sanity checks
 * via 01-stack-bof-native.c and (b) cross-compiled by SP1's RISC-V
 * toolchain and linked into the SP1 guest harness/guest/.
 *
 * The bug under proof — `for (i = 0; i < n; ...)` with no bound check
 * against `buf_size` — is unchanged from the original. The C function
 * itself does not detect or signal the overflow; the SP1 gadget wrapper
 * places ASan-style sentinel canaries on either side of the caller-
 * provided buffer and checks them after the call returns.
 */

#include <stddef.h>

/*
 * Buggy primitive. Copies `n` bytes from `input` into `buf`, ignoring
 * `buf_size`. Returns buf[0] so the compiler keeps the writes live (the
 * native wrapper also reads it as a no-op sentinel).
 */
char zkpox_target_01_victim(
    char *buf,
    size_t buf_size,
    const char *input,
    size_t n)
{
    (void)buf_size;  /* deliberately unused — that's the bug */
    for (size_t i = 0; i < n; i++) {
        buf[i] = input[i];
    }
    return buf[0];
}

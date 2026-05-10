/*
 * Native wrapper around the freestanding `zkpox_target_01_victim`. Used by
 * the native sanity check (`make -C targets verify`) so an operator can
 * confirm the bug exists in the original C source independently of the
 * SP1 proof. The wrapper itself is not part of the ZK circuit.
 *
 * Build (with stack canaries on, so the BOF is detected at runtime):
 *   clang -O0 -fstack-protector-strong -o 01-stack-bof \
 *         01-stack-bof-native.c 01-stack-bof.c
 *
 * Witnesses:
 *   ../witnesses/01-benign.bin   <= 16 bytes, exits 0.
 *   ../witnesses/01-crash.bin    32 'A's, triggers __stack_chk_fail.
 */

#include <stddef.h>
#include <unistd.h>

extern char zkpox_target_01_victim(
    char *buf, size_t buf_size,
    const char *input, size_t n);

int main(void) {
    char input[256];
    char buf[16];
    ssize_t n = read(0, input, sizeof(input));
    if (n <= 0) return 0;
    char sentinel = zkpox_target_01_victim(buf, sizeof(buf), input, (size_t)n);
    if (sentinel == (char)0xff) {
        write(1, "sentinel\n", 9);
    }
    return 0;
}

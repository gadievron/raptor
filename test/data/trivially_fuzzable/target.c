/*
 * Trivially-fuzzable target for end-to-end testing of:
 *   - /fuzz crash collection
 *   - /fuzz --execute-exploits (PR E) Witness capture
 *   - exploit_verify.compile_and_execute with sanitizers
 *
 * Reads up to 64 bytes from stdin. The first byte is a tag:
 *
 *   'A'  → strcpy() the rest into an 8-byte stack buffer.
 *          With -fsanitize=address, AFL or a hand-written PoC of
 *          more than 8 bytes triggers a stack-buffer-overflow
 *          ASAN report. Without sanitizers, it usually crashes
 *          with SIGSEGV.
 *   'B'  → dereference NULL → SIGSEGV.
 *   'C'  → clean exit (control case — exercises NO_OBVIOUS_EFFECT).
 *   else → exit(0) silently.
 *
 * Deliberately compact + obvious: this is a TEST FIXTURE, not a
 * realistic vulnerability. Operators run RAPTOR against it to
 * verify the full pipeline (compile → fuzz → crash collect →
 * LLM analyse → execute exploit in sandbox → record Witness)
 * works end-to-end with sanitized binaries.
 *
 * Build:
 *   make -C test/data/trivially_fuzzable         # with sanitizers
 *   make -C test/data/trivially_fuzzable plain   # without
 *
 * Probe:
 *   echo -n 'AAAAAAAAAAAAAAAAAAAA' | ./target    # BOF
 *   echo -n 'B'                    | ./target    # NULL deref
 *   echo -n 'C'                    | ./target    # clean
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

int main(void) {
    char input[64];
    ssize_t n = read(0, input, sizeof(input) - 1);
    if (n <= 0) {
        return 1;
    }
    input[n] = '\0';

    switch (input[0]) {
    case 'A': {
        char buf[8];
        /* Deliberate strcpy of attacker-controlled bytes into
         * an 8-byte buffer. ASAN reports stack-buffer-overflow
         * on any input where strlen(input + 1) >= 8. */
        strcpy(buf, input + 1);
        puts(buf);
        return 0;
    }
    case 'B': {
        /* Deliberate NULL deref → SIGSEGV. */
        int *p = NULL;
        *p = 42;
        return 0;
    }
    case 'C':
        /* Control: clean exit, no observable bug signal. */
        puts("ok");
        return 0;
    default:
        return 0;
    }
}

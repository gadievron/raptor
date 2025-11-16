/*
 * vuln_fuzz_target.c
 *
 * Educational fuzz target for AFL / AFL++
 * Contains several intentional vulnerabilities:
 *  - stack buffer overflow via unsafe strcpy
 *  - heap use-after-free
 *  - integer overflow -> heap overflow
 *  - uncontrolled format string
 *
 * Build with: afl-clang-fast -g -O2 -o vuln_fuzz_target vuln_fuzz_target.c
 * (or compile with sanitizers for debugging)
 *
 * Only use in isolated lab environments.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static void vuln_stack_overflow(const uint8_t *data, size_t size) {
    /* Trigger when first byte is 'A' to guide fuzzer into this path */
    if (size < 1 || data[0] != 'A') return;

    /* Intentionally small fixed buffer */
    char buf[32];
    /* unsafe copy to create stack overflow when input is longer than 31 chars */
    /* This models legacy C code that trusts external input. */
    strcpy(buf, (const char *)data + 1);

    /* Use buf so compiler does not optimise away */
    if (buf[0] == 'X') {
        puts("stack overflow path reached");
    }
}

static void vuln_use_after_free(const uint8_t *data, size_t size) {
    /* Trigger when first byte is 'B' */
    if (size < 1 || data[0] != 'B') return;

    char *p = malloc(64);
    if (!p) return;
    /* populate buffer */
    memset(p, 0, 64);
    memcpy(p, data + 1, (size > 63) ? 63 : (size - 1));

    /* free and then use */
    free(p);

    /* Intentional use after free */
    if (size > 10) {
        /* access freed memory */
        if (p[0] == 'U') {
            puts("use after free path reached");
        }
    }
}

static void vuln_integer_overflow(const uint8_t *data, size_t size) {
    /* Trigger when first byte is 'C' */
    if (size < 1 || data[0] != 'C') return;

    /* Use small header: next two bytes indicate element count and element size */
    if (size < 3) return;
    uint8_t count = data[1];
    uint8_t elt_size = data[2];

    /* Intentionally naive multiplication may overflow and create small allocation */
    /* This models mistakes where untrusted lengths are multiplied */
    size_t total = (size_t)count * (size_t)elt_size;

    /* If total wraps to a small value, subsequent writes will overflow heap allocation */
    char *buf = malloc(total + 1);
    if (!buf) return;

    /* Copy as if there were count * elt_size bytes available */
    /* This will overflow when multiplication overflowed */
    size_t tocopy = (size > 3) ? (size - 3) : 0;
    memcpy(buf, data + 3, tocopy);

    /* Check something to avoid optimisation */
    if (tocopy > 0 && buf[0] == 'O') {
        puts("integer/heap overflow path reached");
    }

    free(buf);
}

static void vuln_format_string(const uint8_t *data, size_t size) {
    /* Trigger when first byte is 'D' */
    if (size < 1 || data[0] != 'D') return;

    /* Use the rest of the input directly as a format string */
    const char *fmt = (const char *)(data + 1);

    /* Dangerous: uncontrolled format string */
    /* Intentionally present for teaching purposes */
    if (size > 1) {
        printf(fmt);
        putchar('\n');
    }
}

int main(int argc, char **argv) {
    (void)argc;
    (void)argv;

    /* Read up to 16 KiB from either the file passed by AFL (argv[1]) or stdin */
    const size_t MAX = 16 * 1024;
    uint8_t *buffer = malloc(MAX);
    if (!buffer) {
        fprintf(stderr, "allocation failed\n");
        return 1;
    }

    size_t readn = 0;

    if (argc > 1 && argv[1] != NULL) {
        /* AFL will replace @@ with a filename; open that file and read it */
        FILE *f = fopen(argv[1], "rb");
        if (f) {
            readn = fread(buffer, 1, MAX, f);
            fclose(f);
        } else {
            fprintf(stderr, "failed to open input file: %s\n", argv[1]);
            free(buffer);
            return 1;
        }
    } else {
        /* fallback to stdin for manual testing */
        readn = fread(buffer, 1, MAX, stdin);
    }

    /* Call vulnerable handlers */
    vuln_stack_overflow(buffer, readn);
    vuln_use_after_free(buffer, readn);
    vuln_integer_overflow(buffer, readn);
    vuln_format_string(buffer, readn);

    free(buffer);
    return 0;
}


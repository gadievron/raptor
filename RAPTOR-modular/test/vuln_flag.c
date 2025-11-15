/*
 * vuln_flag.c
 *
 * Intentionally vulnerable program for classroom use.
 *
 * Vulnerabilities:
 *  - heap overflow: writes past a heap buffer into an adjacent struct which contains
 *    a function pointer that, if overwritten, will be called and will print the flag.
 *  - stack buffer overflow: legacy function uses unsafe strcpy on a fixed-size stack buffer.
 *
 * Build with:
 *   afl-clang-fast -g -O2 -fno-stack-protector -fno-builtin -no-pie -o vuln_flag_mac vuln_flag.c
 *
 * Safety:
 *  - Run only in isolated lab VMs. Do not expose to networks or untrusted users.
 *  - This file is intentionally insecure for teaching mitigation, triage and fuzzing.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* PATH_TO_FLAG: path to the flag file used in lab. Create a file named flag.txt next to the binary. */
static const char *FLAG_PATH = "flag.txt";

/* Helper that prints the flag to stdout. Intentionally present as a target for hijack in the lab. */
void get_flag(void) {
    FILE *f = fopen(FLAG_PATH, "r");
    if (!f) {
        fprintf(stderr, "[get_flag] Could not open flag file: %s\n", FLAG_PATH);
        return;
    }
    char buf[512];
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    buf[n] = '\0';
    printf("[FLAG] %s\n", buf);
}

/* A safe-looking function used in normal program flow */
void safe_print(void) {
    puts("[safe_print] Access denied.");
}

/* A small heap-allocated object that stores a pointer to a callback and some metadata.
   The heap overflow will target the adjacent buffer and try to overwrite this->cb. */
typedef struct {
    void (*cb)(void);
    uint32_t id;
    char name[16];
} handler_t;

/* vuln_heap_overflow: allocate a handler and a data buffer adjacent and then memcpy unbounded */
void vuln_heap_overflow(const uint8_t *data, size_t size) {
    /* Only exercise this path when first byte is 'H' */
    if (size < 1 || data[0] != 'H') return;

    /* allocate two heap blocks consecutively */
    handler_t *h = malloc(sizeof(handler_t));
    if (!h) return;
    h->cb = safe_print;
    h->id = 0x41414141;
    strncpy(h->name, "handler", sizeof(h->name) - 1);
    h->name[sizeof(h->name) - 1] = '\0';

    /* a second allocation which we will overflow from */
    size_t bufsz = 64;
    char *buf = malloc(bufsz);
    if (!buf) {
        free(h);
        return;
    }

    /* Populate buf with controlled data (this intentionally omits bounds checks) */
    /* By copying size-1 bytes into buf we allow overwriting h->cb if size is large enough */
    size_t tocopy = (size > 1) ? (size - 1) : 0;
    memcpy(buf, data + 1, tocopy); /* INTENTIONAL: unsafe copy for lab */

    /* Show current callback behaviour */
    puts("[vuln_heap_overflow] calling handler callback:");
    h->cb();

    /* Clean up */
    free(buf);
    free(h);
}

/* vuln_stack_overflow: classic unsafe strcpy on a small stack buffer.
   Triggered when first byte equals 'S'. */
void vuln_stack_overflow(const uint8_t *data, size_t size) {
    if (size < 1 || data[0] != 'S') return;

    char small[32];
    /* Unsafe copy: if input after 'S' is >31 chars this will overflow onto the stack */
    strcpy(small, (const char *)(data + 1));

    /* Simple check so the fuzzer finds a path */
    if (small[0] == 'X') {
        puts("[vuln_stack_overflow] path reached");
    }
}

int main(int argc, char **argv) {
    (void)argc;
    (void)argv;

    const size_t MAX = 16 * 1024;
    uint8_t *buffer = malloc(MAX);
    if (!buffer) {
        fprintf(stderr, "allocation failed\n");
        return 1;
    }

    size_t readn = 0;
    /* support AFL style filename argument */
    if (argc > 1 && argv[1] != NULL) {
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
        readn = fread(buffer, 1, MAX, stdin);
    }

    /* Call vulnerable handlers */
    vuln_heap_overflow(buffer, readn);
    vuln_stack_overflow(buffer, readn);

    /* Added call to get_flag to read and print the flag */
    get_flag();

    free(buffer);
    return 0;
}

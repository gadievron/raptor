/*
 * SMT Testbench — cases designed to exercise Z3 path condition analysis
 *
 * Organised into three groups:
 *
 *   GROUP 1 — SAT with non-obvious PoC values
 *     Z3 finds a concrete satisfying assignment that a human (or LLM) would
 *     likely miss because it requires reasoning about unsigned bitvector
 *     wraparound or compound inequality constraints.  ALLOC/SUM/MASK depend
 *     on 32-bit unsigned wraparound — pass ``profile=BV_C_UINT32`` to
 *     ``check_path_feasibility`` for those.  OBO is profile-agnostic.
 *
 *   GROUP 2 — UNSAT (provably dead paths)
 *     CodeQL reports a flow to a dangerous sink, but the path conditions are
 *     mutually exclusive.  Z3 proves UNSAT and the LLM call is skipped.
 *     Without Z3 these would be time-wasting false positives.
 *
 *   GROUP 3 — INDETERMINATE (Z3 falls through to LLM)
 *     Conditions involve function calls or idioms the bitvector parser
 *     cannot encode.  Z3 returns feasible=None and full LLM analysis runs.
 *     Included to show graceful degradation.
 *
 * Compile (no mitigations, so crashes are visible):
 *   gcc -fno-stack-protector -Wno-format-security -o smt_codeql_testbench smt_codeql_testbench.c
 *
 * Input format (stdin):
 *   <COMMAND>:<args separated by commas>
 *
 * Commands match function names below.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* =========================================================================
 * GROUP 1 — SAT WITH NON-OBVIOUS PoC VALUES
 * =========================================================================
 *
 * These functions contain real bugs that are hard to spot by inspection
 * because the dangerous input is a large unsigned value that still satisfies
 * all visible guards due to 32-bit wraparound.
 *
 * Z3 advantage: bitvector arithmetic finds the exact wraparound value
 * immediately; the LLM prompt gets it as a concrete candidate input.
 */

/* -------------------------------------------------------------------------
 * CASE 1a — allocation size overflow (CWE-190 → CWE-122)
 *
 * Invoke check_path_feasibility with profile=BV_C_UINT32.
 *
 * Guard:    count < MAX_RECORDS  (looks protective)
 * Bug:      count * sizeof(record) overflows to a small value
 * Z3 finds: count = (UINT32_MAX / 16) + 1 = 0x10000001
 *           0x10000001 * 16 = 0x100000010 truncated to 32 bits = 0x10
 *           0x10 < MAX_ALLOC=0x8000 ✓ — malloc gets 16 bytes
 *           then loop writes count*16 = 2GB+ into it
 *
 * Path conditions for SMT:
 *   count < 268435456        (count < MAX_RECORDS = 0x10000000)
 *   alloc_size < 32768       (alloc_size < MAX_ALLOC = 0x8000)
 *   alloc_size == count * 16 (relation — encoded as alloc_size = count * 16)
 *
 * Z3 encodes the multiplication as bitvector mul with wraparound and finds
 * count=0x10000001 satisfying all three conditions simultaneously.
 * -------------------------------------------------------------------------*/
/* MAX_RECORDS must be > UINT32_MAX/RECORD_SIZE so that values passing the
 * count check can still cause count*RECORD_SIZE to wrap.
 * UINT32_MAX/16 = 0xFFFFFFF = 268435455; any count > that and < MAX_RECORDS
 * will overflow the multiplication.  MAX_RECORDS = 0x40000000 gives a wide
 * window: count in [0x10000001, 0x3FFFFFFF] all pass the guard AND overflow. */
#define MAX_RECORDS  0x40000000u
#define MAX_ALLOC    0x8000u
#define RECORD_SIZE  16u

typedef struct { char data[RECORD_SIZE]; } record_t;

void case_alloc_overflow(unsigned int count) {
    unsigned int alloc_size = count * RECORD_SIZE;   /* ← wraparound here */

    if (count >= MAX_RECORDS) {
        fprintf(stderr, "[ALLOC] count too large\n");
        return;
    }
    if (alloc_size >= MAX_ALLOC) {
        fprintf(stderr, "[ALLOC] allocation too large\n");
        return;
    }

    record_t *records = malloc(alloc_size);
    if (!records) return;

    /* write count records into a buffer sized for alloc_size/RECORD_SIZE */
    for (unsigned int i = 0; i < count; i++) {
        memset(&records[i], 'A', RECORD_SIZE);   /* VULNERABILITY: OOB write */
    }

    printf("[ALLOC] Wrote %u records\n", count);
    free(records);
}

/* -------------------------------------------------------------------------
 * CASE 1b — compound bounds check bypass (CWE-190 → CWE-120)
 *
 * Invoke check_path_feasibility with profile=BV_C_UINT32.
 *
 * This mimics the classic safe-looking copy guard:
 *   if (offset + length <= buffer_size) { memcpy(...) }
 *
 * Guard looks correct; Z3 finds a wraparound assignment:
 *   offset = 0xffff0000, length = 0x00010001
 *   sum    = 0x00000001 (wraps!) which is <= buffer_size
 *
 * Path conditions:
 *   offset + length <= buffer_size
 *   buffer_size == 64
 *   offset > 0
 *   length > 0
 *
 * Z3 SAT: offset=0xffff0010, length=0x00010000 gives sum=0x10 <= 64
 * -------------------------------------------------------------------------*/
#define FIXED_BUFFER_SIZE 64u

static char shared_buffer[FIXED_BUFFER_SIZE];

void case_sum_overflow(unsigned int offset, unsigned int length,
                       const char *src, unsigned int buffer_size) {

    if (buffer_size > FIXED_BUFFER_SIZE) {
        fprintf(stderr, "[SUM] buffer_size out of range\n");
        return;
    }

    /* Guard looks protective — but both operands are unsigned 32-bit */
    if (offset + length <= buffer_size) {            /* ← wraparound bypass */
        memcpy(shared_buffer + offset, src, length); /* VULNERABILITY: OOB */
        printf("[SUM] Copied %u bytes at offset %u\n", length, offset);
    }
}

/* -------------------------------------------------------------------------
 * CASE 1c — off-by-one via <= instead of < (CWE-193)
 *
 * Guard:   index >= 0 AND index <= LIMIT
 * Bug:     index == LIMIT writes exactly one byte past the array end
 *
 * Z3 finds: index = LIMIT (= 128) satisfies all conditions AND
 *           index = LIMIT makes write land at buf[128] which is OOB
 *           (buf is declared as char buf[128])
 *
 * Path conditions:
 *   index >= 0
 *   index <= 128   (should be < 128)
 * -------------------------------------------------------------------------*/
#define INDEX_LIMIT 128

void case_offbyone(int index, char value) {
    char buf[INDEX_LIMIT];   /* buf[0..127] valid */

    if (index < 0) {
        fprintf(stderr, "[OBO] negative index\n");
        return;
    }
    if (index > INDEX_LIMIT) {       /* BUG: should be >= INDEX_LIMIT */
        fprintf(stderr, "[OBO] index too large\n");
        return;
    }

    buf[index] = value;              /* VULNERABILITY: OOB when index == 128 */
    printf("[OBO] Wrote 0x%02x at index %d\n", (unsigned char)value, index);
}

/* -------------------------------------------------------------------------
 * CASE 1d — bitmask check bypass (alignment constraint + wraparound)
 *
 * Invoke check_path_feasibility with profile=BV_C_UINT32.
 *
 * Guard:  flags & PRIV_FLAG == 0   ("unprivileged request only")
 *         size < MAX_SIZE
 * Bug:    a large size combined with a base address causes OOB
 *         Z3 finds the exact size that passes the guard
 *
 * Path conditions (for the dangerous branch):
 *   flags & 0x80000000 == 0
 *   size < 4096
 *   base + size <= 8192   (← another sum that can overflow)
 * -------------------------------------------------------------------------*/
#define PRIV_FLAG  0x80000000u
#define MAX_SIZE   4096u
#define HEAP_SIZE  8192u

static char heap_region[HEAP_SIZE];

void case_bitmask_bypass(unsigned int flags, unsigned int base,
                         unsigned int size, const char *payload) {
    if (flags & PRIV_FLAG) {
        fprintf(stderr, "[MASK] privileged flag set — rejected\n");
        return;
    }
    if (size >= MAX_SIZE) {
        fprintf(stderr, "[MASK] size too large\n");
        return;
    }
    /* base + size overflow: base=0xffffE000, size=4000 → sum=0x3ee0 <= 8192 */
    if (base + size <= HEAP_SIZE) {                  /* ← overflow bypass */
        memcpy(heap_region + base, payload, size);   /* VULNERABILITY: OOB */
        printf("[MASK] Wrote %u bytes at base %u\n", size, base);
    }
}


/* =========================================================================
 * GROUP 2 — UNSAT (PROVABLY DEAD PATHS / TRUE NEGATIVES)
 * =========================================================================
 *
 * CodeQL will report a flow to the dangerous sink.  Z3 proves the path
 * conditions are mutually exclusive → finding is skipped, no LLM call.
 *
 * Without Z3 these generate expensive false-positive LLM calls and produce
 * report noise that wastes analyst time.
 */

/* -------------------------------------------------------------------------
 * CASE 2a — value range contradiction
 *
 * The outer guard requires x > 100.
 * An inner guard (simulating a second validation layer) requires x < 50.
 * These are mutually exclusive — Z3 reports UNSAT immediately.
 *
 * Path conditions (for the sink):
 *   x > 100
 *   x < 50        ← contradiction
 *
 * Z3: UNSAT. Conflicting conditions: "x > 100" ⊥ "x < 50"
 * -------------------------------------------------------------------------*/
char dead_buf[32];

void case_dead_range(int x, const char *data) {
    if (x <= 100) {
        fprintf(stderr, "[DEAD_RANGE] x must be > 100\n");
        return;
    }

    /* imagine this is a second validation in a different module */
    if (x >= 50) {
        /* this branch is NOT dead — but the sub-condition below is */
        if (x < 50) {
            /* provably unreachable: x > 100 AND x < 50 is impossible */
            strcpy(dead_buf, data);    /* CodeQL flags this; Z3 proves dead */
            printf("[DEAD_RANGE] unreachable write\n");
        }
    }
}

/* -------------------------------------------------------------------------
 * CASE 2b — pointer nullness contradiction
 *
 * After a NULL check passes (ptr != NULL), a defensive re-check later in
 * the path tests ptr == NULL.  Z3 encodes both conditions and finds UNSAT.
 *
 * Path conditions for the sink:
 *   ptr != NULL   (guard at top of function)
 *   ptr == NULL   (defensive re-check that makes the inner branch dead)
 *
 * Z3: UNSAT. ptr != NULL AND ptr == NULL is unsatisfiable.
 * -------------------------------------------------------------------------*/
void case_dead_null(const char *ptr, char *dst) {
    if (ptr == NULL) {
        fprintf(stderr, "[DEAD_NULL] null input\n");
        return;
    }

    /* ptr is non-null here — the branch below is dead */
    if (ptr != NULL) {
        /* ... do real work ... */
        strncpy(dst, ptr, 32);
    } else {
        /* provably dead: ptr == NULL AND ptr != NULL is impossible */
        strcpy(dst, ptr);  /* CodeQL may flag; Z3 proves dead */
        printf("[DEAD_NULL] unreachable strcpy\n");
    }
}

/* -------------------------------------------------------------------------
 * CASE 2c — bitmask contradiction
 *
 * An outer check ensures bit 0 of flags is 0 (even).
 * An inner check requires bit 0 of flags is 1 (odd).
 * These are mutually exclusive by definition.
 *
 * Path conditions:
 *   flags & 0x1 == 0   (outer: even-only path)
 *   flags & 0x1 == 1   (inner: odd required)
 *
 * Z3: UNSAT. flags & 0x1 cannot be both 0 and 1 simultaneously.
 * -------------------------------------------------------------------------*/
char flag_buf[64];

void case_dead_bitmask(unsigned int flags, const char *payload, size_t len) {
    if (flags & 0x1) {
        fprintf(stderr, "[DEAD_MASK] odd flags rejected\n");
        return;
    }
    /* flags & 0x1 == 0 here */

    if ((flags & 0x1) == 1) {   /* provably false */
        /* unreachable: flags & 0x1 was just confirmed to be 0 */
        if (len < sizeof(flag_buf)) {
            memcpy(flag_buf, payload, len);  /* CodeQL flags; Z3 proves dead */
        }
        printf("[DEAD_MASK] unreachable memcpy\n");
    }
}


/* =========================================================================
 * GROUP 3 — INDETERMINATE (Z3 FALLS THROUGH TO LLM)
 * =========================================================================
 *
 * Conditions involve function calls, strlen, or runtime values that the
 * bitvector parser cannot encode (returns None → full LLM analysis runs).
 * These are included to demonstrate graceful degradation.
 */

/* -------------------------------------------------------------------------
 * CASE 3a — function-call condition (strlen)
 *
 * The guard uses strlen() which the SMT parser rejects (contains '(' ')').
 * Z3 returns feasible=None; LLM analysis runs unchanged.
 *
 * This IS a real vulnerability (classic stack overflow via strcpy).
 * -------------------------------------------------------------------------*/
void case_llm_fallthrough(const char *input) {
    char local[64];

    /* strlen() call makes this condition unparseable by the bitvector engine */
    if (strlen(input) < sizeof(local)) {
        strcpy(local, input);    /* safe when guard holds; but LLM must verify */
        printf("[LLM] Copied: %s\n", local);
    } else {
        printf("[LLM] Input too long, skipped\n");
    }
}

/* -------------------------------------------------------------------------
 * CASE 3b — combined: one parseable + one unparseable condition
 *
 * Z3 can encode `size < 256` but not `validate(ptr)`.
 * The parseable condition alone gives a partial sat result (feasible=None
 * because not all conditions could be checked).  LLM still runs.
 * -------------------------------------------------------------------------*/
static int validate(const char *ptr) {
    return ptr != NULL && ptr[0] != '\0';
}

void case_partial_smt(unsigned int size, const char *ptr) {
    char buf[256];

    if (size >= sizeof(buf)) {
        return;
    }
    /* validate() call is unparseable; Z3 returns None for this branch */
    if (validate(ptr)) {
        memcpy(buf, ptr, size);    /* real vulnerability if ptr is attacker-controlled */
        printf("[PARTIAL] Copied %u bytes\n", size);
    }
}


/* =========================================================================
 * DISPATCHER
 * =========================================================================*/

static void usage(void) {
    fprintf(stderr,
        "Commands (stdin: COMMAND:arg1,arg2,...):\n"
        "  ALLOC:<count>\n"
        "  SUM:<offset>,<length>,<buffer_size>\n"
        "  OBO:<index>,<value_hex>\n"
        "  MASK:<flags_hex>,<base>,<size>\n"
        "  DEAD_RANGE:<x>\n"
        "  DEAD_NULL:<string>\n"
        "  DEAD_MASK:<flags_hex>\n"
        "  LLM:<string>\n"
        "  PARTIAL:<size>,<string>\n"
    );
}

int main(void) {
    char line[4096];
    if (!fgets(line, sizeof(line), stdin)) {
        usage();
        return 1;
    }
    line[strcspn(line, "\n")] = '\0';

    char *colon = strchr(line, ':');
    if (!colon) { usage(); return 1; }
    *colon = '\0';
    char *cmd  = line;
    char *args = colon + 1;

    if (strcmp(cmd, "ALLOC") == 0) {
        unsigned int count = (unsigned int)strtoul(args, NULL, 0);
        case_alloc_overflow(count);

    } else if (strcmp(cmd, "SUM") == 0) {
        unsigned int offset = 0, length = 0, bsz = 0;
        sscanf(args, "%u,%u,%u", &offset, &length, &bsz);
        char src[4096] = {0};
        memset(src, 'S', sizeof(src) - 1);
        case_sum_overflow(offset, length, src, bsz);

    } else if (strcmp(cmd, "OBO") == 0) {
        int index = 0; unsigned int val = 0;
        sscanf(args, "%d,%x", &index, &val);
        case_offbyone(index, (char)(val & 0xff));

    } else if (strcmp(cmd, "MASK") == 0) {
        unsigned int flags = 0, base = 0, sz = 0;
        sscanf(args, "%x,%u,%u", &flags, &base, &sz);
        char payload[4096];
        memset(payload, 'P', sizeof(payload));
        case_bitmask_bypass(flags, base, sz, payload);

    } else if (strcmp(cmd, "DEAD_RANGE") == 0) {
        int x = atoi(args);
        case_dead_range(x, "overflow_payload_that_would_crash");

    } else if (strcmp(cmd, "DEAD_NULL") == 0) {
        char dst[128] = {0};
        case_dead_null(args, dst);
        printf("[DEAD_NULL] dst = %.32s\n", dst);

    } else if (strcmp(cmd, "DEAD_MASK") == 0) {
        unsigned int flags = (unsigned int)strtoul(args, NULL, 16);
        case_dead_bitmask(flags, "payload_data", 12);

    } else if (strcmp(cmd, "LLM") == 0) {
        case_llm_fallthrough(args);

    } else if (strcmp(cmd, "PARTIAL") == 0) {
        unsigned int sz = 0;
        char *comma = strchr(args, ',');
        if (comma) { sz = (unsigned int)strtoul(args, NULL, 0); args = comma + 1; }
        case_partial_smt(sz, args);

    } else {
        usage();
        return 1;
    }

    return 0;
}

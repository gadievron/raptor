/* Binary-oracle reachability ground-truth fixture.
 *
 * Each function below has a KNOWN fate when built with the fixture's Makefile
 * (-O2 -g -ffunction-sections -Wl,--gc-sections, +LTO where supported, +ICF
 * when the linker can do it). The unit test asserts the classifier returns
 * these verdicts. Keep the function set small + sharply-distinct so a wrong
 * classification is unambiguous.
 *
 * Expected verdicts at build time:
 *
 *   live_called           symbol_present     direct call from main
 *   live_address_taken    symbol_present     fn-pointer stored in global table
 *   inlined_only          inlined            static inline, no standalone
 *   dead_static_unused    absent             static + no caller → DCE'd
 *   dead_extern_unused    absent             extern + no caller + ffunction-
 *                                            sections + --gc-sections → DCE'd
 *   folded_a / folded_b   folded (when ICF)  identical bodies + ICF-capable ld
 *                         symbol_present     (fallback, when no ICF available)
 *   volatile_call_target  symbol_present +   indirect call via volatile fn-ptr
 *                         binary call edge   the source graph would miss
 */

#include <stdio.h>
#include "lib.h"

/* 1. live_called — direct call from main(). */
int live_called(int x) {
    return x + 1;
}

/* 2. live_address_taken — held in a global fn-pointer table; address-taken
 *    keeps it even if the table is never indexed. */
int (*GLOBAL_TABLE[])(int) = { live_called };
/* and one more entry so the linker can't trivially elide the array */
int (*GLOBAL_TABLE2[])(int) = { live_address_taken_target };
int live_address_taken_target(int x) {
    return x * 2;
}

/* 3. inlined_only — static inline. Body must be visible to callers so the
 *    compiler can absorb it; no standalone symbol should remain. */
static inline int inlined_only(int x) {
    return x - 1;
}
/* a small caller that uses inlined_only so it isn't simply dead */
int inlined_only_user(int x) {
    return inlined_only(x);
}

/* 4. dead_static_unused — static, never called → DCE'd at -O2. */
static int dead_static_unused(int x) {
    return x + 99;
}

/* 5. dead_extern_unused — extern, never called from this TU or main; with
 *    -ffunction-sections + --gc-sections the linker should garbage-collect
 *    the section. (LTO not required for this on GNU ld; gcc puts each fn
 *    in its own .text.<name> section.) */
int dead_extern_unused(int x) {
    return x * 17;
}

/* 6. folded_a / folded_b — IDENTICAL bodies; an ICF-capable linker should
 *    merge them. Without ICF (e.g. plain GNU ld without --icf=all), both
 *    survive as separate symbols and classify as symbol_present. The
 *    classifier's fold detection covers the ICF case. */
int folded_a(int x) {
    return (x ^ 0xA5) + 42;
}
int folded_b(int x) {
    return (x ^ 0xA5) + 42;
}

/* 7. volatile_call_target — called only through a volatile function pointer.
 *    The source call graph can't easily see this edge; the binary's call
 *    graph (aflcj) should reveal it. */
int volatile_call_target(int x) {
    return x + 1000;
}
typedef int (*ptr_t)(int);
volatile ptr_t INDIRECT_PTR = volatile_call_target;
int indirect_caller(int x) {
    return INDIRECT_PTR(x);
}

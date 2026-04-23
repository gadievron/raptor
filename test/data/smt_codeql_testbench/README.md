# SMT Testbench

Cases designed to exercise Z3 path condition analysis in CodeQL dataflow findings.

## Group 1 — SAT with non-obvious PoC values

Z3 finds concrete satisfying assignments that require reasoning about unsigned bitvector wraparound or compound inequality constraints.

**Profile:** `ALLOC`, `SUM`, and `MASK` rely on 32-bit unsigned wraparound — invoke `check_path_feasibility(..., profile=BV_C_UINT32)` on their conditions (import from `core.smt_solver`). `OBO` is profile-agnostic. The dataflow validator auto-selects `BV_C_UINT32` when the CodeQL rule id mentions CWE-190 / overflow / wraparound; the LLM extractor can also override via `path_width` / `path_signed` hints in the extracted-conditions JSON.

| Case | File | Sink line | Guard (visible) | Bug | Z3 PoC value |
|------|------|-----------|-----------------|-----|--------------|
| `ALLOC` | `smt_codeql_testbench.c:93` | `memset(&records[i], ...)` | `count < 0x40000000` | `count * 16` overflows uint32 | `count = 0x10000001` → alloc = 16 bytes, loop writes 4 GB |
| `SUM` | `smt_codeql_testbench.c:132` | `memcpy(shared_buffer + offset, ...)` | `offset + length <= buffer_size` | unsigned sum wraps | `offset=0xFFFF0000, length=0x10010` → sum=0x10 ≤ 64 |
| `OBO` | `smt_codeql_testbench.c:165` | `buf[index] = value` | `index > INDEX_LIMIT` (should be `>=`) | off-by-one | `index=128` passes `> 128` check, writes `buf[128]` |
| `MASK` | `smt_codeql_testbench.c:200` | `memcpy(heap_region + base, ...)` | `base + size <= HEAP_SIZE` | unsigned base+size wrap | `base=0xFFFFE000, size=4000` → sum=0x3E80 ≤ 8192 |

## Group 2 — UNSAT (provably dead paths)

CodeQL reports a flow to the sink; Z3 proves the path conditions are mutually exclusive and suppresses the LLM call.

| Case | File | Sink line | Conditions Z3 checks | Conflict |
|------|------|-----------|----------------------|----------|
| `DEAD_RANGE` | `smt_codeql_testbench.c:243` | `strcpy(dead_buf, data)` | `x > 100` AND `x < 50` | ⊥ immediately |
| `DEAD_NULL` | `smt_codeql_testbench.c:280` | `strcpy(dst, ptr)` | `ptr != NULL` AND `ptr == NULL` | ⊥ immediately |
| `DEAD_MASK` | `smt_codeql_testbench.c:308` | `memcpy(flag_buf, payload, len)` | `flags & 0x1 == 0` AND `flags & 0x1 == 1` | ⊥ immediately |

## Group 3 — Indeterminate (Z3 falls through to LLM)

Conditions contain function calls the bitvector parser cannot encode. Z3 returns `feasible=None` and full LLM analysis runs unchanged.

| Case | File | Why Z3 returns `None` |
|------|------|-----------------------|
| `LLM` | `smt_codeql_testbench.c:327` | `strlen(input)` call — parentheses rejected by bitvector parser |
| `PARTIAL` | `smt_codeql_testbench.c:350` | `validate(ptr)` call — same reason; `size < 256` is parseable but alone is indeterminate |

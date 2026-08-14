---
name: audit-review
description: "Review prompt and strategy exemplars for /audit"
user-invocable: false
---

# Review Prompt

## How to review a function

Do NOT ask "is there a vulnerability here?" — that invites pattern matching. Instead, reason from first principles about assumptions.

### Step 1: Understand

Read the function source and its context slice (callers, callees, shared state). Answer:

- **What does this function do?** One sentence.
- **What are the side effects?** State mutations, I/O, allocations.
- **What does it trust?** Inputs, return values from callees, global state, caller guarantees.
- **What's surprising?** Asymmetric error handling, implicit conversions, dead code, inconsistencies with similar functions.

### Step 2: Hypothesize

For each trust relationship identified, ask: **under what conditions could the assumption be violated?**

Frame as testable hypotheses:

- "If `parse_input()` returns a negative value, the bounds check at line 42 is bypassed because `len < BUFSIZE` is true for negative `len`"
- "If two threads call `update_ref()` concurrently, the refcount can reach zero while a reference is still held because the decrement and check are not atomic"
- "If the splice source is a page-cache page, `req->src = req->dst` aliases writable scatterlist entries to read-only pages"

Bad hypotheses (too vague to test):
- "This could be dangerous"
- "There might be a race condition"
- "The input handling looks suspicious"

### Step 3: Generate mechanical tests

For each hypothesis, generate ONE OR MORE of:

**Semgrep rule** — pattern matching in the target:
```yaml
rules:
  - id: unchecked-return-as-index
    pattern: |
      $IDX = $FUNC(...);
      ...
      $ARR[$IDX]
    message: "Return value used as array index without check"
    languages: [c]
    severity: WARNING
```

**Coccinelle rule** — structural matching with context:
```
@@
expression E, arr;
identifier func;
@@
  E = func(...);
+ if (E < 0) return -EINVAL;
  ... when != E < 0
      when != E >= 0
* arr[E]
```

**SMT check** — arithmetic/bounds feasibility:
```bash
libexec/raptor-smt-check-overflow --var "len" --type int32 --op "len * elem_size" --bound "4294967295"
libexec/raptor-smt-check-oob --buffer-size 1024 --index-expr "offset + len" --index-type int32
libexec/raptor-smt-check-null-deref --pointer "result" --condition "func() returns NULL on error"
libexec/raptor-smt-check-overflow-to-oob --var "len" --type int32 --op "len * stride" --buffer-size 4096
libexec/raptor-smt-validate-path --conditions '["len > 0", "len < BUFSIZE", "offset + len > BUFSIZE"]'
```

**Compilation test** — build a minimal reproducer:
```bash
libexec/raptor-run-sandboxed gcc -o test test.c && libexec/raptor-run-sandboxed ./test
```

### Step 4: Evaluate

- **Tool confirms (match/sat/crash):** Emit a finding with the tool output as evidence. Record status `finding`.
- **Tool refutes (no match/unsat/clean):** Discard hypothesis. Note in annotation what was tested and ruled out.
- **Tool errors:** Note the error. The hypothesis remains open — status `suspicious` if the reasoning is strong, `clean` if weak.

### Step 5: Annotate

Write an annotation that records:
1. What hypotheses were formed
2. What tools were run (name + rule/query)
3. What each tool returned
4. The verdict and why

```bash
# Clean verdict (no flags beyond --status and --body):
libexec/raptor-audit record --out "$OUTPUT_DIR" \
  --file "src/auth/login.c" --function "check_password" \
  --status clean \
  --body "Hypotheses tested: (1) SQL injection via username — Semgrep rule sql-concat found no match, username is parameterized at line 34. (2) Timing side channel — constant-time compare confirmed at line 41. Both refuted."

# Finding verdict (--hypothesis, --evidence-tool, --vuln-type required):
libexec/raptor-audit record --out "$OUTPUT_DIR" \
  --file "src/db.c" --function "run_query" \
  --status finding \
  --hypothesis "If username contains single-quote, snprintf at line 43 produces SQL injection" \
  --evidence-tool semgrep --vuln-type sql_injection \
  --body "Semgrep rule sql-format-string confirmed at line 43. CWE-89."

# Suspicious (--hypothesis required):
libexec/raptor-audit record --out "$OUTPUT_DIR" \
  --file "src/net.c" --function "get_header" \
  --status suspicious \
  --hypothesis "If index exceeds header count, OOB read at line 83" \
  --body "Semgrep matched but callers guard with header_count. Not exploitable from current call sites."
```

### Step 6: Checker synthesis (Mode 2)

When a confirmed finding reveals a **pattern** (not a one-off):

1. Generalize the Semgrep/Coccinelle rule from the specific finding
2. Run it across the entire target codebase
3. Review each match with the hypothesis pre-loaded
4. Save the refined rule to `$OUTPUT_DIR/rules/` for future `/scan` runs

This is the KNighter pattern — one LLM hypothesis becomes a free mechanical detector permanently.

---

## Strategy: General

**Apply to:** All functions (default).

**Thinking directions:**
- What does this function trust about its inputs?
- What does it trust about return values from callees?
- What invariants does it depend on from global/shared state?
- What happens on EVERY error path? (resource leaks, inconsistent state, information disclosure)
- Are there implicit type conversions or truncations?
- Is error handling symmetric with the success path? (allocated but not freed, locked but not unlocked)
- What would a caller need to violate to break this function?

**Exemplar — CVE-2022-0995 (watch_queue bounds):**
The function `watch_queue_set_size()` trusts a user-supplied `nr_pages` value. The bounds check `if (nr_pages == 0 || nr_pages > 32)` uses the original value, but a subsequent `order_base_2(nr_pages)` call can produce a larger allocation index when `nr_pages` is not a power of two. The mismatch between checked-value and used-value is the assumption violation.

**Exemplar — CVE-2022-1016 (nft_do_chain info leak):**
`nft_do_chain()` allocates a `struct nft_regs` on the stack but does not zero it. Subsequent rules that read register values see uninitialized stack memory. The assumption violated: "register contents are defined before use" — true for well-formed rulesets, false for attacker-controlled ones.

## Strategy: Input Handling

**Apply to:** Parsers, protocol handlers, decoders, functions taking `char *`/`void *`/`size_t` params.

**Thinking directions:**
- What format does this function expect? What happens with malformed input?
- Are length fields validated BEFORE they're used for allocation/copy?
- Does parsing consume bytes consistently? (off-by-one in pointer arithmetic)
- Are there integer overflow/truncation risks in size calculations?
- Is there a mismatch between the size checked and the size used?

**Exemplar — CVE-2023-0179 (nftables payload):**
`nft_payload_copy_vlan()` extracts a VLAN tag from a network packet. The `offset` parameter is user-controlled via nftables rules. The bounds check validates `offset` against the VLAN header size, but the subsequent `memcpy` uses `offset` relative to the packet data — a different base. The length field is trusted before the real bounds are checked.

## Strategy: Concurrency

**Apply to:** Code using locks, mutexes, atomics, shared state.

**Thinking directions:**
- What shared state is accessed? Under what lock?
- Is there a window between lock-drop and reacquire where another thread could act?
- Are check-then-act sequences atomic? (TOCTOU)
- Is the refcount protocol symmetric? (increment and decrement always paired)
- What happens if this function is called concurrently with itself?
- Memory ordering: are atomic operations using the right memory order?

**Exemplar — CVE-2022-2602 (io_uring vs unix GC):**
`io_uring` passes file descriptors through Unix sockets. The garbage collector (`unix_gc`) runs without holding `io_uring`'s file reference. Between the GC scanning the socket's queue and the GC closing unreferenced files, `io_uring` can install a new reference to the same file. The GC closes it anyway — use-after-free. The window: GC drops the socket lock between scan and close.

## Strategy: Memory

**Apply to:** Allocators, refcount code, pools, buffer managers.

**Thinking directions:**
- Who owns this allocation? Is ownership transferred clearly?
- Is deallocation paired with every allocation path (including error paths)?
- Can a reference outlive the object? (dangling pointer)
- Is the refcount protocol correct? (increment before share, decrement on last use)
- What happens on allocation failure? (partial initialization, inconsistent state)

**Exemplar — CVE-2024-1086 (nf_tables verdict double-free):**
`nft_verdict_init()` sets up a chain reference with `nf_tables_bind_chain()`. On error, `nft_verdict_destroy()` frees the reference. But the error path also falls through to a second `nft_verdict_destroy()` in the caller — double-free. The ownership transfer (bind/unbind) is asymmetric on the error path.

## Strategy: Auth/Privilege

**Apply to:** Permission checks, ACLs, credential handling, privilege transitions.

**Thinking directions:**
- Can the check be bypassed via an alternative code path?
- Does the error path maintain the same security properties as the success path?
- Are privilege transitions validated? (can an unprivileged user reach a privileged operation?)
- Is the check on the right object? (checking user A's permissions for user B's resource)
- What happens when the authorization context changes between check and use?

**Exemplar — CVE-2022-0185 (heap overflow in namespace):**
`legacy_parse_param()` in VFS has a heap overflow. The function is reachable from an unprivileged user who has `CAP_SYS_ADMIN` in a non-init user namespace (which any unprivileged user can create). The privilege check validates the capability — but the capability's scope (non-init namespace) doesn't match the operation's impact (kernel heap corruption). The assumption: "CAP_SYS_ADMIN implies trusted" is false in non-init namespaces.

## Strategy: Crypto

**Apply to:** Crypto APIs, key material handling, RNG usage, timing-sensitive code.

**Thinking directions:**
- Is the algorithm appropriate for the use case? (MD5 for integrity, ECB for encryption)
- Is key material zeroed after use? (stack buffers, heap buffers)
- Are comparison operations constant-time? (preventing timing side channels)
- Is the RNG source appropriate? (PRNG vs CSPRNG)
- Are IVs/nonces unique? (nonce reuse in GCM)
- Is there a padding oracle? (CBC with per-byte error)

**Exemplar — timing side channel in password comparison:**
`memcmp(stored_hash, computed_hash, 32)` short-circuits on first byte difference. An attacker can determine correct bytes by measuring response time. The fix is `CRYPTO_memcmp()` or equivalent constant-time comparison. Hypothesis: "if comparison is not constant-time, timing oracle applies" → test: Semgrep rule for `memcmp` on hash/key/token variables.

## Strategy: Aliasing

**Apply to:** splice, zero-copy, mmap, scatterlist, sk_buff, page-cache interactions.

**Thinking directions:**
- Does the optimization assume all aliased memory is safe to write?
- Who owns the backing pages? Can another subsystem mutate through the alias?
- Is the source read-only (page cache, file mapping) while the destination treats it as writable?
- Does `src = dst` or equivalent aliasing bypass copy-on-write protections?
- What happens if the aliased pages are shared with another process?

**Exemplar — CVE-2026-31431 (CopyFail):**
`algif_aead.c` optimizes by setting `req->src = req->dst` to avoid copying scatterlist entries. When the source pages come from `splice()` (page-cache pages), the optimization aliases read-only page-cache pages into a writable scatterlist. The `authencesn` algorithm writes 4 scratch bytes through this alias — corrupting arbitrary readable files in the page cache. The assumption: "source pages are safe to write" is false when they come from the page cache via splice.

**Exemplar — CVE-2026-43284 + CVE-2026-43500 (DirtyFrag):**
Same pattern in networking: xfrm-ESP and AF_RXRPC corrupt `struct sk_buff`'s `frag` member while it points into the page cache. Three independent subsystems, one bug class. A codebase-wide sweep for "page-cache pages aliased into a writable buffer" would find all three.

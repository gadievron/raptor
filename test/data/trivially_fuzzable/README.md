# trivially_fuzzable — RAPTOR end-to-end test target

A 60-line C program with three deliberate, obvious bugs reachable by a
single byte of stdin. Used to E2E-test the chain:

```
/fuzz → crash collection → CrashAnalysisAgent →
  exploit_verify.compile_and_execute (with sanitizers) →
    sandbox run → outcome classification → Witness record
```

Each branch exercises a distinct `WitnessOutcome`:

| Trigger | Tag | Outcome (no sanitizers) | Outcome (`-fsanitize=address`) |
|---------|-----|-------------------------|---------------------------------|
| `A` + ≥8 attacker bytes | strcpy BOF | `EXIT_SIGNAL` (SIGSEGV usually) | `SANITIZER_REPORT` (`asan`) |
| `B` | NULL deref | `EXIT_SIGNAL` (SIGSEGV) | `EXIT_SIGNAL` (SIGSEGV) |
| `C` | clean exit | `NO_OBVIOUS_EFFECT` | `NO_OBVIOUS_EFFECT` |

## Build

```sh
make           # default: -fsanitize=address
make plain     # without sanitizers
```

## Operator probes

```sh
# BOF — should produce ASAN report
echo -n 'AAAAAAAAAAAAAAAAAA' | ./target

# NULL deref
echo -n 'B' | ./target

# Clean exit
echo -n 'C' | ./target
```

## Why this exists

`/fuzz --execute-exploits` (PR E) needs a target where RAPTOR can:
1. Find a crash via AFL++
2. Have the LLM emit a PoC
3. Compile-and-execute the PoC in the sandbox
4. Observe a sanitizer/signal outcome
5. Persist that outcome as a `Witness`

A handful of single-byte inputs reach all three outcomes deterministically,
which is good enough to exercise the wiring without paying real-world
fuzzing wall-clock time.

This is intentionally **not** a benchmark or realistic vuln — it's a
fixture, sibling to `test/data/javascript_xss.js` and
`test/data/python_sql_injection.py`.

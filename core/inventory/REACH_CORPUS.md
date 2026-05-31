# Reachability corpora

The reachability audit harness (`core/inventory/reach_audit.py`,
`audit_corpus`) measures classification accuracy against a labelled tree.
It is corpus-agnostic — point it at any directory plus a label map. Three
roles, with three corpora:

| role | what it proves | corpus |
|---|---|---|
| **coverage** | dead code is caught | committed synthetic fixtures (`tests/test_reach_audit.py`) + any operator-supplied labelled tree (path-configurable, not committed) |
| **FN-gate** | live reachable code is never called dead | OWASP Benchmark (below) |
| **over-fire** | the `#if 0` detector stays off config `#ifdef` | OpenSSL (below) |

Large external corpora are **not vendored** — they're pinned and fetched on
demand (same pattern as `core/dataflow/corpus/SOURCES.md`). The synthetic
coverage corpus runs in CI; the external corpora are fetched locally / in a
networked CI job.

## OWASP Benchmark (FN-gate, Java)

Whole-project labelled corpus: 2740 servlet test cases with TP/FP verdicts
in `expectedresults-1.2.csv`. RAPTOR reachability needs only the Java
source (no Maven build).

- Upstream: `https://github.com/OWASP-Benchmark/BenchmarkJava`
- Pinned sha: `b06d6efaebd577a327514364951916e7df3290b4`
- Fetch:
  ```
  git clone --depth 1 https://github.com/OWASP-Benchmark/BenchmarkJava <dir>
  cd <dir> && git fetch --depth 1 origin b06d6ef… && git checkout b06d6ef…
  ```
- Run: build an inventory of `<dir>/src`, label each TP test's
  `doPost`/`doGet` `"live"`, and assert `audit_corpus(...).false_suppress == 0`.

Note: OWASP exercises the *surface* Java reachability (and was what
surfaced the servlet-entry handling now in `entry_reachability`). It does
**not** exercise the enforce-eligible sound witnesses — `module_aborts`
(py/js/ts/go/rust/ruby/php) and `lexical_dead` (py/js/ts/rust/ruby/php) — for
those, use live trees in those languages. (Java/C# have neither: no top-level
execution, no def-inside-always-false-guard.)

## OpenSSL (over-fire gate, C)

- Upstream: `https://github.com/openssl/openssl`
- Run: `detect_preprocessor_dead_ranges` over every `.c`; assert it fires
  only on literal-`0` conditions, never on `#ifdef`/`#if SYMBOL`.

## Earning enforcement

A witness kind earns the right to hard-suppress (see
`reach_witness.may_suppress`) only once a labelled corpus shows
`false_suppress == 0` for it. The enforcement consumer passes the earned
set; nothing is suppressed otherwise.

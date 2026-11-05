# Static Analysis

[Documentation index](README.md)

Mechanical rule scanning with Semgrep and Coccinelle. No LLM calls --
purely pattern-based detection. Semgrep handles multi-language taint
and pattern rules; Coccinelle handles C/C++ semantic patches that
express control-flow-sensitive structural patterns Semgrep cannot
reach.

For LLM-powered analysis of scan results, use `/agentic` or
`/analyze`. For deeper dataflow analysis with CodeQL, see
[CodeQL](codeql.md).

**Related documentation:**
[CodeQL](codeql.md) |
[sandbox](sandbox.md)


**On this page:**

- [Usage](#usage)
- [Rule version requirements](#rule-version-requirements)
- [Bundled rule coverage](#bundled-rule-coverage)
- [Semgrep Rules](#semgrep-rules)
- [Coccinelle Rules](#coccinelle-rules)
- [Inline Suppression](#inline-suppression)
- [Output](#output)
- [Error Handling](#error-handling)

## Usage

```
/scan --repo <path> [options]
```

Dispatches to `python3 raptor.py scan`. Runs Semgrep (always) and
Coccinelle (default-on for C/C++ targets). CodeQL is opt-in via
`--codeql`; when enabled it runs **concurrently with the Semgrep
stage** (they are independent SARIF producers — the CodeQL database
build is usually the critical path, so it starts first and its
console lines are tagged `[codeql]`). Two further opt-in channels
run as their own stages after Semgrep on C/C++ targets: the
compiler analyzers (`--compiler-scan`) and the expanded-view
Semgrep pass (`--expanded-semgrep`).

### CLI Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--repo <path>` | required | Repository path or Git URL |
| `--policy-version <ver>` | `v1` | Policy version identifier |
| `--policy-groups <list>` | `all` | Comma-separated rule group names (see [Policy Groups](#policy-groups)) |
| `--codeql` | off | Run [CodeQL](codeql.md) concurrently with Semgrep (sequential with `--sequential`) |
| `--no-codeql` | -- | Explicitly disable CodeQL |
| `--no-cocci` | off | Disable Coccinelle stage |
| `--languages <list>` | auto | CodeQL language list (only relevant with `--codeql`) |
| `--build-command <cmd>` | auto | CodeQL build command override (only relevant with `--codeql`; implies a traced build) |
| `--traced-build` | off | Opt into traced-build C/C++ CodeQL extraction — executes the repo's build system (asserts trust). Default is buildless: no repo code runs during database creation |
| `--no-traced-build` | -- | Force buildless extraction for this run, overriding `--traced-build` and the project's `build` trust marker |
| `--compiler-scan` | off | Run gcc `-fanalyzer` / clang `--analyze` per C/C++ translation unit as an extra scan channel (sandboxed; no repo code executes). TUs whose analyzer silence is repo-steerable are reported as a coverage limitation, never as a finding — see [Compiler-scan coverage limitations](#compiler-scan-coverage-limitations) |
| `--no-compiler-scan` | -- | Explicitly disable the compiler-analyzer channel |
| `--compiler-scan-max-seconds <seconds>` | 300 | Shared compiler analysis budget, also available in `/agentic`. Completed findings are retained; unfinished coverage is reported. Discovery and cleanup add overhead. |
| `--compiler-scan-max-tus <n>` | 2000 | Cap on translation units analysed by `--compiler-scan` (skipped TUs are reported) |
| `--expanded-semgrep` | off | Re-run the loaded ruleset over fidelity-3 preprocessor-expanded views of macro-heavy C/C++ TUs, line-mapped back to the originals |
| `--no-sanitizer-cut-postpass` | on by default | Disable the sanitizer-cut post-pass over scan findings (see [Sanitizer-cut post-pass](#sanitizer-cut-post-pass)) |
| `--no-sanitizer-cut-enforce` | enforcement on | Record sanitizer-cut verdicts but keep suppressed findings in `combined.sarif` |
| `--no-config-resolved` | on by default | Disable the Java config-resolved weak-algorithm stage (additive findings when a `getInstance(...)` argument resolves to a weak algorithm through configuration) |
| `--no-source-wrappers` | on by default | Disable the Java taint-source wrapper projection stage (project source-wrapper summaries into taint rules) |
| `--no-graduated-rules` / `--graduated-rules-dir <dir>` | on by default | Disable (or point elsewhere) the project's graduated synthesized-rules stage — proven rules from checker synthesis run as a standard scan stage |
| `--keep` | off | Keep temporary working directory after completion |
| `--sequential` | off | Fully serial run: packs one at a time and stages in order (no Semgrep/CodeQL overlap) |
| `--out <dir>` | auto | Output directory override |
| `--exclude-dir <glob>` | none | Drop results from matching paths (repeatable, OR semantics) |
| `--extra-config <path>` | none | Additional Semgrep rule source path (repeatable) |
| `--show-suppressed` | off | Include `nosemgrep`-suppressed findings in output summary |
| `--sandbox <profile>` | full | [Sandbox](sandbox.md) profile (`full` / `strict` / `debug` / `target_run` / `frida` / `network-only` / `none`) |
| `--no-sandbox` | off | Alias for `--sandbox none` (consent-gated — see [Sandbox](sandbox.md#disabling-the-sandbox)) |
| `--audit` | off | Engage [sandbox](sandbox.md) audit mode |
| `--audit-verbose` | off | Log every traced syscall (requires `--audit`) |
| `--audit-budget <n>` | 10000 | Override audit-record cap |


## Rule version requirements

The startup banner shows installed Semgrep, Coccinelle and CodeQL versions.
It warns about known compatibility limitations without disabling an entire
backend. Tool-wide capability requirements and individual rule requirements
are separate: a version that cannot run one rule may still run others.

An older tool can still run compatible rules. Rules with a declared minimum
are skipped individually when the tool is too old; their absence is a coverage
limitation, not a clean result. Upgrade the affected tool to restore coverage.
An unknown tool version also skips rules that declare a requirement. Rules
without a declaration keep their existing behavior; this does not prove they
are compatible with every version.

Semgrep rules use the native [`min-version` field](https://docs.semgrep.dev/writing-rules/rule-syntax#min-version-and-max-version),
which Semgrep supports from version 1.38.0:

```yaml
rules:
  - id: example
    min-version: "1.38.0"
    languages: [python]
    pattern: dangerous_call(...)
    message: Review this call
    severity: WARNING
```

For a custom Coccinelle rule or CodeQL query, put this declaration in its
leading `//` comment header, before the rule or query documentation:

```c
// raptor-min-version: 1.3.0
```

Use the actual minimum required by that rule, written as `major.minor.patch`.
The example is a spatch version; a CodeQL query must declare a CodeQL CLI
version instead. A declaration applies to one `.cocci` or `.ql` file, not the
whole backend. CodeQL library compatibility must also be satisfied by the
query pack's dependencies. Imported `.qll` files do not inherit their own
runtime gates; the executable query must declare its requirements.

Skipped Coccinelle rules appear in their per-rule error records. Semgrep keeps
native incompatibility notices in its JSON output and exposes them as
`skipped_rules` in its package results. Custom CodeQL results include
`skipped_rules`, also retained in the workflow report. Other compatible rules
continue to produce findings. If every selected CodeQL query is incompatible,
the query result is unsuccessful rather than an empty successful scan.

A minimum requirement and a tested version mean different things. Declare a
minimum when a required construct or API establishes it; do not assign the
current CI version to every rule just because that version passes the tests.

## Bundled rule coverage

RAPTOR ships over 200 custom static analysis rules, adversarially tested against false
positives:

- **Semgrep (~150 rules)** — taint-tracking and pattern rules for Python, Go, Java, and
  JS/TS. Covers SQLi, XSS, SSRF, SSTI, command injection, deserialisation, XXE,
  LDAP/NoSQL injection, path traversal, open redirect, log/header injection, eval
  injection, ReDoS, prototype pollution, JWT misconfiguration, weak crypto, insecure
  TLS, and hardcoded secrets.
- **Coccinelle (68 rules)** — structural matching for C/C++. Memory safety (double free,
  use-after-free, free of non-base pointer, free of stack array, mmap'd memory,
  use-after-close), integer bugs (overflow, sign extension, double sizeof), resource
  leaks (popen/fclose mismatch, fdopendir double close), buffer handling (strncpy
  without NUL, copy_user size mismatch, malloc/strlen off-by-one), signal handler
  safety, API misuse (fcntl flag domain, SIGKILL/SIGSTOP, double byte-swap, inet_ntoa
  static buffer), compiler dead-store elimination, kernel IS_ERR/PTR_ERR confusion,
  format string injection, TOCTOU races, and more.
- **CodeQL (8 queries)** — interprocedural taint tracking for C++ (format string
  injection, integer truncation, use-after-move, iterator invalidation) and Java (XXE,
  insecure deserialisation, log injection, Spring SSRF).

Browse the rules directly: `engine/semgrep/rules/`, `engine/coccinelle/rules/`,
`engine/codeql/queries/`. These complement the Semgrep registry packs RAPTOR pulls in
(`p/security-audit`, `p/owasp-top-ten`, `p/secrets` always; per-policy-group packs like
`p/command-injection`, `p/jwt`, `p/xss` on top) — overlap is minimal.

## Semgrep Rules

Python JWT checks flag single-entry literal `verify_signature: False` options on both
`jwt.decode` and `jwt.decode_complete`. An `algorithms=["none"]` allow-list
alone does not establish that PyJWT accepts an unverified token. Legacy
`verify=False` calls are reported separately at medium severity because they
disable verification in PyJWT 1.x but are ignored in 2.x. Check the target
application's dependency version when reviewing those notices. Decoded claims
become a security issue when trusted without verification. Options stored in
variables, merged dictionaries, duplicate keys and multi-option dictionaries
are outside this narrow check; absence of a finding does not establish verification.

### Rule Categories

RAPTOR ships custom YAML rule files under `engine/semgrep/rules/`,
organised by category:

| Category | Covers |
|----------|--------|
| `crypto` | Weak hash, weak PRNG, weak ciphers, weak KDF iterations/keysize, reused nonce, insecure IV, PKCS1v15 padding, insecure password hash, weak asymmetric keysize, weak block modes |
| `injection` | SQL taint, SQL concat, command taint (single + multi-lang), eval taint, SSTI taint, NoSQL taint, XSS, LDAP taint, header injection, log injection, regex DoS |
| `auth` | JWT signature bypass, TLS certificate skip |
| `deserialisation` | Unsafe deserialise (Python/Ruby/PHP), unsafe Java deserialise |
| `sinks` | SSRF, open redirect |
| `filesystem` | Path traversal |
| `flows` | Bad MAC order (encrypt-then-MAC vs MAC-then-encrypt) |
| `go` | Go-specific security rules |
| `java` | Java-specific security rules |
| `javascript` | JavaScript-specific security rules |
| `logging` | Secrets in log output |
| `python` | Python-specific security rules |
| `secrets` | Hardcoded API keys |
| `web` | Prototype pollution |
| `xml` | XXE |

Run `ls engine/semgrep/rules/` for the current file list.

### Upstream Registry Packs

In addition to the local rules, RAPTOR fetches upstream Semgrep
registry packs at scan time. Three baseline packs are always included:

| Pack ID | Coverage |
|---------|----------|
| `p/security-audit` | Broad security audit rules |
| `p/owasp-top-ten` | OWASP Top 10 categories |
| `p/secrets` | Secret and credential detection |

Additional packs are added when specific policy groups are selected:

| Policy group | Registry pack |
|--------------|---------------|
| `secrets` | `p/secrets` |
| `injection` | `p/command-injection` |
| `auth` | `p/jwt` |
| `flows` | `p/default` |
| `sinks` | `p/xss` |
| `best-practices` | `p/default` |

**Network reachability:** a 3-second TCP probe to `semgrep.dev:443`
runs before pack resolution. If the registry is unreachable, all
uncached `p/` packs are dropped silently and the scan proceeds with
local rules only. Previously fetched packs cached under
`engine/semgrep/rules/registry-cache/` are used regardless of
connectivity. The directory ships empty; use
`engine/semgrep/tools/cache-packs.py` to pre-populate it for
airgapped deployments (supports `list`, `update`, `fetch`, and
`import` subcommands).

### Policy Groups

The `--policy-groups` flag selects which rule subdirectories to scan.
The default value `all` expands to every subdirectory under
`engine/semgrep/rules/` except `registry-cache`.

To scan only specific categories:

```text
/scan --repo /path/to/code --policy-groups secrets,injection,crypto
```

Each selected group resolves to a local rule directory and,
optionally, a matching upstream registry pack (see table above). Both
are scanned.

### Custom Rules

To add custom Semgrep rules:

1. **Local rules:** create a YAML file under a new or existing
   subdirectory of `engine/semgrep/rules/`. The file is automatically
   picked up when the containing directory's group is selected (or when
   `--policy-groups all` is active).

2. **Per-scan rules:** pass `--extra-config <path>` (repeatable) to
   include an external rule file or directory for this scan only. Each
   extra config becomes a peer pack with its own SARIF output, running
   in parallel with the built-in packs.

Extra-config paths are validated at parse time (must exist on disk)
and deduplicated by resolved absolute path.


## Coccinelle Rules

### Rule Inventory

RAPTOR ships custom semantic patches under `engine/coccinelle/rules/`,
covering C/C++ structural patterns that require control-flow sensitivity:

| Category | Covers |
|----------|--------|
| Memory safety | Use-after-free, double free, realloc losing pointer, stack address escape, missing null check, mmap free |
| Uninitialised data | copy_to_user uninit, uninitialised return |
| Resource leaks | Resource leak on error, mmap leak, double close, popen/fclose mismatch |
| Integer issues | Integer overflow in alloc, shift overflow, sign extension, division by zero, UID truncation |
| Buffer handling | Missing bounds check, strncpy without NUL, snprintf advance, sizeof mismatches |
| Concurrency | Lock imbalance, sleep under spinlock, RCU violations, use after unlock, missing memory barriers, lock ordering |
| TOCTOU and races | stat/open TOCTOU, double fetch, check-then-act |
| Sandbox escape | chroot without chdir, socket without CLOEXEC |
| Unchecked returns | Unchecked return value, unchecked strtol |
| Format strings | Format string from untrusted input |
| API misuse | Signal misuse, fcntl flag domain, double byteswap, inet_ntoa double call |
| Compiler optimisation hazards | Dead memset before free |
| Kernel-specific | IS_ERR/PTR_ERR confusion, kfree without RCU grace period |

Run `ls engine/coccinelle/rules/` for the current file list.

### Uninitialised returns

`uninitialized_return` distinguishes a loop initializer or mandatory first
assignment from an assignment that may never execute. A zero-iteration loop,
an early break before assignment, or an optional assignment can still leave
the returned local uninitialised.

The rule handles these initialization patterns conservatively. Complex
control flow, functions with `goto`, and macro-defined initialization can
still require manual review; an empty result is not a general proof of definite assignment.

### Memory leaks on error paths

`resource_leak_err` reports kernel allocations that may remain allocated
when a function returns an error. It checks allocations made in assignments
and variable declarations. Returning because allocation failed is not a leak;
cleanup with `kfree_sensitive` is recognized.

In C files, the rule can recognize correct conditional cleanup for buffers
that use either stack or heap storage. It may still warn about these patterns
in C++ files and headers.

Review a warning against every path to the reported return. If another
function takes ownership of the allocation, or a custom cleanup function
releases it, the warning may be a false alarm.

### Double-free checks

`double_free` looks for two free sites connected by a path without an
intervening pointer assignment. This includes a free inside a branch
followed by another free after the branch. A pointer assignment ends that
comparison; resetting it to null or replacing an allocation avoids the
common cleanup-loop false alarm.

The rule does not track alias identity across assignments or different
pointer expressions. It can also miss repeated executions of a single free
site inside a loop. An empty
result does not establish that a function is free of double-free bugs.

### Prerequisites

`spatch` (the Coccinelle binary) must be on `PATH`. Minimum version
1.3 is required -- older versions (e.g. the 1.1.1 build shipped with
Ubuntu 22.04/24.04 via `apt`) cannot parse certain attribute rules
and will produce per-rule degradation.

### Auto-Skip Logic

The Coccinelle stage skips automatically (with a debug-level log) when
any of these conditions hold:

1. `spatch` is not on `PATH`.
2. The repository contains no C/C++ source files (checked by walking
   up to 200 files looking for `.c`, `.h`, `.cc`, `.cpp`, `.cxx`,
   `.hpp`, `.hh` extensions).
3. The shipped rules directory (`engine/coccinelle/rules/`) is missing.

To explicitly disable the stage regardless, pass `--no-cocci`.


## Inline Suppression

### Semgrep

A Semgrep parser error can leave a file only partially analysed. Findings
recovered from that file remain useful, but an empty result does not establish
that the file is clean. Check the reported exclusions and analysis errors when
assessing scan coverage, especially for C code with compiler extensions.

Semgrep is invoked with `--disable-nosem` so that all findings reach
SARIF regardless of inline comments. After scanning, RAPTOR's own
post-processor (`packages/semgrep/nosemgrep.py`) reads source files
and annotates each result whose location line (or the line above)
contains a suppression comment:

```python
x = eval(user_input)  # nosemgrep: eval-taint
```

Accepted forms: `# nosemgrep: <rule-id>`, `// nosemgrep`,
`/* nosemgrep */`. Suppression is annotation-only -- the finding
remains in the SARIF file with
`result.properties.nosemgrep.suppressed = true`. Use
`--show-suppressed` to include suppressed findings in the output
summary.

### Coccinelle

Coccinelle rules have no inline suppression mechanism. Unwanted
findings can be excluded via `--exclude-dir` globs.


### Overlapping memory copies

With `--compiler-scan`, C files containing direct or macro-wrapped `memcpy`
calls also receive an overlap check when a GCC analyzer supporting
`-Wanalyzer-overlapping-buffers` (GCC 14 or newer) are available. Candidate
matches select files; only compiler overlap warnings become findings. Candidate
discovery scans only the capped C files whose ordinary compiler analysis
succeeded, rather than scanning the entire project. A bounded source scan
checks up to 1,048,576 characters per file within a shared 30-second budget.
Semgrep is not required for this check. For files not selected from source,
the compiler expands macros and RAPTOR checks for live `memcpy` identifiers
at original source locations, including lowercase wrappers and header-defined
aliases. Neither candidate path needs a language parser. Comments, quoted text
and identifiers originating only in expanded header
bodies are excluded. An identifier selects a file for analysis; it is not itself
a finding. Declarations and function-pointer references can also select files;
only the compiler's overlap diagnostic can produce a finding.

The fallback expands at most 50 files and processes at most 32 MiB of expanded
text, keeping one view at a time. It shares an overall 60-second candidate
deadline; unavailable or unfinished views produce coverage limitations.

The fallback adds one preprocessor invocation per attempted expansion. Selected
files receive at most one supplemental analyzer invocation each, plus one
capability probe per scan. It shares the TU cap and worker limit and
runs only after the ordinary compiler analysis succeeds. Its compiler settings
preserve copy calls for analysis; the ordinary pass also runs to retain other
warnings. C++ files and unresolved compiler paths are
outside this additional check's coverage.

Unavailable tools, failed candidate scans and failed supplemental compiles are
reported as coverage limitations. Existing compiler findings are retained.
No overlap warning means no finding from this check; it does not establish that
the file is safe.

### Returning stack addresses

With `--compiler-scan`, GCC warnings about returning a local address select C
files for a targeted Clang analysis. A finding requires Clang's path-sensitive
stack-return diagnostic at the same original source location. A frontend warning
alone is not enough: it can also fire in an unreachable branch.

Clang analyzes a source view preprocessed by GCC, preserving the original macro
decisions. This avoids treating a different compiler-specific branch as proof.
Corroborated findings use `raptor.compiler.stack-return`, carry CWE-562 and record
both compilers and the GCC preprocessing context in their SARIF properties.
Existing compiler findings remain.

Only candidate files get the additional preprocessing and analysis, with at most
50 candidate translation units and 256 candidate locations per unit, with the
existing worker and tool timeout limits. Missing Clang or an incompatible source view limits this additional check
and is reported as a coverage warning; it does not disable the compiler scan.

### Compiler analysis time budget

Compiler scanning shares a 300-second analysis budget across ordinary compiler
runs, suppression checks, memcpy overlap analysis and stack-return corroboration.
Use `--compiler-scan-max-seconds 600` to allow ten minutes, or a smaller positive
value to limit extra analysis time. This option does not enable compiler scanning
by itself; `--compiler-scan` is still required and `--no-compiler-scan` takes
precedence.

When the budget expires, no further translation units are submitted. In-flight
tool calls receive the remaining time as their timeout and are allowed to clean
up. Completed findings are retained. The summary and SARIF coverage warnings
report the interruption, including ordinary translation units that never
started; supplementary checks can also be incomplete even when all ordinary
translation units finished.

The analysis window starts after tool and source discovery. Result processing,
filesystem operations and sandbox teardown can add overhead, so this is not a
hard wall-clock limit for the entire command.

### Compiler-scan coverage limitations

`--compiler-scan` treats analyzer silence on a TU as evidence only
when nothing in the TU or its repo headers can steer the analyzer.
TUs where the source carries a steering construct — `[[clang::suppress]]`
(any spelling or position in the attribute list), `_Pragma(`,
`#ifndef __clang_analyzer__`, diagnostic-ignore pragmas, system-header
line markers — are listed as coverage limitations in the summary and as
SARIF `toolExecutionNotification` entries, never as findings.  TUs whose
include closure cannot be fully vetted (unresolvable `#line` names,
missing or truncated `-E` output, resolution limits) are listed
separately as "not vetted".  Findings that clang still reports on a
flagged TU are always kept — the annotation is additive.

When `/audit` checks a hypothesis with a compiler analyzer, a warning from
a recognized checker whose wording cannot be classified remains inconclusive.
It is not treated as analyzer silence or as confirmation of the hypothesis.

Missing or malformed GCC diagnostic output is reported as an analysis error
or scan coverage limitation. It cannot establish a clean result, and `/audit`
retries the analyzer if a later hypothesis needs the same translation unit.

For compiler-backed hypothesis checks in `/audit`, quote variable names
(for example, ``use-after-free of `buffer` ``) to request attribution to that
identifier. Common names such as `buffer`, `size` and `index` are preserved
when quoted, so they are checked as identifiers rather than interpreted as
generic prose.

When GCC explicitly names a simple identifier as the subject of a warning,
`/audit` uses that name for attribution. Mentioning another variable on the
same source line does not make that warning evidence about the other variable.

For compiler-backed hypothesis checks, `/audit` resolves relative diagnostic
paths from the translation unit’s directory, as `/scan` does. A warning in
`include/unit.c` is not attributed to `unit.c` merely because the basenames
match.

## Output

### SARIF Files

Each Semgrep pack (local + registry + extra-config) produces its own
SARIF file. The Coccinelle stage produces one SARIF file. When CodeQL
is enabled via `--codeql`, per-language CodeQL SARIF files are added.

All per-tool SARIFs are merged via `core.sarif.parser.merge_sarif()`
into a single `combined.sarif`:

- Runs are grouped by tool name.
- Per-tool deduplication by `(ruleId, uri, startLine, endLine,
  startColumn, fingerprint)` -- latest occurrence wins on collision.
- `tool.driver.rules` are unioned across same-tool runs.

### Filtering

`--exclude-dir` globs are applied post-merge using `fnmatch`. Per-tool
SARIFs remain unfiltered as a forensic record; only `combined.sarif`
and downstream metrics reflect the exclusion.

### Sanitizer-cut post-pass

After the merge, the sanitizer-cut gate re-checks taint findings whose
every source-to-sink path crosses a full-proof sanitizer.  Enforcement
is the default: suppress-verdict findings are removed from
`combined.sarif`, with one evidence record per suppression in
`suppressions.jsonl`.  Per-tool SARIFs are never filtered in any mode.
`--no-sanitizer-cut-enforce` keeps the verdicts record-only;
`--no-sanitizer-cut-postpass` skips the pass entirely.

### Sanitizer-recognition contract

Across the rule engines, multi-step sanitizer chains are recognized
only within a single expression. A sanitization sequence written as
one chained expression (`value.replace('\r', '').replace('\n', '')`)
is recognized; the identical sequence split across statements
(`v = v.replace('\r', ''); v = v.replace('\n', '')`) is not — the
finding is still reported. This is deliberate:

- Every miss in this class is FP-direction: the code is still
  flagged and downstream validation adjudicates. Nothing is ever
  silently suppressed by the contract.
- Recognitions that carry SUPPRESSION authority must be either
  single-call sanitizers (one call is complete — most rules) or
  proof-gated (the SMT barrier validator only claims a barrier when
  a solver proof backs it).

### Metrics

`scan_metrics.json` contains timing data, per-pack finding counts,
`nosemgrep_suppressed_count`, and a coverage-record manifest.


## Error Handling

### Per-Pack Isolation

Each Semgrep pack runs in its own [sandbox](sandbox.md) invocation.
If a pack fails (bad rule syntax, timeout, runtime error), the scanner:

1. Writes an empty SARIF (`{"runs": []}`) for the failed pack.
2. Logs the error.
3. Continues with the remaining packs.

A single bad rule or unreachable registry pack does not crash the
batch.

### Timeouts

| Scope | Default | Notes |
|-------|---------|-------|
| Overall scan | 30 min | `DEFAULT_TIMEOUT` |
| Per Semgrep pack (local rules) | 15 min | `SEMGREP_TIMEOUT` |
| Per Semgrep pack (registry) | 5 min | `SEMGREP_PACK_TIMEOUT` -- capped lower to limit registry latency |
| Per Semgrep rule | 2 min | `SEMGREP_RULE_TIMEOUT` |
| Per Coccinelle rule | 5 min | Partial output captured on timeout |

### Sandbox Failures

`SandboxSetupError` is not caught per-pack -- it propagates
immediately and aborts the scan, because a sandbox setup failure
affects every pack identically.

When every dispatched Semgrep pack fails, the scan exits with code 4
(distinct from the sandbox-engagement-failure exit code 3) to prevent
a false-pass "0 findings" result.

### Parallel Execution

By default, packs run in parallel (`max_semgrep_workers` in
`tuning.json`, default `auto` = half the available CPUs). Concurrent
packs share the cores instead of each claiming every one, and a
post-completion check adds any pack whose SARIF never landed on disk
to the `failed_scans` list.

With `--codeql`, the CodeQL stage (database build + analyze) runs
concurrently with the Semgrep packs; its console lines are tagged
`[codeql]` and a stage-completion line reports its duration. Multi-
language builds also divide `-j` between concurrent per-language
invocations when `codeql_threads` is `auto`.

Pass `--sequential` for a fully serial run: packs one at a time AND
stages in order (no Semgrep/CodeQL overlap).

### Compiler review candidates

Strict-aliasing warnings can also describe safe pointer conversions or unreachable
code. Compiler scanning preserves these warnings in
`scan/compiler-review-candidates.json` with status `needs_review`. They require
independent corroboration and are excluded from normal findings and automatic
finding analysis. The scan summary reports their count. In `/audit`, these
warnings alone produce an inconclusive result, even when they match the hypothesis.
A clean run does not refute an aliasing hypothesis.

When GCC and Clang are available, compiler scanning also checks a limited class
of C aliasing candidates against Clang's parsed types. Direct loads, stores,
and local pointer aliases can become findings when they access a known local
scalar through an incompatible builtin scalar type on a straight-line path.
The report identifies the object and both types under Raptor's strict-aliasing
compiler model; project build flags are not inferred. Harmless casts alone do
not qualify. `/audit` uses the same check for matching CWE-843 hypotheses.

Calls, conditional paths, unknown pointer origins, typedefs, compiler-specific
aliasing exceptions, and C++ remain outside this check. Their warnings stay in
the review report. Missing tools, unsupported Clang output, timeouts, and
analysis limits also preserve the candidates; silence never proves them safe.
The extra parsing runs once per candidate-bearing C translation unit, up to
25 units per scan, within the shared compiler analysis budget.

### Compiler diagnostic paths

When GCC reports the calls and branches leading to a warning, compiler scan
retains those paths in its SARIF output and supplies them as context during
finding review. `/audit` also retains them in compiler sweep receipts.
Distinct paths to the same reported location are kept with that finding.

These are the compiler's control-flow assumptions, not taint traces or proof
that a path is feasible in the application. Caller contracts still need
review. Paths are limited to the target tree and bounded in count, size and
retained memory. If a path is malformed, outside scope or over a limit, the
warning remains and its metadata records why path context was omitted.

### Compiler weakness classification

Compiler finding CWE tags use the compiler's own diagnostic classification when
it supplies one. For shared Clang checkers, Raptor uses the diagnostic message
to distinguish supported cases such as leaks, double-free and use-after-free.
Compiler verification includes leaks from C++ `new` allocations as well as
C allocation leaks.
A checker name alone does not establish a specific weakness.

If the subtype remains ambiguous, the finding is retained with a broad family
or no CWE tag. Findings merged at one location with conflicting classifications
keep the observed CWE values in their metadata without selecting one by order.
Per-result tags take precedence over rule-level defaults during SARIF import.
These tags describe the reported mechanism; they do not prove path feasibility.

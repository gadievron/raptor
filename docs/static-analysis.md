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
- [Compiler analysis](#compiler-analysis)
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

Use command help for all options and their current defaults:

```bash
python3 raptor.py scan --help
```

Enable deeper analysis with `--codeql`, compiler checks with `--compiler-scan`,
or macro-expanded scanning with `--expanded-semgrep`. Use `--extra-config` for
additional Semgrep rules, `--exclude-dir` to filter reported paths, and `--out`
to choose the report directory. Examples and limitations appear below.

## Rule version requirements

The startup banner shows installed tool versions and compatibility warnings.
Rules that require a newer version are skipped individually; compatible rules
can still run. Unknown versions also skip rules with declared requirements.
These skips reduce coverage and do not establish a clean result.

Check reported skipped rules and upgrade the affected tool when necessary.
For custom rule authoring, start with the
[developer guidance](developers.md#engine-authoring-detection-rules) and the
selected tool's rule syntax.


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

JWT warnings need the target's PyJWT version for interpretation. Legacy
`verify=False` disables verification in PyJWT 1.x but is ignored in 2.x.
An `algorithms=["none"]` allowlist alone does not establish that an unverified
token is accepted. Review how decoded claims are trusted.

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
| `php` | Request-driven command, include, redirect, HTML attribute, socket CRLF, reflection and deserialisation checks |
| `python` | Python-specific security rules |
| `secrets` | Hardcoded API keys |
| `web` | Prototype pollution |
| `xml` | XXE |

PHP rules cover request-driven injection, unsafe deserialization, and HTML
attribute encoding. Custom wrappers, dynamic dispatch, complex templates, and
application-specific guards can need separate review.

Allowlist and map checks are recognized conservatively. A recognized guard is
not proof that its data or key domain is trustworthy. For deserialization,
a depth limit does not restrict allowed object types; review the application's
class policy and prefer JSON for untrusted data.

For HTML attributes, check both the surrounding quotes and the encoder flags.
`ENT_QUOTES` protects quote characters but does not make an unquoted attribute
safe. Quote the value as well as encoding it. Defaults vary by PHP version;
review omitted or dynamic flags against the target's runtime. The additional
unquoted-attribute check requires Semgrep 1.47.0 or newer; older installations
can still run the quoted-attribute checks.

Run `ls engine/semgrep/rules/` for the current file list.

PHP command quoting does not establish that a program will treat an argument
as data rather than an option. Review option parsing separately. CRLF checks
also need a network-output context; unknown stream origins and aliases can
require review. Weak-crypto checks use naming heuristics, so confirm whether
the value is used for passwords or security tokens before accepting a warning.

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

Stream-lifetime checks cover operations after `fclose()` or `pclose()` and
repeated stream closure. They follow direct pointer uses rather than aliases;
custom ownership transfers can require review.

The missing-creation-mode check covers `open`, `openat` and their `64`
variants. It reports omitted mode arguments when exact `O_CREAT` or `O_TMPFILE`
flags demonstrably survive bitwise OR/AND expressions. Numeric flag values,
casts, other arithmetic, indirect flag definitions and expressions longer
than 512 characters
are outside this check's proof scope.

The flag-domain check covers `fcntl` and `fcntl64`. It reports descriptor
flags passed to `F_SETFL` and file-status flags passed to `F_SETFD`, including
calls that mix correct and incorrect flag types. Similarly named identifiers
and flags that are masked out do not trigger these reports. Numeric flag
values and indirect flag definitions need source review.

The directory-ownership check detects closing both an `fdopendir` stream and
its underlying descriptor in either order. It stops following an ownership
chain when the relevant pointer or descriptor is replaced or passed by address,
and excludes explicit descriptor rebinding between releases. Arithmetic and
bitwise assignments end tracking too. Direct self-duplication, such as
`dup2(fd, fd)`, does not repair a closed descriptor or suppress the report.
Only the destination argument of `dup2`/`dup3` counts as rebinding. The check
follows direct uses rather than aliases.

The mapping-release check covers `mmap`, `mmap64` and `mremap`. It reports
`free` on a mapping-derived pointer, including through C-style pointer casts
and after `munmap`: unmapping does
not make that pointer a heap allocation. Reassigning the pointer or passing
its address to a helper ends tracking. Pointer aliases are outside its scope.

The kernel error-return check highlights suspicious `IS_ERR` return values
for review. It excludes explicit `bool`/`_Bool` predicates and checks that an
assigned value actually reaches the return. Matches remain review candidates
in `/audit`; check the expected errno contract before reporting a defect.

The variadic-type check covers `va_arg` and `__builtin_va_arg`, including
argument lists stored in structures, arrays or accessed through pointers.
It flags narrow integer, `_Bool` and real `float` extraction where argument
promotion requires a different type. Use the actual promoted type: some
unsigned integer promotions require `unsigned int` rather than `int`.

The `snprintf`/`vsnprintf` cursor check follows return values into pointer
advances and remaining-size updates for the same formatting destination.
It excludes unrelated length tallies and ends local tracking when the return
value, cursor or size changes. Supported truncation exits and non-truncated
update branches are excluded per update. A comparison that only logs, a return
that covers only some paths, or an update inside the truncation branch does not
hide a candidate. Unsupported casts, goto/loop exits, error handling and aliases
still require review. Reports remain candidates for bounds review.

The `snprintf`/`vsnprintf` boundary check reports review candidates when a
return value is compared with `> size`: equality also means truncation.
Decide whether the caller requires complete output before treating this as a
bug; intentional truncation and diagnostic comparisons can be valid. The check
recognizes direct assignments and declarations, stops tracking rewritten return
values or sizes, and excludes simple inclusive comparisons and separate equality
branches that return to the caller. Logging equality alone does not handle the
boundary. Aliases and arbitrary compound guard logic require manual review.

The `strncpy` termination check follows direct destinations into string uses,
including either input of `strcmp` and `strcat`. It excludes `strncmp` and
`strncat` source reads bounded by the same unchanged local or literal copy
count on every path; a conditional count change retains the candidate.
`strncat` still requires a terminated destination. Destination replacement
ends tracking.
Nonzero fills and zero-byte `memset` calls do not establish termination.
Reads can be reported again after recognized byte or memory writes that may
remove a NUL, including after a `strlen(src) + 1` copy. Zero writes preserve
existing termination, and recognized retermination keeps later reads quiet.
Conditional termination protects only the paths on which it executes. Manual
terminator bounds, uncertain write ranges, wrappers and aliases still need review.
For supported literal formats, it checks the actual argument conversion,
including positional arguments and width/precision arguments. Pointer displays,
numeric conversions and unused arguments do not count as string reads. Recognized
precision bounds within a literal copy count are excluded. Dynamic formats,
unsupported syntax and unknown precision values remain candidates for review.
Reports remain review candidates: source length, existing NUL bytes, aliases and
smaller read bounds can determine whether a read is safe.

The RCU checks report missing recognized local read-side protection as review
candidates. A caller may already hold RCU or use another valid protection
contract. The checks exclude `rcu_dereference_check` and
`rcu_dereference_protected`, whose [explicit assertions can describe alternate
protection](https://www.kernel.org/doc/html/latest/RCU/lockdep.html).
They distinguish protection at the dereference from a missing later unlock,
which is a separate balance issue. Simple nested sections are recognized;
complex nesting, wrappers and pointer use after unlocking still require review.

The sensitive-buffer release check uses local variable and direct field names
as hints for review. It recognizes zero-valued clearing requests with their
standard argument roles, including `memset_s` and `memset_explicit`. Known
zero-length calls and nonzero fills do not count as clearing requests.
Conditional wipes and writes or rebinding after a wipe can retain a candidate;
recognized re-clearing keeps the release quiet. `kfree_sensitive` clears its
allocation and is excluded from the uncleared-release check.
A clearing request does not prove that it covers every secret byte or survives
optimization. The separate ordinary-`memset`-before-`free` check reports a
compiler-removal candidate. Review sensitivity, ranges, aliases and compiler
behavior before treating either signal as a security defect.

The allocation-product check recognizes common overflow guards only when
an overflow branch returns before allocation on every relevant path.
Ignored checked-multiply results, log-only branches, and recognized operand
writes after a check keep the candidate visible. Both operand orders are
recognized for checked multiplication. Result storage that overwrites an
operand does not protect a later recomputation. Caller bounds, aliases,
operand types and more complex cleanup paths still require review. The
existing exclusions for literal products and products with a `sizeof`
factor remain; absence of a candidate does not establish overflow safety.

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

### Non-base deallocation

Pointer-arithmetic deallocation warnings require review of the allocation
origin and effective offset. An adjustment can be legitimate base recovery;
unsupported recovery idioms and C++ operators need independent verification.

### Uninitialised returns

`uninitialized_return` reports locals that may be returned without an
assignment. Complex control flow, `goto`, and macro-defined initialization can
require manual review; an empty result is not a proof of definite assignment.


### Memory leaks on error paths

`resource_leak_err` reports kernel allocations that may remain allocated on an
error return. Review ownership transfers and custom cleanup functions before
accepting a warning; these can cause false alarms.


### Double-free checks

`double_free` looks for connected free sites without an intervening pointer
assignment. It does not fully track aliases or repeated execution of one free
site in a loop. An empty result does not establish freedom from double frees.


### Prerequisites

`spatch` (the Coccinelle binary) must be on `PATH`. Minimum version
1.3 is required -- older versions (e.g. the 1.1.1 build shipped with
Ubuntu 22.04/24.04 via `apt`) cannot parse certain attribute rules
and will produce per-rule degradation.

### Auto-Skip Logic

Coccinelle is skipped when `spatch` is unavailable, no C/C++ sources are found,
or the bundled rules are missing. Check startup diagnostics when expected
Coccinelle coverage is absent. Use `--no-cocci` to disable it explicitly.


## Inline Suppression

### Semgrep

Inline suppression comments annotate findings; they do not remove them from
SARIF. Suppressed findings are hidden from the console summary unless
`--show-suppressed` is set.

```python
x = eval(user_input)  # nosemgrep: eval-taint
```

Accepted comment forms include `# nosemgrep: <rule-id>`, `// nosemgrep`, and
`/* nosemgrep */`, on the finding's line or the line above it. The SARIF result
records the suppression for later review.

### Coccinelle

Coccinelle rules have no inline suppression mechanism. Unwanted
findings can be excluded via `--exclude-dir` globs.


## Compiler analysis

### Overlapping memory copies

With `--compiler-scan`, RAPTOR checks selected C files for overlapping memory
copies. A finding requires corroborating compiler analysis. Missing tools or
failed supplemental checks are reported as coverage limitations while existing
findings are retained. This additional check does not cover C++ files or
unresolved compiler paths.


### Returning stack addresses

With `--compiler-scan`, RAPTOR checks selected C files for returns of local
addresses. A frontend warning alone is insufficient; the finding requires
path-sensitive corroboration under the same preprocessing context.

Missing tools, incompatible source views, or analysis limits reduce this
additional coverage and are reported without discarding other findings.


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

The compiler summary and SARIF diagnostics identify files that could not be
fully analyzed, including source constructs that can suppress analyzer output,
unresolved includes, malformed diagnostics, and analysis limits. Findings from
partially analyzed files remain available. Analyzer silence on those files
does not establish safety.

For compiler-backed hypotheses in `/audit`, quote a variable name when you need
attribution to that identifier, for example ``use-after-free of `buffer` ``.
Warnings with uncertain classification or location remain inconclusive rather
than proving or refuting the claim.


## Output

### SARIF Files

Each Semgrep pack produces its own SARIF report. Coccinelle produces a separate
report, and `--codeql` adds per-language CodeQL reports. `combined.sarif` merges
usable findings from the current scan and applies exclusions and enforced
suppression decisions. Per-tool reports remain available for inspection.

Use the **current scan** summary for this invocation's coverage. Older artifacts
in a reused output directory do not count as work performed by the new scan.
Project coverage reports separately show accumulated history.

### Scan completeness

The final JSON and `scan_metrics.json` record execution as `ok`, `partial`, or
`error`. Check that status and the reported coverage warnings when automation
requires every requested analysis to finish. A successful tool process or zero
findings alone does not establish complete coverage or safe code.

Pack failures, unavailable tools, parse errors, malformed reports, and skipped
analysis can leave execution partial. Usable findings are retained where
possible, and the reports identify the missing coverage. Informational compiler
review candidates are separate from confirmed findings and coverage failures.


### Filtering

`--exclude-dir` filters matching paths from `combined.sarif` and downstream
metrics. Per-tool SARIF reports retain the original findings for inspection.

### Sanitizer-cut post-pass

After the merge, the sanitizer-cut gate re-checks taint findings whose
every source-to-sink path crosses a full-proof sanitizer.  Enforcement
is the default: suppress-verdict findings are removed from
`combined.sarif`, with one evidence record per suppression in
`suppressions.jsonl`.  Per-tool SARIFs are never filtered in any mode.
`--no-sanitizer-cut-enforce` keeps the verdicts record-only;
`--no-sanitizer-cut-postpass` skips the pass entirely.

### Sanitizer-recognition contract

Some multi-step sanitizer chains are recognized only within a single
expression. The same operations split across statements can still produce a
finding. Review the complete sanitizer behavior and sink context before
suppressing such a result.


### Metrics

`scan_metrics.json` reports finding totals by tool, rule, and severity,
suppressed findings, execution status, and coverage limitations. Counts follow
the merged report when merging succeeds; otherwise they use retained per-tool
reports. Inspect the coverage diagnostics alongside finding counts.


## Error Handling

### Per-Pack Isolation

A failed Semgrep pack is reported without stopping the remaining packs. Check
the final execution status and diagnostics to see which analyses completed;
a partial result still contains findings from successful packs.


### Timeouts

| Scope | Default |
|-------|---------|
| Overall scan | 30 min |
| Local Semgrep pack | 15 min |
| Registry Semgrep pack | 5 min |
| Semgrep rule | 2 min |
| Coccinelle rule | 5 min |

Timeouts reduce coverage. Consult execution diagnostics before treating an
empty report as a completed scan.


### Sandbox Failures

A sandbox setup failure aborts the scan rather than continuing without the
requested isolation. See [sandbox troubleshooting](sandbox.md#troubleshooting).

If every dispatched Semgrep pack fails, the command exits with code 4. Sandbox
engagement failure uses exit code 3. Other incomplete scans can retain the
existing exit-code behavior; check the saved execution status as well.


### Parallel Execution

Semgrep packs run in parallel by default. With `--codeql`, CodeQL also runs
concurrently with Semgrep; its console messages are tagged `[codeql]`.

Use `--sequential` to run packs and stages one at a time. Worker limits are
configurable through `max_semgrep_workers` in `tuning.json`.


### Compiler review candidates

Strict-aliasing warnings can describe safe casts or unreachable code. Warnings
without sufficient corroboration are saved in
`scan/compiler-review-candidates.json` with status `needs_review`, separately
from normal findings and automatic finding analysis.

For a limited set of C cases, additional type analysis can corroborate an
incompatible scalar access. The report states the compiler model used; project
build flags are not inferred. Unsupported cases, missing tools, and analysis
limits leave candidates available for review. Silence does not prove them safe.


### Compiler diagnostic paths

Compiler findings can include the calls and branches leading to a warning.
These paths help review the compiler's assumptions; they do not prove that the
path is feasible in the application. Missing or truncated path context does
not discard an otherwise usable warning.


### Compiler weakness classification

CWE tags describe the diagnostic's reported mechanism, not application
reachability. Ambiguous warnings may retain a broad family or no CWE tag;
review the diagnostic and source rather than relying on the tag alone.

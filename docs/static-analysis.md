# Static Analysis

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
| `--codeql` | off | Run [CodeQL](codeql.md) stage after Semgrep |
| `--no-codeql` | -- | Explicitly disable CodeQL |
| `--no-cocci` | off | Disable Coccinelle stage |
| `--languages <list>` | auto | CodeQL language list (only relevant with `--codeql`) |
| `--build-command <cmd>` | auto | CodeQL build command override (only relevant with `--codeql`; implies a traced build) |
| `--traced-build` | off | Opt into traced-build C/C++ CodeQL extraction — executes the repo's build system (asserts trust). Default is buildless: no repo code runs during database creation |
| `--no-traced-build` | -- | Force buildless extraction for this run, overriding `--traced-build` and the project's `build` trust marker |
| `--compiler-scan` | off | Run gcc `-fanalyzer` / clang `--analyze` per C/C++ translation unit as an extra scan channel (sandboxed; no repo code executes). TUs whose analyzer silence is repo-steerable are reported as a coverage limitation, never as a finding — see [Compiler-scan coverage limitations](#compiler-scan-coverage-limitations) |
| `--no-compiler-scan` | -- | Explicitly disable the compiler-analyzer channel |
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


## Semgrep Rules

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

```bash
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


### Compiler-scan coverage limitations

`--compiler-scan` treats analyzer silence on a TU as evidence only when nothing in the TU or its repo headers can steer the
analyzer. Otherwise the TU is counted as analysed but listed as a coverage limitation: one summary clause (with the
witness kind, e.g. `` `_Pragma` operator, payload not checked``, `analyzer-conditional code`, `` `suppress` attribute``,
`unverifiable attribute list`) and one SARIF `toolExecutionNotification` per TU (`properties.witness_kind`). The kind is a
label only; it never changes the result. Findings that clang still reports are always kept.

- **Reported as "carry an in-source analyzer suppression or steering construct":** `suppress` / `__suppress__` in a
  `[[...]]`, `<:<:...:>:>` or `__attribute__((...))` list (any position, any nesting, across lines), any `_Pragma(`
  operator, `#ifndef __clang_analyzer__`-style analyzer-conditional code, diagnostic-ignore and system-header pragmas, and
  system-header line markers — in the TU or a repo header, including token-pasted forms visible in the `-E` output.
- **Reported as "not vetted":** a `#line` / linemarker whose presumed name leaves the tree (a relative name is resolved
  against the TU directory, matching how diagnostic paths are attributed), cannot be resolved, cannot be decoded, or looks
  like a Windows path (a drive prefix or any backslash — a conservative policy; backslashes are legal POSIX characters);
  a relative include marker; missing, empty or unparseable `-E` output; a TU or header over the size caps; a symlinked TU;
  more than 20,000 distinct linemarker names reaching the attribution checks in one TU (measured on real code: at most
  813, a C++ TU including ten standard-library headers); a linemarker name that must be resolved on the filesystem and is
  longer than 4,096 characters, resolves through more than 256 path components or follows more than 40 symbolic links;
  more than 250,000 filesystem operations (each lstat, each readlink and each component of a followed link's target) in
  one TU; or a vet still running after its 60 s per-TU deadline (measured on 4,405 real `clang -E` closures: at most
  181 characters, 22 components, 2 links per name and 21,825 operations per TU). These reasons give counts and the `-E`
  line number, never the name. Containment is decided as on a POSIX filesystem (clang runs on POSIX here); Windows paths
  and case-insensitive matching are not supported.
- **Accepted false positives** (they only add a limitation): `suppress` as an attribute argument or in a string on an
  attribute line; an attribute list the scan cannot verify (unbalanced, unclosed, nested deeper than 4096, or a literal
  running to end of file after an opener); Obj-C message expressions such as `[[obj suppress:1] x]`; any `_Pragma`, even a
  harmless one — on brotli 29 of 32 TUs carry `_Pragma` portability macros in compiler branches inactive under clang; a
  C++ raw-string line starting `# <digit>` in `-E` output.
- **Not detected (residuals):** a suppression assembled by token pasting that leaves no text in the sources or the `-E`
  output (e.g. `#define CA __clang_ ## analyzer__` / `#if CA`); clang lexing beyond the scanner's model; a nameless or
  in-tree `#line` relabel (the scan keeps the finding, but the audit sweep may refute); a self-include with
  `_Pragma("clang system_header")`.
- **Witness text:** the witness quoted in the summary and SARIF is source or `-E` text with the target root removed;
  linemarker and other directive lines inside a quoted attribute list are replaced by a space, so a toolchain header path
  never appears. A path literal written in the scanned source itself is quoted as written.
- **Untested paths:** the gcc `-fanalyzer` path was never executed (on gcc, `#ifndef __clang_analyzer__` may be reported
  although gcc does not define it); all measurements used an unsandboxed runner, not the real seatbelt sandbox.
- **Cost (observed, Apple clang 21, unsandboxed runner, 3 runs, median; host load 12–60):** end to end, brotli (32 TUs)
  9.4 s → 11.0 s (about 1.2×); a 22-TU C tree 0.59 s → 1.00 s (+0.4 s); a synthetic 200-TU × 30-header workload 2.0 s
  → 7.1 s (about 3.5×: one extra `-E` run per TU plus about 14 s of summed witness time across the 4 worker threads).
  The witness function alone on a synthetic 14 MB preprocessed closure: 0.13 s → about 3.2 s. Measured maxima for the
  tested shapes near the 64M-character `-E` cap (host load 22–110, so times are indicative; not proven bounds): about
  1.8 GB peak process memory per TU on two-character or CRLF lines (one-character lines: about 950 MB), mostly the
  per-line splits of the pre-existing and layer-1 walks; one TU including 31 headers of 2 MB short lines through real
  clang, about 90–120 s, mostly the layer-2 token scan and per-header scans. The scan runs 4 workers, so about 7.2 GB
  plus process overhead with four such TUs in flight. Linemarker-name resolution is bounded by the per-name and per-TU
  limits above, symlink expansion included: a chain of 1,000 links named by 200 `#line` markers ends "not vetted" in
  about 0.4 s end to end. The pre-existing closure check, which runs before these limits, is not covered by them: a long
  symlink chain named by absolute `#line` paths is slow there, as it is on main. The 60 s deadline is cooperative: it is
  checked between steps and cannot interrupt a blocked system call, filesystem latency, or the uninstrumented linear
  scans of the `-E` text.

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
- A statement-chain upgrade is per-engine dataflow work (a CodeQL
  local-flow join; Semgrep cannot express it outside
  `by-side-effect`) with no observed FP burden justifying it.
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

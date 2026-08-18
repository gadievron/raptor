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
| `--compiler-scan` | off | Run gcc `-fanalyzer` / clang `--analyze` per C/C++ translation unit as an extra scan channel (sandboxed; no repo code executes) |
| `--no-compiler-scan` | -- | Explicitly disable the compiler-analyzer channel |
| `--compiler-scan-max-tus <n>` | 2000 | Cap on translation units analysed by `--compiler-scan` (skipped TUs are reported) |
| `--expanded-semgrep` | off | Re-run the loaded ruleset over fidelity-3 preprocessor-expanded views of macro-heavy C/C++ TUs, line-mapped back to the originals |
| `--keep` | off | Keep temporary working directory after completion |
| `--sequential` | off | Fully serial run: packs one at a time and stages in order (no Semgrep/CodeQL overlap) |
| `--out <dir>` | auto | Output directory override |
| `--exclude-dir <glob>` | none | Drop results from matching paths (repeatable, OR semantics) |
| `--extra-config <path>` | none | Additional Semgrep rule source path (repeatable) |
| `--show-suppressed` | off | Include `nosemgrep`-suppressed findings in output summary |
| `--sandbox <profile>` | full | [Sandbox](sandbox.md) profile (`full` / `strict` / `debug` / `target_run` / `frida` / `network-only` / `none`) |
| `--no-sandbox` | off | Alias for `--sandbox none` |
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

By default, packs run in parallel via `ThreadPoolExecutor` with
`max_workers` from `tuning.json` (`max_semgrep_workers`, default
`auto` = half the available CPUs). Each pack's semgrep process gets a
`--jobs` share of the cores divided by the number of packs actually
running at once, so concurrent packs cannot each claim every core. A
post-completion check verifies that every submitted pack's SARIF file
actually exists on disk -- missing files (filesystem error, sandbox
teardown race) are added to the `failed_scans` list.

With `--codeql`, the CodeQL stage (database build + analyze) runs
concurrently with the Semgrep packs; its console lines are tagged
`[codeql]` and a stage-completion line reports its duration. Multi-
language builds also divide `-j` between concurrent per-language
invocations when `codeql_threads` is `auto`.

Pass `--sequential` for a fully serial run: packs one at a time AND
stages in order (no Semgrep/CodeQL overlap).

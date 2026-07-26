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
`--codeql`.

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
| `--build-command <cmd>` | auto | CodeQL build command override (only relevant with `--codeql`) |
| `--keep` | off | Keep temporary working directory after completion |
| `--sequential` | off | Disable parallel scanning; run packs one at a time |
| `--out <dir>` | auto | Output directory override |
| `--exclude-dir <glob>` | none | Drop results from matching paths (repeatable, OR semantics) |
| `--extra-config <path>` | none | Additional Semgrep rule source path (repeatable) |
| `--show-suppressed` | off | Include `nosemgrep`-suppressed findings in output summary |
| `--sandbox <profile>` | full | [Sandbox](sandbox.md) profile (`debug` / `full` / `network-only` / `none`) |
| `--no-sandbox` | off | Alias for `--sandbox none` |
| `--audit` | off | Engage [sandbox](sandbox.md) audit mode |
| `--audit-verbose` | off | Log every traced syscall (requires `--audit`) |
| `--audit-budget <n>` | 10000 | Override audit-record cap |


## Semgrep Rules

### Rule Categories

RAPTOR ships 40 YAML rule files across 15 categories under
`engine/semgrep/rules/`:

| Category | Count | Covers |
|----------|------:|--------|
| `crypto` | 12 | Weak hash, weak PRNG, weak ciphers, weak KDF iterations/keysize, reused nonce, insecure IV, PKCS1v15 padding, insecure password hash, weak asymmetric keysize, weak block modes |
| `injection` | 12 | SQL taint, SQL concat, command taint (single + multi-lang), eval taint, SSTI taint, NoSQL taint, XSS, LDAP taint, header injection, log injection, regex DoS |
| `auth` | 2 | JWT signature bypass (`jwt-no-verify`), TLS certificate skip (`tls-skip-verify`) |
| `deserialisation` | 2 | Unsafe deserialise (Python/Ruby/PHP), unsafe Java deserialise |
| `sinks` | 2 | SSRF, open redirect |
| `filesystem` | 1 | Path traversal |
| `flows` | 1 | Bad MAC order (encrypt-then-MAC vs MAC-then-encrypt) |
| `go` | 1 | Go-specific security rules |
| `java` | 1 | Java-specific security rules |
| `javascript` | 1 | JavaScript-specific security rules |
| `logging` | 1 | Secrets in log output |
| `python` | 1 | Python-specific security rules |
| `secrets` | 1 | Hardcoded API keys |
| `web` | 1 | Prototype pollution |
| `xml` | 1 | XXE |

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

54 semantic patch files under `engine/coccinelle/rules/`, covering
C/C++ structural patterns that require control-flow sensitivity:

**Memory safety:**
`use_after_free`, `double_free`, `realloc_losing_ptr`,
`free_nonbase_ptr`, `stack_addr_escape`, `missing_null_check`,
`free_stack_array`, `mmap_free`, `use_after_close`,
`use_after_fclose`

**Uninitialised data:**
`copy_to_user_uninit`, `uninitialized_return`

**Resource leaks:**
`resource_leak_err`, `mmap_leak_err`, `double_close`,
`popen_fclose`, `fdopendir_double_close`

**Integer issues:**
`integer_overflow_alloc`, `shift_overflow`, `sign_extension_widen`,
`division_by_zero`, `uid_truncation`, `double_sizeof`

**Buffer handling:**
`missing_bounds_check`, `strncpy_no_nul`, `snprintf_advance`,
`copy_user_size_mismatch`, `sizeof_array_param`,
`sizeof_container_of`, `malloc_strlen_strcpy`

**Concurrency:**
`lock_imbalance`, `sleep_under_spinlock`,
`gfp_kernel_under_spinlock`, `rcu_no_lock`, `use_after_unlock`,
`signal_handler_unsafe`

**TOCTOU and race conditions:**
`toctou_stat_open`, `double_fetch`

**Sandbox escape:**
`chroot_no_chdir`, `socket_no_cloexec`

**Unchecked returns:**
`unchecked_return`, `unchecked_strtol`

**Format strings:**
`format_string`

**API misuse:**
`signal_sigkill_sigstop`, `fcntl_flag_domain`,
`double_byteswap`, `inet_ntoa_double_call`,
`open_creat_no_mode`

**Compiler optimisation hazards:**
`dead_memset_free`

**Kernel-specific:**
`is_err_not_ptr_err`

**Miscellaneous:**
`va_arg_mismatch`, `init_after_register`, `unsafe_list_del`,
`sensitive_data_leak`

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
`max_workers` defaulting to 4 (or half the available CPUs when set to
`auto`). A post-completion check verifies that every submitted pack's
SARIF file actually exists on disk -- missing files (filesystem error,
sandbox teardown race) are added to the `failed_scans` list.

Pass `--sequential` to disable parallelism and run packs one at a
time.

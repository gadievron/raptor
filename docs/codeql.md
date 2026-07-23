# CodeQL

Deep static analysis with semantic dataflow queries. CodeQL builds a
database from compiled (or extracted) source, then evaluates queries
that model taint propagation, control-flow predicates, and type
relationships -- finding vulnerabilities that pattern-matching tools
like Semgrep cannot reach.

RAPTOR wraps the CodeQL CLI into a fully autonomous pipeline: language
detection, build orchestration, database creation, query execution,
and -- optionally -- LLM-powered analysis with exploit generation.

**Related documentation:**
[static analysis](static-analysis.md) |
[binary analysis](binary-analysis.md) |
[sandbox](sandbox.md)


## Usage

```
/codeql --repo <path> [options]
```

Dispatches to `python3 raptor.py codeql`. Default mode is `--scan-only`
(SARIF output, no LLM calls). Pass `--analyze` to enable the full
autonomous analysis pipeline.

### CLI Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--repo <path>` | required | Repository path to analyse |
| `--languages <list>` | auto-detect | Comma-separated languages (aliases accepted: `c`, `js`, `ts`, `c#`, `kt`, `py`) |
| `--build-command <cmd>` | auto-detect | Custom build command (requires exactly one `--languages` entry) |
| `--out <dir>` | auto | Output directory |
| `--force` | off | Delete and recreate the CodeQL database from scratch |
| `--extended` | off | Use `security-extended` suites instead of `security-and-quality` |
| `--min-files <n>` | 3 | Minimum source files to consider a language present |
| `--codeql-cli <path>` | auto | Path to the `codeql` binary |
| `--scan-only` | **default** | Produce SARIF only, skip LLM analysis |
| `--analyze` | off | Enable autonomous LLM analysis, dataflow validation, and exploit generation |
| `--allow-unreachable` | off | Disable the reachability prefilter's hard-suppress; full LLM analysis runs on dead-code findings |
| `--target-kind <kind>` | auto | `library` / `hybrid` / `application` / `auto` -- controls entry-point reachability semantics |
| `--max-findings <n>` | 20 | Maximum findings to analyse (with `--analyze`) |
| `--no-visualizations` | off | Disable HTML/Mermaid/ASCII/DOT dataflow visualisations |
| `--trust-repo` | off | Trust the target repo's config files and skip safety checks |
| `--phase-timeout <sec>` | config | Wall-clock timeout for the database creation phase (0 = unlimited) |
| `--binary <path>` | none | Explicit debug binary for reachability oracle (repeatable) |
| `--binary-auto` | off | Auto-detect locally-built debug binaries |
| `--binary-edges` | off | Extract direct call edges and vtable resolution via r2 |
| `--no-binary-oracle` | off | Disable binary-oracle filtering entirely |
| `--sanitizer-cut <mode>` | off | Sanitiser-cut value-bound suppression mode (`off` / `on` / `strict` / `shadow`) |
| `--no-iris-tier1` | off | Skip IRIS Tier 1 in-repo LocalFlowSource pack analysis |
| `--sandbox <profile>` | full | [Sandbox](sandbox.md) profile (`debug` / `full` / `network-only` / `none`) |
| `--no-sandbox` | off | Alias for `--sandbox none` |
| `--audit` | off | Engage [sandbox](sandbox.md) audit mode |
| `--audit-verbose` | off | Log every traced syscall (requires `--audit`) |
| `--audit-budget <n>` | 10000 | Override audit-record cap |


## Pipeline

The scan pipeline runs in five phases. All five execute in `--scan-only`
mode (the default). When `--analyze` is passed, a second stage adds
LLM-powered analysis on top of the SARIF output.

### Phase 1 -- Language Detection

Implemented in `packages/codeql/language_detector.py`.

The detector walks the repository, classifying files by extension,
build manifests, and structural indicators (e.g. `src/main/java/`).
Each language receives a confidence score between 0.0 and 1.0:

- Base 0.3 for any matching source files
- Up to +0.4 for recognised build files
- Up to +0.3 for structural indicators
- Up to +0.3 based on file-count ratio

Languages below their per-language minimum confidence threshold are
filtered out. Detection uses a three-tier retry strategy:

1. **Tier 1** -- `min_files=3`, confidence gate active. Catches most
   real projects.
2. **Tier 2** -- `min_files=1`, same confidence gate. Fires when
   Tier 1 finds nothing (single-file fixtures, minimal repros).
3. **Tier 3** -- `floor=2` files, confidence gate bypassed. Fires
   when both prior tiers found nothing; logs a WARNING.

Operator-friendly aliases are normalised at the entry point:
`c`/`c++`/`cxx`/`cc` become `cpp`, `js` becomes `javascript`,
`ts` becomes `typescript`, `cs`/`c#` become `csharp`, `kt` becomes
`kotlin`, `py` becomes `python`.

### Phase 2 -- Build Detection

Implemented in `core/build/build_detector.py`.

For each detected language the detector identifies the build system
and generates the appropriate command:

| Language | Build systems (priority order) |
|----------|-------------------------------|
| Java | Maven, Gradle, Ant |
| Python | Poetry, pip, setuptools |
| JavaScript | npm, yarn, pnpm |
| TypeScript | npm, yarn |
| Go | gomod (`go build ./...`) |
| C/C++ | cmake, autotools, meson, make |
| C# | dotnet, msbuild |
| Ruby | bundler, rake |

**Fallback chain:** auto-detect the build system, validate that the
tool is installed, try `synthesise_build_command` (generates a Python
shim to compile individual files; C++ and Java only), then fall back to
no-build mode (interpreted languages or when nothing else works).

SAGE build-recall context is threaded into the detection when
available, providing hints from previous successful builds of the
same repository.

### Phase 3 -- Database Creation

Implemented in `packages/codeql/database_manager.py`.

Databases are created via `codeql database create` and cached by a
content hash:

- **Git repositories (fast path):** `SHA256(repo_path + ":" +
  HEAD_hash)` truncated to 16 hex characters.
- **Non-git targets (fallback):** walks up to 1000 files, hashes
  `(relative_path, file_size)` tuples.

Cache lookup validates existence, a success flag in metadata, age
(7-day maximum), and integrity (presence of `codeql-database.yml`
plus a `db-*` subdirectory above 100 KB).

Multi-language targets build databases in parallel via
`ThreadPoolExecutor`. Concurrent writes are handled with atomic
staging directories (`.staging-<lang>-<pid>-<random>` renamed on
completion). Stale staging markers older than one hour are
garbage-collected automatically.

Pass `--force` to bypass the cache and recreate from scratch.

### Phase 4 -- Query Execution

Implemented in `packages/codeql/query_runner.py`.

Each database is analysed against an upstream CodeQL suite:

| Suite | Flag | Coverage |
|-------|------|----------|
| `security-and-quality` | default | Broad: security rules plus code-quality queries |
| `security-extended` | `--extended` | Deeper: experimental and preview security rules |

Both suites are defined for Java, Python, JavaScript, TypeScript, Go,
C/C++, C#, Ruby, Swift, Kotlin, and Rust -- 11 languages total.
TypeScript reuses the JavaScript suite; Kotlin reuses the Java suite.

If a required query pack is not installed locally, the runner
automatically downloads it via `codeql pack download` with up to
three retries and exponential backoff.

**IRIS LocalFlowSource pass:** After the standard suite, RAPTOR runs
in-repo query packs (`packages/llm_analysis/codeql_packs/`) that
extend source coverage to CLI arguments, environment variables, stdin,
file reads, and database inputs. IRIS packs exist for Python, Java,
JavaScript, and Go (28 queries across 8 CWEs). C++ is excluded because
the upstream stdlib already covers local flow sources. Disable with
`--no-iris-tier1`.

Per-language SARIF files are written to the output directory. IRIS
findings produce a separate `codeql_<lang>_iris.sarif` file.

### Phase 5 -- Reporting

The agent writes `codeql_report.json` containing language detection
results, database creation status, per-language finding counts, SARIF
file paths, timing, and any errors.

A two-stage serialisation strategy ensures that a report file always
lands on disk: if the full `to_dict()` raises, a minimal report with
high-level stats and an explicit error field is written instead.


## Autonomous Analysis (`--analyze`)

When `--analyze` is passed, the pipeline continues into a second
phase powered by `packages/codeql/autonomous_analyzer.py`. Each
SARIF finding is processed through a seven-stage pipeline.

### Reachability Prefilter

Before spending LLM tokens, the analyser consults a source-level
call graph (`core/analysis/reach_audit.py`) to determine whether the
function containing the finding's sink is reachable from any entry
point.

The classifier runs a 10-stage precedence chain:

1. **Module aborts** -- file's top-level execution aborts before the
   sink's function binds.
2. **Lexical dead** -- sink defined inside an always-false guard.
3. **Frida runtime trace** -- function observed at runtime (SOUND
   promote).
4. **Binary oracle absent** -- function absent from analysed binary.
5. **Build excluded** -- file excluded from build (heuristic).
6. **Framework callable** -- function carries a framework-dispatch
   decorator (`@app.route`, `@shared_task`, etc.).
7. **Registered via call** -- function passed as argument to a
   framework registration call.
8. **Binary call edge** -- direct call edge from binary analysis.
9. **Entry reachability** -- graph walk from known entry points.
10. **One-hop caller** -- at least one direct caller exists.

The reachability chokepoint (`core/analysis/reach_chokepoint.py`)
enforces policy: only SOUND witnesses (module-aborts, lexical-dead,
binary-oracle-absent) can authorise hard suppression. Heuristic
verdicts (not-called, no-path-from-entry) are recorded but never
cause suppression. Suppressed findings are logged to
`suppressions.jsonl`. See [binary analysis](binary-analysis.md)
for the binary oracle integration.

Pass `--allow-unreachable` to disable hard suppression entirely (for
CTF targets, vendor snippets, or intentional dead-code audits).

### Dataflow Validation

Implemented in `packages/codeql/dataflow_validator.py`.

The validator parses SARIF `codeFlows` to reconstruct the taint path
from source to sink, then identifies potential sanitisers along the
path. Evidence collection is CWE-dispatched: injection-class findings
receive sanitiser evidence; memory-corruption findings receive
source-intel structural evidence.

### SMT Path Feasibility

Implemented in `core/smt_solver/path_feasibility.py`. Requires
`z3-solver` (`pip install z3-solver`); degrades gracefully when
absent.

After the LLM extracts branch conditions from each dataflow step as
structured predicates (`"size > 0"`, `"offset + length <=
buffer_size"`, etc.), Z3 checks whether those conditions are jointly
satisfiable:

- **unsat** -- path is provably unreachable. Finding skipped (no full
  LLM call). Exploitability confidence capped at 0.7.
- **sat** -- concrete satisfying values returned. Injected as
  "Candidate input values" into the LLM analysis prompt and the
  `prerequisites` field of `DataflowValidation`.
- **None** -- Z3 unavailable or conditions unparseable. Full LLM
  analysis runs without SMT hint.

Bitvector width is inferred per-CWE: CWE-190 family uses 32-bit
unsigned (modelling C integer wraparound); others default to 64-bit.
The extraction LLM can override width and signedness via per-path
hints.

**Best CWE coverage:** CWE-190 (integer overflow including 32-bit
wraparound), CWE-120/122 (buffer size checks), CWE-193 (off-by-one),
CWE-476 (null deref). String-based findings (e.g. CWE-89 SQL
injection) fall through to LLM analysis.

### LLM Analysis

Two-tier architecture:

1. **Fast FP prefilter** -- a cheap model (`TaskType.VERDICT_BINARY`)
   with a `CONSERVATIVE` prompt envelope is asked whether the finding
   is a confident false positive. The framing is deliberately
   asymmetric: only `clear_fp` verdicts short-circuit; `needs_analysis`
   falls through. A scorecard policy gate
   (`core/llm/scorecard/prefilter.py`) decides whether to honour the
   cheap model's verdict based on historical agreement with the full
   analyser.

2. **Full analysis** -- the finding, source context, dataflow path,
   and any SMT-derived input values are sent to the primary analysis
   model with a Mark Dowd security researcher persona. The prompt
   requests the 11-field `VULNERABILITY_ANALYSIS_SCHEMA` covering
   true-positive determination, exploitability score, severity,
   reasoning, attack scenario, prerequisites, impact, CVSS estimate,
   and mitigation.

All untrusted content is wrapped in `UntrustedBlock` objects and
`TaintedString` slots before prompt construction.

### Exploit Generation

When a finding is assessed as exploitable, the analyser generates a
proof-of-concept exploit via an LLM call (`TaskType.GENERATE_CODE`,
temperature 0.8).

The generated code is then passed through an iterative
compile-test-fix loop:

1. Compile via `ExploitValidator.validate_exploit` (sandboxed, network
   blocked).
2. If compilation fails, send errors to
   `MultiTurnAnalyser.refine_exploit_iteratively`.
3. Loop terminates on: compile success, LLM returns identical or empty
   code, or maximum refinement iterations exhausted (default 3).

Source-scan rejection (`poc_source_scan.scan`) checks for
exfiltration patterns before the exploit is written to disk.

### Visualisation

When `--no-visualizations` is not set, four output formats are
generated per dataflow path via
`packages/codeql/dataflow_visualizer.py`:

| Format | Extension | Description |
|--------|-----------|-------------|
| HTML | `.html` | Self-contained interactive visualisation with colour-coded nodes (source, step, sanitiser, sink) |
| Mermaid | `.mmd` | `graph TD` diagram suitable for Markdown rendering |
| ASCII | `.txt` | Box-drawing terminal visualisation |
| DOT | `.dot` | Graphviz format for custom rendering |


## Custom Queries

RAPTOR ships 8 hand-written queries under `engine/codeql/queries/`,
complementing the upstream suites with patterns that CodeQL's standard
packs do not cover.

### C++ (`engine/codeql/queries/cpp/`)

| Query | CWEs | Severity | Description |
|-------|------|----------|-------------|
| `FormatStringFromUntrusted.ql` | CWE-134 | 9.3 | Printf-family format string from untrusted source (file, network, env, argv). Taint-tracking path-problem. |
| `IntegerTruncationInCast.ql` | CWE-681, 190, 122 | 8.0 | Explicit cast from wider to narrower integer flowing to allocation or buffer operation without prior range check. |
| `IteratorInvalidation.ql` | CWE-416, 825 | 7.5 | Container mutation (erase, insert, push_back, resize, clear) during active iteration. Excludes safe `it = container.erase(it)`. |
| `UseAfterMove.ql` | CWE-416 | 6.0 | Access to variable after `std::move()` without intervening reassignment. Excludes safe post-move operations (clear, reset, swap). |

### Java (`engine/codeql/queries/java/`)

| Query | CWEs | Severity | Description |
|-------|------|----------|-------------|
| `InsecureDeserialization.ql` | CWE-502 | 9.8 | `ObjectInputStream` from untrusted input calling `readObject()` without a JEP 290 type filter. Taint-tracking path-problem. |
| `SpringSSRFAnnotationSource.ql` | CWE-918 | 9.1 | SSRF via Spring MVC annotation-injected parameters (`@RequestParam`, `@PathVariable`, `@RequestBody`) flowing to HTTP client calls. |
| `XXEDocumentBuilder.ql` | CWE-611 | 9.0 | `DocumentBuilder` parsing XML without disabling external entity resolution. |
| `LogInjection.ql` | CWE-117 | 5.0 | User-controlled data to logging methods (java.util.logging, SLF4J, Log4j2, Commons Logging) without CRLF sanitisation. |


## Supported Languages

CodeQL suite coverage across both suite tiers:

| Language | `security-and-quality` | `security-extended` | Notes |
|----------|:---------------------:|:-------------------:|-------|
| Java | yes | yes | |
| Python | yes | yes | |
| JavaScript | yes | yes | |
| TypeScript | yes | yes | Reuses JavaScript suite |
| Go | yes | yes | |
| C/C++ | yes | yes | |
| C# | yes | yes | |
| Ruby | yes | yes | |
| Swift | yes | -- | Extended suite not defined upstream |
| Kotlin | yes | -- | Reuses Java suite |
| Rust | yes | yes | |

Language auto-detection covers 10 languages (all except Rust, which
has no detection pattern but can be specified via `--languages rust`).


## Prerequisites

- **CodeQL CLI** -- must be on `PATH` or specified via `--codeql-cli`.
  Query packs are auto-downloaded on first use.
- **Build toolchain** -- for compiled languages (C/C++, Java, C#, Go,
  Swift, Kotlin), the appropriate compiler or build tool must be
  installed. Interpreted languages (Python, JavaScript, TypeScript,
  Ruby) use no-build extraction.
- **z3-solver** (optional) -- `pip install z3-solver` to enable SMT
  path feasibility checks. Without it, the SMT stage is silently
  skipped and all findings proceed to full LLM analysis.
- **LLM API key** (for `--analyze`) -- `ANTHROPIC_API_KEY` or
  `OPENAI_API_KEY` must be set. Not needed for `--scan-only`.

All subprocess invocations run inside the RAPTOR [sandbox](sandbox.md)
by default. Pass `--no-sandbox` to disable.

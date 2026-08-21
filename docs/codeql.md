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
| `--build-command <cmd>` | auto-detect | Custom build command (requires exactly one `--languages` entry; implies a traced build for that language) |
| `--traced-build` | off | Opt into traced-build C/C++ extraction (executes the repo's build system — asserts trust in the repo). Default is buildless |
| `--no-traced-build` | off | Force buildless extraction for this run, overriding both `--traced-build` and the project's `build` trust marker |
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
| `--no-trust-repo` | off | Keep the strict trust checks for this run, overriding both `--trust-repo` and the project's `config` trust marker |
| `--phase-timeout <sec>` | config | Wall-clock timeout for the database creation phase (0 = unlimited) |
| `--binary <path>` | none | Explicit debug binary for reachability oracle (repeatable) |
| `--binary-auto` | off | Auto-detect locally-built debug binaries |
| `--binary-edges` | off | Extract direct call edges and vtable resolution via r2 |
| `--no-binary-oracle` | off | Disable binary-oracle filtering entirely |
| `--sanitizer-cut <mode>` | off | Sanitiser-cut value-bound suppression mode (`off` / `on` / `strict` / `shadow`) |
| `--sanitizer-cut-parity-log <path>` | auto | Parity-log path for `--sanitizer-cut shadow` (default: `<run_dir>/sanitizer_cut_parity.jsonl`) |
| `--no-iris-tier1` | off | Skip IRIS Tier 1 in-repo LocalFlowSource pack analysis |
| `--no-curated-queries` | off | Skip the curated in-repo query pass (`engine/codeql/queries/<lang>/`) |
| `--no-learned-models` | off | Skip the learned-models measurement pass (IRIS taint specs emitted as a models-as-data pack; baseline vs augmented diff) |
| `--threat-models <csv>` | `local` | Threat models enabled on the standard suite (`--threat-model=<name>` per entry) |
| `--no-threat-models` | off | Pass no `--threat-model` flag (stock remote-only source models) |
| `--sandbox <profile>` | full | [Sandbox](sandbox.md) profile (`full` / `strict` / `debug` / `target_run` / `frida` / `network-only` / `none`) |
| `--no-sandbox` | off | Alias for `--sandbox none` |
| `--audit` | off | Engage [sandbox](sandbox.md) audit mode |
| `--audit-verbose` | off | Log every traced syscall (requires `--audit`) |
| `--audit-budget <n>` | 10000 | Override audit-record cap |


## Pipeline

The scan pipeline runs in five phases. All five execute in `--scan-only`
mode (the default). When `--analyze` is passed, a second stage adds
LLM-powered analysis on top of the SARIF output.

### Phase 1 -- Language Detection

The detector walks the repository, classifying files by extension,
build manifests, and structural indicators (e.g. `src/main/java/`),
and scores each language's confidence. Low-confidence languages are
filtered out; if nothing survives, progressively looser retries handle
single-file fixtures and minimal repros (the loosest tier logs a
WARNING). `--min-files` and `--languages` override the detection.

Operator-friendly aliases are normalised at the entry point:
`c`/`c++`/`cxx`/`cc` become `cpp`, `js` becomes `javascript`,
`ts` becomes `typescript`, `cs`/`c#` become `csharp`, `kt` becomes
`kotlin`, `py` becomes `python`.

### Phase 2 -- Build Detection

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
tool is installed, try synthesising a minimal per-file build (C++ and
Java only), then fall back to no-build mode (interpreted languages or
when nothing else works).

[SAGE](sage.md) build-recall context is threaded into the detection
when available, providing hints from previous successful builds of the
same repository.

### Phase 3 -- Database Creation

**Buildless C/C++, Java, and C# (default).** These databases are
created with `--build-mode=none`: the extractor parses source without
invoking any build system, so no repo-controlled code executes during
`database create`. This is the untrusted-repo posture — a build
system is repo code, and there is no mechanical signal that running
it is safe. For Java it is also the only mode that works by
construction: `database create` runs with the sandbox network
blocked, so an autobuild that needs to fetch dependencies always
fails, while buildless extraction proceeds with unresolved
dependencies at reduced type fidelity. Version floors: CLI >= 2.16
for C/C++, >= 2.16.4 for Java, >= 2.17.1 for C#; older CLIs get a
clear skip, never a silent fallback to a traced build. When an
operator's explicit traced build (`--traced-build` /
`--build-command`) fails for a buildless-capable language, one
buildless retry runs with a loud degradation warning and a
provenance note on the result. Languages with no buildless mode
(Go, Swift, Kotlin) run the extractor's autobuild, disclosed with a
loud untrusted-traced-build banner and a run-metadata record.

The trade-off is accuracy: buildless extraction cannot see
build-generated headers (`config.h`, yacc/protobuf output), so TUs
that include them parse partially and dataflow through those regions
is lost, and macro configurations are inferred rather than recorded
from real compiler invocations. After every buildless creation the
run log carries one line summarising the damage — a WARNING with the
count of unresolved-include extractor diagnostics when any exist, an
INFO notice otherwise — so reduced coverage never silently reads as
full coverage.

**Traced build (opt-in).** `--traced-build` (or an explicit
`--build-command`) restores full-fidelity extraction by executing the
repo's build under the sandbox. This is an explicit operator
assertion of trust in the target — appropriate for first-party code
and well-known upstreams you would build anyway. It is deliberately
independent of `--trust-repo`, which gates the CodeQL pack-config
surface (custom extractors / build hooks declared in
`codeql-pack.yml`): that check is an anomaly alarm — legitimate
projects essentially never carry custom extractors, and the alarm
matters most on repos you otherwise trust, where a poisoned analysis
would be believed. A traced-build run that hits unsafe pack config
therefore still refuses and prints the findings; escalate with
`--trust-repo` only after auditing them. Build detection (Phase 2)
still runs for traced builds and for the non-C/C++ languages whose
extractors need it. For targets you audit repeatedly, the assertion
can be persisted per project — `raptor project trust build` makes
every subsequent `/codeql` and `/agentic` run on that project behave
as if `--traced-build` was passed (per-run `--no-traced-build`
overrides; the `config` marker for `--trust-repo` stays independent).

Databases are cached by a content hash of the tree (git HEAD when
available), validated for integrity, and expire after 7 days.
Multi-language targets build databases in parallel. Pass `--force` to
bypass the cache and recreate from scratch.

### Phase 4 -- Query Execution

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
three attempts and exponential backoff (1s, 2s).

**IRIS LocalFlowSource pass:** After the standard suite, RAPTOR runs
bundled query packs that extend source coverage to CLI arguments,
environment variables, stdin, file reads, and database inputs. IRIS
packs exist for Python, Java, JavaScript, and Go; C++ is excluded
because the upstream stdlib already covers local flow sources. Disable
with `--no-iris-tier1`.

Per-language SARIF files are written to the output directory. IRIS
findings produce a separate `codeql_<lang>_iris.sarif` file.

**Threat models on the standard suite:** The standard-suite pass runs
with `--threat-model=local` by default (CLI ≥ 2.15.3; older CLIs never
see the flag). This enables the environment / commandargs / stdin /
file / database source kinds on stock queries for languages whose
packs support threat models — the same source classes the IRIS packs
model by hand. The flag is a documented no-op for packs without
threat-model support. Override the set per run with
`--threat-models <csv>` (e.g. `local,!environment` — entries are
processed in order, `!` disables) or disable with `--no-threat-models`.
When both the IRIS pass and threat models ran, a per-(language, CWE)
standard-vs-IRIS finding-count comparison is recorded as
`threat_model_overlap` in `codeql_report.json`.

**Learned-models measurement pass:** IRIS taint specs learned for the
target are emitted as a CodeQL models-as-data extension pack and the
suite is re-run with it, recording a baseline-vs-augmented finding
diff -- data for whether learned specs widen real coverage. Disable
with `--no-learned-models`.

### Phase 5 -- Reporting

The agent writes `codeql_report.json` containing language detection
results, database creation status, per-language finding counts, SARIF
file paths, timing, and any errors. A report file always lands on
disk, even when full serialisation fails.


## Autonomous Analysis (`--analyze`)

When `--analyze` is passed, each SARIF finding continues into a
second, LLM-powered phase.

### Reachability Prefilter

Before spending LLM tokens, the analyser consults a source-level
call graph to determine whether the function containing the finding's
sink is reachable from any entry point.

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

The reachability chokepoint enforces policy: only SOUND witnesses
(module-aborts, lexical-dead,
binary-oracle-absent) can authorise hard suppression. Heuristic
verdicts (not-called, no-path-from-entry) are recorded but never
cause suppression. Suppressed findings are logged to
`suppressions.jsonl`. See [binary analysis](binary-analysis.md)
for the binary oracle integration.

Pass `--allow-unreachable` to disable hard suppression entirely (for
CTF targets, vendor snippets, or intentional dead-code audits).

### Dataflow Validation

The validator parses SARIF `codeFlows` to reconstruct the taint path
from source to sink, then identifies potential sanitisers along the
path. Evidence collection is CWE-dispatched: injection-class findings
receive sanitiser evidence; memory-corruption findings receive
source-intel structural evidence.

### SMT Path Feasibility

Requires `z3-solver` (`pip install z3-solver`); degrades gracefully
when absent.

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

1. **Fast FP prefilter** -- a cheap model is asked whether the finding
   is a confident false positive. The framing is deliberately
   asymmetric: only confident-FP verdicts short-circuit; anything else
   falls through to full analysis. A scorecard policy gate decides
   whether to honour the cheap model's verdict based on its historical
   agreement with the full analyser.

2. **Full analysis** -- the finding, source context, dataflow path,
   and any SMT-derived input values are sent to the primary analysis
   model, which returns a structured assessment: true-positive
   determination, exploitability score, severity, reasoning, attack
   scenario, prerequisites, impact, CVSS estimate, and mitigation.

All untrusted content is wrapped in untrusted-content envelopes before
prompt construction.

### Exploit Generation

When a finding is assessed as exploitable, the analyser generates a
proof-of-concept exploit and runs it through an iterative
compile-test-fix loop (sandboxed, network blocked; up to 3 refinement
iterations). A source scan checks for exfiltration patterns before the
exploit is written to disk.

### Visualisation

When `--no-visualizations` is not set, four output formats are
generated per dataflow path:

| Format | Extension | Description |
|--------|-----------|-------------|
| HTML | `.html` | Self-contained interactive visualisation with colour-coded nodes (source, step, sanitiser, sink) |
| Mermaid | `.mmd` | `graph TD` diagram suitable for Markdown rendering |
| ASCII | `.txt` | Box-drawing terminal visualisation |
| DOT | `.dot` | Graphviz format for custom rendering |


## Custom Queries

RAPTOR ships hand-written C++ and Java queries under
`engine/codeql/queries/` (format string, integer truncation, iterator
invalidation, use-after-move; insecure deserialisation, Spring SSRF,
XXE, log injection), complementing the upstream suites with patterns
their standard packs do not cover. Run
`ls engine/codeql/queries/*/` for the current list. They run
automatically after the standard suite for every language that has a
curated pack, writing `codeql_<lang>_curated.sarif` alongside the
suite SARIF. Opt out per run with `--no-curated-queries`. Import
resolution prefers packs already on disk (no network needed); a
failure degrades to a warning without affecting the standard-suite
results.


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
| Swift | yes | yes | |
| Kotlin | yes | yes | Reuses Java suite |
| Rust | yes | yes | |

Language auto-detection covers all 11 languages. Rust is additionally
extractor-probed (`codeql resolve languages`), so CLIs without the
Rust extractor get a clear skip.


## Prerequisites

- **CodeQL CLI** -- must be on `PATH` or specified via `--codeql-cli`.
  Query packs are auto-downloaded on first use.
- **Build toolchain** -- only for traced builds (`--traced-build` /
  `--build-command`) and for the autobuild languages (Go, Swift,
  Kotlin). C/C++, Java, and C# default to buildless extraction, and
  interpreted languages (Python, JavaScript, TypeScript, Ruby) use
  no-build extraction -- neither needs a compiler.
- **z3-solver** (optional) -- `pip install z3-solver` to enable SMT
  path feasibility checks. Without it, the SMT stage is silently
  skipped and all findings proceed to full LLM analysis.
- **LLM API key** (for `--analyze`) -- `ANTHROPIC_API_KEY` or
  `OPENAI_API_KEY` must be set. Not needed for `--scan-only`.

All subprocess invocations run inside the RAPTOR [sandbox](sandbox.md)
by default. Pass `--no-sandbox` to disable.

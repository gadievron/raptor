# Exploitability Validation

The `/validate` command runs a multi-stage pipeline that determines whether
vulnerability findings are real, reachable, and exploitable.  It sits between
scanning (which discovers candidates) and exploit development (which builds
working payloads), filtering out hallucinated findings, dead code, test
artefacts, and vulnerabilities whose exploitation is blocked by system
mitigations.

The pipeline consists of eight stages executed in strict sequence: **0 -- A --
B -- C -- D -- E -- F -- 1**.  Numbered stages (0, E, 1) are mostly
mechanical -- Python computation with optional light enrichment.  Lettered
stages (A--F) are LLM reasoning, where the analyst performs the substantive
assessment work.

## Usage

```bash
/validate <target_path> [flags]
```

| Flag | Purpose |
|------|---------|
| `--vuln-type <type>` | Restrict to a single vulnerability class (e.g. `command_injection`, `format_string`) |
| `--findings <file>` | Validate pre-existing findings from a SARIF or JSON file instead of scanning first |
| `--binary <path>` | Provide a compiled binary for Stage E feasibility analysis |
| `--skip-feasibility` | Skip Stage E entirely (useful when no binary is available) |
| `--out <dir>` | Write output to a specific directory instead of the default |

The canonical entry point is `python3 raptor.py validate` or the `/validate`
slash command.

### Typical workflows

Full pipeline after a scan:

```bash
/scan ./webapp
/validate ./webapp
```

Validate with a binary for feasibility analysis:

```bash
/validate ./webapp --binary ./build/webapp
```

Validate existing scanner output:

```bash
/validate ./webapp --findings scanner-results.json
```

Chain with `/understand` for richer context:

```bash
/understand ./webapp --map
/validate ./webapp
```

The `/understand` output is imported automatically by Stage 0 -- no manual
`--out` alignment is needed.  See [Integration](#integration) below.

## Pipeline Stages

### Stage 0 -- Inventory (Mechanical)

Builds `checklist.json` via `core.inventory`.  This is the ground-truth file
and function inventory that every subsequent stage checks against.  It:

- Enumerates all source files (12+ languages supported).
- Excludes test, mock, vendor, generated, and build output files (with reasons
  recorded).
- Extracts every function and method per file (AST for Python, regex for
  others).
- Computes a SHA-256 checksum per file.
- Carries forward `checked_by` coverage from prior runs when a file has not
  changed.

Stage 0 also imports `/understand` output when available.  The bridge
(`core/orchestration/understand_bridge.py`) searches three locations in order:
(1) co-located files in the same output directory, (2) sibling runs within the
same [project](commands.md#project), (3) global `out/` directories matched by
target path and SHA-256 freshness.  When found, it pre-populates
`attack-surface.json` with entry points, sinks, and trust boundaries from
`context-map.json`, and imports flow traces as attack paths with
`source: "understand:trace"`.

**Output:** `checklist.json`, plus any imported `/understand` artefacts.

### Stage A -- One-Shot Assessment (LLM)

A rapid, breadth-first exploitability sweep.  The prep step
(`raptor-validation-helper A`) discovers binaries in the target tree, compiles
standalone C files with mitigations disabled into `$OUTPUT_DIR/build/`, and
prints available binaries for PoC testing.

The LLM then:

1. Walks every function in `checklist.json`, prioritising `priority_targets`
   (unchecked flows flagged by `/understand --map`) and triaging by source type
   -- direct attacker input to dangerous sinks first, then persistent-storage
   flows, then internal computed values.
2. For each promising candidate, attempts a harmless proof-of-concept.  PoCs
   are compiled and executed inside the [sandbox](sandbox.md)

3. Classifies each finding as `poc_success`, `not_disproven`, or `disproven`.
   Disproved findings require a structured `disproved_because` record
   explaining what was investigated, why it is definitively not exploitable,
   and what would trigger reconsideration.

Stage A also applies sanitisation-gate detection (parameterisation, escaping,
whitelist validation, length checks, type-narrowing casts) and cross-class
escalation for persistent-storage sources (e.g. a database row flowing to an
HTML render is flagged as a stored-XSS candidate regardless of how safe the
sink looks in isolation).

**Output:** `stage-a.json` (merged into `findings.json` by the next prep
script).

### Stage B -- Hypothesis-Driven Analysis (LLM)

Systematic, adversarial verification of every finding that was not disproved in
Stage A.  The analyst maintains five working documents throughout this stage:

| Document | Purpose |
|----------|---------|
| `attack-tree.json` | Knowledge graph; source of truth.  Node statuses: `unexplored`, `exploring`, `confirmed`, `disproven`, `uncertain`. |
| `hypotheses.json` | Active exploitation hypotheses with testable, value-level predictions.  Statuses: `testing`, `confirmed`, `disproven`. |
| `disproven.json` | Failed hypotheses -- what was tried, why it failed, what was learned. |
| `attack-paths.json` | Every attempted attack path with step-by-step results and PROXIMITY scores (0--10). |
| `attack-surface.json` | Sources, sinks, and trust boundaries.  Pre-populated by the `/understand` bridge when available. |

**PROXIMITY** is a 0--10 scale tracking how close each attack path has come to
successful exploitation:

| Score | Meaning |
|-------|---------|
| 0--1 | Theoretical only; no source-to-sink flow confirmed. |
| 2--3 | Flow confirmed but blocked by mitigations or preconditions. |
| 4--5 | Reachable with attacker input; partial bypass achieved. |
| 6--7 | Exploit primitive confirmed (write/read/control-flow); payload constraints remain. |
| 8--9 | Working PoC with minor reliability issues. |
| 10 | Reliable, repeatable exploitation demonstrated. |

Same bug class in different locations must score the same unless there is a
specific difference in reachability or constraints.

For memory-corruption and arithmetic CWEs (CWE-119/120/121/122/125/190/191/
193/476/787), Stage B invokes SMT pre-flight via Z3 before constructing attack
paths.  Tools include `raptor-smt-validate-path` (general-purpose path
condition checking), `raptor-smt-check-overflow` (CWE-190), `raptor-smt-check-oob`
(CWE-125/787), and `raptor-smt-check-null-deref` (CWE-476).  An `unsat`
verdict caps PROXIMITY at 1 and moves the hypothesis to `disproven.json`; a
`sat` verdict with a concrete witness model floors PROXIMITY at 6 and provides
PoC input values directly.

Stage B also annotates attack paths with [Frida](frida.md) runtime evidence
when available.  If a function was observed executing at runtime, reachability
is empirically confirmed and PROXIMITY is floored at 6.

**Output:** `stage-b.json`, `attack-tree.json`, `hypotheses.json`,
`disproven.json`, `attack-paths.json`, `attack-surface.json`.

### Stage C -- Sanity Check (LLM)

A mechanical fact-check that catches hallucinated code.  Stage C does **not**
change finding statuses -- it only answers "did the LLM describe the code
accurately?"

For each finding, the analyst:

1. Reads the actual file and verifies the code matches **verbatim**
   (character-for-character, not paraphrased).
2. Confirms line numbers are accurate.
3. Traces the source-to-sink data flow manually to verify it exists.
4. Checks that the function is actually called somewhere (not dead code).

The prep script (`raptor-validation-helper C`) mechanically pre-checks each
finding against the checklist inventory, flagging mismatches.  For C/C++
targets, it also runs a Coccinelle structural pre-check
(`function_inventory.cocci`) to verify that named functions actually exist as
definitions in the source tree and have callers.  These Coccinelle facts are
advisory -- they flag cases worth investigating but do not decide finding
status.

Findings where `runtime_evidence.function_observed: true` appears in
`attack-paths.json` get an automatic reachability pass -- [Frida](frida.md)
confirmed the function executes at runtime.

A finding passes Stage C when: the file exists, the code is verbatim, the
flow is real, and the code is reachable.  A finding with real, reachable,
accurately-described code passes even if Stage B proved it unexploitable --
exploitability rulings belong to Stage D.

**Output:** `stage-c.json` (with `sanity_check` and `stage_c_summary` per
finding).

### Stage D -- Ruling (LLM)

The exploitability ruling.  Stage D synthesises evidence from all prior stages
and applies a series of disqualifier checks:

- **D-0: Evidence Synthesis** -- Cross-references Stage A confidence, Stage B
  hypothesis status, Stage C code verification, and any [Frida](frida.md)
  runtime evidence.  A disproved Stage B hypothesis rules out the finding
  regardless of whether Stage C confirmed the code exists.
- **D-1: Code Context** -- Filters findings in test files, mock files, example
  code, documentation code blocks, and commented-out code.  Uses a
  reachability-aware `likely_test_harness` flag (path matching plus
  production-caller analysis, not just path patterns).
- **D-1.5: Privilege Tautology** -- Filters findings where the required
  exploit privileges already imply the outcome (e.g. root reading a file).
  Auth bypass findings are exempt.
- **D-2: Preconditions** -- Filters findings that require chaining with
  another vulnerability, a compromised dependency, physical access, or social
  engineering.  A stored-flow exception preserves legitimate stored-XSS and
  stored-injection findings where the data-plant step uses ordinary
  functionality (posting a comment, setting a profile field).
- **D-3: Hedging Language** -- Detects unverified hedging ("could potentially",
  "in theory", "if misconfigured").  Hedged claims that cannot be verified are
  ruled out.
- **D-4: No Security Impact** -- Filters real bugs with no exploitable
  security impact (pure memory leaks without corruption, performance issues,
  cosmetic errors).

For each surviving finding, Stage D assigns a CVSS v3.1 vector.  The CVSS
vector scores the vulnerability's **inherent** impact, not the binary's
mitigations -- a heap overflow that could achieve code execution gets
C:H/I:H/A:H even if the binary has Full RELRO, PIE, and NX.  Binary
mitigations are captured separately by Stage E.

**Output:** `stage-d.json` with ruling, CVSS vector, and final status per
finding (`exploitable`, `confirmed`, or `ruled_out`).

### Stage E -- Binary Feasibility (Mechanical + LLM)

Applies **only** to memory corruption vulnerability types.  The canonical set
of 13 applicable types lives in `core/schema_constants.py` as
`MEMORY_CORRUPTION_TYPES` and includes buffer overflow, format string,
use-after-free, heap overflow, double free, integer overflow, out-of-bounds
read/write, null dereference, and type confusion.  Non-memory-corruption
findings receive `feasibility.status: "not_applicable"` and skip this stage.

The prep script (`raptor-validation-helper E`) scans the target for executables
matching source files, sets `feasibility.binary_path` on each finding, and
groups them by binary.  The feasibility analysis then runs via:

```bash
libexec/raptor-run-feasibility <binary_path> "$OUTPUT_DIR/findings.json" "$OUTPUT_DIR" --target "$TARGET_PATH"
```

This invokes the `exploit_feasibility` package (`packages/exploit_feasibility/`)
to run approximately 30 checks per binary:

- **Binary protections:** PIE, NX, stack canary, RELRO (partial/full).
- **Glibc mitigations:** removed hooks (glibc 2.34+), `%n` blocking (empirical
  two-probe test -- not a version heuristic), safe linking, tcache key double-free
  detection, alignment checks.
- **Input handler constraints:** null bytes, bad characters, maximum writable
  length.
- **ROP gadget availability:** filtered by bad bytes; counts usable gadgets,
  not total.
- **One-gadget constraints:** with optional SMT verification (Z3) when
  `z3-solver` is installed.

The analysis produces a verdict along with `chain_breaks` (techniques that are
architecturally blocked) and `what_would_help` (suggestions for making
exploitation viable).  Chain breaks from source-level analysis (Stage B) and
binary analysis (Stage E) are merged with `[source]` / `[binary]` prefixes to
prevent ambiguity.

When `--target` is passed, the script additionally runs empirical mitigation
analysis: it rebuilds the source under four mitigation profiles (permissive,
default-debian, hardened, asan-only), replays any available witness against
each, and attaches an `empirical_mitigation_map` to the finding.

**Verdict mapping to final status:**

| Source Validation | Feasibility Verdict | Final Status |
|-------------------|---------------------|--------------|
| confirmed | likely_exploitable | `exploitable` |
| confirmed | difficult | `confirmed_constrained` |
| confirmed | unlikely | `confirmed_blocked` |
| confirmed | not_applicable | `confirmed` |
| confirmed | binary_not_found | `confirmed_unverified` |

When a binary cannot be located, the finding is marked `confirmed_unverified`
with guidance on how to provide one (`/validate --binary /path/to/binary`).

**Output:** `stage-e.json`, updated `findings.json` with feasibility data.

### Stage F -- Self-Review (LLM)

A critical self-review pass where the analyst asks "what did I get wrong?"
The prep script computes preliminary CVSS scores and runs consistency checks
(verdict mapping, proximity score uniformity).

The analyst then:

1. Verifies that every precondition in a ruling cites specific evidence (line
   numbers, grep results, tool output).
2. Checks that value-level traces exist for each finding sharing the same
   syntactic pattern.
3. Validates that every causal claim in `disproven.json`, `hypotheses.json`,
   and `findings.json` cites a concrete verification method.
4. Checks CVSS vector accuracy -- AV reflects how the attacker reaches the
   code (not the machine), C/I/A reflect inherent impact (not mitigations).
5. Cross-checks SMT verdicts against rulings -- an `smt:refuted` finding must
   not be `exploitable`; an `smt:witness` finding ruled `false_positive` is a
   contradiction.
6. Cross-checks [Frida](frida.md) runtime evidence -- a finding ruled
   `false_positive` whose attack path has observed runtime evidence is a
   contradiction.

Corrections are written to `stage-f.json`.  Stage F does **not** generate the
report -- that is Stage 1's job.

**Output:** `stage-f.json` (with corrections and `stage_f_review` summary).

### Stage 1 -- Report Generation (Mechanical)

The terminal stage.  It:

1. Merges `stage-f.json` into `findings.json`.
2. Recomputes CVSS scores from the final vectors (after any Stage F
   corrections) using `packages.cvss.compute_base_score`.
3. Validates all output against JSON schemas.
4. Generates `validation-report.md` (human-readable summary).
5. Generates `diagrams.md` (Mermaid visual maps -- see
   [commands](commands.md#diagram)).
6. Writes coverage records for the run.
7. Completes the run lifecycle.

Stage 1 never changes verdicts.  It only renders the final data.

**Output:** `validation-report.md`, `diagrams.md`, `findings.json` (final),
`summary.txt`, coverage records.

## Integration

### /understand bridge

The `/understand` command produces `context-map.json` and `flow-trace-*.json`
files.  When `/validate` runs on the same target, Stage 0 automatically
imports this output via `core/orchestration/understand_bridge.py`.  The bridge:

- Pre-populates `attack-surface.json` with entry points, sinks, and trust
  boundaries.
- Imports flow traces as attack paths with `status: "uncertain"` and
  `source: "understand:trace"`.  Stage B reviews imported traces rather than
  discovering from scratch.
- Marks imported entry points and sinks as high-priority in the checklist.

No `--out` alignment is needed -- the bridge searches co-located files,
[project](commands.md#project) siblings, and global `out/` directories
automatically.

### Frida bridge

When [Frida](frida.md) runtime evidence is collected during Stage B, it
annotates attack-path steps with `runtime_evidence.function_observed: true` and
observed call counts.  This evidence:

- Provides empirical proof of code reachability (Stage C).
- Floors PROXIMITY at 6 (Stage B).
- Prevents reachability-based dismissals in Stage D.
- Corroborates feasibility claims in Stage E.
- Is cross-checked against rulings in Stage F.

### SMT tools

Stage B and Stage E both use Z3-backed SMT tools for path-condition
verification.  The tools share a common architecture:
`core/smt_solver/` provides the shared primitives (bitvector factories,
timed solver construction, witness formatting), and domain-specific encodings
live in the individual scripts and packages.

| Tool | Pattern | CWEs |
|------|---------|------|
| `raptor-smt-validate-path` | General-purpose path conditions | Any (free-form predicates) |
| `raptor-smt-check-overflow` | Integer overflow / wraparound | CWE-190, CWE-191 |
| `raptor-smt-check-oob` | Array out-of-bounds access | CWE-125, CWE-787 |
| `raptor-smt-check-null-deref` | Null pointer dereference | CWE-476 |
| `raptor-smt-check-overflow-to-oob` | Chained overflow then OOB | CWE-680 |

Z3 is a soft dependency (`pip install z3-solver`).  When absent, all tools
return `feasible: null` and the pipeline falls back to LLM reasoning alone.

See [binary analysis](binary-analysis.md) for further detail on the exploit
feasibility package and its target profiles.

### Binary oracle

The binary oracle (used by `/agentic` and `/codeql` for dead-code
suppression) is **not** part of `/validate`.  Stage E uses the
`exploit_feasibility` package for binary-level constraint analysis, which is a
separate system.  See [binary analysis](binary-analysis.md) for the binary
oracle's reachability filtering.

### Exploit feasibility package

Stage E delegates to `packages/exploit_feasibility/` for the actual binary
analysis.  The package supports multiple target profiles:

| Profile | Use case |
|---------|----------|
| `LOCAL_BINARY` | Local binaries, CTF challenges (default) |
| `REMOTE_BINARY` | Remote services with known glibc version |
| `WEB_APPLICATION` | Web vulnerabilities (skips memory mitigations entirely) |
| `KERNEL` | Kernel exploitation (SMEP, SMAP, KASLR, KPTI) |

The two-axis feasibility model separates **triggerability** (`verdict`) from
**consequence** (`impact`).  A null-pointer dereference can be `exploitable`
(the bug fires) with impact `dos` (it only crashes).

### Context persistence

The exploit context file from `save_exploit_context()` survives conversation
compaction.  Reference it during [exploit development](commands.md#exploit):

```python
from packages.exploit_feasibility import load_exploit_context
ctx = load_exploit_context(finding.feasibility.context_file)
```

## Output

A completed `/validate` run produces the following directory structure:

```
out/exploitability-validation-<timestamp>/
  checklist.json            -- Ground truth inventory (Stage 0)
  findings.json             -- Final validated findings with all stage data
  attack-tree.json          -- Knowledge graph (Stage B)
  hypotheses.json           -- Tested hypotheses (Stage B)
  disproven.json            -- Failed hypotheses (Stage B)
  attack-paths.json         -- Attack paths with PROXIMITY (Stage B)
  attack-surface.json       -- Sources, sinks, trust boundaries (Stage B)
  validation-report.md      -- Human-readable summary (Stage 1)
  diagrams.md               -- Mermaid visual maps (Stage 1)
  summary.txt               -- Tabular summary (Stage 1)
  build/                    -- Compiled PoCs (Stage A)
  coverage-record.json      -- Coverage tracking data
```

### Validation gates

The pipeline enforces eight MUST-GATEs throughout the LLM stages:

| Gate | Rule |
|------|------|
| GATE-1 | Assume exploitable until proven otherwise |
| GATE-2 | Strict sequence; additional ideas presented separately |
| GATE-3 | Track checklist compliance |
| GATE-4 | Verify all hedged claims ("if", "maybe", "uncertain") |
| GATE-5 | Check ALL code; no sampling |
| GATE-6 | Show proof for every finding |
| GATE-7 | Verify vuln_type / severity / status consistency |
| GATE-8 | PoC requires observable evidence |

### Status values

Status values in JSON are always `snake_case` (`exploitable`, `confirmed`,
`ruled_out`, `disproven`).  Human-readable output (reports, terminal tables)
uses Title Case (`Exploitable`, `Confirmed`, `Ruled Out`).  The pipeline never
uses ALL_CAPS.

### Final status reference

| Final Status | Meaning |
|--------------|---------|
| `exploitable` | Confirmed exploitable; standard techniques work |
| `likely_exploitable` | Viable paths exist with some constraints |
| `confirmed_constrained` | Possible but requires advanced techniques |
| `confirmed_blocked` | No viable path given current mitigations |
| `confirmed_unverified` | Analysis incomplete (no binary, error, unknown) |
| `confirmed` | Non-memory-corruption finding (Stage E not applicable) |
| `ruled_out` | Failed sanity, ruling, or disqualifier checks |
| `disproven` | Pre-ruled by Stage B evidence (e.g. SMT refutation, dead code) |

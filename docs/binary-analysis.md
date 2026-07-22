# Binary Analysis

RAPTOR provides three distinct subsystems for compiled artefacts, each
solving a different problem: black-box investigation of unknown binaries,
reachability filtering to suppress dead-code findings in source scans,
and exploit feasibility profiling to determine what is actually
exploitable before wasting time on impossible approaches.

These subsystems are independent but complementary. `/binary` produces
evidence from the artefact itself; the binary oracle joins that evidence
with source-level findings; exploit feasibility assesses what the
compiled mitigations actually permit.

See also: [commands](python-cli.md), [validation](validation.md),
[Frida](frida.md), [sandbox](sandbox.md).

---

## /binary -- Black-Box Investigation

The `/binary` command is the operator-facing surface for evidence-backed
binary analysis via radare2. It takes a compiled artefact (ELF, Mach-O,
PE) and builds a structured evidence layer without requiring source code.

### Subcommands

| Command | Purpose |
|---------|---------|
| `investigate <binary>` | Map the binary, rank leads, write an evidence-separated investigation report. Default when bare `/binary <path>` is used. |
| `map <binary>` | Build the binary manifest, context map, decompilations, graph and validation handoff. The lower-level mechanical substrate. |
| `runtime <binary>` | Run Frida with `binary-flow-trace` to collect input-callsite evidence. |
| `trace-parser <run-dir>` | Run parser-focused Frida tracing and fold new runtime evidence back into an existing binary run. |
| `harness <run-dir>` | Turn a recovered ingress candidate into a harness plan. Emits source only when the ABI contract is explicit. |
| `fuzz <binary>` | Hand off to the `/fuzz` orchestrator for crash witnesses. |
| `graph <run-dir>` | Query the persistent binary graph (SQLite). |
| `report <run-dir>` | Regenerate the human-readable report from an existing run. |
| `handoff <run-dir>` | Regenerate the validation handoff record. |
| `diagram <run-dir>` | Render Mermaid diagrams from a binary run's JSON outputs. |

### Usage and Flags

```bash
# Default: investigate (static only)
/binary /path/to/app

# Explicit subcommands
/binary investigate /path/to/app
/binary map /path/to/app --out out/binary-app

# Allow dynamic phases
/binary investigate /path/to/app --runtime
/binary investigate /path/to/app --fuzz
/binary investigate /path/to/app --active    # both runtime + fuzzing

# Decompilation control
/binary map /path/to/app --max-decompile 50
/binary map /path/to/app --decompile-all

# Quick intake-only mode
/binary map /path/to/app --quick

# Universal Mach-O: pin architecture
/binary map /path/to/App.app/Contents/MacOS/App --slice-arch x86_64

# Compare two builds
/binary map /path/to/new --compare /path/to/old --out out/binary-app

# Add runtime evidence (two approaches)
/binary trace-parser out/understand_app_.../ --duration 20
/binary runtime /path/to/app --duration 20

# Add fuzz witnesses
/binary fuzz /path/to/app --duration 60
/binary map /path/to/app --out out/binary-app --fuzz-dir out/fuzz-...

# SMT check against explicit conditions
/binary map /path/to/app --constraint-file conditions.json

# Graph queries
/binary graph out/binary-app --edges --json
/binary graph out/binary-app --edges --kind MAY_REACH --json
/binary graph out/binary-app --evidence --tier replayed_crash --json

# Harness generation
/binary harness out/understand_app_.../ --ingress BINGRESS-07b2007ea85a
/binary harness out/understand_codec_.../ --ingress BINGRESS-... --abi buffer-size
```

Without `--runtime`, `--fuzz` or `--active`, RAPTOR never spawns,
attaches to or fuzzes the target.

### Output Artefacts

`/binary map` produces:

| File | Purpose |
|------|---------|
| `binary-manifest.json` | Byte-bound artefact manifest |
| `binary-evidence.json` | Evidence ledger with provenance tiers |
| `context-map.json` | Context-map-compatible bridge (shared with `/understand`) |
| `binary-context-map.json` | Binary-specific alias of the context map |
| `binary-checklist.json` | Address-stable checklist: functions, entry points, imports, witnesses |
| `binary-decompilations.json` | Persisted pseudocode for highest-value recovered functions |
| `binary-validation-handoff.json` | What evidence is present and what is still missing per candidate |
| `graph/binary-graph.sqlite` | Queryable graph of functions, xrefs, evidence edges |
| `binary-analysis-report.md` | Short human-readable report |
| `binary-diff.json` | Build comparison (when `--compare` is used) |

`/binary investigate` adds:

| File | Purpose |
|------|---------|
| `binary-investigation.json` | Evidence-separated investigation record (facts, inferences, hypotheses kept distinct) |
| `binary-investigation-report.md` | One-screen operator report with ranked surfaces and priority queue of next evidence actions |

### Radare2 Integration

radare2 provides the core mechanical substrate: function recovery,
cross-references, decompilation hints, and direct call-graph edges. The
binary analyser uses radare2 for:

- Function boundary recovery and address mapping
- Import table and export resolution
- Cross-reference (xref) enumeration
- Pseudocode generation for selected functions
- COFF/PE/ELF/Mach-O header parsing
- Objective-C and Swift class metadata extraction

For Mach-O universal binaries, radare2 selects a slice automatically;
use `--slice-arch` to pin a specific architecture.

r2 runs under `core.sandbox.run` (namespace + Landlock + network deny);
binutils tools (readelf, nm, objdump, c++filt) run under
`core.sandbox.run_trusted`. See [sandbox](sandbox.md) for the
isolation model.

### Evidence Tiers

Every record in the evidence ledger declares its provenance:

| Tier | Source |
|------|--------|
| `observed_runtime` | Frida or a fuzzer observed it during execution |
| `replayed_crash` | A crash was replayed against the bound binary |
| `smt_proved` | Z3 checked explicit path conditions and returned a mechanical result |
| `xref_backed` | radare2 recovered a concrete call/xref relationship |
| `header_backed` | File header, magic, imports or archive members prove it |
| `decompiler_inferred` | Pseudocode suggests it, but it is not proof |
| `heuristic` | Useful lead only, such as a name-based entry point |

Import-backed input channels are candidates until runtime confirms them.
Direct xrefs to security-relevant imports are call-graph facts, not
taint facts. Transitive reachability is labelled `may_reach`. No trust
boundary or unchecked flow is emitted without actual evidence.

### Format Support

| Artefact | Ingress RAPTOR looks for | Fuzz follow-on |
|----------|--------------------------|----------------|
| Mach-O app | URL/file handlers, XPC listeners, WebView callbacks, bundle metadata | Trace the handler, then extract a narrow harness |
| ELF executable | Process entry, imported input channels, exported APIs | Campaign only when an input contract exists |
| ELF kernel module | `unlocked_ioctl`/`compat_ioctl` dispatchers | IOCTL harness or snapshot fuzzing |
| PE EXE | Process entry, imported input channels | Runtime first unless a harness is already present |
| PE DLL | Exported APIs bound back to recovered functions | Typed export harness |
| PE driver | `EvtIoDeviceControl`/`DispatchDeviceControl` dispatchers | IOCTL harness or snapshot fuzzing |

Architecture is read from the COFF/ELF/Mach-O header, so a 32-bit DLL,
64-bit EXE and ARM64 driver are not flattened into the same bucket.
Managed artefacts (JAR/APK, .NET, Go, Rust) are recorded as runtime
signals for future adapters.

### Parser Boundary Extraction

For GUI apps, XPC listeners, URL handlers and protocol callbacks, the
useful fuzz target is rarely the framework callback itself. RAPTOR
retains radare2's direct call graph and looks for bounded paths from
recovered external ingress to internal functions that directly call
known parser surfaces.

This produces `parser_boundary_candidates` with: the ingress candidate
that starts the path, the internal boundary function worth reviewing,
the parser surface it calls, the bounded call-graph path and depth, and
the evidence tier (`xref_backed` or `observed_runtime`).

When Swift/ObjC dynamic dispatch hides the static edge, the
[Frida](frida.md) trace retains target-module backtrace frames for
parser calls. If the backtrace contains both the recovered ingress and
the parser caller, RAPTOR can recover an `observed_runtime` parser
boundary even when the static call graph cannot join the two.

### Harness Generation

`/binary harness` turns a recovered ingress into a harness plan. By
default it selects the highest-ranked external ingress; use `--ingress`
to pin one.

RAPTOR only emits source code when the boundary is explicit enough:

- `--abi buffer-size` for exported APIs callable as `(const uint8_t *, size_t)`.
- `--abi cstring` for NUL-terminated string inputs.
- `--device` and `--ioctl-code` for driver dispatch boundaries.

For app callbacks, XPC listeners, URL handlers and WebView callbacks,
the first harness pass normally stops at `needs_runtime_trace`. Once
RAPTOR recovers a bounded ingress-to-parser path it moves to
`parser_boundary_candidate` and shows the narrowed function in the
harness report. The framework callback is real, but the useful fuzz
boundary is usually the parser or protocol helper behind it, and RAPTOR
still needs a callable contract before it can emit source honestly.

### Pipeline Integration

`/binary` output feeds into:

- [Exploitability validation](validation.md):
  `binary-checklist.json` and `binary-validation-handoff.json` provide
  candidates and evidence gaps for downstream validation.
- [Frida](frida.md): `trace-parser` uses the `binary-flow-trace` template
  to collect runtime evidence tied to the mapped binary.

---

## Binary Oracle -- Reachability Filtering

The binary oracle joins source inventory with debug binaries via DWARF
and nm to suppress dead-code findings before they reach LLM analysis.
Used by `/agentic` and `/codeql` to filter findings for functions the
compiler removed.

Implementation: `core/analysis/binary_oracle.py` (classifier),
`core/analysis/binary_oracle_autodetect.py` (auto-detection),
`core/analysis/binary_oracle_precision.py` (measurement harness).

### How It Works

The classifier examines each function from the source inventory against
the debug binary's symbol table and DWARF information, producing one of
four verdicts:

| Verdict | Meaning |
|---------|---------|
| `symbol_present` | Function survives compilation with a matching symbol |
| `inlined` | Function was inlined by the compiler (present in DWARF but no discrete symbol) |
| `folded` | Function was merged with another via identical code folding (ICF) |
| `absent` | Compiler or linker removed the function entirely |

The `absent` verdict drives suppression: findings on absent functions
are hard-suppressed before LLM analysis, saving API cost and avoiding
false positives on dead code.

The verdict flows through the existing reachability chokepoint:
`/codeql` and `/agentic` skip LLM analysis on absent-function findings
(pre-LLM hard-suppress); `/validate`'s demoter clamps attack-path
proximity; `/understand --map` annotates entry points and sinks with
the per-binary verdict and tier.

### Auto-Detection

By default (no flags), `/agentic` and `/codeql` auto-detect debug
binaries under common build directories:

`build/`, `target/release/`, `cmake-build-*/`, `bazel-bin/`,
`builddir/`, `Debug/`, `Release/`, `out/`, `dist/`, `bin/`,
Rust `target/<triple>/release` cross-target globs, and the source root.

Auto-detection filters to **locally-built binaries only**: files
untracked by git. The result cap is 8 binaries.

### Provenance Gate

Git-tracked binaries (committed to the source tree) are dropped from
auto-detection. This defends against:

- **Attacker-planted binaries**: a malicious binary committed to the
  repo could steer `absent` verdicts toward suppressing real findings.
- **Stale committed pre-builds**: old binaries that no longer match the
  source would produce incorrect verdicts.

The operator can bypass this via explicit `--binary <path>` when they
have verified provenance.

### Source-Coverage Floor

A source-coverage floor (at least 5% of project source names matched,
minimum 3 matches, kicking in at 8 or more project names) rejects
binaries unrelated to the source. A planted ELF for a different project
is dropped with a warning rather than driving every source function to
`absent`.

### Precision

Precision has been validated across multiple corpora:

- **1952/1952 verdicts correct** across 6 iteratively-tuned corpora
  (consistency).
- **187/187 correct on the held-out zstd v1.5.6 corpus** with no
  classifier tuning (generalisation). Rule-of-three 95% upper bound
  on miss rate: 1.6% on first-contact-with-unseen-data.

The held-out corpus is non-vacuous: 473/1431 functions were exercised by
the workload, and zero `absent` verdicts were issued on actually-live
functions. Conditional on full-DWARF evidence -- a stripped binary
downgrades to `tier="symbol_only"` and the chokepoint refuses to
suppress.

### CLI Flags

| Flag | Purpose |
|------|---------|
| (default, no flags) | Auto-detect locally-built binaries; soft hint when nothing found. |
| `--binary <path>` | Explicit debug binary. Repeatable for hybrid targets. Bypasses the git-tracked filter (operator asserts trust). Suppresses default auto-detect. |
| `--binary-auto` | Same auto-detect + git-filter logic as default, with louder "nothing found" message. Honours `--target-kind`. Warns at result cap (8). |
| `--binary-edges` | Extract direct call edges and vtable resolution via r2 (single-invocation script-file mode; cached per build-id with cross-target collision check). Required for the `binary_call_edge` REACHABLE promote witness. Slow (~10-30s per binary, then cached). |
| `--no-binary-oracle` | Disable binary-oracle filtering entirely. Use for library-only targets, runs where every finding should be unfiltered, or build-mismatch scenarios. Overrides `--binary`/`--binary-auto` with a warning if combined. |

For `--target-kind=hybrid` deployments (library + application both
shipped), declare multiple binaries -- a function is `absent` only when
every declared binary lacks it. Tier-weighted combine: when full-DWARF
and symbol-only disagree, full-DWARF wins (`alive-in-any` rule only
applies same-tier).

### Project Persistence

Per-project binary configuration is managed with `/project binary`:

```bash
/project binary add /path/to/debug/binary
/project binary list
/project binary remove /path/to/debug/binary
/project binary clear
```

Persisted binaries are auto-loaded by every subsequent `/agentic`,
`/codeql` and `/validate` run on the project. Paths are
`is_file()`-validated at add time.

### Audit Trail

`suppressions.jsonl` is written to the run's output directory whenever
the chokepoint hard-suppresses a finding. Each JSON record contains:

```json
{
  "finding_id": "...",
  "rule_id": "...",
  "file_path": "...",
  "line": 42,
  "function": "process_input",
  "verdict": "absent",
  "reason": "..."
}
```

Both `/agentic` and `/codeql` write to the same file shape. Query with
`jq -c . suppressions.jsonl`.

The classifier's per-finding analysis record also carries
`analysis.reachability_suppression` and
`analysis.reachability_verdict` for per-finding inspection.

### Verification

Two verification tools are provided:

- `libexec/raptor-binary-oracle-e2e` -- end-to-end audit: builds a real
  C target and walks 15 consumer surfaces (54 assertions). No LLM calls.
  Run via `bin/raptor` or `CLAUDECODE=1 libexec/...`.
- `libexec/raptor-binary-oracle-precision --corpus <name>` -- re-measure
  absent-precision on any corpus driver (synthetic, zlib, libsodium,
  snappy, leveldb, regex-rust, zstd_holdout). Report includes per-corpus
  cross-tab, aggregate with rule-of-three upper bound, n-concentration
  dominator detection, and toolchain block for reproducibility.

---

## Exploit Feasibility

The exploit feasibility subsystem analyses a compiled binary's
mitigations, ROP gadget quality, one-gadget constraints and glibc
version to determine what exploitation techniques are architecturally
possible. It answers "can this bug actually be weaponised?" before any
time is spent on technique selection.

Implementation: `packages/exploit_feasibility/`.
Entry point: `libexec/raptor-run-feasibility`.

### Mitigation Profiling

The analyser runs approximately 30 checks in a few seconds, covering:

- **Binary protections**: RELRO (partial/full), stack canary, NX, PIE,
  ASLR.
- **glibc version**: Detected empirically, not just from the binary.
  Determines which techniques (hooks, safe-linking, tcache keys) are
  available.
- **ROP gadget quality**: Total gadgets filtered by bad-byte constraints
  to count *usable* gadgets.
- **One-gadget constraints**: Extracted with constraint analysis;
  optionally validated via Z3/SMT.
- **Heap mitigations**: Safe-linking, alignment checks, double-free
  detection (glibc 2.32+).
- **Input handler constraints**: Bad-byte analysis for strcpy, gets, etc.
  determines which address ranges are writable.

The output is structured into three categories:

| Field | Purpose |
|-------|---------|
| `exploitation_paths` | Per-vulnerability `{technique, target}` pairs that might work |
| `chain_breaks` | Techniques that are architecturally impossible (do not attempt) |
| `what_would_help` | Environmental changes or info leaks that could enable exploitation |

### Verdicts

| Verdict | Meaning | Action |
|---------|---------|--------|
| Likely exploitable | Good primitives, clear path | Proceed with suggested techniques |
| Difficult | Primitives exist but hard to chain | Be honest about challenges, try alternatives |
| Unlikely | No known viable path | Suggest environment changes or move on |

### Target Profiles

Different exploitation contexts use different analysis strategies:

| Profile | Use case | What changes |
|---------|----------|--------------|
| `LOCAL_BINARY` | Local privilege escalation, CTF | Full local detection (default) |
| `REMOTE_BINARY` | Network services, remote CTF | Uses provided glibc, skips empirical tests |
| `WEB_APPLICATION` | SQLi, XSS, SSRF | Skips memory mitigations entirely |
| `KERNEL` | Kernel exploits, LPE | Checks SMEP, SMAP, KASLR, KPTI |

Web vulnerability types (`sql_injection`, `xss`, `ssrf`,
`path_traversal`, `command_injection`, `xxe`, `ssti`, `idor`, `csrf`,
`open_redirect`, `deserialization`) are auto-detected and routed to the
web profile. Memory corruption types use `LOCAL_BINARY` by default.

### Empirical vs Theoretical

The package emphasises empirical verification over static assumptions:

| Check | Theoretical | Empirical |
|-------|-------------|-----------|
| %n works? | Check glibc version | Two-probe test: baseline `-U_FORTIFY_SOURCE` + FORTIFY-with-writable-format; cross-checked against ELF's `__printf_chk` presence. Tri-state verdict. |
| ASLR entropy | Read /proc/sys/kernel/randomize_va_space | Sample multiple addresses |
| ROP gadgets | Count total gadgets | Filter by bad bytes, count usable |
| Hooks available | Check glibc version | Check if symbols exist in nm output |

This catches edge cases: custom glibc builds with different flags,
kernel configurations that override defaults, and binary-specific
constraints not visible statically.

### SMT Integration

Optional Z3/SMT integration (requires `pip install z3-solver`) provides
two capabilities:

1. **One-gadget feasibility** (`packages/exploit_feasibility/smt_onegadget.py`):
   Checks whether a one-gadget's register/memory constraints are
   satisfiable given a crash state. Result appears in
   `exploitation_paths[vuln].one_gadget_info.smt_feasibility`.

2. **CodeQL dataflow path validation** (`packages/codeql/smt_path_validator.py`):
   Checks whether branch conditions along a dataflow path are jointly
   satisfiable. `unsat` means false positive (skip LLM); `sat` produces
   concrete input values fed into the LLM prompt. Best coverage:
   CWE-190, CWE-120/122, CWE-193, CWE-476.

Both degrade gracefully when Z3 is absent.

### Usage

**Python API:**

```python
from packages.exploit_feasibility import analyze_binary, format_analysis_summary

result = analyze_binary('/path/to/binary')
print(format_analysis_summary(result, verbose=True))
```

**Remote targets (known glibc):**

```python
from packages.exploit_feasibility import FeasibilityAnalyzer, create_remote_profile

profile = create_remote_profile(
    binary_path="./challenge",
    glibc_version="2.31",
    host="pwn.ctf.com",
    port=1337,
)
analyzer = FeasibilityAnalyzer(profile=profile)
report = analyzer.full_analysis(vuln_type="format_string")
```

**Per-finding feasibility mapping:**

```python
from packages.exploit_feasibility import map_findings_to_constraints, load_exploit_context

constraints = load_exploit_context(context_file)
mapped = map_findings_to_constraints(findings, constraints)
```

Each mapped finding carries a two-axis assessment: `verdict` (can you
trigger it?) and `impact` (what happens -- `code_execution`, `dos`,
`info_leak`). The two axes avoid conflating triggerability with
consequence.

**Context persistence for long sessions:**

```python
from packages.exploit_feasibility import save_exploit_context, load_exploit_context

context_file = save_exploit_context('/path/to/binary')
ctx = load_exploit_context(context_file)
```

### Pipeline Integration

- `/exploit` automatically runs feasibility analysis before technique
  selection.
- `/validate` Stage E uses feasibility output to assess exploitability.
- The `check_exploit_viability()` API provides a single-call verdict
  for pipeline consumers.
- See [exploit feasibility guide](binary-analysis.md) for detailed
  scenario walkthroughs and API reference.

### What Feasibility Does Not Do

- Generate exploits (use `/exploit` for that).
- Find vulnerabilities (use `/scan` for that).
- Bypass mitigations (tells you what is blocked, not how to bypass).

It tells you what is possible so you do not waste time on what is
impossible.

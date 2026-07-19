# Black-box binary understanding

Compiled
applications were the awkward gap: radare2 existed inside fuzzing, but it was
mostly a handy pre-pass rather than a proper evidence layer.

The black-box binary path makes that a first-class `/understand` surface.

Most operators should use `/binary`, which wraps the same substrate with
subcommands for mapping, runtime evidence, fuzz handoff, graph queries and
reports:

```bash
/binary /path/to/app
/binary investigate /path/to/app
/binary map /path/to/app
/binary runtime /path/to/app --duration 30
/binary trace-parser out/understand_app_.../ --duration 30
/binary graph out/understand_app_.../
```

Bare `/binary <path>` runs `investigate`, not just `map`. That gives the
operator a compact `binary-investigation-report.md` with ranked surfaces,
declared helper/sibling artefacts, automatic graph rollups and a priority queue
of next evidence actions. The lower-level `map` command is still there when
you only want the mechanical substrate.

## Prerequisites

Required:

- `radare2` in `PATH` (`apt install radare2` / `brew install radare2`)
- the `r2pipe` Python module (`pip install r2pipe`)

Optional, enable specific evidence tiers:

- `r2ghidra` radare2 plugin for higher-quality decompilation (falls back to
  the built-in `pdc` otherwise)
- `frida-tools`, for `--runtime` / `trace-parser` dynamic evidence
- `z3-solver`, for explicit-condition SMT checks (`--constraint-file`)
- AFL++, for `--fuzz` witnesses

Every `/binary map` / `/binary investigate` run resolves its own output
directory the same way `/understand` does: `--out <dir>` if given, otherwise
an auto-generated `out/understand_<target-stem>_<timestamp>_pid.../` (or, with
an active project, a timestamped `understand-...` run inside the project
directory). The examples below use `out/understand_app_.../` as a stand-in
for that generated path.

## What it does

`/binary map` takes one compiled artefact and builds:

- a byte-bound manifest (`binary-manifest.json`)
- an evidence ledger (`binary-evidence.json`)
- a context-map-compatible bridge (`context-map.json`)
- a binary-specific alias (`binary-context-map.json`)
- an address-stable checklist (`binary-checklist.json`)
- persisted pseudocode for reviewed functions (`binary-decompilations.json`)
- bounded ingress-to-parser candidates (`parser_boundary_candidates` in `context-map.json`)
- an honest next-step record (`binary-validation-handoff.json`)
- a queryable graph (`graph/binary-graph.sqlite`)
- a short human report (`binary-analysis-report.md`)

`/binary investigate` adds:

- an evidence-separated investigation record (`binary-investigation.json`)
- a one-screen operator report (`binary-investigation-report.md`)

The investigation report is intentionally split into facts, structural
inferences and unproven hypotheses. That keeps the useful analyst steering
without letting a class name, import or xref quietly turn into a vulnerability
claim.

It uses the parts RAPTOR already has:

- file magic, SHA-256 and import tables for intake
- radare2 for function recovery, xrefs and decompilation hints
- Mach-O headers, Info.plist and code-signing metadata for universal app bundles
- Objective-C / Swift class metadata for methods, selectors and framework callback candidates
- Frida run output for runtime observations
- fuzz output for execution-backed crash witnesses
- Z3 only for explicit path conditions
- byte/import/runtime-marker diffs for version comparison

The same evidence model distinguishes:

| Artefact | External ingress RAPTOR looks for | Normal fuzz follow-on |
|---|---|---|
| Mach-O app | URL/file handlers, XPC listeners, WebView callbacks, bundle metadata | Trace the handler, then extract a narrow harness |
| ELF executable | Process entry, imported input channels, exported APIs | Plan a campaign only when an input contract exists |
| ELF kernel module | `unlocked_ioctl` / `compat_ioctl` style dispatchers | IOCTL harness or snapshot fuzzing, never a blind user-mode run |
| PE EXE | Process entry, imported input channels | Runtime first unless a harness is already present |
| PE DLL | Exported APIs bound back to recovered functions | Typed export harness |
| PE driver | `EvtIoDeviceControl` / `DispatchDeviceControl` style dispatchers | IOCTL harness or snapshot fuzzing |

PE architecture comes from the COFF header, so a 32-bit DLL, 64-bit EXE and
ARM64 driver are not all quietly flattened into the same bucket. The driver
paths are still conservative: seeing an IOCTL dispatcher is a boundary
candidate, not proof that any request reaches a bug.

Managed artefacts are deliberately conservative. JAR/APK,
.NET, Go and Rust markers are recorded as runtime signals so later adapters
can pick the right decompiler or metadata reader. RAPTOR does not claim
managed-language reachability just because a marker is present.

## The evidence rule

Binary analysis is full of ways to blag it. Too many ways to lie and cheat and do stuff that it shouldn't. 
RAPTOR does not turn “I saw `strcpy`” into “this is exploitable”.

Every record says where it came from. Proof or GTFO:

| Tier | Means |
|------|-------|
| `observed_runtime` | Frida or a fuzzer actually saw it happen |
| `replayed_crash` | A crash was replayed against the bound binary |
| `smt_proved` | Z3 checked explicit path conditions and returned a mechanical result |
| `xref_backed` | radare2 recovered a concrete call/xref relationship |
| `header_backed` | File header, magic, imports or archive members prove it |
| `decompiler_inferred` | Pseudocode suggests it, but it is not proof |
| `heuristic` | Useful lead only, such as a name-based entry point |

That means:

- import-backed input channels are candidates until runtime confirms them
- direct xrefs to security-relevant imports are call-graph facts, not taint facts
- transitive reachability is labelled `may_reach`
- no trust boundary or unchecked flow is emitted without actual evidence
- Objective-C / Swift selectors are structure, not proof that the framework invoked them
- SMT only runs when we have explicit conditions to ask it about

## Basic use

```bash
/binary investigate /path/to/app
```

This is the normal path. It is static only unless you explicitly allow a
dynamic phase:

```bash
/binary investigate /path/to/app --runtime
/binary investigate /path/to/app --fuzz
/binary investigate /path/to/app --active
```

`--active` allows both runtime and fuzzing. Without those flags RAPTOR does not
spawn, attach to or fuzz the target.

For the raw map only:

```bash
/binary map /path/to/app --out out/understand_app_.../
```

For universal Mach-O applications, RAPTOR inventories every slice and deeply
analyses one architecture at a time. The default follows the slice radare2
opened; pin it when you need the other side of the app:

```bash
/binary map /path/to/App.app/Contents/MacOS/App \
  --slice-arch x86_64 \
  --out out/understand_App_x86_.../
```

By default it persists pseudocode for the 20 highest-value recovered
functions. Use `--max-decompile 50` to widen that review window, or
`--decompile-all` when you are happy to wait and accept a much larger
artefact.

`--quick` is intake-only: it records headers, slices, imports and bundle
metadata, then stops. The output labels that as `metadata_only` and does not
pretend a deep function map happened.

The lower-level helper and its old positional form still work for tests and
power users, but they are not the normal operator surface:

```bash
_RAPTOR_TRUSTED=1 libexec/raptor-binary map /path/to/app --out out/understand_app_.../
```

## Add runtime evidence

For the normal parser-boundary follow-on, point RAPTOR at the existing binary
run and let it collect and re-ingest the trace in one go:

```bash
/binary trace-parser out/understand_app_.../ --duration 20
```

That runs the narrow `binary-flow-trace` Frida template into
`parser-runtime/` inside the existing run, then refreshes:

- `context-map.json`
- `binary-context-map.json`
- `binary-checklist.json`
- `binary-validation-handoff.json`
- `binary-investigation.json`
- `binary-investigation-report.md`
- `graph/binary-graph.sqlite`

The older explicit two-step route still works when you already have a Frida
run you want to ingest:

```bash
/binary runtime /path/to/app --duration 20

/binary map /path/to/app \
  --out out/understand_app_.../ \
  --runtime-dir out/frida-...
```

If you later remap with separate fuzz evidence, pass the parser runtime
directory again as well:

```bash
/binary map /path/to/app \
  --out out/understand_app_.../ \
  --runtime-dir out/understand_app_.../parser-runtime \
  --fuzz-dir out/fuzz-...
```

The binary analyser never silently spawns or attaches to a target. `trace-parser`
is an explicit operator action against an already-mapped run, so the dynamic
step is obvious and the output stays tied to the exact binary hash RAPTOR
originally mapped.

`binary-flow-trace` records ASLR-relative callsites for input APIs such as
`recv`, `recvfrom` and `read`, plus high-value parser entry points such as
`XML_Parse`, `xmlReadMemory`, `d2i_X509`, `jpeg_read_header` and `inflate`.
When the callsite maps back to a recovered function address, RAPTOR emits an
`OBSERVED_CALLSITE` or `OBSERVED_PARSER_CALLSITE` graph edge. That proves the
function called the API during that run; it still does not claim those bytes
reached a later sink.

## Parser boundary extraction

For GUI apps, XPC listeners, URL handlers and protocol callbacks, the useful
fuzz target is rarely the framework callback itself. RAPTOR retains
radare2's direct call graph and looks for a bounded path from a recovered
external ingress to an internal function that directly calls a known parser
surface.

That produces `parser_boundary_candidates` with:

- the ingress candidate that starts the path
- the internal boundary function worth reviewing
- the parser surface it calls
- the bounded call-graph path and depth
- the evidence tier (`xref_backed` or `observed_runtime`)

The graph stores these as:

- `PARSER_BOUNDARY_FOR_INGRESS`
- `PARSER_BOUNDARY_CALLS_SURFACE`
- `OBSERVED_PARSER_CALLSITE`

This is the bit that turns “the app has an `openURLs:` callback” into “this
specific internal function appears to be the parser boundary behind it”.
RAPTOR still does not emit a harness from that alone. It needs a callable ABI,
object schema or stronger runtime contract first.

When Swift/ObjC dynamic dispatch hides the static edge, the Frida trace
retains target-module backtrace frames for parser calls. If the backtrace
contains both the recovered ingress and the parser caller, RAPTOR can recover
an `observed_runtime` parser boundary even when the static call graph cannot
join the two.

That is why the investigation priority queue points at
`/binary trace-parser <run-dir>` rather than leaving the operator to manually
join a Frida run back to a map.

## Plan or generate a harness

After investigation, ask RAPTOR to turn one ingress candidate into a harness
plan:

```bash
/binary harness out/understand_app_.../
```

By default it selects the highest-ranked external ingress. Pin one when you
want a specific route:

```bash
/binary harness out/understand_app_.../ --ingress BINGRESS-07b2007ea85a
```

Every harness run writes:

- `harness/<ingress>/harness-spec.json`
- `harness/<ingress>/harness-report.md`

Those files record the binary hash, ingress evidence, what is still unknown,
the operator-supplied contract if one exists, and the verification steps needed
before the harness can be trusted.

RAPTOR only emits source code when the boundary is explicit enough:

```bash
# Exported DLL/shared-library API where the operator confirms a byte-buffer ABI
/binary harness out/understand_codec_.../ \
  --ingress BINGRESS-... \
  --abi buffer-size

# Driver dispatch boundary where the operator confirms device path and ioctl code
/binary harness out/understand_driver_.../ \
  --ingress BINGRESS-... \
  --device '\\\\.\\Demo' \
  --ioctl-code 0x222003
```

For exported APIs, `--abi buffer-size` means the operator is explicitly saying
the function is callable as `(const uint8_t *, size_t)`. `--abi cstring` means
the operator is explicitly saying it takes one NUL-terminated string. RAPTOR
does not infer either from a symbol name.

For app callbacks, XPC listeners, URL handlers and WebView callbacks, the first
harness pass normally stops at `needs_runtime_trace`. Once RAPTOR recovers a
bounded ingress-to-parser path it moves to `parser_boundary_candidate` and
shows the narrowed function in the harness report. That is intentional. The
framework callback is real, but the useful fuzz boundary is usually the parser
or protocol helper behind it.

## Add fuzz witnesses

```bash
/binary fuzz /path/to/app --duration 60

/binary map /path/to/app \
  --out out/understand_app_.../ \
  --fuzz-dir out/fuzz-...
```

Crash inputs are recorded as execution-backed witnesses. They are still not
root-cause triage by themselves; a replay or debugger pass can strengthen them
later. When a fuzz run already contains `crash_analysis/replay/replay-summary.json`,
RAPTOR ingests successful ASAN/debug sibling replays as separate
`replayed_crash` evidence and links them into the graph.

## Add a narrow SMT check

`conditions.json`:

```json
{
  "profile": "int64",
  "conditions": [
    "declared_len > 2147483647",
    "declared_len <= 9223372036854775807"
  ],
  "prefer_witness": "min:declared_len"
}
```

```bash
/binary map /path/to/app \
  --out out/understand_app_.../ \
  --constraint-file conditions.json
```

This is deliberately narrow. RAPTOR checks a stated hypothesis; it does not
pretend whole-binary symbolic execution has happened.

## Compare two builds

```bash
/binary map /path/to/new/app \
  --compare /path/to/old/app \
  --out out/understand_app_.../
```

`binary-diff.json` reports byte, metadata, import capability and runtime-marker
changes. It does not claim the new build introduced a reachable bug.

## Query the graph

```bash
/binary graph out/understand_app_.../
/binary graph out/understand_app_.../ --edges --json
/binary graph out/understand_app_.../ --edges --kind MAY_REACH --json
/binary graph out/understand_app_.../ --evidence --tier replayed_crash --json
```

The graph is internal memory, not the public contract. The JSON files remain
the thing other RAPTOR flows can safely consume.

`binary-checklist.json` is the compact handoff record: recovered functions,
entry-point candidates, input-channel candidates, sensitive imports, candidate
call edges, runtime observations, fuzz witnesses, explicit SMT checks and
binary diffs all land there with their evidence tier intact. On Mach-O apps it
also carries the class inventory, method-to-function bindings and framework
callback candidates. Those selectors are useful context for follow-on work,
but RAPTOR keeps them separate from entry points until runtime evidence proves
they fire.

`binary-validation-handoff.json` is the bit that stops the binary path getting
ahead of itself. It lists each call-graph candidate, the evidence already
present, and what is still missing before that candidate could become a real
finding: usually a runtime input callsite, a replay or debugger witness, any
explicit SMT check the claim depends on, and a root-cause binding.

The investigation report also carries `fuzz_suitability`. This answers a
different question from “is AFL installed?”:

- `direct_harness` means RAPTOR has a concrete harness boundary such as `LLVMFuzzerTestOneInput`
- `extract_harness_from_ingress` means an app has an interesting URL/file/IPC handler, but fuzzing the whole process would be daft
- `extract_export_harness` means a DLL/shared library needs typed arguments and ownership rules wrapped first
- `snapshot_or_ioctl_harness` means a driver needs kernel-aware infrastructure
- `campaign_plan_required` means RAPTOR can ask the fuzzer planner, but still has not claimed the target is a good campaign

`/binary investigate --active` maps first and uses that strategy before it
launches anything. It will run a real fuzz campaign only for a concrete direct
harness. For app, DLL and driver-shaped targets it records the harness step
instead of pretending a whole-process fuzz run is useful.

Runtime collection follows the same rule. Apps and executables can usually be
observed as processes. Bare DLLs need a caller harness first; `.sys` and `.ko`
drivers need a kernel-aware harness, VM trace or debugger rather than a fake
Frida run against a file that cannot execute on its own.

---
description: Black-box binary investigation — autonomous ranking, map, parser tracing, fuzz, graph, report, handoff, diagram
dispatch: libexec/raptor-binary <command> [args]
---

# /binary — Black-box Binary Understanding

Use RAPTOR against a compiled artefact when source is not available. This is
the operator-facing surface for the evidence-backed binary work behind
`/understand --map`.

## Usage

```bash
/binary [command] [args]
```

With no command, `/binary <path>` defaults to `investigate`.

## Commands

| Command | Description |
|---------|-------------|
| `investigate <binary>` | Map the binary, query its graph, rank the strongest leads and write an evidence-separated investigation report |
| `map <binary>` | Build the binary manifest, context map, decompilations, graph and validation handoff |
| `runtime <binary>` | Run Frida with `binary-flow-trace` to collect explicit input-callsite evidence |
| `trace-parser <run-dir>` | Run parser-focused Frida tracing and fold the new runtime evidence back into the existing binary run |
| `harness <run-dir>` | Turn one recovered ingress into a harness plan, and emit candidate source only when the contract is explicit |
| `fuzz <binary> [fuzz args]` | Hand off to the normal `/fuzz` orchestrator for crash witnesses |
| `graph <run-dir>` | Query the persistent binary graph |
| `report <run-dir>` | Print `binary-investigation-report.md` when present, otherwise the lower-level map report |
| `handoff <run-dir>` | Print `binary-validation-handoff.json` |
| `diagram <run-dir>` | Render Mermaid diagrams from the binary map |
| `help` | Show wrapper help |

## Examples

```bash
/binary /Applications/JamfCheck.app/Contents/MacOS/JamfCheck
/binary investigate /Applications/JamfCheck.app/Contents/MacOS/JamfCheck
/binary map /Applications/JamfCheck.app/Contents/MacOS/JamfCheck
/binary map /Applications/JamfCheck.app/Contents/MacOS/JamfCheck --slice-arch arm64
/binary map /Applications/JamfCheck.app/Contents/MacOS/JamfCheck --quick

/binary runtime /Applications/JamfCheck.app/Contents/MacOS/JamfCheck --duration 30
/binary trace-parser out/understand_JamfCheck_.../ --duration 30

/binary harness out/understand_JamfCheck_.../
/binary harness out/understand_codec_.../ --ingress BINGRESS-... --abi buffer-size
/binary harness out/understand_driver_.../ --ingress BINGRESS-... --device '\\\\.\\Demo' --ioctl-code 0x222003

/binary fuzz /path/to/fuzzable-binary --duration 60

/binary graph out/understand_JamfCheck_.../
/binary graph out/understand_JamfCheck_.../ --edges --kind FRAMEWORK_CALLBACK_CANDIDATE --json
/binary graph out/understand_JamfCheck_.../ --evidence --tier observed_runtime --json

/binary report out/understand_JamfCheck_.../
/binary handoff out/understand_JamfCheck_.../
/binary diagram out/understand_JamfCheck_.../
/binary diagram out/understand_JamfCheck_.../ --stdout
```

## Investigation Behaviour

`investigate` is the normal operator path. It runs the static map, reads its
own artefacts, queries the graph for the obvious follow-on questions, discovers
declared helper/sibling executables, ranks external ingress before generic
sink surfaces, and
writes:

- `binary-investigation.json`
- `binary-investigation-report.md`

The report keeps three things separate:

- facts backed by headers, xrefs, runtime or crash evidence
- structural inferences that are useful for review but are not findings
- hypotheses that still need runtime, replay, SMT or root-cause evidence

Do not manually grep JSON after an investigation unless the user explicitly
asks for a deeper drill-down. Read `binary-investigation-report.md`, surface
the top three leads and the priority queue, and stop there unless the user asks
to continue.

Dynamic phases remain explicit because they execute unknown code:

```bash
/binary investigate /path/to/app --runtime
/binary investigate /path/to/app --fuzz
/binary investigate /path/to/app --active
```

`--active` means both runtime and fuzz phases are allowed. Without one of those
flags, investigation is static only.

`--active` still maps first. RAPTOR only launches a real whole-target fuzz
campaign when it has a concrete harness boundary. GUI apps, DLLs and drivers
normally get a harness-extraction or snapshot-fuzzing step instead, because
blindly throwing AFL at the whole artefact is not useful evidence.

`harness` is deliberately stingy. It always writes a `harness-spec.json` and
`harness-report.md`, but it only writes source code when the boundary is
mechanically defined enough:

- existing `LLVMFuzzerTestOneInput`: no new source needed
- exported API: requires `--abi buffer-size` or `--abi cstring`
- driver IOCTL boundary: requires `--device` and `--ioctl-code`
- app/XPC/WebView callback: remains a runtime-trace plan until RAPTOR has the narrower parser boundary behind it

Once a bounded ingress-to-parser path is recovered, `harness` reports
`parser_boundary_candidate` and names the internal function RAPTOR thinks is
worth instrumenting next. That boundary is xref-backed structure, not a
trusted ABI, so source is still withheld until runtime or operator-supplied
contract evidence makes it callable.

## Evidence Flow

`map` and plain `investigate` are static only. They never quietly run the target.

To strengthen the map:

1. Run `/binary trace-parser <run-dir>` to collect Frida input/parser callsite evidence and refresh that run in place.
2. Run `/binary fuzz <binary>` to collect crash witnesses.
3. Re-run `/binary map <binary> --runtime-dir <run-dir>/parser-runtime --fuzz-dir <fuzz-run>` when you want to fold a separate fuzz campaign into the map while keeping the trace evidence.

`trace-parser` updates `context-map.json`, the binary graph, validation handoff
and investigation report in the same run directory. It is still only runtime
shape evidence: a parser backtrace can confirm the boundary RAPTOR saw, but it
does not pretend the bytes are tainted or the boundary is exploitable.

## Important Notes

- Objective-C / Swift selectors are recorded as framework callback candidates, not attacker-controlled entry points.
- PE DLL exports, Windows driver dispatchers and Linux kernel-module ioctl handlers are recorded as external ingress candidates when the bytes prove they exist.
- PE architecture is read from the COFF header; 32-bit, 64-bit and ARM64 targets are kept distinct.
- `--quick` is metadata-only and will not claim deep analysis happened.
- `--slice-arch arm64|x86_64` lets you analyse one side of a universal Mach-O app.
- `--constraint-file <conditions.json>` only checks explicit SMT conditions you provide.
- `--compare <older-binary>` records binary/import/runtime-marker diffs without claiming reachability.
- Parser-boundary candidates come from bounded call-graph paths into known parser surfaces; they are not attacker-byte taint proof.

## Execution

Run binary commands via Bash:

```bash
libexec/raptor-binary <command> [args]
```

Show the output path and the key summary lines after each command. For `report`
and `handoff`, print the artefact contents verbatim.

ARGUMENTS: $ARGS

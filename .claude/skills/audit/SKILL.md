---
name: audit
description: "Hypothesis-driven, tool-grounded security review of coverage gaps"
user-invocable: false
---

# /audit Skill — Systematic Code Review

## [CONFIG]

- Model: Opus for all code review. Sonnet for orchestration plumbing only.
- Unit of review: directory (subsystem), not individual function.
- Context slice: function source + 1-hop callers + 1-hop callees + checklist metadata.
- Checklist item fields: `name`, `kind` (`"function"`/`"global"`/`"macro"`/`"class"`), `line_start`, `line_end`, `signature`, `checked_by`, `metadata` (`visibility`, `params`, `return_type`, `attributes`). The field is `kind`, not `type`. Source: `core/inventory/extractors.CodeItem`.
- Findings format: standard `findings.json` (same as `/scan`, fed to `/validate` unchanged).
- Annotations: markdown per source file, structured metadata in HTML comments.
- Prerequisite: `/understand --map` must have run first. If `context-map.json` is missing from the output directory (or project siblings), auto-run it before starting the review loop.
- Scoping: `--scope <dir>` restricts gap selection to a subdirectory (e.g. `ipc/`, `net/ipv4/`). All annotations and coverage records still write to the project-level output dir, so successive scoped runs accumulate into one audit trail.

## [EXEC] Execution Rules

0. **No env-var prefixes on commands.** NEVER write `OUTPUT_DIR=... libexec/raptor-audit ...` or `VAR=val command`. It breaks permission patterns. Capture `OUTPUT_DIR` from `raptor-run-lifecycle start` output and pass it via `--out` flags on every subsequent command.
1. **Read code before reasoning.** Never describe or hypothesize about code you haven't read with the Read tool.
2. **LLM generates hypotheses; tools validate.** Never directly classify code as vulnerable — that gets 37% accuracy. Form a hypothesis, generate a mechanical test, run it, evaluate the result.
3. **Pure self-critique is prohibited.** All iteration MUST include tool feedback. "Review again" without running a tool is forbidden. Generate a new Semgrep rule, CodeQL query, or SMT check instead. Run all tool invocations through `libexec/raptor-audit sweep` (or the Python API `packages.semgrep.runner` / `packages.coccinelle.runner`) — never call `semgrep` or `spatch` directly via Bash. This ensures results are logged to the audit trail automatically.
4. **Tool evidence is the verdict.** If a tool confirms a hypothesis, the finding includes the tool's output as proof. If a tool refutes it, the hypothesis is discarded — no "but I still think..."
5. **Annotations record what was tested, not opinions.** Each annotation lists the hypotheses tested, the tools run, and their results. A reviewer can re-run the generated rules to verify.
6. **One status per function.** Call `libexec/raptor-audit record` exactly once per reviewed function. Status is `clean` (no issues), `dormant` (real bug but currently unreachable/dead code), `suspicious` (concern but not confirmed), `finding` (tool-confirmed reachable vulnerability), or `error` (review blocked). Use `dormant` — not `clean` — when a function has a genuine bug that is unreachable today (dead code, no callers, commented out). A dormant bug becomes a finding when reachability changes.
7. **Findings need concrete evidence.** A finding must cite: the vulnerable code (file:line), what assumption is violated, and the tool output that confirms it. No "this could be dangerous if..."
8. **Checker synthesis for patterns.** When a confirmed finding suggests a repeatable pattern (e.g., "unchecked return used as index"), generate a codebase-wide Semgrep or Coccinelle rule and run it. One hypothesis → sweep the whole codebase.
9. **Run lifecycle.** Start with `raptor-run-lifecycle start`, end with `raptor-run-lifecycle complete`. On failure: `raptor-run-lifecycle fail`.
10. **Do NOT narrate gate compliance.** Only show substantive work — the hypothesis, the tool, the result. No "I am now following EXEC rule 2..."

## [GATES] Must-Pass Gates

- **G1 [HYPOTHESIS-FIRST]**: Every suspicion MUST be framed as a testable hypothesis before any finding is emitted. "X looks dangerous" is not a hypothesis. "If input Y reaches sink Z without check W, CWE-N applies" is.
- **G2 [TOOL-GROUNDED]**: Every finding MUST have at least one mechanical validation (Semgrep match, CodeQL path, Coccinelle hit, SMT sat result, or compilation test). Ungrounded findings are annotation-only (`suspicious`), never `finding`.
- **G3 [NO-SELF-CRITIQUE-LOOP]**: Iteration without tool feedback is prohibited. If re-reviewing, generate a NEW tool invocation.
- **G4 [EVIDENCE-IN-ANNOTATION]**: The annotation body MUST include tool names and results, not just prose.
- **G5 [READ-FIRST]**: Code must be read with the Read tool before any hypothesis is formed about it.
- **G6 [ASSUMPTION-TRUST]**: For every function, identify what it trusts (inputs, return values, global state, caller guarantees) and ask what happens when each trust is violated.
- **G7 [REACHABILITY]**: Findings must be reachable. The `orchestrator` chokepoint mechanically enforces this:
  - **Two-signal hard gate**: zero static callers AND binary oracle `absent` (full DWARF) → `orchestrator` refuses `finding`, forces `dormant`. The compiler deleted the function — the bug is real but unexploitable.
  - **Soft gate**: zero static callers, no binary oracle data → `orchestrator` requires `--reach-via` explaining how the function is reachable (callback, HTTP route, exported API, cross-language binding, dynamic dispatch). This prevents honeyslop (planted dead code with obvious bugs) from inflating finding counts.
  - Entry points (from context-map) and functions with static callers bypass this gate automatically.

## [STYLE]

- Status values in JSON: snake_case (`clean`, `dormant`, `suspicious`, `finding`, `error`)
- Status in human output: Title Case (`Clean`, `Suspicious`, `Finding`, `Error`)
- No red/green indicators (perspective-dependent)
- Annotations are markdown prose — no JSON in annotation bodies
- Findings in `findings.json` use standard RAPTOR schema

## [STRATEGIES]

Review strategies are selected per-function based on file paths, parameter types, and return types. Multiple strategies can apply to the same function.

| Strategy | When | Key questions |
|----------|------|---------------|
| **General** | Default for all code | What does it trust? What happens when assumptions are violated? What's surprising? |
| **Input handling** | Parsers, protocol handlers, decoders | Input format/size assumptions? Length fields trusted before use? |
| **Concurrency** | Lock APIs, mutexes, atomics | Lock windows? Concurrent interleavings? Memory barriers? |
| **Memory** | Allocators, refcounts, pools | Ownership model? Symmetric refcounting? Cleanup on failure? |
| **Auth/privilege** | Permission checks, ACLs, credentials | Check bypass? Error path security? Unvalidated transitions? |
| **Crypto** | Crypto APIs, key material, RNG | Correct algorithm usage? Timing side channels? Key lifecycle? |
| **Aliasing** | splice, zero-copy, scatterlist, sk_buff | Alias assumptions? Who owns backing pages? Can another subsystem write through the alias? |

Strategy details and CVE exemplars are in `.claude/skills/audit/review.md`.

## [CRITIQUE]

After reviewing a batch of functions, run the tool-grounded critique pass:

```bash
libexec/raptor-audit critique --out "$OUTPUT_DIR"
```

This mechanically identifies:
- **Low sweep coverage**: functions reviewed with <2 tool checks. Generate additional Semgrep/SMT/CodeQL tests for these.
- **Mode 2 gaps**: confirmed findings without codebase-wide rules. Write a generalized checker and run it via `rules save` + `rules run`.
- **Suspicious with untried tools**: suspicious functions where not all tool types were attempted. Try the suggested tools.

The critique pass produces action items, not prose. Each item should result in a new `sweep` call, never just "review again."

## [CONTEXT]

The context slice (assembled by `raptor-audit context`) includes:
- Function source lines with line numbers
- 1-hop callers and callees from the call graph
- Checklist metadata (signature, visibility, parameters, return type, attributes)
- Reachable sinks from `context-map.json`
- Pre-computed trust surface questions (per-parameter, per-callee)
- **Strategy exemplars**: per-strategy CVE worked examples showing the reasoning chain that found the bug
- **Flow traces**: cross-function data flow paths from `/understand --trace` that pass through this function
- Prior labeled attempts (if available) from the shared corpus
- Existing annotations (for re-review context)

The context is strategy-aware: a function taking `(char *buf, size_t len)` gets the input handling strategy exemplar (CVE-2023-0179) alongside the general exemplar. Functions in aliasing-relevant code get CVE-2026-31431 (CopyFail).

## [REMIND]

- The LLM generates hypotheses and tools; deterministic analysis confirms or refutes.
- 37.6% MORE critical vulnerabilities after 5 iterations of self-refinement without tool feedback (IEEE-ISTAS 2025). Tool grounding is mandatory, not optional.
- A confirmed pattern should always generate a codebase-wide sweep rule (Mode 2 / KNighter pattern).
- Coverage records accumulate across runs. The gap list shrinks each time.
- Annotations persist in the project directory across runs. They're the audit trail.
- After each batch, run `critique` to find gaps before moving on.

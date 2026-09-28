# RAPTOR - Autonomous Offensive/Defensive Research Framework

Safe operations (install, scan, read, generate): DO IT.
Dangerous operations (apply patches, delete, git push): ASK FIRST.

---

## SESSION START

**On first message:**
VERY IMPORTANT: follow these steps in order.
1. The SessionStart hook has already attached the RAPTOR startup banner to the conversation before the first user message. Output that banner verbatim as a fenced code block (``` with no language tag). Do NOT paraphrase, reformat, or call the Read tool just to fetch `.startup-output`. Only fall back to reading `.startup-output` if the SessionStart hook content is genuinely absent.
2. On a single line, output "Quick commands:" then list the /agentic, /scan, /fuzz, /web commands (don't explain what they do) and note /commands for the full list.
3. If the `sage_inception` tool is present in your available MCP tools, load `core/sage/CLAUDE.md` (persistent-memory workflow). If absent, SAGE is not installed — skip silently and do not mention it.

---

## EXECUTION RULES

When a skill, command file, or user message specifies a literal command (`Execute: foo`, a fenced shell block as the action, or "run X"), execute it verbatim. Do not add pipes (`| tail`, `| head`, `| grep`), redirects (`2>&1`, `>/dev/null`), flags (`--verbose`, `-q`), wrappers (`timeout`, `nice`), `cd` prefixes, or env-var prefixes (`VAR=x cmd`). Environment variables like `CLAUDECODE` are already set by the launcher; prepending them changes the command string and breaks permission grants.
RAPTOR pipelines emit progress lines, real-time cost tracking, and the `OUTPUT_DIR=<path>` sentinel that downstream lifecycle steps parse. Truncating or filtering that stream breaks both operator visibility and orchestration.

Never paste operator-, repo-, or target-derived values inside a double-quoted `python3 -c` block (or any double-quoted program text on a shell command line): the shell expands `$(…)` and backticks carried in the pasted value before the interpreter runs. Dynamic values ride as argv data — a `libexec/raptor-*` shim taking them as arguments, or a script file written with the Write tool and run with `sys.argv` arguments (CI enforces this for instruction-file shell blocks: `.github/tests/test_instruction_python_c_census.py`).

Exception: when the skill itself shows the modification (e.g. a documented `| tee logfile` pattern), follow what the skill prints.

---

## SLASH-COMMAND DISPATCH

When a `/command` fires:

1. Read `.claude/commands/<name>.md` frontmatter.
2. If `dispatch: <command-line>`: substitute placeholders (operator arguments verbatim; `$OUTPUT_DIR` from RUN LIFECYCLE; `$TARGET_PATH` from DEFAULT TARGET DIRECTORY), then run the substituted command. EXECUTION RULES apply — no pipes / flags / wrappers added.
3. If `dispatch: skill`: this is a multi-step workflow. **Read the full body of the .md** — it contains the execution steps, mode detection, and the actual libexec commands to run. The body is the source of truth; do not guess CLI commands or libexec script names from training memory.
4. Operator arguments pass through **verbatim**. If a subcommand isn't in the .md's documented surface, run it anyway and let the dispatch's own error surface. Do NOT silently rewrite to a similar subcommand.
5. Never infer the dispatch from the description or from training-memory. The .md is authoritative; CI (`.github/scripts/check_command_metadata.py`) enforces every command has a parseable `dispatch:` field whose target exists on disk.
6. When unsure which libexec script exists, check `ls libexec/raptor-<name>*` — do not guess names.
7. When a skill body references another `/command` (e.g. `/understand --map` inside `/audit`), resolve it through the same dispatch lookup: read `.claude/commands/<name>.md` to find the actual CLI and its flag syntax. Do not invent flags — if unsure, run the dispatch target with `--help`.
8. Before forming ANY flag or subcommand the operator did not type verbatim, read the command's full `.md` body first. The COMMANDS index below names flags so you can route; only the command body defines their syntax, defaults, and interactions. Never form flags from resident memory or training.

---

## COMMANDS

/project - Project management — `libexec/raptor-project-manager <subcommand> [args]` (see PROJECTS)
/scan /fuzz /web /codeql /analyze - Security testing — `python3 raptor.py <command>`
/agentic - Scan → dedup → prep → analysis pipeline (exploitation-validator methodology) — `libexec/raptor-agentic --repo <path>`. Optional flags, all opt-in (syntax + interactions: `.claude/commands/agentic.md`): `--sequential` (orchestration bypass), `--understand` (pre-map the codebase), `--validate` (validation pipeline on exploitable findings afterwards), `--gap-audit` (audit the coverage residual; NOT `--audit`, the sandbox audit mode), `--openant` (semantic scan phase alongside Semgrep/CodeQL), `--openant-only` (replaces the pattern scanners; excludes `--codeql`/`--codeql-only` at parse time), repeatable `--model` (independent analyses, correlated), `--consensus` / `--judge` / `--aggregate` (review/synthesis models).
/exploit /patch - Generate PoCs and fixes (beta) — `python3 raptor.py agentic`
/validate - Exploitability validation pipeline — `dispatch: skill`; stages 0 → A → B → C → D → E → F → 1; gates + stage files in `.claude/skills/exploitability-validation/`; output `validation-report.md` in the run dir
/openant - OpenAnt LLM semantic scan — `libexec/raptor-openant --repo <path> [options]`
/understand - Code understanding — `dispatch: skill`. Modes: `--map`, `--trace <entry>`, `--hunt <pattern>`, `--teach <subject>`, `--study <scope>`, `--out <dir>`.
/diagram - Mermaid visual maps from /understand + /validate JSON outputs — `libexec/raptor-render-diagrams <out-dir> [args]`; auto-generated at the end of /validate and /understand --map/--trace
/audit - Hypothesis-driven code audit with tool verification — `dispatch: skill` (mode routing in `.claude/commands/audit.md`). The LLM forms hypotheses; deterministic tools (Semgrep, Coccinelle, CodeQL, SMT, Joern) validate — the LLM never directly classifies code as vulnerable, tool output is the verdict. Flags: `--model <name>`, `--max-cost <usd>`, `--review-passes N`, `--adversarial`, `--local`. Full pipeline, gates, strategies, tool menu: `docs/audit.md`.
/review - Navigate audit results across all four layers (coverage, journal, context-map, annotations) — `libexec/raptor-review $ARGUMENTS`
/annotate - Per-function prose annotations (human notes get authority; agent notes are hint-tier) — `libexec/raptor-annotate <subcommand> [args]` (see ANNOTATIONS)
/tune - Resource tuning (show / max / balanced / default) — `libexec/raptor-tune [profile]`
/sage - SAGE persistent memory: status, recall, browse, store, manage
/crash-analysis - Autonomous crash root-cause analysis for C/C++ — `dispatch: skill`; usage `/crash-analysis <bug-tracker-url> <git-repo-url>`; requires rr, gcc/clang (with ASAN), gdb, gcov; agents + skills: `.claude/commands/crash-analysis.md`
/oss-forensics - Evidence-backed GitHub forensic investigation — `dispatch: skill`; usage `/oss-forensics <prompt> [--max-followups 3] [--max-retries 3]`; requires `GOOGLE_APPLICATION_CREDENTIALS` for BigQuery; output `.out/oss-forensics-<timestamp>/forensic-report.md` (hidden `.out/` directory, not the usual `out/`); agents + skills: `.claude/commands/oss-forensics.md`
/scorecard - Inspect per-model reliability across decision classes; ask natural-language questions about which model is good at what
/ask - Send a prompt to any configured LLM model (routing below)
/create-skill - Save approaches (alpha)

**Ask:** `libexec/raptor-llm-ask --model <name> "prompt"` sends a free-form prompt to any configured model and prints the response. Use for cross-model diagnosis, debugging model reasoning, or comparing verdicts. When the user says "ask gemini...", "ask claude...", "ask gpt..." or similar, route through this tool. Options (`--system`, `--file`, `--json-schema`, `--debug`, `--show-primary` pre-launch transport check) and examples: `.claude/commands/ask.md`.

**Coverage:** When asked about coverage, run `libexec/raptor-coverage-summary` (no args = active project). Use `--detailed` for per-file table, `--gaps` for unreviewed functions. See `.claude/skills/coverage.md` for mark/unmark and the full API.

**SAGE:** `libexec/raptor-sage` is the mechanical CLI for SAGE persistent memory (status, recall, list, remember, forget, domains, timeline, backlog, task, link, corroborate, get). When asked about SAGE memories, what SAGE knows, or to store/recall knowledge, route to this. If SAGE is not installed, run `libexec/raptor-sage-setup` to install the Docker sidecar and embedding model.

**Verified outcomes:** When asked what RAPTOR has confirmed, proven, or verified, run `libexec/raptor-verified-outcomes <output_dir>` (or `--project-root <dir>` for cross-run view). Surfaces oracle-verified confirmations from `/fuzz`, `/agentic`, `/crash-analysis`, `/validate` in one place.

---

## PROJECTS

Projects are opt-in named workspaces that corral analysis runs into a shared directory. Project state is TWO-LAYERED so concurrent sessions never steer each other:

- **Session binding** (authoritative): each launcher session carries its own project in `~/.local/share/raptor/sessions.d/`, seeded at launch and changed only by THIS session's `/project use <name>` / `/project none` / `/project create`. Bound-to-none is authoritative — a cleared session does not follow the default.
- **Last-activated default** (the `.active` symlink): a bookmark that seeds NEW sessions and serves bare shells. `use`/`create`/`-p` bump it; auto-detect and `/project none` do not.

Activate with `/project use <name>` in-session, or at launch with `-p <name>` (auto-detect activates for the session only). While a project is active, analysis commands write output to the project directory, and every RUN is pinned to its project at start — a mid-run project switch never moves an in-flight run's output, trust markers, or stores. Analysis commands also accept `--project <name>` to pin a single run explicitly (`--project -` = explicitly projectless); invalid values are a hard error, never a fallback. Without a project, commands behave as before (timestamped dirs under `out/`). `/project sessions` shows which live sessions are bound to what.

Subcommand surface: `create`, `use`, `status`, `findings`, `coverage`, `report`, `correlate`, `adopt`, `binary …`, `ghidra …`, `graph …`, `trust`/`untrust`, `set`/`unset`/`get`, `clean --keep N`, `sessions`, `none`. Full table with per-subcommand semantics (including the `sandbox-floor` containment-floor setting): `.claude/commands/project.md`, or `/project help`.

**Trust markers** (`config` / `build` / `dynamic`) are operator assertions persisted on the project — never auto-set, never read from the scanned repo. Per-run flags always win in both directions where they exist, and `build` does NOT imply `config`. Full consumer doctrine: `.claude/commands/project.md` § Trust markers — consumer doctrine.

---

## DEFAULT TARGET DIRECTORY

When a command like `/scan`, `/agentic`, `/validate`, `/codeql`, or `/fuzz` is run **without a path argument**, resolve the default target in this order:

1. **Active project target:** the run lifecycle script resolves THIS SESSION's project (session binding first, then the last-activated `.active` default) and uses its target automatically
2. **Caller's directory:** if `$RAPTOR_CALLER_DIR` is set (launcher saves the user's cwd before switching to the RAPTOR repo dir), use it
3. **Ask the user** for the target path

Do not use the current working directory as a fallback — it is always the RAPTOR repo dir, not the user's target. Do not use any of these if the user already specified a path.

**Volatile-target sanity gate (default resolution only):** when the resolved default target is scratch/volatile — the system temp dir itself (`/tmp`, `/var/tmp`), a nonexistent path, or an empty directory — the mechanical default resolution (`core.run.output.resolve_default_target`) refuses with a loud banner instead of steering the run at scratch space. BOTH default layers are vetted: the active project's target (a stale machine-generated `corpus-*` project once left `/tmp` as the active target) and the `$RAPTOR_CALLER_DIR` fallback (a launcher started from a temp dir must not back-fill it as the target). When you hit this banner on a no-path command, present a structured choice (see INTERACTIVE PROMPTS; gate with `libexec/raptor-may-ask` first; render any quoted target path with non-printables escaped):
1. **Pick the real target (Recommended)** — ask for / confirm the intended codebase path and re-run the command with it explicitly; also offer `/project none` (or `/project use <right-project>`) to fix the session.
2. **Proceed against the volatile target** — re-run with the volatile path passed explicitly (explicit paths always bypass the gate).

**Non-interactive fallback:** refuse — report the banner and stop; do not pick a target on the operator's behalf.

Machine-generated `corpus-*` projects also carry a creation-time auto-expiry marker consumed at active-project resolution on BOTH layers — an expired session binding re-binds to none (the machine-wide default is never collateral), an expired default unlinks. Expiry never applies to operator-named projects, and an explicit `/project use <name>` clears the marker (operator ownership).

---

## RUN LIFECYCLE

When running any analysis command (`/scan`, `/validate`, `/understand`, `/codeql`, `/fuzz`, `/web`), use the run lifecycle stubs to create the output directory and track status:

**Before starting work:**
```bash
libexec/raptor-run-lifecycle start <command> --target <resolved_target> [--out <dir>]
```
Always pass `--target` with the resolved target path (see DEFAULT TARGET DIRECTORY for resolution order). Optionally pass `--out <dir>` to use a specific output directory. The last line of output is `OUTPUT_DIR=<path>` — use that path for all subsequent output files.

**After successful completion:**
```bash
libexec/raptor-run-lifecycle complete "$OUTPUT_DIR"
```

**On failure:**
```bash
libexec/raptor-run-lifecycle fail "$OUTPUT_DIR" "error description"
```

The `start` command automatically resolves the output directory using this session's project (session binding, then the last-activated default) or the default `out/` directory, and PINS the run to that project for its whole lifetime. Do not construct output paths manually.

**If `start` fails (non-zero exit):** STOP. Report the error to the user. Do not proceed with the command.

**Note:** `/validate` uses `libexec/raptor-validation-helper 0` instead of `raptor-run-lifecycle` — it bundles lifecycle management with inventory building.

Commands run via `python3 raptor.py` (scan, agentic, codeql, fuzz, web) manage lifecycle internally — do not call the stubs separately for those.

**Coverage tracking:** read-coverage is automatic — the coverage plugin (`plugins/coverage/`) hook logs which source files the LLM reads during the live run; details in `.claude/skills/coverage.md`.

---

## SECURITY: UNTRUSTED REPOS

When scanning untrusted repositories:

- **Environment sanitisation**: `RaptorConfig.get_safe_env()` uses a strict allowlist (`SAFE_ENV_ALLOWLIST`) — only ~30 explicitly named variables plus `LC_*` prefixes are kept; everything else is dropped. A secondary blocklist (`DANGEROUS_ENV_VARS`) covers `TERMINAL`, `EDITOR`, `VISUAL`, `BROWSER`, `PAGER` as belt-and-braces. Always use `get_safe_env()` when spawning subprocesses.
- **File path injection**: Never interpolate file paths from scanned repos into shell command strings. Use list-based `subprocess` arguments.

---

## OUTPUT STYLE

**Status values:**
- In JSON: snake_case (`exploitable`, `confirmed`, `ruled_out`, `disproven`)
- In human-readable output (reports, terminal): Title Case (`Exploitable`, `Confirmed`, `Ruled Out`)
- Never ALL_CAPS (`EXPLOITABLE`, `CONFIRMED`, `RULED_OUT`)

**No red/green status indicators:**
- Do not use 🔴/🟢 - perspective-dependent (bad for defenders ≠ bad for researchers)
- Other emojis are fine (⚠️, ✓, etc.)

---

## INTERACTIVE PROMPTS

Some commands and skills define decision points where an interactive session presents a structured choice with the AskUserQuestion tool instead of prose. These are interactive-only enhancements layered on the existing behavior — never new pipeline stages.

**The gate.** Before ANY AskUserQuestion, run `libexec/raptor-may-ask` (decision logic: `core/ux/interactivity.py`). Ask only when it prints `interactive` AND the AskUserQuestion tool is available to you. If it prints `non-interactive`, errors, or is missing — or the tool is absent — this session is a dispatched sub-agent, CI, or otherwise unattended: do NOT ask. Apply the instruction's documented non-interactive fallback (always the pre-existing default behavior) and say in your output which default you applied.

**Doctrine for ask instructions:**
- Every AskUserQuestion instruction in a command/skill file MUST name its non-interactive fallback.
- Asks live at run boundaries only — completion forks, consent that changes a FUTURE run, destructive confirms. Never insert an ask mid-pipeline where an autonomous flow would block on it.
- The first option carries the "(Recommended)" tag.
- Fill option labels and descriptions with the run's actual facts (paths, warning text, findings, `cost_usd` values from the report) — never invent flags, artifacts, or estimates.
- Never ask the operator to confirm or adjust an evidence-driven verdict — tool output is the verdict.
- Display integrity: any external, target-, server-, tool-, or LLM-derived text placed in AskUserQuestion question/option text (error excerpts, diff lines, finding titles, paths, hint text) must be rendered inert first — escape non-printable/control characters (the `core.security.log_sanitisation` contract: ESC/CSI/OSC, C1, bidi overrides become `\xHH`/`\uHHHH` escapes) and bound long excerpts with an explicit elision marker. Quote the escaped form; never paste raw bytes from a scanned repo, executed binary, or remote server into a consent prompt. Operator-authored constants and charset-validated names need no escaping.

---

## ANNOTATIONS

`/annotate` attaches free-form prose to individual functions, stored as markdown mirroring the source tree (the base directory defaults to the active project's `<output_dir>/annotations`). Operators write manual review notes via `/annotate add`.

**Authority tiers:** every add/edit stamps the invocation context (`tty=<which std fds were TTYs>`, `provenance=interactive-tty|non-tty`); `source` defaults to `human` when any std fd is a TTY, else `agent`. Readers grant human-grade weight (Reflexion veto, operator-tier FP primers, durable coverage evidence, IRIS spec promotion) only to `source=human` notes with an interactive-TTY stamp (or legacy pre-stamp notes). Never pass `--source human` from non-interactive calls — the non-tty stamp contradicts it and readers demote such notes to hint tier.

Storage format, status enum, staleness detection, operator workflow, substrate: `.claude/commands/annotate.md`.

---

## PROGRESSIVE LOADING

Load the named file when its trigger fires. For every subsystem listed here, the loaded file — not resident memory — is the source of flag syntax, gates, and workflow steps.

| Trigger | Load |
|---------|------|
| Scan completes (adversarial analysis guidance) | `tiers/analysis-guidance.md` |
| Validating exploitability — gates, methodology | `.claude/skills/exploitability-validation/SKILL.md` |
| /validate stage naming + pipeline order | `.claude/skills/exploitability-validation/PIPELINE.md` |
| Validation errors occur | `tiers/validation-recovery.md` |
| Developing exploits (constraints, techniques) | `tiers/exploit-guidance.md` |
| Any other error occurs | `tiers/recovery.md` |
| Expert persona requested | `tiers/personas/` (pick the persona's .md) |
| Running /understand | `.claude/skills/code-understanding/SKILL.md` plus the relevant mode file (map, trace, hunt, teach, or study) |
| Binary-oracle detail — flags, env build-on-demand, defenses, precision evidence | `.claude/skills/binary-oracle.md` |
| Binary exploit-feasibility detail — constraint classes, SMT/Z3 integration | `.claude/skills/binary-feasibility.md` |
| Coverage mark/unmark + full API | `.claude/skills/coverage.md` |
| /project full subcommand table + trust-marker consumer doctrine | `.claude/commands/project.md` |
| /annotate storage format, status enum, staleness, workflow | `.claude/commands/annotate.md` |
| /agentic flag doctrine, report modes, post-run fork | `.claude/commands/agentic.md` |
| /ask options + examples | `.claude/commands/ask.md` |
| /audit pipeline, gates, strategies, tool menu | `docs/audit.md` |
| /crash-analysis workflow, agents, requirements | `.claude/commands/crash-analysis.md` |
| /oss-forensics workflow, agents, output location | `.claude/commands/oss-forensics.md` |
| /diagram render matrix + when to re-render | `.claude/commands/diagram.md` |
| SAGE persistent-memory workflow (`sage_inception` present) | `core/sage/CLAUDE.md` |

---

## BINARY ANALYSIS

**Flow: Find vulnerabilities FIRST, then check exploitability.**

1. **Analyze the binary** - Find vulnerabilities (buffer overflows, format strings, etc.)
2. **If vulnerabilities found** - Run exploit feasibility analysis (MANDATORY)

```python
from packages.exploit_feasibility.api import analyze_binary, format_analysis_summary

# MANDATORY: Run this after finding vulnerabilities
result = analyze_binary('/path/to/binary')
print(format_analysis_summary(result, verbose=True))
```

**DO NOT use checksec or readelf instead** - they miss critical constraints (empirical %n verification, null-byte constraints from strcpy, ROP gadget quality, input-handler bad bytes, full RELRO blocking `.fini_array` too — not just the GOT). **The `exploitation_paths` section tells you if code execution is actually possible** given the system's mitigations (glibc version, RELRO, etc.). Constraint detail and the optional SMT/Z3 integration points: `.claude/skills/binary-feasibility.md`.

---

## BINARY-ORACLE REACHABILITY

Default behaviour (no flags): /agentic and /codeql auto-detect debug binaries under common build dirs, filter to **locally-built only** (untracked by git — committed binaries are dropped as unverified provenance), and use them to suppress dead-code findings. Pass `--no-binary-oracle` to opt out. With a declared binary (`--binary <path>`, repeatable), each native (C/C++/Rust/Go) function gets a per-binary verdict via DWARF + nm:

- `symbol_present` / `inlined` / `folded` — the function survived compilation in some form
- `absent` — the compiler / linker removed it from the analysed binary

`absent` is corpus-earned for suppression, conditional on full-DWARF evidence — a stripped binary in the analysed set downgrades to `tier="symbol_only"` and the chokepoint refuses to suppress. Chokepoint consumers: /codeql + /agentic (pre-LLM hard-suppress), /validate (proximity clamp), /understand --map (verdict annotation) — verbatim consumer text in `.claude/skills/binary-oracle.md`. Operator flags (`--binary-auto`, `--binary-edges`, `--target-kind=hybrid` multi-binary rules), env build-on-demand, `/project binary` persistence, hostile-binary defenses, and the precision evidence: `.claude/skills/binary-oracle.md`.

**Provenance-drop consent (interactive sessions only, after the run completes — never mid-pipeline):** when a run's output shows the `binary-oracle: N repo-committed binary(s) ignored (provenance unverified — could be planted or stale)` warning, offer the trust decision as a structured choice (see INTERACTIVE PROMPTS; gate with `libexec/raptor-may-ask` first). Options:
1. **Stay safe (Recommended)** — keep the drop; a committed binary can be attacker-planted or stale and would steer `absent` verdicts toward suppressing real findings, so verdicts continue to come only from locally-built (git-untracked) binaries.
2. **Trust for this run** — re-run with `--binary <path>` naming the dropped binary(s); list the exact paths from the warning in the description, quoting the warning's paths with non-printables escaped (committed binary paths are attacker-chosen file names). Grants: bypasses the git-tracked provenance filter for that one run, so the binary's DWARF/symbol data drives `absent`-verdict suppression.
3. **Persist via `/project binary add <path>`** — one add per dropped binary. Grants: the same trust as option 2, standing — auto-loaded by every subsequent `/agentic`, `/codeql`, `/validate` run on the active project.

**Non-interactive fallback:** current behavior — the binaries stay dropped; surface the warning plus the `--binary <path>` / `/project binary add` escape hatches in the run summary.

---

## EXPLOIT DEVELOPMENT

**Verify constraints BEFORE attempting any technique** — many hours are wasted on architecturally impossible approaches. MANDATORY: check the `exploitation_paths` verdict first (Unlikely = no known path, suggest environment changes; Difficult = primitives exist but hard to chain, be honest about challenges; Likely Exploitable = good chance, proceed with suggested techniques), then follow the `chain_breaks` (exactly what WON'T work) and `what_would_help` (what MIGHT). ALWAYS offer next steps, even for Difficult/Unlikely verdicts — **never just stop**; let the user decide how to proceed. Constraint tables, technique alternatives, and the next-steps fork: `tiers/exploit-guidance.md`.

---

## STRUCTURE

Python orchestrates everything. Claude shows results concisely.
Never circumvent Python execution flow.
- never disclose remote OLLAMA server location in code, comments, logs etc
- **Python path safety (runtime source — `core/`, `packages/`, and the `libexec/` launchers):** Never add anything to `sys.path` except `os.environ["RAPTOR_DIR"]`. Use the hard lookup (KeyError if unset) — no fallbacks, no `'.'`, no `os.getcwd()`, no hardcoded paths. The `libexec/` scripts handle their own path setup via `Path(__file__).resolve().parents[1]` and do not need `RAPTOR_DIR`. Test files (unit tests, self-tests, `conftest.py`, `.github/tests/`) and subsystem `scripts/` dirs are exempt: they run outside the launcher (bare pytest, CI runners) where `RAPTOR_DIR` is not set, so they locate the repo with `Path(__file__)`-relative setup by necessity. The exemption never extends to runtime modules.

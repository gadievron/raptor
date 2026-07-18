# RAPTOR Command Reference

The single source of truth for every RAPTOR slash command. Commands are grouped by
where they sit in a security workflow, not alphabetically. Start at the top
(**Plan & Setup**) and move down as you go from "what is this target" to
"here are the exploitable findings".

## How to read an entry

- **Purpose** — one line on what it does.
- **Key params** — the flags you reach for most. Not exhaustive.
- **Full flags** — every command with a `--help` prints its own authoritative flag
  list. When in doubt, run `<command> --help` (for `python3 raptor.py` and `libexec`
  commands) rather than trusting any summary — that is the source of truth for flags.
- **Maturity** — unmarked = stable. `(beta)` = usable, rough edges. `(alpha)` =
  experimental, expect false positives / incomplete coverage.

Eight high-surface commands have their own in-depth guide; those entries give the
essentials and link out. Every other command is documented in full here.

Slash form (`/scan`) and shell form (`raptor scan` / `python3 raptor.py scan` /
`libexec/raptor-...`) are equivalent — the slash command dispatches the shell command.

---

## Plan & Setup

Know your host and your target before you spend LLM budget scanning.

### /doctor

- **Purpose:** Host-level setup diagnostic — checks tools, LLM config, env vars,
  language toolchains, and the active project. Answers "is RAPTOR set up on this
  machine?" No LLM required; runs even when Claude itself is missing.
- **Key params:** `--strict` (also fail on warnings, for CI gating).
- **Run:** `raptor doctor` (or `python3 raptor.py doctor`). Prints failures first,
  then warnings, then a pass summary; non-zero exit on real failure.
- **Workflow:** Run once per host at first contact. Complements `/describe`.

### /describe

- **Purpose:** Target-level pre-flight — language mix, build system, catalog match,
  target-specific tool gaps, and a cost/time estimate for `/agentic`. Read-only: it
  never executes target code, never runs builds, never recommends shell commands.
- **Key params:** `<target>` (defaults to active project's target); `--json` for
  machine-readable output.
- **Run:** `libexec/raptor-describe --target <path> [--json]`.
- **Workflow:** Run per target at first contact. Complements `/doctor`.

### /tune

- **Purpose:** Show or update RAPTOR's resource tuning (parallelism, memory caps).
- **Key params:** bare `/tune` shows current resolved values + hardware; `/tune max`
  uses all available resources; `/tune balanced` for shared machines; `/tune default`
  resets to shipped defaults.
- **Run:** `libexec/raptor-tune [max|balanced|default]`.

### /project

- **Purpose:** Named workspaces that corral analysis runs into one shared directory.
  With an active project, commands write there instead of timestamped `out/` dirs.
- **Key subcommands:** `create <name> --target <path> [-d <desc>]`, `use <name>`
  (`none` clears), `list`, `status`, `coverage [--detailed]`, `findings [--detailed]`,
  `annotations`, `report`, `correlate`, `diff <run1> <run2>`, `merge`, `clean --keep <n>`,
  `export <path>` / `import <path>`, `rename`, `delete [--purge]`.
- **Binary oracle:** `project binary add <path>` / `list` / `remove` / `clear` persist
  debug binaries used for reachability enrichment on later `/agentic` and `/codeql` runs.
- **Run:** `libexec/raptor-project-manager <subcommand> [args]`. Destructive subcommands
  (`merge`, `clean`, `delete --purge`) require confirmation before `--yes`.
- **Full list:** `/project help`.

### /threat-model

- **Purpose:** Manage a project-owned threat model that steers `/agentic`,
  `/understand`, and `/validate` (focus areas, in/out-of-scope vuln classes, known bug
  shapes). Steers priority, not conclusions — claims are still proven from code.
- **Key subcommands:** `show` (default), `init`, `export`, `sync`, `lint`, `diff
  --context-map <path>`, `report`, `add --field <f> --value <v>`, `remove ...`,
  `build [agentic args]`, `refresh`, `use-stale`.
- **Run:** `libexec/raptor-threat-model <command> [args]`.

---

## Discover

Find vulnerabilities. Static scanners, dependency analysis, fuzzing, and the
autonomous orchestrator that ties them together.

### /agentic → [full guide](agentic.md)

- **Purpose:** The flagship autonomous workflow. Runs scan → dedup → prep →
  per-finding validate+analyse (exploitation-validator methodology, Stages A–D) →
  self-review → optional consensus/judge/aggregate → exploit PoCs → patches →
  cross-finding analysis. Nothing is applied to your code; everything lands in `out/`.
- **Key params:** `[path]` (or active-project/caller target); `--understand`
  (pre-map the codebase, add architectural priority markers); `--validate` (run the
  validation pipeline on exploitable findings afterwards); `--model <m>` (repeatable —
  multi-model correlation); `--consensus <m>`, `--judge <m>`, `--aggregate <m>`;
  `--sequential` (bypass parallel orchestration); `--binary <path>` / `--binary-auto` /
  `--no-binary-oracle` (reachability enrichment); `--max-findings <n>`.
- **Run:** `libexec/raptor-agentic --repo <path>` (flags pass straight through).
- **Full flags:** `libexec/raptor-agentic --help`.

### /scan

- **Purpose:** Fast static scan of a repository (Semgrep, with CodeQL available for
  deeper passes). SARIF findings, no LLM analysis by itself.
- **Key params:** `--repo <path>`; `--policy-groups <groups>` (e.g. `secrets,owasp`).
- **Run:** `python3 raptor.py scan --repo <path>`. Full flags: `raptor scan --help`.
- **Alias:** `/raptor-scan` (deprecated).

### /codeql

- **Purpose:** CodeQL deep static analysis with dataflow validation. Slower than
  Semgrep but finds tainted flows, use-after-free, and injection chains it misses.
  Optional Z3 SMT dataflow pre-check prunes provably-unreachable paths before the LLM.
- **Key params:** `--repo <path>` (required); `--languages <list>` (auto-detected if
  omitted); `--scan-only` (SARIF only, default) vs `--analyze` (LLM analysis + exploit
  gen); `--build-command <cmd>`; `--extended` (more rules, slower); `--force` (rebuild
  DB); `--max-findings <n>`.
- **Run:** `python3 raptor.py codeql --repo <path>`. Full flags: `raptor codeql --help`.

### /sca → [full guide](sca.md)

- **Purpose:** Software Composition Analysis — walks manifests + lockfiles, queries
  OSV/KEV/EPSS, runs reachability + supply-chain + hygiene checks, emits `findings.json`,
  `report.md`, and a CycloneDX SBOM. Can also fix and pin vulnerable dependencies.
- **Key params:** `<target>` (analyse whole project); `fix <target> [--apply]
  [--cve-only|--harden|--allow-major] [--no-llm]`; `check <ecosystem> <name> <version>`
  (pre-add verdict); `upgrade <ecosystem> <name> <from> <to>` (upgrade impact);
  `--fail-on-severity <s>` / `--fail-on-kev` (CI gate, exit 0/1); `--offline`.
- **Run:** `libexec/raptor-sca-run <target|subcommand> [args]`. Full flags:
  `raptor sca --help`.
- **Alias:** `/raptor-sca`.

### /fuzz → [full guide](fuzzing.md)

- **Purpose:** Binary fuzzing with AFL++. Finds crashes, then auto-analyses them and
  generates exploits.
- **Key params:** `--binary <path>` (required); `--duration <seconds>` (default 3600);
  `--corpus <path>` (seed inputs); `--max-crashes <n>`.
- **Run:** `python3 raptor.py fuzz --binary <path> --duration <sec>`. Full flags:
  `raptor fuzz --help`. Binary ideally compiled with AFL instrumentation + ASAN.
- **Alias:** `/raptor-fuzz`.

### /web  (alpha)

- **Purpose:** Web application scanner for OWASP Top 10 (XSS, SQLi, CSRF, etc.).
- **Key params:** `--url <url>`. Authenticated scanning is not currently supported —
  scan only unauthenticated endpoints you own.
- **Run:** `python3 raptor.py web --url <url>`. Full flags: `raptor web --help`.
- **Maturity:** alpha — expect false positives and incomplete coverage.
- **Alias:** `/raptor-web`.

---

## Understand

Build deep, adversarial comprehension of the code or binary before (or alongside)
scanning. This is where you map attack surface and trace flows.

### /understand  (beta) → [full guide](understand.md)

- **Purpose:** Deep code comprehension for security research — map the attack surface,
  trace one data flow source→sink, hunt variants of a pattern, or teach an unfamiliar
  framework. Output feeds `/validate` automatically via the bridge.
- **Key params:** `<target>`; `--map` (default — entry points, trust boundaries,
  sinks → `context-map.json`); `--trace <entry>` (one flow with full call chain);
  `--hunt <pattern>` (all variants → `variants.json`); `--teach <subject>` (inline
  explanation); `--out <dir>`; `--model <name>` (repeatable — multi-model, only for
  `--hunt`/`--trace`). Modes combine and run in order map → trace → hunt → teach. Also
  handles single compiled artefacts (ELF/Mach-O/PE/JAR/APK) via the binary substrate.
- **Run:** `libexec/raptor-understand [args]`.
- **Renamed:** formerly `/audit`. Use `/understand`.

### /binary → [full guide](binary-understanding.md)

- **Purpose:** Black-box binary investigation when source is unavailable —
  autonomous ranking, static map, parser tracing, fuzz handoff, graph queries,
  evidence-separated report. Evidence-first: imports/xrefs are candidates, never
  silently promoted to findings.
- **Key subcommands:** `investigate <binary>` (default), `map <binary>`,
  `runtime <binary>`, `trace-parser <run-dir>`, `harness <run-dir>`, `fuzz <binary>`,
  `graph <run-dir>`, `report <run-dir>`, `handoff <run-dir>`, `diagram <run-dir>`.
- **Key params:** `--runtime` / `--fuzz` / `--active` (opt-in dynamic phases; static
  only by default); `--quick`; `--slice-arch arm64|x86_64`; `--constraint-file <json>`;
  `--compare <older-binary>`.
- **Run:** `libexec/raptor-binary <command> [args]`.

---

## Analyse

Go deeper on findings you already have, or on a specific crash.

### /analyze

- **Purpose:** Run LLM analysis over existing SARIF findings from a previous scan —
  no re-scan. Use when you already have SARIF and want the analysis pass.
- **Key params:** `--repo <path>`; `--sarif <file>`; multi-model roles
  `--model`, `--consensus`, `--judge`, `--aggregate` (same semantics as `/agentic`;
  any role flag routes through the parallel orchestrator).
- **Run:** `python3 raptor.py analyze --repo <path> --sarif <file>`. Full flags:
  `raptor analyze --help`.

### /crash-analysis → [full guide](crash-analysis.md)

- **Purpose:** Autonomous root-cause analysis for C/C++ crashes. Fetches a bug report,
  clones and rebuilds with ASAN + debug symbols, reproduces the crash, generates rr
  traces / coverage / function traces, and runs a hypothesis-validation loop until a
  root cause is confirmed.
- **Key params:** `<bug-tracker-url> <git-repo-url>` (both positional).
- **Run:** dispatched as a multi-agent skill. Requires `rr`, `gcc`/`clang` with ASAN,
  `gdb`, and `gcov` on the host.
- **Output:** `crash-analysis-<timestamp>/` with rr trace, traces, gcov, and confirmed
  root-cause hypothesis docs.

---

## Validate

Confirm findings are real, reachable, and exploitable before investing in exploits.

### /validate → [full guide](validate.md)

- **Purpose:** Exploitability validation pipeline. Proves each finding is real,
  reachable, and exploitable — filtering scanner false positives, dead code, and
  unrealistic preconditions. You (Claude) are the LLM for stages A–D and F; mechanical
  stages 0, E, 1 run via `libexec`. Stages run 0 → A → B → C → D → E → F → 1
  (E applies to memory-corruption findings only).
- **Key params:** `<target>`; `--vuln-type <type>` (focus one class);
  `--findings <file>` (validate pre-existing scanner output, skips Stage A discovery);
  `--binary <path>` (for Stage E feasibility); `--skip-feasibility`; `--out <dir>`
  (share with `/understand`).
- **Run:** driven by the skill via `libexec/raptor-validation-helper <stage> "$OUTPUT_DIR"`.
- **Workflow:** after `/scan` or `/agentic`, before `/exploit`.

---

## Exploit & Patch

Act on confirmed findings — generate proof-of-concepts, secure fixes, or diff a CVE's
upstream fix.

### /exploit  (beta)

- **Purpose:** Generate working exploit PoCs (Python, C, pwntools) for findings.
  Does not generate patches — use `/patch` for that. For memory-corruption targets it
  runs a feasibility analysis first (empirical `%n` check, ROP gadget quality, bad-byte
  constraints) so it never suggests architecturally impossible techniques.
- **Requires:** findings from a previous `/scan` (or an identified vulnerability).
- **Run:** `python3 raptor.py agentic --repo <path> --no-patches --max-findings <n>`.
  PoCs land in `out/*/exploits/`.

### /patch  (beta)

- **Purpose:** Generate secure patch code for confirmed vulnerabilities. Does not
  generate exploits — use `/exploit` for that.
- **Requires:** findings from a previous `/scan`.
- **Run:** `python3 raptor.py agentic --repo <path> --no-exploits --max-findings <n>`.
  Patches land in `out/*/patches/`. Review before applying to production.

### /cve-diff

- **Purpose:** CVE patch discovery — an agentic loop searches OSV/NVD/GitHub/cgit/
  GitLab for a CVE's canonical fix commit, clones the repo, extracts the fix diff, and
  produces an analysis report + OSV JSON.
- **Key params:** `<CVE-ID>`; `--output-dir <dir>`; `--budget-multiplier <n>` (retry
  after a budget cap, e.g. `2`); `--with-root-cause` (classify vuln type + CWE).
  `/cve-diff health` runs a pre-flight reachability check.
- **Run:** `libexec/raptor-cve-diff run <CVE-ID> [options]`.
- **Requires:** `ANTHROPIC_API_KEY`; `GITHUB_TOKEN` recommended; `NVD_API_KEY` optional.

---

## Runtime

Observe the target executing.

### /frida  (alpha) → [full guide](frida/QUICKSTART.md)

- **Purpose:** Dynamic instrumentation via Frida — attach to (or spawn) a process,
  load a JS hook script, and capture `send(...)` events into a lifecycle-managed run
  directory. Local, USB-attached, and remote `frida-server` targets.
- **Key params:** `--target <pid|name|bundle-id|binary>`; one of `--template <name>`
  (bundled: `api-trace`, `ssl-unpin`) or `--script <path>` (your JS); `--host
  HOST[:PORT]`; `--usb`; `--duration <n>` (default 60); `--spawn` (hooks in place
  before `main()`); `--unsafe-attach` (forward-looking, logged only).
- **Run:** `libexec/raptor-frida --target ... (--template ... | --script ...)`.
- **Maturity:** alpha — two templates ship, sandbox envelope not yet wrapped.
- **Alias:** `/raptor-frida`.

---

## Report & Manage

Present results and manage the meta layer — diagrams, annotations, model scorecards,
version, and command discovery.

### /diagram  (beta)

- **Purpose:** Render Mermaid visual maps from `/understand` and `/validate` JSON
  outputs — entry points, trust boundaries, sinks, attack trees, and attack paths.
- **Key params:** `<out-dir>`; `--target <name>` (header label); `--stdout`
  (read-only preview); `--force` (overwrite existing `diagrams.md`).
- **Run:** `libexec/raptor-render-diagrams <out-dir> [args]`. Writes `diagrams.md`
  into the directory. Auto-generated at the end of `/validate` and `/understand`.

### /annotate

- **Purpose:** Attach free-form per-function prose to source, stored as markdown
  mirroring the source tree. Operator review notes plus auto-emitted notes from
  `/agentic` and `/understand`. Manual (`source=human`) notes are never silently
  clobbered by later LLM passes.
- **Key subcommands:** `add <file> <function>`, `ls`, `show <file> <function>`,
  `edit <file> <function>`, `rm <file> <function>`, `stale`.
- **Key params:** `--status <clean|suspicious|finding|error>`; `--cwe CWE-XX`;
  `-m/--body <text>` or `--body-file <path>`; `--lines N-M` (+ `--target <root>` for a
  staleness hash); `--base <path>` (defaults to active project's `annotations/` dir).
- **Run:** `libexec/raptor-annotate <subcommand> [args]`.

### /scorecard

- **Purpose:** Per-model reliability tracker — how often each LLM is overruled by an
  authoritative signal (full analysis, judge, consensus, tool evidence, operator
  feedback). Powers fast-tier short-circuit routing. Ask natural-language questions
  about which model is good at what.
- **Key subcommands:** bare `/scorecard` (list all cells); `list [flags]`
  (`--by-savings`, `--by-miss-rate`, `--untrusted`, `--learning`, `--consumer <prefix>`,
  `--since`, `--recency`); `compare <model-a> <model-b>`; `samples <decision_class>`;
  `pin` / `unpin`; `reset`.
- **Run:** `libexec/raptor-llm-scorecard [args]`. Output is markdown.

### /version

- **Purpose:** Report the running RAPTOR framework version.
- **Run:** `python3 raptor.py --version`. In a git checkout the value is the true
  position past the last release tag (`<tag>-<commits>-g<sha>`, `-local` when dirty).

### /commands

- **Purpose:** List all available RAPTOR slash commands, grouped by workflow stage,
  omitting any whose dependencies are missing.
- **Run:** dispatched as a skill (derives the list from installed skills).

### /create-skill  (alpha)

- **Purpose:** Save a successful custom approach (priorities, focus, techniques) as a
  reusable auto-loading skill under `.claude/skills/`.
- **Run:** dispatched as an interactive skill; walks you through capture → parameters →
  extraction → token-budget check → file creation (`<500` tokens).

---

## Forensics

A standalone investigative track — not part of the code-analysis pipeline.

### /oss-forensics

- **Purpose:** Evidence-backed forensic investigation of a public GitHub repository.
  Orchestrates specialist agents to query GH Archive (BigQuery), the live GitHub API,
  the Wayback Machine, and cloned-repo git forensics; forms evidence-backed hypotheses,
  verifies every claim against sources, and produces a forensic report with timeline,
  attribution, and IOCs.
- **Key params:** `<prompt>` (the investigation request, e.g. an incident or actor);
  `--max-followups <n>` (default 3, evidence rounds); `--max-retries <n>` (default 3,
  hypothesis revisions).
- **Run:** dispatched as a multi-agent skill.
- **Requires:** `GOOGLE_APPLICATION_CREDENTIALS` for BigQuery; internet access.
- **Output:** `.out/oss-forensics-<timestamp>/forensic-report.md`.

---

## Aliases & renames

Back-compat command names. Prefer the canonical form.

| Alias / old name | Canonical | Status |
|---|---|---|
| `/raptor-scan` | `/scan` | back-compat alias |
| `/raptor-fuzz` | `/fuzz` | back-compat alias |
| `/raptor-web` | `/web` | back-compat alias |
| `/raptor-sca` | `/sca` | back-compat alias |
| `/raptor-frida` | `/frida` | back-compat alias |
| `/raptor` | `/agentic` | generic assistant entry (routes to the agentic workflow) |
| `/audit` | `/understand` | renamed — `/audit` no longer used |

---

## In-depth guides

The eight highest-surface commands have dedicated guides:

| Command | Guide |
|---|---|
| `/agentic` | [agentic.md](agentic.md) |
| `/understand` | [understand.md](understand.md) |
| `/validate` | [validate.md](validate.md) |
| `/sca` | [sca.md](sca.md) |
| `/fuzz` | [fuzzing.md](fuzzing.md) |
| `/binary` | [binary-understanding.md](binary-understanding.md) |
| `/crash-analysis` | [crash-analysis.md](crash-analysis.md) |
| `/frida` | [frida/QUICKSTART.md](frida/QUICKSTART.md) |

Everything else is documented in full above. For any command's complete flag list,
run `<command> --help`.

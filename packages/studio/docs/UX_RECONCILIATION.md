# UX reconciliation: vulngraph patterns → raptor's actual shape

This document captures the design decisions that drive raptor-studio's information architecture. It's written for a reader who has touched vulngraph (from which we borrow) and is learning raptor (which we serve).

## TL;DR

Vulngraph has **one linear pipeline** (Ingest → Hunt → Precision → Pathways → Exploits → Report) because firmware RE is a sequential journey per binary. Raptor is a **branching framework** with three parallel lanes (source analysis, binary fuzzing, OSS forensics) that share a project container but do not compose into a single pipeline. The 240px project sidebar pattern carries over; the single six-stage pipeline inside it does not.

## What raptor actually is

From reading every file in `docs/` and `.claude/commands/`:

- **21 slash commands and 17 specialist agents.** This is not a tool; it's a framework with its own command system, agent taxonomy, progressive context loading, and budget controls.
- **Three execution modes that are mutually exclusive per run.** Source (`--repo`, Semgrep + CodeQL + LLM), binary (`--binary`, AFL++ + GDB + LLM), and OSS forensics (GitHub URL + GH Archive + Wayback). Not compose-able into one pipeline.
- **Two separate LLM layers.** Orchestration = Claude Code (always). Analysis = any provider via `~/.config/raptor/models.json`, with **four roles**: `analysis`, `code`, `consensus`, `fallback`.
- **Two-axis verdict model for findings.** `verdict` (exploitable / likely / difficult / unlikely / unknown) × `impact` (code_execution / dos / info_leak / resource_exhaustion / data_corruption / unknown). Null-deref can be `exploitable × dos`; format-string can be `exploitable × code_execution`. A single "severity" column is lossy.
- **Validation stages A–F on every finding.** A (not noise) → B (attacker reach + chain_breaks) → C (code verbatim, flow real) → D (not test code, not hedged) → E (binary feasibility with protections + glibc + ROP + constraints) → F (self-review). This is the core reasoning contribution; surfacing only "confidence: high/medium/low" throws it away.
- **Rich per-run artifacts beyond findings.** Attack surface, attack tree, hypotheses tried, disproven approaches, attack paths, checklist (ground truth), dataflow JSON + SVG, crash hypotheses (confirmed + rejected), rr traces, gcov coverage, exploit context with binary protections. Vulngraph has findings + exploits + pathways + diff. Raptor has an order of magnitude more kinds of artifact.
- **Nine expert personas** bound to specific packages (Exploit Developer → `llm_analysis/agent.py`, Crash Analyst → `llm_analysis/crash_agent.py`, etc.). Personas are a first-class UX primitive in raptor's CLI; they deserve surface area in the web UI too.
- **Budget is a real UX concern.** `RAPTOR_MAX_COST` caps spend per run; cost tracking is emitted per model call. Vulngraph doesn't model cost. We need to.

## What vulngraph's UX patterns do well — and what to keep

Kept wholesale:

- **Project as the container.** Everything hangs off a named project. Raptor agrees (via `/project`).
- **240px sidebar + main content shell.** Clean, proven. We use the same grid.
- **Expandable-row pattern for findings detail.** Works for raptor's rich per-finding data.
- **Dark mode by default, Inter + JetBrains Mono, monospace for paths/code.** Matches raptor's terminal heritage.
- **Stage indicators (○ pending / ◐ partial / ✓ complete).** The three-state visual is as useful for raptor as for vulngraph.
- **Empty states with configuration hints.** Raptor users will bounce off a web UI that shows nothing and explains nothing.
- **Card KPI layout on dashboard.** Kept.
- **Last-action CTA ("Next: Hunt →").** Kept, but computed per lane.

Adapted:

- **One pipeline sidebar → three-lane sidebar.** Overview + a "Navigation" cluster up top (Findings, Runs, Artifacts), then three grouped lanes (Source / Binary / Forensics), then Project meta (Activity, Settings). Each lane has its own numbered stages with their own status computation.
- **Composite score everywhere → two-axis verdict × impact, plus feasibility verdict when binary is present.** Users see `exploitable · code_execution · Full RELRO blocks GOT overwrite [binary]` instead of `composite 0.87`.
- **Mermaid attack-surface diagram → Mermaid from `attack-surface.json` (sources / sinks / trust boundaries).** Different data model, same affordance.

Dropped (do not apply):

- **COMPOSES_WITH graph edges.** Vulngraph-specific firmware concept; raptor doesn't chain findings that way.
- **EntryPoint `trust_level` with reachability math.** Different reachability model — raptor does path satisfiability via Z3 and CodeQL dataflow.
- **`disasm_hash` identity + firmware A/B diff.** Raptor diffs runs against the same repo (and uses git for source identity). Different axis.
- **"Precision hunt" 5-stage specialist pipeline.** Vulngraph-specific; raptor's equivalent is the A–F validation stages.

## Proposed information architecture

### Global nav (top)
- Dashboard · Projects · Settings

Dashboard shows cross-project stats (projects, active runs, findings by status, budget used). Settings is global (raptor's models.json + budget + default provider).

### Project sidebar (240px, left of every project page)
```
[Project Name]
target: /path/to/code
backend: source | binary | forensics

Overview                              (KPIs + next-action per lane)

── Navigation ──
Findings            (all, filterable)
Runs                (flat list, diff two)
Artifacts           (exploits + patches + reports)

── Source analysis ──
1. Understand       ○ / ◐ / ✓        (attack surface map)
2. Scan             ○ / ◐ / ✓        (Semgrep + CodeQL)
3. Validate         ○ / ◐ / ✓        (stages A–F)

── Binary fuzzing ──
1. Fuzz             ○ / ◐ / ✓        (AFL++ campaign)
2. Crash analysis   ○ / ◐ / ✓        (rr + hypotheses)

── Forensics ──
OSS forensics                        (investigate GitHub repo)

── Project ──
Activity                             (JSONL audit log)
Settings                             (project-scoped overrides)
```

Stage status is computed from run directories and `.raptor-run.json` command strings: e.g., "Scan" is ✓ if any run exists with command containing `scan`, `agentic`, or `codeql`; ◐ if any run is running; ○ if none.

### Routes (shipping in this iteration)

```
GET  /                                   dashboard (cross-project)
GET  /projects                           project list
GET  /projects/new                       new project form
POST /projects/new                       submit
GET  /projects/{name}                    overview (lane cards)
GET  /projects/{name}/findings           all findings, filtered by status/verdict/impact
GET  /projects/{name}/runs               flat run list, kind-typed
GET  /projects/{name}/runs/{run}         run detail (kind-aware)
GET  /projects/{name}/runs/{run}/findings
GET  /projects/{name}/understand         attack surface artifacts
GET  /projects/{name}/scan               scan runs overview
GET  /projects/{name}/validate           validation runs overview
GET  /projects/{name}/fuzz               fuzzing campaigns
GET  /projects/{name}/crash-analysis     crash analysis runs
GET  /projects/{name}/exploits           generated PoCs browser
GET  /projects/{name}/patches            generated patches browser
GET  /projects/{name}/reports            merged reports
GET  /projects/{name}/activity           JSONL audit tail
GET  /projects/{name}/settings           project overrides
GET  /settings                           global models + budget + personas
POST /settings                           update
```

### Findings view — raptor-literate

Finding row (collapsed):

```
[final_status]  [verdict × impact]  type   file:line                    [confidence]  ▶
exploitable     exploitable · RCE    cmd_injection   src/shell.py:42    high
```

Finding row (expanded):

- **Attack scenario** (one-paragraph prose)
- **Proof**: `source` · `sink` · `flow` (sequence)
- **Vulnerable code** (mono pre)
- **PoC payload + result** (mono pre)
- **Stage E feasibility** (if memory corruption): `binary_analysis.protections`, `exploitation_paths` (technique → target), `chain_breaks` tagged `[source]`/`[binary]`, `what_would_help`
- **Validation trail**: per-stage ruling (A/B/C/D/E/F) with pass/fail icon + reasoning quote

This is strictly richer than vulngraph's findings view — because raptor's data is strictly richer.

### Settings — raptor's actual knobs

Two sections:

1. **Models config (`~/.config/raptor/models.json`).** Four role cards (analysis / code / consensus / fallback); each holds provider + model + api_key_ref. We write the file and show which env vars are set as fallbacks. Budget input (`RAPTOR_MAX_COST`) lives here too.

2. **Project overrides.** Per-project overrides of the global defaults, written to a raptor-studio sidecar at `~/.raptor-studio/project-overrides/<name>.json` (raptor itself doesn't read this yet — these are studio-scoped until upstreamed).

We do not store API keys in plaintext on disk from the web UI unless the user explicitly chooses "store in file" — otherwise we write them to the system keyring or accept them only as env refs (`${ANTHROPIC_API_KEY}`).

## What shipped in this iteration

All of the below landed across two commits (`42ac26a`, `a follow-up`):

1. **IA reshape.** `project_base.html` shared shell with the three-lane sidebar, `project.html` rewritten as a lane-cards overview with next-action CTA, run-kind detection in `services/run_kind.py`, per-stage pages for every navigation item.
2. **Findings upgrade.** Raptor-literate findings template (`final_status` / `verdict` × `impact` / Stage E feasibility block with protections + exploitation_paths + chain_breaks + what_would_help), finding detail extracted to `_finding_detail.html` and shared between per-run and project-wide findings views.
3. **SARIF fallback.** `services/sarif_reader.py` parses Semgrep + CodeQL SARIF 2.1.0 into the same shape the rest of the UI expects. `RaptorRun.findings()` falls back to SARIF when no `findings.json` is present, so a plain `/scan` run renders its findings with zero extra config.
4. **Run-detail page.** `/projects/{name}/runs/{run}` shows kind + command + artifact summary (findings count, exploits, patches, scan metrics if present, fuzzing report if present, validation bundle counts). Deep-links down to findings / exploits / patches.
5. **Validation bundle reader.** `services/validation_reader.py` loads `findings.json`, `attack-tree.json`, `hypotheses.json`, `disproven.json`, `attack-paths.json`, `attack-surface.json`, `validation-report.md` in one call. `summarize_run()` feeds the run-detail page.
6. **Settings page.** `services/models_reader.py` reads + writes `~/.config/raptor/models.json` in raptor's exact schema. Four role cards (analysis / code / consensus / fallback), env-var status table, budget cap display. API-key env refs (`${ANTHROPIC_API_KEY}`) preserved; raw keys masked in display.
7. **Artifacts browsers.** Exploits, Patches, Reports, Activity pages walk the well-known subdirs of each run.
8. **Tests.** 23 → 78 (16 run_kind, 10 models_reader, 7 artifacts_reader, 6 sarif_reader, 6 validation_reader, 9 existing). All green.
9. **End-to-end.** 10/10 content-checks pass against a seeded project with a SARIF-only scan, a rich `/validate` run (full artifact bundle), and a `/fuzz` run (fuzzing_report + AFL crashes).

## Remaining punch-list

- Coverage view (needs `gcov` reader and `checked_by` merge)
- First-class rendering of raptor's dataflow SVG diagrams (`dataflow_*.svg`)
- Markdown rendering for `*.md` reports instead of raw `<pre>` blocks
- Auth / multi-user (raptor is single-user by design)

Shipped: three-lane IA, findings schema, SARIF fallback, run-detail page, validation bundle reader, attack-surface Mermaid, settings page, create-project, run triggering, SSE log streaming, run diff, OSS forensics walkthrough, per-persona panels.

## Shipped in the job-triggering pass

- **Job queue** (`services/jobs.py`) backed by SQLite at `$STUDIO_DATA_DIR/jobs.db`. Schema: `(id, project_name, kind, target, argv_json, status, created_at, started_at, finished_at, exit_code, pid, log_path, run_dir, error)`. Status machine: `queued → running → completed|failed|cancelled`.
- **Background worker** (`services/worker.py`) — daemon thread polling the queue, `subprocess.Popen` with `start_new_session=True` so we can cancel the whole process group, stdout+stderr redirected to `$STUDIO_DATA_DIR/job-logs/<id>.log`.
- **Run-spec translation** (`services/run_spec.py`) — four runnable kinds with typed form fields (`agentic`, `scan`, `codeql`, `fuzz`). Claude-only kinds (`understand`, `validate`, `oss-forensics`, `crash-analysis`) expose a CLI-hint fallback instead of a runnable form.
- **UI**:
  - `+ New run` button on every runnable stage page.
  - `/projects/{name}/{kind}/new` — typed form with live CLI preview.
  - `/projects/{name}/jobs` + `/jobs/{id}` — project + detail views.
  - `/jobs/{id}/cancel` — SIGTERM the process group, mark cancelled.
- **Live log tail via SSE** — `/api/jobs/{id}/stream` emits `event: log` and `event: status` frames; the job detail page consumes it with `EventSource`, auto-reloads on terminal status. Poll interval 0.4s; tails the log file by byte offset.
- **Sidebar** gains a "Jobs" entry under "Project".
- **Lifecycle** — worker `start()` on FastAPI startup, `stop()` on shutdown.

Tests: 78 → 103. New: `test_run_spec` (11), `test_jobs` (9), `test_worker_integration` (4 — actually spawns subprocesses).

End-to-end verified via TestClient: GET new-run form → POST → 303 redirect to `/jobs/{id}` → worker picks up → subprocess completes → log captured → detail page + project jobs list + API log endpoint all show the job correctly.

## Shipped in the diff + forensics + personas pass

- **Run diff** (`services/diff_reader.py`) classifies findings across two runs by identity tuple `(file, line, normalized_vuln_type)` — matching raptor's SARIF dedup rule — into `new` / `carried` / `resolved`. Carried findings surface status + verdict transitions (e.g., `pending → exploitable`). Route `/projects/{name}/diff?a=&b=` with two dropdowns and three coloured result tables. Sidebar adds a "Diff" entry under Navigation.
- **OSS forensics walkthrough** (`services/forensics_reader.py`) reads the artifacts an `/oss-forensics` run emits (`evidence.json`, `evidence-verification-report.md`, `hypothesis-*.md` iterations, `forensic-report.md`). `run_detail.html` gains a dedicated walkthrough card when the run is oss-forensics: research question highlighted, evidence-source count table, hypothesis timeline as collapsible cards with confirmed/rejected badges derived from filename hints, collapsible verification report, final forensic report in a prominent box.
- **Expert personas** (`services/personas.py`) reads the 10 markdown briefs at `$RAPTOR_HOME/tiers/personas/*.md`. `personas_for_finding(f)` ranks relevant personas by vuln category (memory-corruption → binary specialists; web → pen tester), tool origin (`tool=codeql` → CodeQL analysts), final status (`exploitable` → exploit developer + patch engineer), filename hints (`afl_output/crashes/*` → fuzzing strategist). Inline cards on every expanded finding detail (capped at 4); full `/personas` browser page via top nav.

Tests: 103 → 128 (+1 skipped). Added `test_diff_reader` (9), `test_forensics_reader` (7), `test_personas` (10).

End-to-end HTTP verified across the pass:
- **Diff**: seeded two runs with overlapping + status-upgraded + resolved + new findings → all four buckets render correctly; error paths handle same-run and missing-run selections.
- **Forensics**: seeded a synthetic oss-forensics run with three hypothesis iterations (one refuted, one confirmed, one neutral) and four evidence sources; 8/8 content checks pass including confirmed + rejected badges and evidence count table.
- **Personas**: seeded three findings of different types (memory-corruption with feasibility, sqli, codeql auth_bypass); each shows the correct specialist cards, `/personas` lists all 10 briefs with load-state.

## Shipped in the project-types + Claude-backed-triggers pass (commit `6a86777`)

- **Typed projects** — `/projects/new` gains a 3-card picker (Source analysis / Binary fuzzing / OSS forensics). Form adapts per type: target label + placeholder swap between "Repository path", "Binary path", "GitHub URL"; type-specific fields surface (CodeQL language for source, optional source-repo for binary, Research question for forensics).
- **URL targets preserved** — forensics projects skip `Path.resolve()` so GitHub URLs aren't mangled. Raptor's schema validator still accepts them because it just requires a non-empty string.
- **Studio sidecar** — `services/project_extras.py` persists `(type, binary, focus, language)` to `$STUDIO_DATA_DIR/project-extras/<name>.json`. Raptor's CLI ignores it; studio uses it to drive the adaptive sidebar and smart defaults on trigger forms.
- **Claude-backed triggers** — the four kinds that previously showed only a CLI hint (`understand`, `validate`, `oss-forensics`, `crash-analysis`) now trigger via the job queue. Worker wraps them as `bash -c "raptor project use <name> && claude -p '<slash-command>'"`. Form shows a "REQUIRES CLAUDE CODE" badge; Equivalent CLI preview reads the real bash wrapper.
- Tests: 135 → 144. Added `test_project_extras` (10), extended `test_run_spec` coverage.

## Shipped in the newcomer UX pass (commit `ace3ef8`)

Design thesis for this pass, from the user's brief:

> Optimize for making it easy to use for new users, without dumbing it down. Surface the options without being overwhelming.

Six concrete moves, each with a named principle:

1. **Welcoming zero-state on the Dashboard** — *replace empty-screen paralysis with one focused next step.* When `stats.projects == 0` the four `0`-KPIs and empty tables disappear; a single centered welcome card takes over with the velociraptor mark, tagline, big "Create your first project →" button, 5-bullet "What you can do here" list, and a collapsed `<details>` hint for users who already have raptor projects at a non-default `RAPTOR_PROJECTS_DIR`. When projects exist, the previously dead "read-only / Mode" KPI is replaced by a live "Worker: idle / N live" KPI tied to the running-run count.

2. **Progressive disclosure on `/projects/new`** — *show essentials, tuck power into "More options".* Essentials visible: type cards, Name, Target, Description. Everything else (Notes, Output directory, CodeQL language, source-repo sidecar, focus) folds into `<details>` "Advanced options", default-closed, auto-open on form replay if any advanced field has a value. Smart-default JS: when Name is empty and Target is edited, auto-fill Name with the target's basename (or URL's last path segment, minus `.git`), sanitised to raptor's name regex.

3. **Type-adaptive sidebar** — *scope reveals itself from context.* `project_base.html` reads `project.kind` (from sidecar or inferred from runs). For typed projects, the relevant lane renders prominently and the other two lanes tuck into a collapsed "Other capabilities" `<details>`. Auto-opens if the active stage is inside a hidden lane. Untyped projects keep today's three-lane layout. Typed projects drop from 13 visible sidebar items to ~7.

4. **Contextual empty-state CTAs** — *an empty page should answer "what now?".* `/findings`, `/runs`, `/exploits`, `/patches`, `/reports` stop being silent when empty. Each shows a card naming what's missing, explaining when it fills, and deep-linking to the single most likely next action for this project's kind (scan for source, fuzz for binary, oss-forensics for forensics).

5. **Progressive disclosure on trigger forms** — *defaults first, overrides on demand.* `project_new_run.html` splits fields into Essentials (required or sole field) and Advanced (rest). Advanced is a `<details>` with badge count, default-collapsed, localStorage-sticky per kind so a returning user's preference persists. For fuzz: duration stays essential, the other 5 fields collapse.

6. **Glossary + inline `<abbr>` tooltips** — *name a concept, always define it once.* New `/glossary` page with six grouped cards covering finding lifecycle, validation stages A–F, binary-exploit anatomy, scanner output (CWE/SARIF/dataflow), pipelines/lanes, and personas. Footer link from every page. Inline `<abbr>` tooltips with dotted-underline styling in `_finding_detail.html` on the most opaque terms: "Stage E", "Chain breaks", "Exploitation paths".

All template + routing. Zero service-layer change. Tests unchanged because the underlying behavior is identical — just a friendlier surface.

## Constraint: do not modify vulngraph

Vulngraph is referenced read-only at `~/Projects/vulngraph/vulngraph/web/`. We borrow layout grammar and CSS idioms. We do not import, link, or copy whole templates.

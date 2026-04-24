# raptor studio — Product Requirements

Status: in-tree at `packages/studio/` (this PR).

---

## 1. What this is

A FastAPI + Jinja2 web UI for raptor. Reads and writes raptor's project data, triggers all of raptor's command families (`scan`, `agentic`, `codeql`, `fuzz`, `understand`, `validate`, `oss-forensics`, `crash-analysis`), streams run logs live, and renders raptor's full finding schema inline — including Stage E feasibility, chain-breaks, exploitation paths, inline CodeQL dataflow SVGs, and an OSS forensics walkthrough.

## 2. Who it's for

A security researcher who is already running raptor on their own machine. Single-user. Operates from their own `$HOME`. Not a multi-tenant deployment.

Two user archetypes studio tries to serve simultaneously:

- **Newcomer** — has cloned raptor and maybe run `raptor project create` once; wants to understand what runs are possible and trigger their first one without reading the manual. Should feel on-boarded within 60 seconds of opening the dashboard.
- **Returning power user** — knows what every command does; wants to browse rich raptor output without retyping `raptor project findings --detailed` every time, and wants to cross-reference runs visually. Should not feel "dumbed down" or miss raptor's full data model.

The design thesis mediating between them:

> Easy for newcomers, not dumbed down, options surfaced without overwhelm.

## 3. Relationship to raptor

- **In-tree**: lives at `packages/studio/` alongside `packages/exploitability_validation/`, `packages/codeql/`, etc. Launched via `python3 raptor_studio.py` from the raptor repo root.
- **Pristine schema**: projects created from the UI write raptor's exact 7-field `project.json` schema. Indistinguishable from `raptor project create`. A test imports `core.project.schema.validate_project` and runs it against studio output.
- **Sidecar for studio-only fields**: metadata that doesn't belong in raptor's schema (project type hint, optional secondary source-repo, focus, language, seed-corpus, vendor-report URL) lives in `$STUDIO_DATA_DIR/project-extras/<name>.json`. Raptor's CLI ignores it. Projects created by `raptor project create` (no sidecar) still work — type is inferred from their runs.
- **Provider-agnostic services**: the services layer doesn't import raptor's runtime. Only `services/raptor_version.py` imports `core.config.RaptorConfig.VERSION` for the top-right display.
- **Companion repo for provenance**: the 27-commit development history lives at [yesnet0/raptor-studio](https://github.com/yesnet0/raptor-studio). This in-tree commit squashes that for reviewability.

## 4. Capabilities

### 4.1 Browsing

- **Dashboard** — cross-project KPIs, recent runs, worker status; dedicated welcome state when no projects exist.
- **Projects list** — every registered project with target, output dir, run count.
- **Project overview** — three-lane status cards (source / binary / forensics), next-action CTA, recent-runs table.
- **Findings** — per-project and per-run views rendering raptor's full schema:
  - `final_status` (exploitable / likely / constrained / blocked / unverified / confirmed / ruled_out)
  - Verdict × impact two-axis
  - Stage E feasibility block with protections, exploitation paths (technique → target), `chain_breaks` tagged `[source]`/`[binary]`, `what_would_help`
  - Per-finding attack scenario, proof (source / sink / flow), vulnerable code, PoC payload
  - Per-finding relevant-persona cards (capped at 4, ranked by specificity)
- **Runs** — flat list + per-run detail with kind-aware artifact summary (scan metrics, fuzzing report, validation bundle counts, SARIF files, reports, inline CodeQL dataflow SVGs).
- **Exploits / Patches / Reports / Activity** — walk every run's well-known subdirs; Activity tails JSONL audit logs.
- **Diff** — compare two runs by `(file, line, normalized_vuln_type)` → new / carried / resolved; carried rows show status and verdict transitions.
- **Attack surface visualization** — when `attack-surface.json` is present, render sources → trust-boundaries → sinks as a Mermaid flowchart plus structured lists.
- **OSS forensics walkthrough** — research question, evidence count table, hypothesis iterations with confirmed/rejected badges, evidence verification, final forensic report (all markdown-rendered).
- **Personas** — all 10 raptor expert personas loaded from `tiers/personas/*.md`; per-finding cards plus a full `/personas` browser.
- **Glossary** — `/glossary` page with grouped cards covering finding lifecycle, validation stages A–F, binary-exploit anatomy, scanner output, pipelines, personas.

### 4.2 Triggering

- **Create project** — typed form (source / binary / forensics) with progressive disclosure; sanitised name auto-inferred from target basename via JS. Forensics targets preserved as URLs (skip `Path.resolve`).
- **Trigger runs** — SQLite-backed job queue + daemon-thread worker + SSE log streaming:
  - Pure-Python kinds (`scan`, `agentic`, `codeql`, `fuzz`) spawn `python3 raptor_*.py`
  - Claude-backed kinds (`understand`, `validate`, `oss-forensics`, `crash-analysis`) wrap as `bash -c "raptor project use <name> && claude -p '<slash-command>'"`
  - Each kind has a typed form with Essentials + `<details>` Advanced (localStorage-sticky).
- **Cancel** — `POST /jobs/{id}/cancel` SIGTERMs the whole process group.
- **Configure raptor models** — read/write `~/.config/raptor/models.json` in raptor's exact 4-role schema.

### 4.3 Navigation

- **Top nav**: Dashboard / Projects / Personas / Settings.
- **Per-project sidebar**: Overview + Navigation (Findings / Runs / Diff) + type-adaptive lane section + Artifacts (Exploits / Patches / Reports) + Project (Jobs / Activity / Settings). Adaptive: for typed projects the irrelevant lanes collapse into "Other capabilities".
- **Glossary** + inline `<abbr>` tooltips on the most opaque schema terms.

## 5. Non-goals (explicit)

- **Auth / multi-user**: single-user, by design — matches raptor's own model.
- **Replacing raptor's CLI**: every UI-triggered action surfaces its Equivalent CLI so power users can always reproduce outside the browser. The UI is additive, not a wall.
- **Long-running service ops**: no log rotation, no graceful shutdown of mid-flight subprocesses on restart, no multi-instance coordination. It's a dev-time local tool.
- **Changing any existing raptor behavior**: studio adds, never edits.

## 6. Non-functional requirements

| Area | Target |
|---|---|
| Startup | `python raptor_studio.py` reaches ready-to-serve in < 2 s on a laptop |
| Cold-cache page render | < 200 ms for any page, assuming local filesystem |
| SSE log-tail latency | ≤ 500 ms from raptor subprocess stdout to browser |
| Zero-project first impression | One meaningful CTA, no dead KPIs, no empty tables |
| Newcomer form load | `/projects/new` shows ≤ 5 visible fields by default |
| Schema preservation | Projects created here round-trip cleanly through `raptor project list` and `raptor project findings` |
| Test coverage | ≥ 140 pytest green per release (current: 160 + 1 skipped) |

## 7. Open work (post-absorption)

Ordered by expected value.

1. **Coverage view** — `gcov`/`checked_by` merge per project; "which files did raptor actually read?" heatmap.
2. **Job-history KPIs** on Dashboard — tokens used today, $ spent this week, most-common failure kind.
3. **Per-finding persona invocation** — a "Re-run with Exploit Developer persona" button that kicks off a scoped job.
4. **Log rotation** inside `$STUDIO_DATA_DIR/job-logs/` for long-running installs.
5. **Attack-tree visualization** — render `attack-tree.json` as a collapsible tree rather than raw JSON.

## 8. Constraints and invariants

- **Do not extend raptor's `project.json` schema** — use the studio sidecar at `$STUDIO_DATA_DIR/project-extras/` instead.
- **Every UI-triggered subprocess must surface its Equivalent CLI** — so power users can always reproduce the action outside the UI.
- **Zero service-layer churn on pure UX changes** — polish passes edit templates and routes only; `services/` stays frozen unless a new capability demands it.
- **The velociraptor mark** — kept minimal, pixel-art, transparent-bg. PNG stores pure black; dark mode relies on CSS `filter: invert(1)` rather than shipping two files. Regenerate via `scripts/process_avatar.py` if the source changes.
- **Top-right chrome (version pill + theme toggle)** — visually mirrors vulngraph for consistency across the two sibling tools.
- **Version pill shows raptor's version, not studio's** — read live from `core.config.RaptorConfig.VERSION`. No hardcoded version strings; the pill is simply suppressed if the import fails.

## 9. Pointers

- `/glossary` in the running app — plain-language definitions for every schema term the UI surfaces.
- `docs/FAQ.md` — pre-answers likely maintainer questions (scope, architecture, security, ops, future).
- `docs/ARCHITECTURE.md` — one-page call-flow + request lifecycles + state locations.
- `docs/UX_RECONCILIATION.md` — the design narrative for why studio's IA looks the way it does.
- `docs/CHANGELOG.md` — full development history, commit by commit.

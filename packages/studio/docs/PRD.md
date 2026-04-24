# raptor-studio — Product Requirements

Status: **v0.0.1 — functionally complete, pre-absorption.**
Last updated: 2026-04-23 (commit `cd58dc9`).

---

## 1. What this is

`raptor-studio` is a web UI for [raptor](https://github.com/gadievron/raptor), the autonomous offensive/defensive security research framework by Gadi Evron et al. Raptor's reasoning quality (Semgrep + CodeQL + multi-stage LLM validation + AFL++ + Z3 + GH Archive forensics) is excellent, but its native surface is a terminal and a Claude Code slash-command grammar. That's fine for solo deep-dives; it's friction for browsing findings at volume, triaging across runs, diffing before/after, and sharing with non-terminal stakeholders.

raptor-studio puts raptor's output in a browsable web surface and lets a single user trigger raptor runs from a form. It **borrows** the UX grammar proven by `vulngraph` (project-centric navigation, pipeline-status sidebar, evidence-inline findings, Mermaid graphs) and **serves** raptor's actual data model (SARIF ingestion, Stage A-F validation, verdict × impact, feasibility, chain-breaks, OSS-forensics artifacts, expert personas).

## 2. Who it's for

**Primary user**: a security researcher who is already running raptor on their own machine. Single-user. Operates from their own `$HOME`.

**Not in scope**: multi-tenant deployments, team collaboration, auth/SSO, enterprise SaaS. If that changes later, it will be explicit.

Two user archetypes the UX serves:

- **Newcomer** — has cloned raptor, perhaps run `raptor project create` once; wants to understand what runs are possible and trigger their first one without reading the manual. Should feel on-boarded within 60 seconds.
- **Returning power user** — knows what every command does; wants to browse rich raptor output without retyping `raptor project findings --detailed` every time, and wants to cross-reference runs visually. Should not feel "dumbed down" or miss raptor's full data model.

The design thesis that mediates between them:

> Easy for newcomers, not dumbed down, options surfaced without overwhelm.

## 3. Relationship to raptor

- **Non-fork**: `raptor-studio` is a separate repository. Raptor is cloned into `$RAPTOR_HOME` (default `~/Projects/raptor/`) and read as a dependency.
- **Pristine schema**: Projects created from the UI land in `$RAPTOR_PROJECTS_DIR/<name>.json` using raptor's exact 7-field schema (`version, name, target, output_dir, description, notes, created`). A project created here is indistinguishable from one created by `raptor project create` — round-trip clean.
- **Sidecar for studio-only fields**: Studio-specific metadata lives in `$STUDIO_DATA_DIR/project-extras/<name>.json`. Current fields:
  - `type` — `source` / `binary` / `forensics`
  - `source_repo` — secondary source tree (binary projects that also want to run source analysis)
  - `focus` — research question for forensics
  - `vendor_report_url` — vendor incident report to validate against (forensics)
  - `language` — CodeQL language hint (source)
  - `corpus_dir` — AFL++ seed corpus directory (binary; pre-fills the fuzz trigger form)
  Raptor's CLI ignores the sidecar. Raptor-created projects without one still work — type is inferred from their runs.
- **Upstream target**: The package layout mirrors where it would live inside raptor (`packages/studio/`). Path-moving is the only friction between this repo and an upstream PR.

## 4. Capabilities

### 4.1 Read-only browsing

- **Dashboard** — cross-project KPIs (projects, runs, findings, worker state); welcome state when no projects exist.
- **Projects list** — every registered project with target, output, run count.
- **Project overview** — three-lane status cards (source / binary / forensics), next-action CTA, recent-runs table.
- **Findings** — per-project and per-run views with raptor's full schema rendered:
  - `final_status` (exploitable / likely / constrained / blocked / unverified / confirmed / ruled_out)
  - verdict × impact two-axis model
  - Stage E feasibility block with protections, exploitation paths (technique → target), chain_breaks tagged `[source]`/`[binary]`, what_would_help
  - Per-finding attack scenario, proof (source/sink/flow), vulnerable code, PoC payload
  - Per-finding relevant-persona cards (capped at 4, ranked by specificity)
- **Runs** — flat list + per-run detail with kind-aware artifact summary (scan metrics, fuzzing report, validation bundle counts, SARIF files, reports).
- **Exploits / Patches / Reports / Activity** — walk every run's well-known subdirs; Activity tails JSONL audit logs.
- **Diff** — compare two runs by `(file, line, normalized_vuln_type)` → new / carried / resolved; carried rows show status and verdict transitions.
- **Attack surface visualization** — when `attack-surface.json` is present, render sources → trust-boundaries → sinks as a Mermaid flowchart plus structured lists.
- **OSS forensics walkthrough** — dedicated run-detail card: research question → evidence count table → hypothesis iterations (with confirmed/rejected badges) → evidence verification → final forensic report.
- **Personas** — all 10 raptor expert personas loaded from `$RAPTOR_HOME/tiers/personas/*.md`; per-finding cards plus a full `/personas` browser.

### 4.2 Write / trigger

- **Create project** — typed form (source / binary / forensics) with progressive disclosure; sanitised name auto-inferred from target basename via JS. Forensics targets preserved as URLs (skip `Path.resolve`).
- **Trigger runs** — SQLite-backed job queue + daemon-thread worker + SSE log streaming:
  - Pure-Python kinds (`scan`, `agentic`, `codeql`, `fuzz`) spawn `python3 raptor_*.py ...`
  - Claude-backed kinds (`understand`, `validate`, `oss-forensics`, `crash-analysis`) wrap as `bash -c "raptor project use <name> && claude -p '<slash-command>'"`
  - Each kind has a typed form with Essentials + `<details>` Advanced (localStorage-sticky).
- **Cancel** — POST `/jobs/{id}/cancel` SIGTERMs the process group.
- **Configure raptor models** — read/write `~/.config/raptor/models.json` in raptor's exact schema (4 role cards: analysis / code / consensus / fallback).

### 4.3 Navigation

- **Top nav**: Dashboard / Projects / Personas / Settings.
- **Per-project sidebar**: Overview + Navigation (Findings / Runs / Diff) + type-adaptive lane section + Artifacts (Exploits / Patches / Reports) + Project (Jobs / Activity / Settings). Adaptive: for typed projects the irrelevant lanes collapse into "Other capabilities".
- **Glossary**: `/glossary` with grouped cards covering finding lifecycle, validation stages, binary-exploit anatomy, scanner output, pipelines, personas. Inline `<abbr>` tooltips in findings detail for the most opaque terms.

## 5. Non-goals (explicit)

- **Auth / multi-user**: single-user, by design — matches raptor's own model.
- **Markdown rendering of `*.md` reports**: raw `<pre>` for now. A markdown-renderer is deferred.
- **Coverage view**: `gcov` reader + `checked_by` merge view isn't shipped; post-MVP.
- **Dataflow SVG rendering**: raptor writes `dataflow_*.svg`; we don't embed them yet.
- **Replacing raptor's CLI**: Every UI-triggered action's "Equivalent CLI" preview shows the exact command a power user could copy — raptor-studio is additive, not a wall.

## 6. Non-functional requirements

| Area | Target |
|---|---|
| Startup | `uvicorn studio.app:app` reaches ready-to-serve in < 2s on a laptop |
| Cold-cache page render | < 200ms for any page, assuming local filesystem |
| SSE log-tail latency | ≤ 500ms from raptor subprocess stdout to browser |
| Zero-project first impression | One meaningful CTA, no dead KPIs, no empty tables |
| Newcomer form load | `/projects/new` should show ≤ 5 visible fields by default |
| Schema preservation | Projects created here round-trip cleanly through `raptor project list` and `raptor project findings` |
| Test coverage | ≥ 140 pytest green per release (current: 144 + 1 skipped) |

## 7. Shipped milestones

A full list lives in `docs/CHANGELOG.md`. High-level:

| Milestone | Commit | What it delivered |
|---|---|---|
| Initial scaffold | `2bf5061` | FastAPI + Jinja2 skeleton; 7 tests |
| TemplateResponse fix | `64429e5` | Starlette 0.37+ compat |
| Create project | `90b5273` | UI create flow, raptor schema round-trip |
| Three-lane IA | `42ac26a` | Shared project shell, typed sidebar, rich findings schema, settings page, SARIF fallback |
| SARIF + run detail | `05c8cf2` | Per-run summary page, validation bundle reader |
| Attack-surface Mermaid | `a4399af` | Live flowchart from `attack-surface.json` |
| Job queue + SSE | `3fac61d` | SQLite jobs, worker thread, live log streaming |
| Run diff | `a70c8a8` | new / carried / resolved classification |
| OSS forensics walkthrough | `2ba6866` | Evidence + hypothesis timeline reader |
| Personas | `559d162` | Per-finding persona cards + `/personas` browser |
| Avatar | `bde028a` | Pixel-art raptor logo + favicon |
| Demo seed script | `b7aa80c` | One-shot `scripts/seed_demo.py` |
| Project types + Claude-backed triggers | `6a86777` | Type picker; `/understand`, `/validate`, `/oss-forensics`, `/crash-analysis` runnable via `claude -p` wrapper |
| Newcomer UX pass | `ace3ef8` | Welcome zero-state, progressive disclosure, adaptive sidebar, contextual CTAs, glossary + abbr tooltips |
| Docs: PRD + CHANGELOG | `0f10c50` | Canonical product doc, commit log, refreshed README and UX narrative |
| Option-matrix alignment | `1a1b686` | `corpus_dir`, `vendor_report_url`; rename `binary` → `source_repo`; trigger forms pre-fill from project-level defaults |
| Dataflow SVGs | `92b1187` | Embed CodeQL `dataflow_*.svg` inline on run detail; safe file-serving route with path-traversal + extension-whitelist protection |
| Markdown rendering | `a84bf3f` | `*.md` reports render as HTML with fenced code / tables / headings instead of raw `<pre>`; "view raw" escape hatch per block |
| Avatar cleanup | `e8d9348` | Transparent-bg + pure-black PNG so `filter: invert(1)` in dark mode produces a clean white raptor with no backing rectangle in either theme |
| Top-right match to vulngraph | `cd58dc9` | Version pill + theme toggle adopt vulngraph's exact styling (green status dot, 36×36 single-glyph toggle) |
| Live raptor version | (latest) | Version pill reads `VERSION = "..."` from `$RAPTOR_HOME/core/config.py` — no hardcoded strings; omitted cleanly when raptor isn't locatable |

## 8. Open work

Ordered by expected value.

1. ~~**Dataflow SVG rendering**~~ ✅ shipped — CodeQL run dirs' `dataflow_*.svg` now render inline on run detail with paired-JSON links.
2. ~~**Markdown rendering** for `*.md` reports~~ ✅ shipped — validation-report / forensic-report / hypothesis iterations now render as structured HTML with a "view raw" escape hatch.
3. **Coverage view** — `gcov`/`checked_by` merge per project, with "which files did raptor actually read?" heatmap.
4. **Job history KPIs** on Dashboard — e.g. tokens used today, $ spent this week, most-common failure kind.
5. **Per-finding persona invocation** — a "Re-run with Exploit Developer persona" button that kicks off a scoped job.
6. **Upstream absorption** — open an issue on `gadievron/raptor`, then PR the code under `packages/studio/`. Requires (a) raptor maintainer signal and (b) path-moving only.

## 9. Constraints and invariants

- **Do not modify vulngraph** — referenced read-only at `~/Projects/vulngraph/vulngraph/web/` for layout idioms only; never imported, never copied as templates.
- **Do not extend raptor's `project.json` schema** — use the studio sidecar at `$STUDIO_DATA_DIR/project-extras/` instead.
- **Every UI-triggered subprocess must surface its Equivalent CLI** — so power users can always reproduce the action outside the UI.
- **Zero service-layer churn on pure UX changes** — polish passes edit templates and routes only; `services/` stays frozen unless a new capability demands it.
- **The velociraptor mark** — kept minimal, pixel-art, transparent-bg. PNG stores pure black; dark mode relies on CSS `filter: invert(1)` rather than shipping two files. Regenerate via `scripts/process_avatar.py` if the source changes.
- **Top-right chrome (version pill + theme toggle)** — visually mirrors vulngraph for consistency across the two sibling tools. If vulngraph's design changes, re-scrape from the live instance and update.
- **Version pill shows raptor's version, not studio's** — read live from `$RAPTOR_HOME/core/config.py` via `services/raptor_version.py`. No hardcoded version strings; the pill is simply suppressed when raptor can't be located.

## 10. Glossary pointer

See `/glossary` in the app or `docs/UX_RECONCILIATION.md` for a longer design narrative. Raptor's own docs live at `$RAPTOR_HOME/docs/`.

# raptor studio

A web UI for raptor — browse findings, trigger scans / fuzz / forensics, watch runs live, diff project versions, review exploit PoCs — without leaving the browser.

Reads and writes raptor's project data (`~/.raptor/projects/*.json` + per-run output directories); projects created in the UI are fully interchangeable with `raptor project create`.

**Companion repo**: this package was developed in the open at [yesnet0/raptor-studio](https://github.com/yesnet0/raptor-studio) (27 commits of history). The commit in this PR squashes that history for reviewability; the full timeline lives there.

## Quick start

From the raptor repo root:

```bash
pip install -r requirements.txt    # includes studio's extra deps
python3 raptor_studio.py           # → http://127.0.0.1:8765
```

If you have no raptor projects yet, the Dashboard shows a Welcome card with a **Create your first project →** button. If you already have projects (from `raptor project create` or a previous studio session), they appear immediately.

**Want a loaded demo?**

```bash
PYTHONPATH=. python3 packages/studio/scripts/seed_demo.py
RAPTOR_PROJECTS_DIR=~/.raptor-studio-demo/projects python3 raptor_studio.py
```

The seed script creates three representative projects (source analysis / binary fuzzing / OSS forensics) with realistic run artifacts.

## Capabilities

| | |
|---|---|
| **Browsing** | Dashboard · Projects · per-project Overview · Findings with full schema (final_status, verdict × impact, Stage E feasibility, chain_breaks, exploitation_paths) · Runs · Diff |
| **Per-run** | Kind-aware summary with scan metrics, fuzzing report, validation bundle counts · inline CodeQL dataflow SVGs · OSS forensics walkthrough (evidence, hypothesis timeline, final report) |
| **Triggering** | Create project (3 types: source / binary / forensics) · SQLite-backed job queue + subprocess worker · live log streaming via SSE · cancel via SIGTERM · Equivalent CLI preview on every form |
| **Runnable kinds** | `scan`, `agentic`, `codeql`, `fuzz` (pure Python) · `understand`, `validate`, `oss-forensics`, `crash-analysis` (shell out to `claude -p`) |
| **Configuration** | Global Settings edits `~/.config/raptor/models.json` (analysis / code / consensus / fallback roles) · Personas browser for the 10 expert briefs · Glossary page for schema terms |

## Environment

| Variable | Default | Purpose |
|---|---|---|
| `RAPTOR_PROJECTS_DIR` | `~/.raptor/projects` | Where raptor stores project registry entries |
| `RAPTOR_OUTPUT_BASE` | `out/projects` | Default base path for new projects' output dirs |
| `STUDIO_DATA_DIR` | `~/.raptor-studio` | Job queue DB, job logs, project-extras sidecars |
| `RAPTOR_MODELS_CONFIG` | `~/.config/raptor/models.json` | Raptor's per-role LLM config |

## Structure

```
packages/studio/
├── app.py                  # FastAPI entry point (~20 routes)
├── config.py               # env-driven runtime paths
├── services/               # 14 modules — readers, writers, job queue, worker, classifiers
├── templates/              # 23 Jinja2 templates (dark + light, Mermaid dataflow, markdown)
├── static/                 # velociraptor avatar + (reserved for future css/js)
├── tests/                  # 17 test modules (161 tests, incl. live-subprocess worker)
├── scripts/                # seed_demo.py, process_avatar.py
├── docs/
│   ├── PRD.md              # product requirements (why, who, what's in / out of scope)
│   ├── CHANGELOG.md        # commit-by-commit narrative
│   └── UX_RECONCILIATION.md    # design narrative: vulngraph patterns + raptor data model
└── fixtures/               # test inputs
```

## Tests

```bash
cd <raptor root>
pip install pytest httpx
python -m pytest packages/studio/tests/
```

Expect 161 passed, 1 skipped.

## Design thesis

> Easy for newcomers, not dumbed down, options surfaced without overwhelm.

Raptor's reasoning quality (Semgrep + CodeQL + Stage A–F validation + AFL++ + Z3 + GH Archive forensics) is excellent, but its native surface is a terminal and a Claude-Code slash-command grammar. That's fine for solo deep-dives; it's friction for browsing findings at volume, triaging across runs, diffing before/after, and sharing with non-terminal stakeholders.

The UX borrows idioms from [vulngraph](https://github.com/yesnet0/vulngraph) (project-centric navigation, pipeline-status sidebar, evidence-inline findings, Mermaid graphs) and serves raptor's actual data model (SARIF, Stage A–F validation, verdict × impact, feasibility, chain-breaks, OSS-forensics artifacts, expert personas).

See `docs/PRD.md` and `docs/UX_RECONCILIATION.md` for the full rationale.

## License

MIT (matches raptor).

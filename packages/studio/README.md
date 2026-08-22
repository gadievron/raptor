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

## Security model

Studio is a single-user tool that can launch raptor jobs and browse the
filesystem, so its HTTP surface is locked down (`packages/studio/security.py`):

- **Cross-origin writes rejected** — state-changing requests with a foreign
  `Origin` / `Sec-Fetch-Site` are refused, and every form carries a
  per-instance CSRF token. A malicious website in your browser cannot drive
  the UI at `127.0.0.1`.
- **Host-header validation** — while bound to loopback (the default), requests
  must name a loopback host, which defeats DNS-rebinding pages that would
  otherwise read responses cross-origin.
- **Sanitised report rendering** — raptor report markdown is rendered through
  `nh3`; script tags, event handlers, and `javascript:` URLs in report
  content are stripped (reports embed model output and scanned-repo text,
  which are untrusted).
- **Sanitised job environment** — worker subprocesses start from
  `RaptorConfig.get_safe_env()` plus a deliberate list of provider/API and
  raptor path variables, not the full host environment.
- **Remote binding is opt-in** — a non-loopback `--host` requires
  `--allow-remote`, prints a warning, and provisions an access token that
  every client must present (`?token=…` once, exchanged for a cookie, or
  `Authorization: Bearer`). Local browsers are not exempt: host-header
  validation is off in remote mode, and the token is what keeps a
  DNS-rebound page in a local browser out (its hostname's cookie jar
  can never hold the auth cookie). Note the `?token=` first-visit URL
  lands in browser history and access logs. Prefer an SSH tunnel over
  remote exposure.

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
│   ├── PRD.md              # product requirements — scope, invariants, non-goals
│   ├── FAQ.md               # pre-answers to likely maintainer questions
│   ├── ARCHITECTURE.md      # one-page call-flow + request lifecycles + state locations
│   ├── UX_RECONCILIATION.md # design narrative: vulngraph patterns + raptor data model
│   └── CHANGELOG.md        # commit-by-commit narrative
└── fixtures/               # test inputs
```

## Tests

```bash
cd <raptor root>
pip install pytest httpx
python -m pytest packages/studio/tests/
```

Expect 160 passed, 1 skipped.

## Design thesis

> Easy for newcomers, not dumbed down, options surfaced without overwhelm.

Raptor's reasoning quality (Semgrep + CodeQL + Stage A–F validation + AFL++ + Z3 + GH Archive forensics) is excellent, but its native surface is a terminal and a Claude-Code slash-command grammar. That's fine for solo deep-dives; it's friction for browsing findings at volume, triaging across runs, diffing before/after, and sharing with non-terminal stakeholders.

The UX borrows idioms from [vulngraph](https://github.com/yesnet0/vulngraph) (project-centric navigation, pipeline-status sidebar, evidence-inline findings, Mermaid graphs) and serves raptor's actual data model (SARIF, Stage A–F validation, verdict × impact, feasibility, chain-breaks, OSS-forensics artifacts, expert personas).

Full rationale: [`docs/PRD.md`](docs/PRD.md) · anticipated maintainer questions: [`docs/FAQ.md`](docs/FAQ.md) · call-flow: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) · design narrative: [`docs/UX_RECONCILIATION.md`](docs/UX_RECONCILIATION.md).

## License

MIT (matches raptor).

# Architecture

One-page call-flow of what happens when a user triggers a run through studio.

## Components

```
┌────────────────────────────────────────────────────────────────────┐
│  Browser (user)                                                    │
│    ├─ renders Jinja2 templates                                    │
│    ├─ EventSource for /api/jobs/{id}/stream (SSE)                 │
│    └─ POST /projects/{n}/{kind}/new                               │
└──────────┬─────────────────────────────────────────┬───────────────┘
           │                                         │
           ▼                                         │ SSE tail
┌──────────────────────────┐             ┌──────────────────────────┐
│  FastAPI  (app.py)       │             │  /api/jobs/{id}/stream   │
│    routes → services     │             │  (_stream_job async gen) │
└──┬─────────┬─────────┬───┘             └─────────▲────────────────┘
   │         │         │                           │ reads log
   │         │         └──► services/run_spec.py   │
   │         │             build_command()         │
   │         │                  │                  │
   │         │                  ▼                  │
   │         │         services/jobs.py            │
   │         │         enqueue() → SQLite          │
   │         │                  │                  │
   │         ▼                  ▼                  │
   │   templates/       ┌───────────────────────┐  │
   │   Jinja2 renders   │  services/worker.py   │  │
   │                    │  daemon thread        │──┘ writes line-buffered
   │                    │  poll next_queued()   │
   │                    │       │               │
   │                    │       ▼               │
   │                    │  subprocess.Popen     │
   │                    │  start_new_session=T  │
   │                    └───────┬───────────────┘
   │                            │
   ▼                            ▼
services/                raptor subprocess
readers                 (raptor_agentic.py,
  ├─ raptor_reader       raptor_codeql.py,
  ├─ sarif_reader        raptor_fuzzing.py,
  ├─ forensics_reader    OR bash -c "… && claude -p '/slash'")
  ├─ validation_reader         │
  ├─ diff_reader               ▼
  ├─ artifacts_reader    ~/.raptor/projects/<n>.json
  └─ models_reader      <project.output_dir>/<run_name>/*
                                │
                                └──► read back by readers on next request
```

## Request lifecycles

### 1. Create project

```
POST /projects/new
  → services/raptor_writer.create_project()
    • validates name regex
    • resolves target path (or preserves URL for forensics)
    • writes ~/.raptor/projects/<name>.json          ← raptor's schema
    • writes $STUDIO_DATA_DIR/project-extras/<name>.json  ← studio extras
  → 303 redirect to /projects/{name}
```

### 2. Browse findings

```
GET /projects/{name}/findings
  → services/raptor_reader.get_project(name)
  → project.runs()                                   # scan run dirs
    → RaptorRun.findings()
      if findings*.json exists: load JSON
      else:                    services/sarif_reader.parse_run_sarif()
  → template project_findings_all.html
    → _finding_detail.html per row
      → services/personas.personas_for_finding(f)    # rank relevant personas
```

### 3. Trigger a run (pure-Python kind)

```
GET /projects/{name}/{kind}/new
  → loads RunnableKind spec (FormField list per kind)
  → renders project_new_run.html with Essentials + <details> Advanced

POST /projects/{name}/{kind}/new
  → services/run_spec.build_command(kind, target, form_values, project_name)
    → ["python3", "raptor_agentic.py", "--repo", target, …]
  → services/jobs.enqueue(Job(...))                  # SQLite insert
  → 303 to /jobs/{id}

Background:
  services/worker._loop()
    → jobs.next_queued()
    → subprocess.Popen(job.argv, cwd=RAPTOR_HOME,
                       start_new_session=True,
                       stdout/stderr → $STUDIO_DATA_DIR/job-logs/<id>.log)
    → jobs.mark_running(pid, log_path)
    → proc.wait()
    → jobs.mark_finished(exit_code, run_dir)

SSE live tail:
  GET /api/jobs/{id}/stream
    → async generator yields
        event: log  \ndata: <line>\n\n
        event: status\ndata: <status>\n\n
    → closes when job.is_terminal
    → browser EventSource auto-reloads page on terminal status
```

### 4. Trigger a Claude-backed run

Identical queue/worker flow, but `build_command` returns:

```
["bash", "-c",
 "bash $RAPTOR/bin/raptor project use <name> && claude -p '/<slash-cmd>'"]
```

`start_new_session=True` on the Popen means `POST /jobs/{id}/cancel` SIGTERMs the whole process group (bash + raptor + claude) rather than orphaning children.

## State locations

| What | Where | Who writes |
|---|---|---|
| Raptor project registry | `~/.raptor/projects/<name>.json` | Raptor CLI + studio create-project |
| Per-project output | `<project.output_dir>/<run>/…` | Raptor subprocesses |
| Studio job queue | `$STUDIO_DATA_DIR/jobs.db` | `services/jobs.py` |
| Studio job logs | `$STUDIO_DATA_DIR/job-logs/<id>.log` | `services/worker.py` |
| Studio project extras | `$STUDIO_DATA_DIR/project-extras/<name>.json` | `services/project_extras.py` |
| Raptor models config | `~/.config/raptor/models.json` | Raptor + studio settings page |

All studio state is local-filesystem. Nothing in `packages/studio/` itself is mutable at runtime.

## Module layering

```
templates/           views (Jinja2)
  │
  ▼
app.py              route handlers — thin; delegates to services
  │
  ▼
services/           business logic
  ├─ readers        (raptor_reader, sarif_reader, forensics_reader, …)
  ├─ writers        (raptor_writer, models_reader)
  ├─ classifiers    (run_kind, run_spec, project_extras, personas)
  ├─ queue          (jobs, worker)
  └─ renderers      (markdown_render)
```

No cross-layer imports other than templates → (context from) app.py → services. Services do not import templates or FastAPI; they're independently testable as pure functions / dataclasses.

## Testing boundaries

- **Unit**: each service module has its own `test_*.py`, uses `pytest.tmp_path` for fixture dirs.
- **Integration**: `test_worker_integration.py` actually `subprocess.Popen`s short commands to exercise the full queue lifecycle.
- **Schema round-trip**: `test_raptor_writer.test_schema_matches_raptor_validate_project` imports `core.project.schema.validate_project` and runs it against studio's output — would catch drift from raptor's canonical schema.
- **Smoke**: seeded fixtures + `fastapi.testclient.TestClient` exercise every route end-to-end.

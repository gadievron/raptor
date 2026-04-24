"""raptor-studio FastAPI entry point.

Read-write web UI for raptor projects.

    uvicorn studio.app:app --reload
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import AsyncIterator, Optional

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from packages.studio.config import (
    APP_TAGLINE,
    APP_TITLE,
    RAPTOR_HOME,
    RAPTOR_MODELS_CONFIG,
    RAPTOR_OUTPUT_BASE,
    RAPTOR_PROJECTS_DIR,
    STUDIO_DATA_DIR,
)
from packages.studio.services import jobs as jobs_service
from packages.studio.services import worker as worker_service
from packages.studio.services.artifacts_reader import (
    list_exploits,
    list_patches,
    list_reports,
    tail_activity,
)
from packages.studio.services.run_spec import (
    RUNNABLE_KINDS,
    UnsupportedKind,
    build_command,
    is_runnable,
)
from packages.studio.services.diff_reader import compute_diff
from packages.studio.services.forensics_reader import is_forensics_run_dir, load_forensics_bundle
from packages.studio.services.markdown_render import render as render_markdown
from packages.studio.services.personas import all_personas, personas_for_finding
from packages.studio.services.raptor_version import raptor_version
from packages.studio.services.project_extras import (
    PROJECT_TYPE_DESCRIPTIONS,
    PROJECT_TYPE_LABELS,
    PROJECT_TYPES,
)
from packages.studio.services.validation_reader import load_validation_bundle, summarize_run
from packages.studio.services.models_reader import (
    PROVIDERS,
    ROLE_DESCRIPTIONS,
    ROLES,
    ModelConfig,
    ModelEntry,
    current_budget_cap,
    env_status,
    load_models_config,
    save_models_config,
)
from packages.studio.services.raptor_reader import RaptorProject, get_project, list_projects
from packages.studio.services.raptor_writer import ProjectCreateError, create_project
from packages.studio.services.run_kind import (
    STAGE_DESCRIPTIONS,
    STAGE_LABELS,
    lane_for,
    lane_status,
    next_action,
    stages_for,
)

BASE_DIR = Path(__file__).parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

# Expose personas_for_finding globally to templates so _finding_detail.html
# can render persona cards inline without every route having to pass it.
templates.env.globals["personas_for"] = personas_for_finding
# Markdown filter: `{{ some_md_text | md | safe }}` — for raptor reports.
templates.env.filters["md"] = render_markdown

app = FastAPI(title=APP_TITLE)
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")


def _ctx(**kwargs) -> dict:
    return {
        "app_title": APP_TITLE,
        "app_tagline": APP_TAGLINE,
        "raptor_version": raptor_version(),
        **kwargs,
    }


def _project_ctx(project: RaptorProject, active_stage: str, **extras) -> dict:
    """Build the context dict needed by every `project_base`-derived page."""
    runs = project.runs()
    return _ctx(
        project=project,
        runs=runs,
        lane_status=lane_status(runs),
        next_action=next_action(runs, project_kind=project.kind),
        active_stage=active_stage,
        **extras,
    )


def _require_project(name: str) -> RaptorProject:
    proj = get_project(name)
    if proj is None:
        raise HTTPException(404, f"project not found: {name}")
    return proj


def _stage_runs(project: RaptorProject, stage: str):
    return [r for r in project.runs() if stage in stages_for(r.kind)]


def _cli_hint(stage: str, project: RaptorProject) -> dict:
    target = project.target
    hints = {
        "understand":     {"command": f"raptor project use {project.name}\nclaude\n/understand --map", "explanation": "Run inside Claude Code after selecting this project."},
        "scan":           {"command": f"raptor project use {project.name}\npython3 raptor.py scan --repo {target}", "explanation": "Static analysis with Semgrep (and CodeQL if --languages is set)."},
        "validate":       {"command": f"raptor project use {project.name}\nclaude\n/validate", "explanation": "Runs the A–F validation pipeline on existing findings."},
        "fuzz":           {"command": f"python3 raptor_fuzzing.py --binary <path-to-binary> --autonomous --duration 3600", "explanation": "Binary fuzzing mode — provide a compiled binary, not a repo."},
        "crash-analysis": {"command": "claude\n/crash-analysis <bug-tracker-url> <git-repo-url>", "explanation": "Requires rr on Linux x86_64 and a reproducer input."},
        "oss-forensics":  {"command": "claude\n/oss-forensics <github-url>", "explanation": "Needs GOOGLE_APPLICATION_CREDENTIALS for GH Archive BigQuery."},
    }
    return hints.get(stage, {"command": "", "explanation": ""})


# --- Dashboard ------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    projects = list_projects()
    runs = [run for p in projects for run in p.runs()]
    findings_count = sum(len(r.findings()) for r in runs)
    return templates.TemplateResponse(
        request,
        "dashboard.html",
        _ctx(
            projects=projects[:5],
            recent_runs=sorted(runs, key=lambda r: r.timestamp, reverse=True)[:10],
            stats={
                "projects": len(projects),
                "runs": len(runs),
                "findings": findings_count,
            },
            projects_dir=str(RAPTOR_PROJECTS_DIR),
        ),
    )


# --- Projects list + new --------------------------------------------------

@app.get("/projects", response_class=HTMLResponse)
def projects_index(request: Request):
    return templates.TemplateResponse(
        request, "projects.html",
        _ctx(projects=list_projects(), projects_dir=str(RAPTOR_PROJECTS_DIR)),
    )


def _new_project_ctx(**overrides):
    default_output = str((RAPTOR_OUTPUT_BASE.expanduser() / "<name>"))
    type_cards = [
        {"key": t, "label": PROJECT_TYPE_LABELS[t], "description": PROJECT_TYPE_DESCRIPTIONS[t]}
        for t in PROJECT_TYPES
    ]
    ctx = {
        "form": {}, "error": None,
        "default_output": default_output,
        "projects_dir": str(RAPTOR_PROJECTS_DIR),
        "studio_dir": str(STUDIO_DATA_DIR),
        "project_types": type_cards,
    }
    ctx.update(overrides)
    return _ctx(**ctx)


@app.get("/projects/new", response_class=HTMLResponse)
def new_project_form(request: Request):
    return templates.TemplateResponse(request, "new_project.html", _new_project_ctx())


@app.post("/projects/new")
async def new_project_submit(request: Request):
    form = await request.form()
    raw = {k: (form.get(k) or "").strip() for k in (
        "name", "target", "description", "output_dir", "notes",
        "project_type",
        "source_repo",
        "focus", "vendor_report_url",
        "language", "corpus_dir",
    )}

    try:
        proj = create_project(
            name=raw["name"],
            target=raw["target"],
            description=raw["description"],
            output_dir=raw["output_dir"] or None,
            notes=raw["notes"],
            project_type=raw["project_type"] or None,
            source_repo=raw["source_repo"],
            focus=raw["focus"],
            vendor_report_url=raw["vendor_report_url"],
            language=raw["language"],
            corpus_dir=raw["corpus_dir"],
        )
    except ProjectCreateError as e:
        return templates.TemplateResponse(
            request, "new_project.html",
            _new_project_ctx(form=raw, error=str(e)),
            status_code=400,
        )
    return RedirectResponse(url=f"/projects/{proj.name}", status_code=303)


# --- Project shell: overview + top-level nav -------------------------------

@app.get("/projects/{name}", response_class=HTMLResponse)
def project_overview(request: Request, name: str):
    proj = _require_project(name)
    return templates.TemplateResponse(
        request, "project.html",
        _project_ctx(proj, active_stage="overview"),
    )


@app.get("/projects/{name}/findings", response_class=HTMLResponse)
def project_findings_all(request: Request, name: str):
    proj = _require_project(name)
    items = []
    for run in proj.runs():
        for f in run.findings():
            items.append({"run": run, "finding": f})
    return templates.TemplateResponse(
        request, "project_findings_all.html",
        _project_ctx(proj, active_stage="findings", findings=items),
    )


@app.get("/projects/{name}/runs", response_class=HTMLResponse)
def project_runs(request: Request, name: str):
    proj = _require_project(name)
    return templates.TemplateResponse(
        request, "project_runs.html",
        _project_ctx(proj, active_stage="runs", run_lane=lambda r: lane_for(r.kind)),
    )


@app.get("/projects/{name}/diff", response_class=HTMLResponse)
def project_diff(request: Request, name: str, a: str = "", b: str = ""):
    proj = _require_project(name)
    all_runs = proj.runs()
    run_a = next((r for r in all_runs if r.name == a), None) if a else None
    run_b = next((r for r in all_runs if r.name == b), None) if b else None

    diff = None
    error: Optional[str] = None
    if a and not run_a:
        error = f"Run A not found: {a}"
    elif b and not run_b:
        error = f"Run B not found: {b}"
    elif a and b and a == b:
        error = "Pick two different runs."
    elif run_a and run_b:
        diff = compute_diff(
            run_a.name, run_a.findings(),
            run_b.name, run_b.findings(),
        )

    return templates.TemplateResponse(
        request, "project_diff.html",
        _project_ctx(
            proj, active_stage="diff",
            a=run_a, b=run_b, diff=diff, error=error,
        ),
    )


# --- Per-stage lane pages (shared template) -------------------------------

def _stage_page(request: Request, name: str, stage: str):
    proj = _require_project(name)
    return templates.TemplateResponse(
        request, "project_stage.html",
        _project_ctx(
            proj, active_stage=stage,
            stage_key=stage,
            stage_label=STAGE_LABELS.get(stage, stage),
            stage_desc=STAGE_DESCRIPTIONS.get(stage, ""),
            stage_runs=_stage_runs(proj, stage),
            cli_hint=_cli_hint(stage, proj),
            is_runnable=is_runnable(stage),
        ),
    )


@app.get("/projects/{name}/understand", response_class=HTMLResponse)
def project_understand(request: Request, name: str):
    return _stage_page(request, name, "understand")


@app.get("/projects/{name}/scan", response_class=HTMLResponse)
def project_scan(request: Request, name: str):
    return _stage_page(request, name, "scan")


@app.get("/projects/{name}/validate", response_class=HTMLResponse)
def project_validate(request: Request, name: str):
    return _stage_page(request, name, "validate")


@app.get("/projects/{name}/fuzz", response_class=HTMLResponse)
def project_fuzz(request: Request, name: str):
    return _stage_page(request, name, "fuzz")


@app.get("/projects/{name}/crash-analysis", response_class=HTMLResponse)
def project_crash_analysis(request: Request, name: str):
    return _stage_page(request, name, "crash-analysis")


@app.get("/projects/{name}/oss-forensics", response_class=HTMLResponse)
def project_oss_forensics(request: Request, name: str):
    return _stage_page(request, name, "oss-forensics")


# --- Artifacts / meta -----------------------------------------------------

@app.get("/projects/{name}/exploits", response_class=HTMLResponse)
def project_exploits(request: Request, name: str):
    proj = _require_project(name)
    return templates.TemplateResponse(
        request, "project_exploits.html",
        _project_ctx(proj, active_stage="exploits", exploits=list_exploits(proj)),
    )


@app.get("/projects/{name}/patches", response_class=HTMLResponse)
def project_patches(request: Request, name: str):
    proj = _require_project(name)
    return templates.TemplateResponse(
        request, "project_patches.html",
        _project_ctx(proj, active_stage="patches", patches=list_patches(proj)),
    )


@app.get("/projects/{name}/reports", response_class=HTMLResponse)
def project_reports(request: Request, name: str):
    proj = _require_project(name)
    return templates.TemplateResponse(
        request, "project_reports.html",
        _project_ctx(proj, active_stage="reports", reports=list_reports(proj)),
    )


@app.get("/projects/{name}/activity", response_class=HTMLResponse)
def project_activity(request: Request, name: str):
    proj = _require_project(name)
    return templates.TemplateResponse(
        request, "project_activity.html",
        _project_ctx(proj, active_stage="activity", activity=tail_activity(proj)),
    )


@app.get("/projects/{name}/settings", response_class=HTMLResponse)
def project_settings(request: Request, name: str, save_ok: int = 0):
    proj = _require_project(name)
    return templates.TemplateResponse(
        request, "project_settings.html",
        _project_ctx(proj, active_stage="settings",
                     save_ok=bool(save_ok),
                     projects_dir=str(RAPTOR_PROJECTS_DIR)),
    )


@app.post("/projects/{name}/settings")
def project_settings_save(
    name: str,
    description: str = Form(""),
    notes: str = Form(""),
):
    """Update description/notes in raptor's project.json. Round-trips the schema."""
    from packages.studio.services.raptor_writer import update_project_metadata
    try:
        update_project_metadata(name, description=description, notes=notes)
    except Exception as exc:
        raise HTTPException(400, f"failed to save: {exc}")
    return RedirectResponse(url=f"/projects/{name}/settings?save_ok=1", status_code=303)


# --- Jobs: trigger + list + detail + cancel + SSE stream -----------------

def _preview_flags(kind: str, form_values: dict, target: str, project_name: str = "") -> str:
    try:
        argv = build_command(
            kind, target or "<target>", RAPTOR_HOME, form_values, project_name=project_name
        )
    except (UnsupportedKind, ValueError):
        return ""
    spec = RUNNABLE_KINDS.get(kind)
    if spec and spec.requires_claude:
        # argv is ["bash", "-c", "<combined>"] — surface the combined string.
        return argv[2] if len(argv) >= 3 else ""
    # Drop "python3 <script>" and the target; show only flags for the preview line.
    return " ".join(argv[3:]) if len(argv) > 3 else ""


def _default_target_for(kind: str, proj: RaptorProject) -> str:
    """Pick a sensible default target for the new-run form based on kind.

    For ``--binary`` kinds the project's ``target`` is already the binary
    (for type=binary projects); no sidecar lookup needed.
    """
    return proj.target


def _default_run_values(kind: str, proj: RaptorProject) -> dict[str, str]:
    """Seed the new-run form with project-level defaults from ProjectExtras."""
    out: dict[str, str] = {}
    if kind == "oss-forensics":
        if proj.extras.focus:
            out["focus"] = proj.extras.focus
        if proj.extras.vendor_report_url:
            out["vendor_report_url"] = proj.extras.vendor_report_url
    elif kind == "fuzz":
        if proj.extras.corpus_dir:
            out["corpus"] = proj.extras.corpus_dir
    return out


@app.get("/projects/{name}/{kind}/new", response_class=HTMLResponse)
def new_run_form(request: Request, name: str, kind: str):
    if not is_runnable(kind):
        raise HTTPException(404, f"Kind '{kind}' cannot be launched from the UI.")
    proj = _require_project(name)
    spec = RUNNABLE_KINDS[kind]
    default_target = _default_target_for(kind, proj)
    default_values = _default_run_values(kind, proj)
    return templates.TemplateResponse(
        request, "project_new_run.html",
        _project_ctx(
            proj, active_stage=kind,
            spec=spec,
            form={"target": default_target, **default_values},
            preview_flags=_preview_flags(kind, default_values, default_target, proj.name),
            raptor_home=str(RAPTOR_HOME),
            error=None,
        ),
    )


@app.post("/projects/{name}/{kind}/new")
async def new_run_submit(request: Request, name: str, kind: str):
    if not is_runnable(kind):
        raise HTTPException(404, f"Kind '{kind}' cannot be launched from the UI.")
    proj = _require_project(name)
    spec = RUNNABLE_KINDS[kind]
    form = await request.form()

    target = (form.get("target") or "").strip() or _default_target_for(kind, proj)
    values = {f.name: (form.get(f.name) or "").strip() for f in spec.fields}

    # Merge project-level defaults that aren't user-overridable in this form
    # (e.g. OSS-forensics vendor_report_url lives on the project, not the run).
    for k, v in _default_run_values(kind, proj).items():
        values.setdefault(k, v)

    try:
        argv = build_command(kind, target, RAPTOR_HOME, values, project_name=proj.name)
    except (UnsupportedKind, ValueError) as e:
        return templates.TemplateResponse(
            request, "project_new_run.html",
            _project_ctx(
                proj, active_stage=kind,
                spec=spec, form={"target": target, **values},
                preview_flags=_preview_flags(kind, values, target, proj.name),
                raptor_home=str(RAPTOR_HOME),
                error=str(e),
            ),
            status_code=400,
        )

    job = jobs_service.Job.new(
        project_name=proj.name, kind=kind, target=target, argv=argv,
    )
    jobs_service.enqueue(job)
    return RedirectResponse(url=f"/jobs/{job.id}", status_code=303)


@app.get("/projects/{name}/jobs", response_class=HTMLResponse)
def project_jobs(request: Request, name: str):
    proj = _require_project(name)
    pjobs = jobs_service.list_jobs(project_name=proj.name, limit=200)
    return templates.TemplateResponse(
        request, "project_jobs.html",
        _project_ctx(proj, active_stage="jobs", project_jobs=pjobs),
    )


@app.get("/jobs/{job_id}", response_class=HTMLResponse)
def job_detail(request: Request, job_id: str):
    job = jobs_service.get(job_id)
    if job is None:
        raise HTTPException(404, f"job not found: {job_id}")
    proj = get_project(job.project_name)
    if proj is None:
        raise HTTPException(404, f"project for job not found: {job.project_name}")

    log_tail = ""
    if job.log_path:
        try:
            log_tail = Path(job.log_path).read_text()[-16000:]
        except OSError:
            log_tail = ""

    return templates.TemplateResponse(
        request, "job_detail.html",
        _project_ctx(proj, active_stage="jobs", job=job, log_tail=log_tail),
    )


@app.post("/jobs/{job_id}/cancel")
def job_cancel(request: Request, job_id: str):
    job = jobs_service.get(job_id)
    if job is None:
        raise HTTPException(404, f"job not found: {job_id}")
    worker_service.cancel(job_id)
    return RedirectResponse(url=f"/jobs/{job_id}", status_code=303)


@app.get("/api/fs/list")
def api_fs_list(path: str = "", include_files: int = 0):
    """Browse the local filesystem for the file-picker widget.

    Single-user localhost tool — exposes the process owner's filesystem.
    No multi-tenant threat model. We only normalize the path and skip
    entries we can't stat (e.g. permission denied on system dirs).
    """
    home = Path.home()
    if not path:
        target = home
    else:
        try:
            target = Path(path).expanduser().resolve()
        except (OSError, RuntimeError) as exc:
            raise HTTPException(400, f"invalid path: {exc}")
    if not target.exists():
        raise HTTPException(404, f"path not found: {target}")
    if not target.is_dir():
        raise HTTPException(400, f"not a directory: {target}")

    entries: list[dict] = []
    try:
        for child in sorted(target.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower())):
            if child.name.startswith("."):
                continue
            try:
                is_dir = child.is_dir()
            except OSError:
                continue
            if not include_files and not is_dir:
                continue
            entries.append({
                "name": child.name,
                "is_dir": is_dir,
                "path": str(child),
            })
    except PermissionError as exc:
        raise HTTPException(403, f"permission denied: {exc}")

    shortcuts = [
        {"label": "Home", "path": str(home)},
        {"label": "Projects", "path": str(home / "Projects")},
        {"label": "Downloads", "path": str(home / "Downloads")},
        {"label": "Desktop", "path": str(home / "Desktop")},
        {"label": "/tmp", "path": "/tmp"},
    ]
    shortcuts = [s for s in shortcuts if Path(s["path"]).is_dir()]

    return JSONResponse({
        "ok": True,
        "path": str(target),
        "parent": str(target.parent) if target != target.parent else None,
        "home": str(home),
        "entries": entries,
        "shortcuts": shortcuts,
    })


@app.get("/api/jobs/{job_id}/log")
def api_job_log(job_id: str):
    job = jobs_service.get(job_id)
    if job is None:
        raise HTTPException(404, f"job not found: {job_id}")
    if not job.log_path:
        return JSONResponse({"log": "", "status": job.status.value})
    try:
        text = Path(job.log_path).read_text()
    except OSError:
        text = ""
    return JSONResponse({"log": text, "status": job.status.value})


async def _stream_job(job_id: str) -> AsyncIterator[bytes]:
    """Server-sent-events stream for a job's log and status updates."""
    last_size = 0
    last_status: Optional[str] = None
    while True:
        job = jobs_service.get(job_id)
        if job is None:
            yield b"event: status\ndata: missing\n\n"
            return

        # Status transitions
        if job.status.value != last_status:
            yield f"event: status\ndata: {job.status.value}\n\n".encode()
            last_status = job.status.value

        # New log bytes
        if job.log_path:
            try:
                size = Path(job.log_path).stat().st_size
            except OSError:
                size = 0
            if size > last_size:
                try:
                    with Path(job.log_path).open("r") as f:
                        f.seek(last_size)
                        chunk = f.read(size - last_size)
                except OSError:
                    chunk = ""
                last_size = size
                for line in chunk.splitlines():
                    # SSE data lines must not contain bare newlines in the data;
                    # we emit one event per line.
                    yield f"event: log\ndata: {line}\n\n".encode()

        if job.is_terminal:
            # Final flush then close.
            yield f"event: status\ndata: {job.status.value}\n\n".encode()
            return

        await asyncio.sleep(0.4)


@app.get("/api/jobs/{job_id}/stream")
async def api_job_stream(job_id: str):
    job = jobs_service.get(job_id)
    if job is None:
        raise HTTPException(404, f"job not found: {job_id}")
    return StreamingResponse(
        _stream_job(job_id),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",  # disable nginx buffering if proxied
        },
    )


# --- Worker lifecycle ------------------------------------------------------

@app.on_event("startup")
def _start_worker():
    worker_service.start()


@app.on_event("shutdown")
def _stop_worker():
    worker_service.stop(timeout=1.0)


# --- Per-run detail -------------------------------------------------------

def _require_run(proj: RaptorProject, run_name: str):
    run = next((r for r in proj.runs() if r.name == run_name), None)
    if run is None:
        raise HTTPException(404, f"run not found: {run_name}")
    return run


@app.get("/projects/{name}/runs/{run_name}", response_class=HTMLResponse)
def run_detail(request: Request, name: str, run_name: str):
    proj = _require_project(name)
    run = _require_run(proj, run_name)
    summary = summarize_run(run.directory)
    bundle = load_validation_bundle(run.directory) if summary.has_validation_bundle else None
    forensics = None
    if run.kind == "oss-forensics" or is_forensics_run_dir(run.directory):
        forensics = load_forensics_bundle(run.directory)
    return templates.TemplateResponse(
        request, "run_detail.html",
        _project_ctx(
            proj, active_stage="runs",
            run=run, summary=summary, bundle=bundle, forensics=forensics,
        ),
    )


# File types we'll serve from a run directory. Keep tight; add more only
# when a new surface needs them.
_ALLOWED_RUN_FILE_SUFFIXES = frozenset({
    ".svg", ".png", ".md", ".json", ".sarif", ".txt",
    # Exploit / patch source + supporting files — read-only inline display
    # on a single-user localhost tool; no execution path from here.
    ".py", ".c", ".h", ".sh", ".rb", ".go", ".js", ".ts",
    ".patch", ".diff", ".yaml", ".yml", ".toml", ".log",
})


@app.get("/projects/{name}/runs/{run_name}/files/{filename:path}")
def run_file(name: str, run_name: str, filename: str):
    """Safely serve a file from a run directory.

    Resolves the requested path and verifies it stays within the run
    directory — blocks `..` traversal. Extension whitelist prevents
    serving arbitrary script / binary content.
    """
    proj = _require_project(name)
    run = _require_run(proj, run_name)
    try:
        target = (run.directory / filename).resolve(strict=True)
    except (FileNotFoundError, OSError):
        raise HTTPException(404, "file not found")
    run_root = str(run.directory.resolve()) + "/"
    if not (str(target) + "/").startswith(run_root) and str(target) != str(run.directory.resolve()):
        raise HTTPException(403, "path traversal blocked")
    if not target.is_file():
        raise HTTPException(404, "not a file")
    if target.suffix.lower() not in _ALLOWED_RUN_FILE_SUFFIXES:
        raise HTTPException(403, f"suffix {target.suffix} not allowed")
    return FileResponse(target)


@app.get(
    "/projects/{name}/runs/{run_name}/findings", response_class=HTMLResponse
)
def run_findings(request: Request, name: str, run_name: str):
    proj = _require_project(name)
    run = _require_run(proj, run_name)
    return templates.TemplateResponse(
        request, "findings.html",
        _project_ctx(
            proj, active_stage="runs",
            run=run, findings=run.findings(),
        ),
    )


# --- Global settings ------------------------------------------------------

def _settings_ctx(**overrides):
    config = load_models_config()
    ctx = {
        "config": config,
        "roles": list(ROLES),
        "providers": list(PROVIDERS),
        "role_descriptions": ROLE_DESCRIPTIONS,
        "env_status": env_status(),
        "budget_cap": current_budget_cap(),
        "saved": False,
        "error": None,
    }
    ctx.update(overrides)
    return _ctx(**ctx)


@app.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request):
    return templates.TemplateResponse(request, "settings.html", _settings_ctx())


@app.get("/personas", response_class=HTMLResponse)
def personas_page(request: Request):
    return templates.TemplateResponse(
        request, "personas.html",
        _ctx(personas=all_personas(), raptor_home=str(RAPTOR_HOME)),
    )


@app.get("/glossary", response_class=HTMLResponse)
def glossary_page(request: Request):
    return templates.TemplateResponse(request, "glossary.html", _ctx())


@app.post("/settings")
async def settings_save(request: Request):
    form = await request.form()
    entries: list[ModelEntry] = []
    for role in ROLES:
        provider = (form.get(f"{role}__provider") or "").strip()
        model = (form.get(f"{role}__model") or "").strip()
        api_key = (form.get(f"{role}__api_key") or "").strip()
        if not provider and not model and not api_key:
            continue
        entries.append(ModelEntry(provider=provider, model=model, api_key=api_key, role=role))
    try:
        save_models_config(ModelConfig(entries=entries, raw_path=RAPTOR_MODELS_CONFIG), RAPTOR_MODELS_CONFIG)
    except OSError as e:
        return templates.TemplateResponse(
            request, "settings.html",
            _settings_ctx(error=f"Could not write {RAPTOR_MODELS_CONFIG}: {e}"),
            status_code=500,
        )
    return templates.TemplateResponse(request, "settings.html", _settings_ctx(saved=True))


# --- Health ---------------------------------------------------------------

@app.get("/api/health")
def health():
    return JSONResponse({
        "status": "ok",
        "app": APP_TITLE,
        "projects_dir": str(RAPTOR_PROJECTS_DIR),
        "projects_dir_exists": RAPTOR_PROJECTS_DIR.is_dir(),
        "models_config": str(RAPTOR_MODELS_CONFIG),
        "models_config_exists": RAPTOR_MODELS_CONFIG.is_file(),
    })

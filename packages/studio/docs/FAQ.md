# FAQ — for maintainer review

This document pre-answers the questions a reviewer is most likely to have about `packages/studio/`. It's deliberately candid about tradeoffs and non-goals.

---

## Scope

**Q. Why add a web UI to raptor at all? Isn't the CLI enough?**
A. The CLI is excellent for solo deep-dives and CI. It's friction for (a) browsing findings at volume across multiple projects, (b) diffing one run against another visually, (c) showing a non-terminal stakeholder what raptor found, (d) triaging a fuzzing campaign's 20 crashes across an afternoon. Studio addresses those without replacing the CLI — every UI action shows its Equivalent CLI, and projects round-trip cleanly between the two.

**Q. Why in-tree and not a companion repo?**
A. We built it as a companion repo first: [yesnet0/raptor-studio](https://github.com/yesnet0/raptor-studio). After ~2 weeks and 27 commits, it felt stable and useful enough to propose upstream so every raptor user gets it. If you prefer it stays a companion, we'll close this PR and keep maintaining it separately — the companion repo stays live either way.

**Q. Will this become a maintenance burden?**
A. Finite surface: 72 files, 9 KLOC, 161 tests. All deps are pure-Python (uvicorn's C extensions are optional). No server, no DB other than a local SQLite file, no external services. The services layer is provider-agnostic and doesn't import raptor's runtime except `raptor_version.py` which reads `RaptorConfig.VERSION`. If the UI regresses, the CLI keeps working unchanged.

**Q. Does this conflict with the existing `packages/web/`?**
A. No. `packages/web/` is the **web endpoint fuzzer** (crawler + scanner for testing web apps under analysis). `packages/studio/` is the **web UI for raptor itself**. Different purposes, different users. Happy to rename if you'd prefer `packages/ui/` or similar.

**Q. CodeQL licensing?**
A. Studio doesn't touch CodeQL. It reads CodeQL's SARIF + `dataflow_*.json` / `dataflow_*.svg` output that raptor already produces. No redistribution of CodeQL queries or binaries.

---

## Architecture

**Q. Why FastAPI + Jinja2 rather than Flask? Django? Starlette? an SPA?**
A. FastAPI + Starlette gives us async SSE for live log streaming with minimal code. Jinja2 matches raptor's existing Python ergonomics and lets every template be reviewed as a single file — no build step, no `node_modules`. An SPA would bring a whole parallel toolchain into raptor for no review-ergonomics gain. Pydantic (a FastAPI dep) is already in raptor's `requirements.txt`.

**Q. Why SQLite for the job queue?**
A. Single-user, no cross-process coordination needed. SQLite is stdlib-only. Schema is 13 columns in one table — trivial to rewrite if a different backend is ever needed.

**Q. Why shell out to `claude -p` for Claude-backed commands?**
A. That's raptor's existing mechanism for invoking Claude Code non-interactively — `bin/raptor` itself uses `exec claude` for non-`project` subcommands. Studio just wraps that same approach with project-activation chained in. If raptor ever gains an official programmatic API for Claude Code, studio can switch to it by editing `services/run_spec.py::_build_claude_command`.

**Q. Why inline CSS in templates?**
A. Matches vulngraph's proven approach (which studio's grammar borrows from). Zero build step. Each template is one self-contained review unit. ~150 lines of CSS lives in `base.html`; per-page styles are co-located with the structure they style. Easy to extract into `static/css/main.css` later if desired.

**Q. Why FastAPI's `{filename:path}` route for file-serving?**
A. Run dirs contain nested artifacts (e.g. `afl_output/main/crashes/id:000000`); `:path` matches slashes. The handler then calls `.resolve()` and asserts the result starts with `run.directory.resolve() + "/"` — this is the primary traversal guard. Plus an extension whitelist (`.svg / .png / .md / .json / .sarif / .txt`). Tested with `..%2F..%2F..%2Fetc%2Fpasswd` → 403, `evil.sh` → 403.

---

## Security posture

**Q. CSRF protection on POST endpoints?**
A. Studio binds to `127.0.0.1` by default and is explicitly single-user. No auth, no cross-origin, no session cookies. If you deploy it behind a tunnel to untrusted networks, you'd add a reverse proxy with auth — same model as `jupyter notebook`.

**Q. Arbitrary command execution?**
A. The worker spawns raptor subprocesses only for whitelisted kinds (`RUNNABLE_KINDS` in `services/run_spec.py`). Arguments are built from a typed `FormField` spec; user input goes through the form fields, not string interpolation. `shlex.quote` escapes everything that reaches `bash -c`. Trust model: same as running `raptor` itself — if the user can start studio, they can already run raptor.

**Q. What if a malicious project is registered?**
A. Project JSONs in `~/.raptor/projects/` are whatever raptor CLI creates plus what studio creates. A maliciously-crafted `project.json` with `target: "/etc/passwd"` would pass to raptor subprocesses, but raptor itself would treat it the same way as if `raptor scan --repo /etc/passwd` were invoked directly. No privilege escalation.

**Q. The file-serving route — could an attacker hit `..` to read arbitrary files?**
A. `target.resolve()` is compared against `run.directory.resolve()` after `.resolve()` eliminates `..` components. The extension whitelist is a belt-and-braces second line. See tests in `tests/test_validation_reader.py` for the resolver + whitelist enforcement.

---

## Integration

**Q. Does this change any existing raptor behavior?**
A. No. Additions only: `packages/studio/` (new), `raptor_studio.py` (new), 5 lines in `requirements.txt`. No existing file edited.

**Q. Will `raptor project list` still work?**
A. Yes, unchanged. Projects created via studio use `raptor`'s exact 7-field schema. A test (`test_raptor_writer.test_schema_matches_raptor_validate_project`) imports `core.project.schema.validate_project` and runs it against studio's output — this PR's CI would catch a regression.

**Q. Can I run both the CLI and studio at the same time?**
A. Yes. Studio reads `~/.raptor/projects/` on each request, so CLI changes show up on the next refresh. Studio's own state (job queue, logs) lives in `$STUDIO_DATA_DIR` separately.

**Q. Does studio need raptor's Python deps installed?**
A. Yes — it triggers raptor subprocesses. If you skip studio's specific deps (`fastapi` etc.), just don't launch `raptor_studio.py`; the rest of raptor keeps working. If you want studio without raptor's other deps, you can install only `fastapi uvicorn[standard] jinja2 python-multipart markdown` and use studio as a read-only viewer against projects raptor already created.

---

## Quality

**Q. Test coverage?**
A. 161 tests across 17 modules. ~95 % services-layer coverage. Includes 4 live-subprocess tests in `test_worker_integration` that actually `subprocess.Popen` to exercise completed / failed / cancelled / missing-executable paths. Template rendering smoke-tested via `TestClient`.

**Q. What's explicitly NOT covered?**
A. The SSE stream's reconnect behavior — we emit one event per log line with best-effort ordering; if the client drops and reconnects, they resume from the latest offset, but we don't handle log-file rotation. Raptor never rotates these logs today.

**Q. Any known bugs?**
A. Two minor:
1. `test_persona_content_loaded_when_file_exists` in the companion repo skips when `$RAPTOR_HOME` is set unusually — not a problem in-tree.
2. `sys.path` manipulation in tests that reload modules is fragile; if pytest changes its collection order, the reloads may need re-ordering. Compensating control: tests that depend on module-reload use fresh `tmp_path` + explicit `cache_clear()`.

**Q. What's the performance profile?**
A. Cold page load < 200 ms from a local filesystem. SSE tail latency ≤ 500 ms. Largest page (Findings across a 50-run project) stays responsive. SQLite job-queue insert/update is sub-millisecond.

---

## Deployment / Ops

**Q. Devcontainer compatibility?**
A. Works as-is. `python3 raptor_studio.py --host 0.0.0.0 --port 8765` + forward the port. Uvicorn's auto-reload is optional (`--reload`).

**Q. How do I uninstall / roll back?**
A. `rm -rf packages/studio raptor_studio.py` and revert the 5 new lines in `requirements.txt`. No other changes.

**Q. Where does state live?**
A. `$STUDIO_DATA_DIR` (default `~/.raptor-studio`). Three subtrees:
- `jobs.db` — SQLite job queue
- `job-logs/*.log` — per-job stdout+stderr capture
- `project-extras/*.json` — studio-only metadata sidecars

All safe to delete; studio recreates on demand.

**Q. Log rotation?**
A. Not implemented — raptor-studio is a local dev tool, not a long-running service. Each job's log lives forever in `job-logs/`; users are expected to `rm -rf job-logs/` periodically if the dir grows.

---

## Future

**Q. What would you add next?**
A. See `docs/PRD.md §8`. In priority order: coverage view (`gcov` + `checked_by` merge), job-history KPIs on the dashboard (tokens used, $ spent), a "Re-run with Exploit Developer persona" per-finding button.

**Q. What would you NOT add?**
A. Auth / multi-user — raptor is single-user. Keeping studio single-user matches raptor's trust model and avoids reinventing auth.

**Q. Willing to maintain this if merged?**
A. Yes. Happy to be the initial point-of-contact for studio-specific issues. If that becomes a burden, labelling issues `area:studio` should route them cleanly.

"""cmd_run lifecycle-start wiring — explicit --out runs get run metadata.

Pre-fix the --out branch only mkdir'd the directory: no .raptor-run.json
was ever written, the end-of-run lifecycle complete failed, and the
supervisor-advertised `raptor-audit resume <dir>` refused the directory.
"""

from __future__ import annotations

import importlib.util
import sys
from importlib.machinery import SourceFileLoader
from pathlib import Path
from types import SimpleNamespace


def _load_cli():
    cli_path = str(
        Path(__file__).resolve().parents[3] / "libexec" / "raptor-audit",
    )
    loader = SourceFileLoader("raptor_audit_cli_test", cli_path)
    spec = importlib.util.spec_from_loader("raptor_audit_cli_test", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def test_explicit_out_goes_through_lifecycle_start(tmp_path, monkeypatch):
    mod = _load_cli()
    target = tmp_path / "target"
    target.mkdir()
    out_dir = tmp_path / "out"
    calls: list[list[str]] = []

    def fake_run(cmd, **kwargs):
        calls.append([str(c) for c in cmd])
        if "raptor-run-lifecycle" in str(cmd[0]):
            return SimpleNamespace(
                returncode=0, stdout=f"OUTPUT_DIR={out_dir}\n", stderr="")
        # First downstream step (checklist build) fails fast so the
        # test never reaches the orchestrator.
        return SimpleNamespace(returncode=1, stdout="", stderr="stub stop")

    import subprocess
    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr(mod, "_lifecycle_fail", lambda *a, **k: None)

    args = SimpleNamespace(target=str(target), out=str(out_dir))
    rc = mod.cmd_run(args)
    assert rc == 1                       # stopped at the stubbed step

    start = calls[0]
    assert start[0].endswith("raptor-run-lifecycle")
    assert start[1:3] == ["start", "audit"]
    assert "--target" in start and str(target) in start
    assert "--out" in start
    assert str(out_dir) in start


def test_no_out_still_resolves_via_lifecycle(tmp_path, monkeypatch):
    mod = _load_cli()
    target = tmp_path / "target"
    target.mkdir()
    resolved = tmp_path / "resolved-run"
    calls: list[list[str]] = []

    def fake_run(cmd, **kwargs):
        calls.append([str(c) for c in cmd])
        if "raptor-run-lifecycle" in str(cmd[0]):
            return SimpleNamespace(
                returncode=0, stdout=f"OUTPUT_DIR={resolved}\n", stderr="")
        return SimpleNamespace(returncode=1, stdout="", stderr="stub stop")

    import subprocess
    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr(mod, "_lifecycle_fail", lambda *a, **k: None)

    rc = mod.cmd_run(SimpleNamespace(target=str(target), out=None))
    assert rc == 1
    assert "--out" not in calls[0]


# ---------------------------------------------------------------------------
# --project pin crosses the process boundary into the lifecycle child.
#
# main() records --project via core.run.pin.set_process_project, but
# that override is an IN-PROCESS global: the raptor-run-lifecycle stub
# is a subprocess and re-resolves the session/symlink layers unless the
# child argv carries the pin. Pre-fix cmd_run parsed the flag and then
# silently dropped it here — the child pinned the run to the stale
# session project and refused with an error that RECOMMENDED the very
# flag being ignored.
# ---------------------------------------------------------------------------


def _lifecycle_spy(monkeypatch, mod, out_dir):
    """Stub subprocess.run: record argv, answer lifecycle start with
    OUTPUT_DIR, and fail the first downstream step so the test never
    reaches the orchestrator (existing convention in this file)."""
    calls: list[list[str]] = []

    def fake_run(cmd, **kwargs):
        calls.append([str(c) for c in cmd])
        if "raptor-run-lifecycle" in str(cmd[0]):
            return SimpleNamespace(
                returncode=0, stdout=f"OUTPUT_DIR={out_dir}\n", stderr="")
        return SimpleNamespace(returncode=1, stdout="", stderr="stub stop")

    import subprocess
    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr(mod, "_lifecycle_fail", lambda *a, **k: None)
    return calls


def _project_argv_pair(argv: list[str]) -> str | None:
    """The value following ``--project`` in *argv*, or None."""
    for i, tok in enumerate(argv):
        if tok == "--project":
            return argv[i + 1] if i + 1 < len(argv) else ""
    return None


def test_project_pin_forwarded_to_lifecycle_child(tmp_path, monkeypatch):
    mod = _load_cli()
    target = tmp_path / "target"
    target.mkdir()
    resolved = tmp_path / "resolved-run"
    resolved.mkdir()
    calls = _lifecycle_spy(monkeypatch, mod, resolved)

    rc = mod.cmd_run(SimpleNamespace(
        target=str(target), out=None, project="myproj"))
    assert rc == 1                       # stopped at the stubbed step

    start = calls[0]
    assert start[1:3] == ["start", "audit"]
    assert _project_argv_pair(start) == "myproj"


def test_explicitly_projectless_dash_forwarded_verbatim(
    tmp_path, monkeypatch,
):
    # '--project -' is the explicit bound-to-none argv (core/run/pin.py
    # ARGV_NONE) — it must reach the child verbatim, not be dropped as
    # falsy or rewritten.
    mod = _load_cli()
    target = tmp_path / "target"
    target.mkdir()
    resolved = tmp_path / "resolved-run"
    resolved.mkdir()
    calls = _lifecycle_spy(monkeypatch, mod, resolved)

    rc = mod.cmd_run(SimpleNamespace(
        target=str(target), out=None, project="-"))
    assert rc == 1
    assert _project_argv_pair(calls[0]) == "-"


def test_no_project_flag_forwards_nothing(tmp_path, monkeypatch):
    # Flag not given (args.project is None): the child must keep
    # resolving its own layers — no --project token at all.
    mod = _load_cli()
    target = tmp_path / "target"
    target.mkdir()
    resolved = tmp_path / "resolved-run"
    resolved.mkdir()
    calls = _lifecycle_spy(monkeypatch, mod, resolved)

    rc = mod.cmd_run(SimpleNamespace(
        target=str(target), out=None, project=None))
    assert rc == 1
    assert "--project" not in calls[0]


def test_project_pin_forwarded_alongside_explicit_out(
    tmp_path, monkeypatch,
):
    # The --out branch appends to the same lifecycle_cmd — both flags
    # must ride together.
    mod = _load_cli()
    target = tmp_path / "target"
    target.mkdir()
    out_dir = tmp_path / "out"
    calls = _lifecycle_spy(monkeypatch, mod, out_dir)

    rc = mod.cmd_run(SimpleNamespace(
        target=str(target), out=str(out_dir), project="myproj"))
    assert rc == 1
    start = calls[0]
    assert _project_argv_pair(start) == "myproj"
    assert "--out" in start and str(out_dir) in start


def test_surface_run_project_reaches_lifecycle_child_argv(
    tmp_path, monkeypatch,
):
    # Full raptor-audit surface: argv → main() → argparse → cmd_run.
    # Proves the run subparser's --project wiring actually reaches the
    # lifecycle child argv (not just the in-process
    # set_process_project global).
    mod = _load_cli()
    target = tmp_path / "target"
    target.mkdir()
    resolved = tmp_path / "resolved-run"
    resolved.mkdir()
    calls = _lifecycle_spy(monkeypatch, mod, resolved)
    monkeypatch.setattr(
        sys, "argv",
        ["raptor-audit", "run", str(target),
         "--project", "audit-pin-fwd-proj"],
    )
    # The parent's sandbox-floor consent read revalidates the argv
    # project against the registry (hard error, never a fallback) —
    # satisfy it without touching the real projects dir. The child's
    # own validation is out of frame (subprocess.run is stubbed).
    import core.run.pin as pin_mod
    monkeypatch.setattr(
        pin_mod, "_project_exists",
        lambda name: name == "audit-pin-fwd-proj",
    )

    from core.run.pin import set_process_project
    try:
        rc = mod.main()
    finally:
        # main() records the flag in the process-scoped pin global;
        # never leak it into later tests in this pytest process.
        set_process_project(None)
    assert rc == 1                       # stopped at the stubbed step

    lifecycle_starts = [
        c for c in calls
        if c and "raptor-run-lifecycle" in c[0] and c[1:2] == ["start"]
    ]
    assert lifecycle_starts, "cmd_run never spawned lifecycle start"
    assert _project_argv_pair(lifecycle_starts[0]) == "audit-pin-fwd-proj"


def test_surface_invalid_project_is_one_line_error(
    tmp_path, monkeypatch, capsys,
):
    # An invalid --project is a hard error by contract — and it must
    # surface as the lifecycle stub's one-line "ERROR: ..." form with
    # exit 1, never an uncaught ProjectArgvError traceback out of
    # main() (the parent's sandbox-floor consent read revalidates the
    # argv project before cmd_run runs). '../evil' fails the project
    # name charset, so no registry is ever consulted — hermetic.
    mod = _load_cli()
    target = tmp_path / "target"
    target.mkdir()
    calls = _lifecycle_spy(monkeypatch, mod, tmp_path / "never-created")
    monkeypatch.setattr(
        sys, "argv",
        ["raptor-audit", "run", str(target), "--project", "../evil"],
    )

    from core.run.pin import set_process_project
    try:
        rc = mod.main()
    finally:
        set_process_project(None)

    assert rc == 1
    err = capsys.readouterr().err
    error_lines = [
        line for line in err.splitlines() if line.startswith("ERROR:")
    ]
    assert len(error_lines) == 1
    assert "--project" in error_lines[0]
    assert "Traceback" not in err
    # The refusal happens before any run is started: no lifecycle
    # child may have been spawned for a run that can never be pinned.
    assert not any("raptor-run-lifecycle" in c[0] for c in calls if c)

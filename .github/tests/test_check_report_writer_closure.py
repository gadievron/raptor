"""The report-writer closure gate must (a) pass on the current tree,
(b) FAIL when a new unregistered writer prints foreign-derived text,
(c) tolerate stale baseline entries with a warning, and (d) refuse
note-less baseline entries. Hermetic: the fail-direction cases run in
a scratch git repo carrying only the audit module."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / ".github" / "scripts" / "check_report_writer_closure.py"


def _run(args: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        capture_output=True, text=True, cwd=str(cwd or REPO_ROOT),
        check=False,
    )


def _scratch_repo(tmp_path: Path) -> Path:
    """Minimal git repo carrying the real audit module so the gate's
    import resolves against the scratch root."""
    root = tmp_path / "repo"
    (root / "core" / "security").mkdir(parents=True)
    (root / "core" / "__init__.py").write_text("")
    (root / "core" / "security" / "__init__.py").write_text("")
    shutil.copy(
        REPO_ROOT / "core" / "security" / "report_writer_audit.py",
        root / "core" / "security" / "report_writer_audit.py",
    )
    env_git = ["git", "-C", str(root)]
    subprocess.run([*env_git[:2], str(root), "init", "-q"], check=True)
    return root


def _git_add_all(root: Path) -> None:
    subprocess.run(["git", "-C", str(root), "add", "-A"], check=True)


def _baseline(tmp_path: Path, entries: dict) -> Path:
    p = tmp_path / "baseline.json"
    p.write_text(json.dumps({"entries": entries}))
    return p


def test_gate_green_on_current_tree():
    cp = _run([])
    assert cp.returncode == 0, cp.stdout + cp.stderr
    assert "0 new" in cp.stdout


def test_new_unregistered_writer_fails(tmp_path):
    root = _scratch_repo(tmp_path)
    (root / "evil_writer.py").write_text(
        "def show(finding):\n"
        "    print(finding.get('title'))\n"
    )
    _git_add_all(root)
    cp = _run(["--root", str(root),
               "--baseline", str(_baseline(tmp_path, {}))])
    assert cp.returncode == 1, cp.stdout + cp.stderr
    assert "NEW unregistered report-writer finding" in cp.stdout
    assert "evil_writer.py" in cp.stdout
    assert "register the file" in cp.stdout


def test_tool_output_writer_fails(tmp_path):
    # The vocabulary covers tool output, not only LLM fields — a raw
    # subprocess-stderr echo is a class member.
    root = _scratch_repo(tmp_path)
    (root / "stderr_echo.py").write_text(
        "def run(proc):\n"
        "    print(proc.stderr)\n"
    )
    _git_add_all(root)
    cp = _run(["--root", str(root),
               "--baseline", str(_baseline(tmp_path, {}))])
    assert cp.returncode == 1
    assert "detail='stderr'" in cp.stdout


def test_sanitised_writer_passes(tmp_path):
    root = _scratch_repo(tmp_path)
    (root / "good_writer.py").write_text(
        "def show(finding, proc):\n"
        "    print(sanitise_for_terminal(finding.get('title')))\n"
        "    print(sanitise_for_terminal(proc.stderr, max_len=500))\n"
    )
    _git_add_all(root)
    cp = _run(["--root", str(root),
               "--baseline", str(_baseline(tmp_path, {}))])
    assert cp.returncode == 0, cp.stdout + cp.stderr


def test_baselined_hit_passes_and_stale_warns(tmp_path):
    root = _scratch_repo(tmp_path)
    (root / "legacy_writer.py").write_text(
        "def show(finding):\n"
        "    print(finding.get('title'))\n"
    )
    _git_add_all(root)
    baseline = _baseline(tmp_path, {
        "legacy_writer.py::show::unsanitised_llm_value::title":
            {"note": "triaged residual for the test"},
        "gone_writer.py::show::unsanitised_llm_value::title":
            {"note": "already fixed"},
    })
    cp = _run(["--root", str(root), "--baseline", str(baseline)])
    assert cp.returncode == 0, cp.stdout + cp.stderr
    assert "stale" in cp.stdout
    assert "gone_writer.py" in cp.stdout


def test_noteless_baseline_entry_refused(tmp_path):
    root = _scratch_repo(tmp_path)
    _git_add_all(root)
    baseline = _baseline(tmp_path, {
        "x.py::f::unsanitised_llm_value::title": {"note": "TODO: later"},
    })
    cp = _run(["--root", str(root), "--baseline", str(baseline)])
    assert cp.returncode != 0
    assert "note" in (cp.stdout + cp.stderr)


def test_mermaid_embed_in_key_free_file_caught(tmp_path):
    # A fence with an unsanitised f-string embed is a finding even
    # when the file contains no _FOREIGN_KEYS member anywhere.
    root = _scratch_repo(tmp_path)
    (root / "diagram_writer.py").write_text(
        "def render(name):\n"
        '    return f"```mermaid\\ngraph LR; {name}\\n```"\n'
    )
    _git_add_all(root)
    cp = _run(["--root", str(root),
               "--baseline", str(_baseline(tmp_path, {}))])
    assert cp.returncode == 1, cp.stdout + cp.stderr
    assert "unsanitised_mermaid_embed" in cp.stdout
    assert "in render()" in cp.stdout


def test_folded_constants_are_findings(tmp_path):
    # Contract against any future content prescreen: the parser folds
    # adjacent string literals and escape sequences into plain
    # ast.Constant values, so these files carry detectable key/fence
    # literals whose SOURCE TEXT never contains the token. A text-level
    # "skip files that don't mention a key" optimisation silently
    # dropped all three of these; the scan must flag every one.
    root = _scratch_repo(tmp_path)
    (root / "p_adjacent.py").write_text(
        "def show(f):\n"
        '    print(f["tit" "le"])\n'
    )
    (root / "p_escaped.py").write_text(
        "def show(f):\n"
        '    print(f["\\x74itle"])\n'
    )
    (root / "p_fence.py").write_text(
        "def render(n):\n"
        '    return f"``\\x60mermaid\\ngraph LR; {n}\\n```"\n'
    )
    _git_add_all(root)
    cp = _run(["--root", str(root),
               "--baseline", str(_baseline(tmp_path, {}))])
    assert cp.returncode == 1, cp.stdout + cp.stderr
    assert "3 NEW" in cp.stdout
    assert "p_adjacent.py" in cp.stdout
    assert "p_escaped.py" in cp.stdout
    assert "p_fence.py" in cp.stdout


def _load_gate_module():
    import importlib.util

    spec = importlib.util.spec_from_file_location("gate_under_test", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_pool_failure_falls_back_serially(tmp_path, monkeypatch, capsys):
    # A broken process pool (sandboxes without working semaphores)
    # must degrade to the serial scan with complete findings, not fail
    # or silently return nothing. The pool is forced to fail so this
    # deterministically pins the FALLBACK leg against a direct
    # per-file ground truth. The genuinely pooled leg is covered end
    # to end by the subprocess tests above: they run the script as
    # __main__ (whose worker function pickles under any start method)
    # and assert exact findings, so pooled-vs-serial divergence would
    # fail those.
    root = _scratch_repo(tmp_path)
    (root / "evil_writer.py").write_text(
        "def show(finding):\n"
        "    print(finding.get('title'))\n"
    )
    (root / "clean.py").write_text("X = 1\n")
    _git_add_all(root)

    gate = _load_gate_module()
    rels = gate._candidates(root)
    gate._init_worker(str(root))
    ground_truth = [gate._audit_one(rel) for rel in rels]
    assert any(v.detail == "title" for vs in ground_truth for v in vs)

    def _boom(*args, **kwargs):
        raise OSError("no pool for you")

    monkeypatch.setattr(gate, "ProcessPoolExecutor", _boom)
    fallback = gate._audit_candidates(root, rels)
    assert fallback == ground_truth
    assert "scanning serially" in capsys.readouterr().err


def test_real_baseline_notes_are_filled():
    data = json.loads(
        (REPO_ROOT / ".github" / "scripts" /
         "report_writer_closure_baseline.json").read_text())
    for key, entry in data["entries"].items():
        note = str(entry.get("note", ""))
        assert note.strip() and "TODO" not in note, (
            f"baseline entry {key} lacks a real triage note"
        )


@pytest.mark.parametrize("rel", [
    "core/security/report_writer_audit.py",
    ".github/scripts/report_writer_closure_baseline.json",
])
def test_gate_inputs_exist(rel):
    assert (REPO_ROOT / rel).is_file()


# ---------------------------------------------------------------------------
# Bash manual-audit tier (walk-scope: the AST detector cannot walk
# non-Python launchers).
# ---------------------------------------------------------------------------


def test_new_bash_script_fails_without_manual_audit_entry(tmp_path):
    root = _scratch_repo(tmp_path)
    (root / "libexec").mkdir()
    script = root / "libexec" / "raptor-new-launcher"
    script.write_text("#!/usr/bin/env bash\necho \"$UNTRUSTED\"\n")
    script.chmod(0o755)
    _git_add_all(root)
    cp = _run(["--root", str(root),
               "--baseline", str(_baseline(tmp_path, {}))])
    assert cp.returncode == 1, cp.stdout + cp.stderr
    assert "manual-audit" in cp.stdout
    assert "raptor-new-launcher" in cp.stdout


def test_bash_script_with_manual_audit_entry_passes(tmp_path):
    root = _scratch_repo(tmp_path)
    (root / "libexec").mkdir()
    script = root / "libexec" / "raptor-new-launcher"
    script.write_text("#!/usr/bin/env bash\necho ok\n")
    script.chmod(0o755)
    _git_add_all(root)
    baseline = tmp_path / "baseline.json"
    baseline.write_text(json.dumps({
        "entries": {},
        "bash_manual_audit": {
            "libexec/raptor-new-launcher": {
                "note": "reviewed: echoes constants only",
            },
        },
    }))
    cp = _run(["--root", str(root), "--baseline", str(baseline)])
    assert cp.returncode == 0, cp.stdout + cp.stderr
    assert "1 bash manual-audit" in cp.stdout


def test_noteless_bash_entry_refused(tmp_path):
    root = _scratch_repo(tmp_path)
    _git_add_all(root)
    baseline = tmp_path / "baseline.json"
    baseline.write_text(json.dumps({
        "entries": {},
        "bash_manual_audit": {"libexec/x": {"note": "TODO: triage"}},
    }))
    cp = _run(["--root", str(root), "--baseline", str(baseline)])
    assert cp.returncode != 0
    assert "missing a real note" in (cp.stdout + cp.stderr)


def test_stale_bash_entry_warns_clean(tmp_path):
    root = _scratch_repo(tmp_path)
    _git_add_all(root)
    baseline = tmp_path / "baseline.json"
    baseline.write_text(json.dumps({
        "entries": {},
        "bash_manual_audit": {
            "libexec/raptor-gone": {"note": "reviewed once, now removed"},
        },
    }))
    cp = _run(["--root", str(root), "--baseline", str(baseline)])
    assert cp.returncode == 0, cp.stdout + cp.stderr
    assert "stale bash_manual_audit" in cp.stdout


def test_every_bash_launcher_has_manual_audit_entry():
    """Closure over the REAL tree: the gate run in
    test_gate_green_on_current_tree already enforces this; this pin
    keeps the requirement visible when editing the baseline."""
    baseline = json.loads(
        (REPO_ROOT / ".github" / "scripts"
         / "report_writer_closure_baseline.json").read_text())
    assert baseline.get("bash_manual_audit"), (
        "bash_manual_audit section missing")

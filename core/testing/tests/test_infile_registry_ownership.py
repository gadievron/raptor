"""Release-archive fixture owners outlive undo and restore caller registries."""

import ast
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest


pytestmark = pytest.mark.slow
ROOT = Path(__file__).resolve().parents[3]
CASES = ['core/audit/tests/test_guess_target_corroboration.py', 'core/audit/tests/test_resume_substrate.py', 'core/inventory/tests/test_shared_checklist.py', 'core/project/tests/test_clean.py', 'core/project/tests/test_cli.py', 'core/project/tests/test_project.py', 'core/project/tests/test_report.py', 'core/run/tests/test_agentic_entrypoint_hardening.py', 'core/run/tests/test_findings_stamp.py', 'core/run/tests/test_hook_finalize_precedence.py', 'core/run/tests/test_interrupt_resume.py', 'core/run/tests/test_metadata.py', 'core/run/tests/test_provenance.py', 'core/run/tests/test_resume.py', 'core/run/tests/test_run_contention.py', 'core/run/tests/test_run_gate_reentrant_oplock.py', 'core/run/tests/test_run_ownership.py', 'core/run/tests/test_tmp_reaper.py', 'core/run/tests/test_worker_liveness.py', 'core/sandbox/tests/test_e2e_sandbox.py', 'core/sandbox/tests/test_summary.py', 'core/sandbox/tests/test_triage.py', 'packages/code_understanding/tests/test_understand_resume.py']


@pytest.mark.parametrize("file", CASES, ids=[Path(p).stem for p in CASES])
@pytest.mark.parametrize("mode", ["normal", "undo", "error", "interrupt"])
def test_infile_registry_lifetime_without_conftests(file, mode, tmp_path):
    """Run the native fixture definitions with actual pytest and MonkeyPatch."""
    tree = ast.parse((ROOT / file).read_text())
    functions = {n.name: n for n in tree.body if isinstance(n, ast.FunctionDef)}
    selected = {"_user_state_in_tmp", "monkeypatch"} & functions.keys()
    # File-owned monkeypatch fixtures can depend on additional lifetime owners.
    # Keep the transitive local closure when conftests are deliberately absent.
    pending = list(selected)
    while pending:
        node = functions[pending.pop()]
        for argument in (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs):
            if argument.arg in functions and argument.arg not in selected:
                selected.add(argument.arg)
                pending.append(argument.arg)
    owners = [node for name, node in functions.items() if name in selected]
    assert any(n.name == "_user_state_in_tmp" for n in owners)
    definitions = "\n\n".join(ast.unparse(n) for n in owners)
    job = tmp_path / "archive-session"
    job.mkdir()
    (job / "fixture_owner.py").write_text(
        "import pytest\nfrom pathlib import Path\n" + definitions + "\n")
    (job / "caller.py").write_text('''import hashlib
import json
import os
from pathlib import Path
import pytest
import core.startup as startup
from core.project import project, registry_home, sessions
JOB = Path(__file__).resolve().parent
CALLER = JOB / 'caller'
FIELDS = [(project, 'PROJECTS_DIR'), (startup, 'PROJECTS_DIR'),
          (startup, 'ACTIVE_LINK'), (sessions, 'SESSIONS_DIR')]
BASES = []
CALLS = []
BODY_CHECKED = False

def files():
    return {str(p.relative_to(CALLER)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in CALLER.rglob('*') if p.is_file()}

def borrowed_walk():
    CALLS.append(True)
    return None

@pytest.hookimpl(trylast=True)
def pytest_configure(config):
    global BEFORE, ENV, CONTENT
    CALLER.mkdir()
    os.environ[registry_home.ENV_REGISTRY_HOME] = str(CALLER)
    for module, key in FIELDS:
        vars(module).pop(key, None)
    sessions._walk_session_pid = borrowed_walk
    code = JOB / 'caller-code'
    code.mkdir()
    manager = project.ProjectManager(projects_dir=CALLER / 'projects')
    manager.create('borrowed', str(code), output_dir=str(JOB / 'caller-out'))
    manager.set_active('borrowed')
    os.environ[sessions.ENV_SESSION_PID] = '12345'
    os.environ[sessions.ENV_SESSION_TOKEN] = 'borrowed-token'
    ENV = {key: os.environ.get(key) for key in
           (registry_home.ENV_REGISTRY_HOME, sessions.ENV_SESSION_PID, sessions.ENV_SESSION_TOKEN)}
    BEFORE = [(module, key, key in vars(module), vars(module).get(key)) for module, key in FIELDS]
    CONTENT = files()
    CALLS.clear()

@pytest.hookimpl(trylast=True)
def pytest_sessionfinish(session, exitstatus):
    restored = {
        'namespace': all((key in vars(module)) is exists and
                         (not exists or vars(module)[key] is value)
                         for module, key, exists, value in BEFORE),
        'environment': all(os.environ.get(key) == value for key, value in ENV.items()),
        'caller_files_untouched': files() == CONTENT,
        'borrowed_walker_unused': not CALLS,
        'walker_identity': sessions._walk_session_pid is borrowed_walk,
        'body_checks_reached': BODY_CHECKED,
        'fresh_test_base': len(BASES) == (1 if MODE == 'interrupt' else 2)
                           and len(set(BASES)) == len(BASES),
    }
    os.environ[registry_home.ENV_REGISTRY_HOME] = str(JOB / 'later')
    restored['dynamic_getters'] = (project.PROJECTS_DIR == JOB / 'later' / 'projects'
        and startup.PROJECTS_DIR == project.PROJECTS_DIR
        and startup.ACTIVE_LINK == project.PROJECTS_DIR / '.active'
        and sessions.SESSIONS_DIR == JOB / 'later' / 'sessions.d')
    (JOB / 'restoration.json').write_text(json.dumps(restored))
'''.replace("MODE", repr(mode)))
    (job / "test_archive.py").write_text('''import json
import os
import subprocess
import sys
import caller
import core.startup as startup
from core.project import project, registry_home, sessions


def test_01_body(monkeypatch, tmp_path):
    base = project._projects_dir().parent
    caller.BASES.append(base)
    assert base != caller.CALLER
    if MODE == 'undo':
        monkeypatch.setitem(vars(project), 'PROJECTS_DIR', tmp_path / 'body-projects')
        monkeypatch.setenv(registry_home.ENV_REGISTRY_HOME, str(tmp_path / 'body-registry'))
        monkeypatch.setenv(sessions.ENV_SESSION_PID, '999')
        monkeypatch.undo()
    target = tmp_path / 'owned-code'
    target.mkdir()
    project.ProjectManager().create('owned-after-undo', str(target), output_dir=str(tmp_path / 'out'))
    assert project.PROJECTS_DIR == base / 'projects'
    assert startup.PROJECTS_DIR == project.PROJECTS_DIR
    assert startup.ACTIVE_LINK == project.PROJECTS_DIR / '.active'
    assert sessions.SESSIONS_DIR == base / 'sessions.d'
    assert registry_home.registry_home() == base
    assert sessions.resolve_session_pid() is None
    assert sessions.ENV_SESSION_PID not in os.environ
    assert sessions.ENV_SESSION_TOKEN not in os.environ
    assert (base / 'projects' / 'owned-after-undo.json').is_file()
    code = "import json; import core.startup as s; from core.project import project as p, sessions as x; print(json.dumps([str(p.PROJECTS_DIR), str(s.PROJECTS_DIR), str(s.ACTIVE_LINK), str(x.SESSIONS_DIR)]))"
    child = subprocess.run([sys.executable, '-c', code], capture_output=True, text=True, timeout=20)
    assert child.returncode == 0, child.stderr
    assert json.loads(child.stdout) == [str(base / 'projects'), str(base / 'projects'), str(base / 'projects' / '.active'), str(base / 'sessions.d')]
    monkeypatch.setitem(vars(project), 'PROJECTS_DIR', tmp_path / 'late-body')
    monkeypatch.setenv(registry_home.ENV_REGISTRY_HOME, str(tmp_path / 'late-base'))
    caller.BODY_CHECKED = True
    if MODE == 'error':
        raise AssertionError('intentional archive body failure')
    if MODE == 'interrupt':
        raise KeyboardInterrupt('intentional archive interruption')


def test_02_fresh():
    base = registry_home.registry_home()
    caller.BASES.append(base)
    assert base != caller.BASES[0]
    assert project.ProjectManager().list_projects() == []
'''.replace("MODE", repr(mode)))
    env = dict(os.environ)
    for key in ("RAPTOR_RANDOMISE_TESTS", "RAPTOR_TEST_LIVE_LLM"):
        env.pop(key, None)
    for key, leaf in (("HOME", "home"), ("TMPDIR", "tmp"), ("XDG_DATA_HOME", "data"),
                      ("XDG_CONFIG_HOME", "config"), ("XDG_CACHE_HOME", "cache"),
                      ("RAPTOR_OUT_DIR", "out")):
        directory = job / leaf
        directory.mkdir()
        env[key] = str(directory)
    env["PYTHONPATH"] = str(job) + os.pathsep + str(ROOT)
    # Archive owners use the plugins named below, not installed entry points.
    env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    args = [sys.executable, "-m", "pytest", "--noconftest", "-c", str(ROOT / "pytest.ini"),
            "-p", "core.testing.llm_tripwire", "-p", "fixture_owner", "-p", "caller",
            str(job / "test_archive.py"), "-q", "-m", "", "--tb=short"]
    result = subprocess.run(args, cwd=job, env=env, capture_output=True, text=True, timeout=60)
    assert result.returncode == {"normal": 0, "undo": 0, "error": 1, "interrupt": 2}[mode], result.stdout + result.stderr
    if mode in ("error", "interrupt"):
        assert "intentional archive" in result.stdout + result.stderr
    restored = json.loads((job / "restoration.json").read_text())
    assert all(restored.values()), restored

"""Composite fixture state survives body undo and unwinds on failure."""

import ast
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest


pytestmark = pytest.mark.slow
ROOT = Path(__file__).resolve().parents[3]
CASES = [('core/sandbox/tests/test_audit_degraded_publication_race.py', 'owned_state'),
 ('core/sandbox/tests/test_calibrate_json_integrity.py', 'owned_state'),
 ('core/sandbox/tests/test_cli_failure_contracts.py', 'owned_state'),
 ('core/sandbox/tests/test_cli_terminal_metadata.py', 'owned_state'),
 ('core/sandbox/tests/test_deep_reader_integrity.py', 'owned_state'),
 ('core/sandbox/tests/test_disable_annotation_reads.py', 'owned_state'),
 ('core/sandbox/tests/test_egress_summary_utf8.py', 'owned_state'),
 ('core/sandbox/tests/test_evidence_close_errors.py', 'owned_state'),
 ('core/sandbox/tests/test_evidence_creation_metadata.py', 'owned_state'),
 ('core/sandbox/tests/test_evidence_metadata_integrity.py', 'owned_state'),
 ('core/sandbox/tests/test_evidence_truncation.py', 'owned_state'),
 ('core/sandbox/tests/test_floor_refusal_publication.py', 'owned_state'),
 ('core/sandbox/tests/test_live_log_metadata.py', 'owned_state'),
 ('core/sandbox/tests/test_observe_budget_integrity.py', 'owned_state'),
 ('core/sandbox/tests/test_observe_duplicate_fields.py', 'owned_state'),
 ('core/sandbox/tests/test_observe_input_integrity.py', 'owned_state'),
 ('core/sandbox/tests/test_observe_metadata_completeness.py', 'owned_state'),
 ('core/sandbox/tests/test_observe_summary_status.py', 'owned_state'),
 ('core/sandbox/tests/test_register_metadata.py', 'owned_state'),
 ('core/sandbox/tests/test_seatbelt_capture_integrity.py', 'owned_state'),
 ('core/sandbox/tests/test_seatbelt_stream_decoding.py', 'owned_state'),
 ('core/sandbox/tests/test_structured_reader_uniqueness.py', 'owned_state'),
 ('core/sandbox/tests/test_summary_cli_metadata.py', 'owned_state'),
 ('core/sandbox/tests/test_summary_consumed_metadata.py', 'owned_state'),
 ('core/sandbox/tests/test_summary_duplicate_fields.py', 'owned_state'),
 ('core/sandbox/tests/test_summary_sweep_presence.py', 'owned_state'),
 ('core/sandbox/tests/test_telemetry_key_foreign_objects.py', 'owned_state'),
 ('core/sandbox/tests/test_telemetry_key_hardlinks.py', 'owned_state'),
 ('core/sandbox/tests/test_telemetry_unicode_metadata.py', 'owned_state'),
 ('core/sandbox/tests/test_tracer_evidence_appends.py', 'owned_state'),
 ('core/sandbox/tests/test_triage_duplicate_fields.py', 'owned_state'),
 ('core/sandbox/tests/test_triage_pending_degradation.py', 'owned_state'),
 ('core/sandbox/tests/test_triage_unreadable_count.py', 'owned_state'),
 ('core/security/tests/test_presence_probes.py', 'owned_user_state')]


@pytest.mark.parametrize("file,fixture", CASES, ids=[Path(p).stem for p, _ in CASES])
def test_composite_owner_without_conftests(file, fixture, tmp_path):
    """Exercise four body exits in one real archive-style pytest session."""
    source = ROOT / file
    node = next(n for n in ast.parse(source.read_text()).body
                if isinstance(n, ast.FunctionDef) and n.name == fixture)
    bindings = []
    for call in ast.walk(node):
        if (isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute)
                and isinstance(call.func.value, ast.Name)
                and call.func.value.id == "monkeypatch" and call.func.attr == "setattr"):
            assert isinstance(call.args[0], ast.Name) and isinstance(call.args[1], ast.Constant)
            bindings.append((call.args[0].id, call.args[1].value))
    job = tmp_path / "archive-session"
    job.mkdir()
    (job / "fixture_owner.py").write_text(
        "from pathlib import Path\n__file__ = " + repr(str(source))
        + "\nexec(compile(Path(__file__).read_text(), __file__, 'exec'), globals())\n")
    (job / "caller.py").write_text('''import copy
import hashlib
import json
import os
from pathlib import Path
import pytest
import fixture_owner
import core.startup as startup
from core.project import project, registry_home, sessions
JOB = Path(__file__).resolve().parent
CALLER = JOB / 'caller'
FIELDS = [(project, 'PROJECTS_DIR'), (startup, 'PROJECTS_DIR'),
          (startup, 'ACTIVE_LINK'), (sessions, 'SESSIONS_DIR')]
EXTRA = [(getattr(fixture_owner, owner), name) for owner, name in BINDINGS_VALUE]
BASES, CHECKED, EVENTS, CALLS = [], [], [], []
KEYS = [registry_home.ENV_REGISTRY_HOME, sessions.ENV_SESSION_PID,
        sessions.ENV_SESSION_TOKEN, 'XDG_DATA_HOME']

def files():
    return {str(p.relative_to(CALLER)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in CALLER.rglob('*') if p.is_file()}

def borrowed_walk():
    CALLS.append(True)
    return None

@pytest.hookimpl(trylast=True)
def pytest_configure(config):
    global BEFORE, ENV, CONTENT, EXTRA_BEFORE
    CALLER.mkdir()
    os.environ[registry_home.ENV_REGISTRY_HOME] = str(CALLER)
    os.environ['XDG_DATA_HOME'] = str(CALLER / 'data')
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
    ENV = {key: (key in os.environ, os.environ.get(key)) for key in KEYS}
    BEFORE = [(module, key, key in vars(module), vars(module).get(key)) for module, key in FIELDS]
    EXTRA_BEFORE = []
    for module, name in EXTRA:
        value = getattr(module, name)
        if isinstance(value, dict):
            value = dict(value)
            value['__borrowed_probe__'] = [{'message': 'borrowed'}] if name == '_floor_refusals' else {'message': 'borrowed'}
            setattr(module, name, value)
        elif isinstance(value, set):
            value = {*value, '__borrowed_probe__'}
            setattr(module, name, value)
        elif isinstance(value, Path):
            value = CALLER / name
            setattr(module, name, value)
        content = copy.deepcopy(value) if isinstance(value, (dict, set)) else None
        EXTRA_BEFORE.append((module, name, value, content))
    CONTENT = files()
    CALLS.clear()

def restored():
    return {
        'namespace': all((key in vars(module)) is exists and
                         (not exists or vars(module)[key] is value)
                         for module, key, exists, value in BEFORE),
        'environment': {key: (key in os.environ, os.environ.get(key)) for key in KEYS} == ENV,
        'extra_identity': all(getattr(module, name) is value for module, name, value, _ in EXTRA_BEFORE),
        'borrowed_contents': all(content is None or value == content for _, _, value, content in EXTRA_BEFORE),
        'caller_files_untouched': files() == CONTENT,
        'borrowed_walker_unused': not CALLS,
        'walker_identity': sessions._walk_session_pid is borrowed_walk,
    }

@pytest.hookimpl(wrapper=True, tryfirst=True)
def pytest_runtest_teardown(item, nextitem):
    try:
        return (yield)
    finally:
        EVENTS.append(restored())

@pytest.hookimpl(trylast=True)
def pytest_sessionfinish(session, exitstatus):
    report = restored()
    report['all_four_bodies_checked'] = CHECKED == ['normal', 'undo', 'error', 'interrupt']
    report['fresh_base_per_body'] = len(BASES) == 4 and len(set(BASES)) == 4
    report['between_test_restoration'] = len(EVENTS) >= 3 and all(all(e.values()) for e in EVENTS)
    os.environ[registry_home.ENV_REGISTRY_HOME] = str(JOB / 'later')
    report['dynamic_getters'] = (project.PROJECTS_DIR == JOB / 'later' / 'projects'
        and startup.PROJECTS_DIR == project.PROJECTS_DIR
        and startup.ACTIVE_LINK == project.PROJECTS_DIR / '.active'
        and sessions.SESSIONS_DIR == JOB / 'later' / 'sessions.d')
    (JOB / 'restoration.json').write_text(json.dumps(report))
'''.replace("BINDINGS_VALUE", repr(bindings)))
    (job / "test_archive.py").write_text('''import json
import os
import subprocess
import sys
import pytest
import caller
import core.startup as startup
from core.project import project, registry_home, sessions

@pytest.mark.parametrize('mode', ['normal', 'undo', 'error', 'interrupt'])
def test_body(mode, monkeypatch, tmp_path):
    base = project._projects_dir().parent
    caller.BASES.append(base)
    assert base != caller.CALLER
    assert project.ProjectManager().list_projects() == []
    expected = [(module, name, getattr(module, name)) for module, name in caller.EXTRA]
    data_home = os.environ['XDG_DATA_HOME']
    if mode == 'undo':
        monkeypatch.setitem(vars(project), 'PROJECTS_DIR', tmp_path / 'body-projects')
        monkeypatch.setenv(registry_home.ENV_REGISTRY_HOME, str(tmp_path / 'body-base'))
        monkeypatch.setenv('XDG_DATA_HOME', str(tmp_path / 'body-data'))
        for module, name, _ in expected:
            monkeypatch.setattr(module, name, object())
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
    assert os.environ['XDG_DATA_HOME'] == data_home
    assert all(getattr(module, name) is value for module, name, value in expected)
    assert (base / 'projects' / 'owned-after-undo.json').is_file()
    for module, name, value in expected:
        if isinstance(value, dict):
            value['__owned_write__'] = {'message': 'owned'}
        elif isinstance(value, set):
            value.add('__owned_write__')
    code = "import json; import core.startup as s; from core.project import project as p, sessions as x; print(json.dumps([str(p.PROJECTS_DIR), str(s.PROJECTS_DIR), str(s.ACTIVE_LINK), str(x.SESSIONS_DIR)]))"
    child = subprocess.run([sys.executable, '-c', code], capture_output=True, text=True, timeout=20)
    assert child.returncode == 0, child.stderr
    assert json.loads(child.stdout) == [str(base / 'projects'), str(base / 'projects'), str(base / 'projects' / '.active'), str(base / 'sessions.d')]
    monkeypatch.setitem(vars(project), 'PROJECTS_DIR', tmp_path / 'late-projects')
    monkeypatch.setenv(registry_home.ENV_REGISTRY_HOME, str(tmp_path / 'late-base'))
    for module, name, _ in expected:
        monkeypatch.setattr(module, name, object())
    caller.CHECKED.append(mode)
    if mode == 'error':
        raise AssertionError('intentional composite body failure')
    if mode == 'interrupt':
        raise KeyboardInterrupt('intentional composite interruption')
''')
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
    args = [sys.executable, "-m", "pytest", "--noconftest", "-c", str(ROOT / "pytest.ini"),
            "-p", "core.testing.llm_tripwire", "-p", "fixture_owner", "-p", "caller",
            str(job / "test_archive.py"), "-q", "-m", "", "--tb=short"]
    result = subprocess.run(args, cwd=job, env=env, capture_output=True, text=True, timeout=90)
    output = result.stdout + result.stderr
    assert result.returncode == 2, output
    assert 'intentional composite body failure' in output
    assert 'intentional composite interruption' in output
    restored = json.loads((job / "restoration.json").read_text())
    assert all(restored.values()), restored

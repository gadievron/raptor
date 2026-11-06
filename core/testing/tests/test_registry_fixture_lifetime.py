"""Registry pins preserve lazy namespaces, credential absence and owner lifetime."""

import os

import pytest

import core.startup as startup
from core.project import project, registry_home, sessions
from core.testing.state_isolation import pin_user_state_dirs


VIRTUAL = [(project, "PROJECTS_DIR"), (startup, "PROJECTS_DIR"),
           (startup, "ACTIVE_LINK"), (sessions, "SESSIONS_DIR")]
ENV = (registry_home.ENV_REGISTRY_HOME, sessions.ENV_SESSION_PID, sessions.ENV_SESSION_TOKEN)


def _snapshot():
    return [(owner, key, key in vars(owner), vars(owner).get(key)) for owner, key in VIRTUAL]


def _assert_snapshot(before):
    for owner, key, present, value in before:
        assert (key in vars(owner)) is present, (owner.__name__, key)
        if present:
            assert vars(owner)[key] is value, (owner.__name__, key)


def _finish(mode):
    if mode == "error":
        raise RuntimeError("owned body failed")
    if mode == "interrupt":
        raise KeyboardInterrupt


def _assert_pin(base):
    assert project._projects_dir() == base / "projects"
    assert startup._projects_dir() == base / "projects"
    assert startup._active_link() == base / "projects" / ".active"
    assert sessions._sessions_dir() == base / "sessions.d"
    assert registry_home.registry_home() == base
    assert sessions.resolve_session_pid() is None


@pytest.mark.parametrize("owner,key", VIRTUAL, ids=[m.__name__ + "." + k for m, k in VIRTUAL])
@pytest.mark.parametrize("initial", ["absent", "none", "path"])
@pytest.mark.parametrize("mode", ["normal", "undo", "error", "interrupt"])
def test_lazy_registry_override_presence_is_restored(owner, key, initial, mode, tmp_path, monkeypatch):
    monkeypatch.setenv(registry_home.ENV_REGISTRY_HOME, str(tmp_path / "caller"))
    if initial == "absent":
        monkeypatch.delitem(vars(owner), key, raising=False)
    else:
        monkeypatch.setitem(vars(owner), key, None if initial == "none" else tmp_path / "borrowed")
    before = _snapshot()
    base = tmp_path / "owned"
    try:
        with pytest.MonkeyPatch.context() as patch:
            pin_user_state_dirs(patch, base)
            _assert_pin(base)
            assert not base.exists(), "pinning must not allocate a directory per test"
            if mode == "undo":
                patch.undo()
            _finish(mode)
    except (RuntimeError, KeyboardInterrupt):
        pass
    _assert_snapshot(before)


@pytest.mark.parametrize("key", ENV)
@pytest.mark.parametrize("initial", [None, "", "value"])
@pytest.mark.parametrize("mode", ["normal", "undo", "error", "interrupt"])
def test_direct_env_writes_restore_absent_empty_and_present(key, initial, mode, tmp_path, monkeypatch):
    value = str(tmp_path / "borrowed") if key == registry_home.ENV_REGISTRY_HOME else "12345"
    if initial is None:
        monkeypatch.delenv(key, raising=False)
    else:
        monkeypatch.setenv(key, "" if initial == "" else value)
    before = {name: (name in os.environ, os.environ.get(name)) for name in ENV}
    try:
        with pytest.MonkeyPatch.context() as patch:
            pin_user_state_dirs(patch, tmp_path / "owned")
            os.environ[key] = str(tmp_path / "body") if key == registry_home.ENV_REGISTRY_HOME else "body-write"
            if mode == "undo":
                patch.undo()
            _finish(mode)
    except (RuntimeError, KeyboardInterrupt):
        pass
    assert {name: (name in os.environ, os.environ.get(name)) for name in ENV} == before


POINTS = [(owner, key) for owner, key in VIRTUAL] + [(sessions, "_walk_session_pid")] + [("environment", name) for name in ENV]


@pytest.mark.parametrize("target,key", POINTS, ids=["publication-" + str(i) for i in range(len(POINTS))])
@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt])
def test_partial_publication_restores_namespace_and_env(target, key, error, tmp_path, monkeypatch):
    if target == "environment":
        target = os.environ
    for owner, name in VIRTUAL:
        monkeypatch.delitem(vars(owner), name, raising=False)
    monkeypatch.setenv(registry_home.ENV_REGISTRY_HOME, str(tmp_path / "caller"))
    for name in ENV[1:]:
        monkeypatch.delenv(name, raising=False)
    before = _snapshot()
    before_env = {name: (name in os.environ, os.environ.get(name)) for name in ENV}
    walker = sessions._walk_session_pid

    class InterruptedPatch(pytest.MonkeyPatch):
        armed = True
        def after(self, obj, name):
            if self.armed and obj is target and name == key:
                self.armed = False
                raise error("after publication")
        def setattr(self, obj, name, value, *args, **kwargs):
            super().setattr(obj, name, value, *args, **kwargs)
            self.after(obj, name)
        def setitem(self, mapping, name, value):
            super().setitem(mapping, name, value)
            self.after(mapping, name)
            for owner, _ in VIRTUAL:
                if mapping is vars(owner):
                    self.after(owner, name)

    try:
        with InterruptedPatch.context() as patch:
            pin_user_state_dirs(patch, tmp_path / "owned")
    except (RuntimeError, KeyboardInterrupt):
        pass
    _assert_snapshot(before)
    assert sessions._walk_session_pid is walker
    assert {name: (name in os.environ, os.environ.get(name)) for name in ENV} == before_env


@pytest.mark.parametrize("value", ["relative", "~", "bad/registry"])
def test_owned_pin_does_not_resolve_malformed_caller_override(value, tmp_path, monkeypatch):
    for owner, key in VIRTUAL:
        monkeypatch.delitem(vars(owner), key, raising=False)
    monkeypatch.setenv(registry_home.ENV_REGISTRY_HOME, value)
    with pytest.MonkeyPatch.context() as patch:
        pin_user_state_dirs(patch, tmp_path / "owned")
        _assert_pin(tmp_path / "owned")
    assert os.environ[registry_home.ENV_REGISTRY_HOME] == value
    for owner, key in VIRTUAL:
        assert key not in vars(owner)


def test_restored_lazy_getters_follow_a_later_registry_home(tmp_path, monkeypatch):
    for owner, key in VIRTUAL:
        monkeypatch.delitem(vars(owner), key, raising=False)
    monkeypatch.setenv(registry_home.ENV_REGISTRY_HOME, str(tmp_path / "caller-a"))
    with pytest.MonkeyPatch.context() as patch:
        pin_user_state_dirs(patch, tmp_path / "owned")
    monkeypatch.setenv(registry_home.ENV_REGISTRY_HOME, str(tmp_path / "caller-b"))
    assert project.PROJECTS_DIR == tmp_path / "caller-b" / "projects"
    assert startup.PROJECTS_DIR == project.PROJECTS_DIR
    assert startup.ACTIVE_LINK == project.PROJECTS_DIR / ".active"
    assert sessions.SESSIONS_DIR == tmp_path / "caller-b" / "sessions.d"


@pytest.mark.parametrize("root", ["home", "parent", "raptor"])
def test_protected_bases_still_refuse_without_publishing(root, tmp_path, monkeypatch):
    home = tmp_path / "home"
    monkeypatch.setenv("HOME", str(home))
    base = {"home": home, "parent": tmp_path, "raptor": home / ".raptor"}[root]
    before, env = _snapshot(), dict(os.environ)
    with pytest.MonkeyPatch.context() as patch, pytest.raises(ValueError, match="covers real user state"):
        pin_user_state_dirs(patch, base)
    _assert_snapshot(before)
    assert dict(os.environ) == env


@pytest.mark.parametrize("stack", ["root", "sandbox", "validation"])
@pytest.mark.parametrize("presence", ["missing", "present"])
def test_real_pytest_registry_owner_outlives_body_undo(stack, presence, tmp_path):
    import json
    from pathlib import Path
    import subprocess
    import sys

    root = Path(__file__).resolve().parents[3]
    job = tmp_path / "child"
    job.mkdir()
    sources = [("root_guards", root / "conftest.py")]
    if stack != "root":
        relative = "core/sandbox/tests/conftest.py" if stack == "sandbox" else "packages/exploitability_validation/tests/conftest.py"
        sources.append(("directory_guards", root / relative))
    for name, path in sources:
        (job / (name + ".py")).write_text(
            "from pathlib import Path\n__file__ = " + repr(str(path))
            + "\nexec(compile(Path(__file__).read_text(), __file__, 'exec'), globals())\n")
    report = job / "restoration.json"
    caller = '''import hashlib
import json
import os
from pathlib import Path
import pytest
import core.startup as startup
from core.project import project, registry_home, sessions
JOB = Path(JOB_VALUE)
REPORT = Path(REPORT_VALUE)
PRESENT = PRESENT_VALUE
FIELDS = [(project, 'PROJECTS_DIR'), (startup, 'PROJECTS_DIR'),
          (startup, 'ACTIVE_LINK'), (sessions, 'SESSIONS_DIR')]
CALLS = []
ROOTS = []

def snapshot_files():
    return {str(path.relative_to(CALLER)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in CALLER.rglob('*') if path.is_file()}

def borrowed_walk():
    CALLS.append('borrowed walk called')
    return None

@pytest.hookimpl(trylast=True)
def pytest_configure(config):
    global CALLER, BEFORE, ENV_BEFORE, FILES_BEFORE
    CALLER = JOB / 'caller-registry'
    CALLER.mkdir()
    os.environ[registry_home.ENV_REGISTRY_HOME] = str(CALLER)
    for module, key in FIELDS:
        vars(module).pop(key, None)
    sessions._walk_session_pid = borrowed_walk
    os.environ.pop(sessions.ENV_SESSION_PID, None)
    os.environ.pop(sessions.ENV_SESSION_TOKEN, None)
    target = JOB / 'caller-code'
    target.mkdir()
    manager = project.ProjectManager(projects_dir=CALLER / 'projects')
    manager.create('borrowed', str(target), output_dir=str(JOB / 'caller-output'))
    manager.set_active('borrowed')
    CALLS.clear()
    if PRESENT:
        paths = [CALLER / 'projects', CALLER / 'projects',
                 CALLER / 'projects' / '.active', CALLER / 'sessions.d']
        for (module, key), value in zip(FIELDS, paths):
            vars(module)[key] = value
    BEFORE = [(module, key, key in vars(module), vars(module).get(key)) for module, key in FIELDS]
    os.environ[sessions.ENV_SESSION_PID] = '12345'
    os.environ[sessions.ENV_SESSION_TOKEN] = 'borrowed-token'
    ENV_BEFORE = {key: os.environ.get(key) for key in
                  (registry_home.ENV_REGISTRY_HOME, sessions.ENV_SESSION_PID, sessions.ENV_SESSION_TOKEN)}
    FILES_BEFORE = snapshot_files()

@pytest.hookimpl(trylast=True)
def pytest_sessionfinish(session, exitstatus):
    namespace = all((key in vars(module)) is exists and
                    (not exists or vars(module)[key] is value)
                    for module, key, exists, value in BEFORE)
    restored = {
        'namespace': namespace,
        'environment': all(os.environ.get(key) == value for key, value in ENV_BEFORE.items()),
        'walker_identity': sessions._walk_session_pid is borrowed_walk,
        'caller_files_untouched': snapshot_files() == FILES_BEFORE,
        'caller_walker_unused': CALLS == [],
        'fresh_base_per_test': len(ROOTS) == 2 and ROOTS[0] != ROOTS[1],
    }
    if not PRESENT:
        os.environ[registry_home.ENV_REGISTRY_HOME] = str(JOB / 'later-home')
        restored['getters_still_dynamic'] = (project.PROJECTS_DIR == JOB / 'later-home' / 'projects'
            and startup.PROJECTS_DIR == project.PROJECTS_DIR
            and startup.ACTIVE_LINK == project.PROJECTS_DIR / '.active'
            and sessions.SESSIONS_DIR == JOB / 'later-home' / 'sessions.d')
    REPORT.write_text(json.dumps(restored))
'''
    caller = caller.replace("JOB_VALUE", repr(str(job))).replace("REPORT_VALUE", repr(str(report))).replace("PRESENT_VALUE", repr(presence == "present"))
    (job / "caller.py").write_text(caller)
    (job / "test_lifetime.py").write_text('''import os
import json
import subprocess
import sys
from pathlib import Path
import caller
import core.startup as startup
from core.project import project, registry_home, sessions


def test_pin_survives_body_undo(monkeypatch, tmp_path):
    base = project._projects_dir().parent
    caller.ROOTS.append(base)
    assert base != caller.CALLER
    monkeypatch.setitem(vars(project), 'PROJECTS_DIR', tmp_path / 'body-projects')
    monkeypatch.setenv(registry_home.ENV_REGISTRY_HOME, str(tmp_path / 'body-base'))
    monkeypatch.setenv(sessions.ENV_SESSION_PID, '999')
    monkeypatch.undo()
    # Exercise a real writer before checking its destination: on the baseline
    # this would create a foreign project in the configure-time caller store.
    target = tmp_path / 'owned-code'
    target.mkdir()
    project.ProjectManager().create('owned-after-undo', str(target), output_dir=str(tmp_path / 'output'))
    assert registry_home.registry_home() == base
    assert project.PROJECTS_DIR == base / 'projects'
    assert startup.PROJECTS_DIR == project.PROJECTS_DIR
    assert startup.ACTIVE_LINK == project.PROJECTS_DIR / '.active'
    assert sessions.SESSIONS_DIR == base / 'sessions.d'
    assert sessions.resolve_session_pid() is None
    assert sessions.ENV_SESSION_PID not in os.environ
    assert sessions.ENV_SESSION_TOKEN not in os.environ
    assert (base / 'projects' / 'owned-after-undo.json').is_file()
    code = "import json; import core.startup as s; from core.project import project as p, sessions as x; print(json.dumps([str(p.PROJECTS_DIR), str(s.PROJECTS_DIR), str(s.ACTIVE_LINK), str(x.SESSIONS_DIR)]))"
    reader = subprocess.run([sys.executable, '-c', code], capture_output=True, text=True, timeout=30)
    assert reader.returncode == 0, reader.stderr
    assert json.loads(reader.stdout) == [str(base / 'projects'), str(base / 'projects'), str(base / 'projects' / '.active'), str(base / 'sessions.d')]


def test_next_pin_is_fresh():
    caller.ROOTS.append(registry_home.registry_home())
    assert project.ProjectManager().list_projects() == []
''')
    env = dict(os.environ)
    env.pop("RAPTOR_RANDOMISE_TESTS", None)
    env.pop("RAPTOR_TEST_LIVE_LLM", None)
    for key, leaf in (("HOME", "home"), ("TMPDIR", "tmp"), ("XDG_DATA_HOME", "data"),
                      ("XDG_CONFIG_HOME", "config"), ("XDG_CACHE_HOME", "cache"),
                      ("RAPTOR_OUT_DIR", "out")):
        directory = job / leaf
        directory.mkdir()
        env[key] = str(directory)
    env["PYTHONPATH"] = str(job) + os.pathsep + str(root)
    args = [sys.executable, "-m", "pytest", "--noconftest", "-c", str(root / "pytest.ini"),
            "-p", "core.testing.llm_tripwire"]
    for name, _ in sources:
        args += ["-p", name]
    args += ["-p", "caller", str(job / "test_lifetime.py"), "-q", "-m", "", "--tb=short"]
    result = subprocess.run(args, cwd=job, env=env, capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stdout + result.stderr
    restored = json.loads(report.read_text())
    assert all(restored.values()), restored

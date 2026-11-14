"""Installed-runtime selection owns metadata; it never runs the fixture tools."""

import os
import json
import subprocess
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

from packages.semgrep import runtime
from packages.semgrep import runner


@pytest.fixture
def installation(tmp_path, monkeypatch):
    root = tmp_path / 'snap'
    app = root / 'semgrep/13'
    base = root / 'core22/3129'
    for directory in [app / 'meta', app / 'bin', base / 'usr/bin',
                      base / 'usr/lib/python3.10',
                      app / 'lib/python3.10/site-packages/semgrep/bin',
                      app / 'lib/python3.10/site-packages/semgrep-1.56.0.dist-info']:
        directory.mkdir(parents=True, exist_ok=True)
    (root / 'semgrep/current').symlink_to('13')
    (root / 'core22/current').symlink_to('3129')
    (app / 'meta/snap.yaml').write_text('name: semgrep\nversion: 1.56.0\nbase: core22\n')
    (app / 'pyvenv.cfg').write_text('home = /usr/bin\nversion = 3.10.12\n')
    (app / 'lib/python3.10/site-packages/semgrep-1.56.0.dist-info/METADATA').write_text(
        'Name: semgrep\nVersion: 1.56.0\n')
    dispatcher = tmp_path / 'usr/bin/snap'
    dispatcher.parent.mkdir(parents=True)
    for executable in [dispatcher, base / 'usr/bin/python3.10', app / 'bin/pysemgrep',
                       app / 'lib/python3.10/site-packages/semgrep/bin/semgrep-core']:
        executable.write_text('owned metadata; never executed\n')
        executable.chmod(0o755)
    launcher = root / 'bin/semgrep'
    launcher.parent.mkdir()
    launcher.symlink_to(dispatcher)
    monkeypatch.delenv('RAPTOR_SEMGREP_OFFLINE', raising=False)
    monkeypatch.setattr(runner, '_SCOPE_PROBE_CACHE', None)
    monkeypatch.setattr(runner, '_SCOPE_PROBE_PENDING', None)
    monkeypatch.setattr(runner, '_SCOPE_PROBE_LOCK', threading.Lock())
    monkeypatch.setattr(runner, '_scope_upgrade_warned', False)
    monkeypatch.setattr(runner, '_SCOPE_WARNING_LOCK', threading.Lock())
    monkeypatch.setattr(runtime, '_SNAP_ROOT', root)
    monkeypatch.setattr(runtime, '_DISPATCHERS', (dispatcher,))

    def owned_trust(path, *, executable=False):
        selected = path.resolve(strict=True)
        assert selected.is_relative_to(tmp_path)
        if executable:
            assert selected.is_file() and selected.stat().st_mode & 0o111
        return selected

    def owned_metadata(path, root):
        selected = runtime._inside(path, root)
        raw, st = runtime.read_capped_with_stat(selected, runtime._METADATA_CAP)
        if raw is None:
            raise runtime.SnapRuntimeError('owned metadata refusal')
        import hashlib
        return raw.decode(), (str(selected), hashlib.sha256(raw).hexdigest())

    # Trust/mount authority is a private consumer adapter, not a production
    # configuration escape hatch. Parser/confinement checks remain actual code.
    monkeypatch.setattr(runtime, '_trusted_path', owned_trust)
    monkeypatch.setattr(runtime, '_readonly_revision', lambda path: None)
    monkeypatch.setattr(runtime, '_metadata', owned_metadata)
    return SimpleNamespace(root=root, app=app, base=base, launcher=launcher,
                           dispatcher=dispatcher)


def test_resolves_one_installed_runtime_and_keeps_environment_local(installation):
    spec = runtime.resolve_snap_runtime(str(installation.launcher))
    assert spec.version == '1.56.0'
    assert spec.command_prefix == (str(installation.base / 'usr/bin/python3.10'),
                                   str(installation.app / 'bin/pysemgrep'))
    inherited = {'PYTHONPATH': '/host/injection', 'PYTHONSTARTUP': '/host/hook',
                 'PATH': '/host/bin', 'HOME': '/owned/fake-home',
                 'LD_PRELOAD': '/host/evil.so', 'BASH_ENV': '/host/hook',
                 'UNKNOWN_SECRET': 'secret', 'LC_TEST_API_KEY': 'secret'}
    child = spec.child_environment(inherited)
    assert inherited['PYTHONPATH'] == '/host/injection'
    assert child['PYTHONPATH'] == str(spec.site_packages)
    assert not ({'PYTHONSTARTUP', 'LD_PRELOAD', 'BASH_ENV',
                 'UNKNOWN_SECRET', 'LC_TEST_API_KEY'} & child.keys())
    assert child['HOME'] == '/owned/fake-home'
    assert str(installation.root / 'bin') not in spec.tool_paths
    assert str(installation.base / 'usr/bin') not in spec.tool_paths
    spec.validate()


def test_ordinary_symlink_is_not_a_snap(installation, tmp_path):
    tool = tmp_path / 'ordinary'
    tool.write_text('owned ordinary launcher\n')
    alias = tmp_path / 'semgrep'
    alias.symlink_to(tool)
    assert runtime.resolve_snap_runtime(str(alias)) is None


def test_bare_name_does_not_resolve_from_target_working_directory(installation, monkeypatch):
    monkeypatch.chdir(installation.launcher.parent)
    assert runtime.resolve_snap_runtime('semgrep') is None


@pytest.mark.parametrize('field,value', [
    ('name', 'other'), ('base', '../../host'), ('base', 'bare'),
    ('version', '1.56.0\nversion: 9.0.0'), ('version', 'unknown'),
])
def test_invalid_snap_metadata_refuses_without_dispatch(installation, field, value):
    fields = {'name': 'semgrep', 'version': '1.56.0', 'base': 'core22'}
    fields[field] = value
    (installation.app / 'meta/snap.yaml').write_text(''.join(f'{k}: {v}\n' for k, v in fields.items()))
    with pytest.raises(runtime.SnapRuntimeError):
        runtime.resolve_snap_runtime(str(installation.launcher))


@pytest.mark.parametrize('target', ['../13', '/host/13', 'current', '0'])
def test_revision_selector_must_be_numeric_and_confined(installation, target):
    alias = installation.root / 'semgrep/current'
    alias.unlink()
    alias.symlink_to(target)
    with pytest.raises(runtime.SnapRuntimeError):
        runtime.resolve_snap_runtime(str(installation.launcher))


def test_refresh_invalidates_pinned_identity(installation):
    spec = runtime.resolve_snap_runtime(str(installation.launcher))
    (installation.app / 'pyvenv.cfg').write_text('version = 3.10.13\n')
    with pytest.raises(runtime.SnapRuntimeError, match='changed'):
        spec.validate()


def test_missing_runtime_is_an_explicit_error(installation):
    (installation.base / 'usr/bin/python3.10').unlink()
    with pytest.raises(runtime.SnapRuntimeError):
        runtime.resolve_snap_runtime(str(installation.launcher))


def test_escaping_site_packages_is_refused(installation, tmp_path):
    site = installation.app / 'lib/python3.10/site-packages'
    site.rename(site.with_name('saved'))
    site.symlink_to(tmp_path)
    with pytest.raises(runtime.SnapRuntimeError, match='escapes'):
        runtime.resolve_snap_runtime(str(installation.launcher))


def test_direct_python_script_does_not_use_host_shebang(installation):
    with pytest.raises(runtime.SnapRuntimeError, match='launcher'):
        runtime.resolve_snap_runtime(str(installation.app / 'bin/pysemgrep'))


@pytest.mark.parametrize('options,filesystem', [('rw', 'squashfs'), ('ro', 'ext4')])
def test_revision_requires_readonly_squashfs(tmp_path, monkeypatch, options, filesystem):
    path = tmp_path / '13'
    monkeypatch.setattr(runtime, 'read_capped', lambda *a, **k:
                        f'1 0 1:2 / {path} {options} - {filesystem} /dev/loop0 ro\n'.encode())
    with pytest.raises(runtime.SnapRuntimeError):
        runtime._readonly_revision(path)


def test_version_capability_build_and_grants_share_the_runtime(installation, monkeypatch):
    monkeypatch.setattr(runner.shutil, 'which', lambda name: str(installation.launcher))
    assert runner.version() == '1.56.0'
    assert not runner.scope_isolation_available()
    spec = runtime.resolve_snap_runtime(str(installation.launcher))
    command = runner.build_cmd(Path('/owned/target'), '/owned/rule.yaml',
                               semgrep_bin=str(installation.launcher),
                               scope_isolation=False, runtime=spec)
    assert command[:2] == list(spec.command_prefix)
    assert '--json' in command and '--sarif' not in command and '--json-output' not in command


def test_run_rule_uses_one_json_invocation_with_fresh_metadata(installation, monkeypatch, tmp_path):
    monkeypatch.setattr(runner.shutil, 'which', lambda name: str(installation.launcher))
    calls = []
    target = tmp_path / 'target'
    target.mkdir()
    payload = json.dumps({'version': '1.56.0', 'errors': [],
                          'paths': {'scanned': ['unsafe.py', 'safe.py']},
                          'results': [{'check_id': 'owned-eval', 'path': 'unsafe.py',
                                       'start': {'line': 2, 'col': 9},
                                       'end': {'line': 2, 'col': 25},
                                       'extra': {'message': 'Owned finding', 'severity': 'WARNING',
                                                 'metadata': {}}}]})

    def execute(command, **kwargs):
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(command, 1, payload, '')

    setattr(execute, "with_semgrep_runtime", lambda selected_runtime: execute)
    output = tmp_path / 'metadata.json'
    output.write_text('{"stale": true}')
    inherited = {'PYTHONPATH': '/host/injection', 'PATH': '/host/bin'}
    result = runner.run_rule(target, '/owned/rule.yaml',
                             subprocess_runner=execute, json_output_path=output,
                             env=inherited)
    assert not result.errors and len(result.findings) == 1
    assert result.files_examined == ['safe.py', 'unsafe.py']
    assert result.semgrep_version == '1.56.0' and result.json_output == payload
    assert output.read_text() == payload and len(calls) == 1
    assert '--json' in calls[0][0] and '--json-output' not in calls[0][0]
    assert calls[0][1]['env']['PYTHONPATH'].startswith(str(installation.app))
    assert inherited['PYTHONPATH'] == '/host/injection'


def test_recognized_bad_runtime_returns_actionable_error(installation, monkeypatch, tmp_path):
    monkeypatch.setattr(runner.shutil, 'which', lambda name: str(installation.launcher))
    (installation.app / 'meta/snap.yaml').write_text('name: semgrep\nbase: unsupported\nversion: 1.56.0\n')
    result = runner.run_rule(tmp_path, '/owned/rule.yaml',
                             subprocess_runner=lambda *a, **k: pytest.fail('tool invoked'))
    assert result.returncode == -1 and result.errors
    assert 'Unsupported Semgrep Snap base' in result.errors[0]


def test_metadata_fifo_is_refused_without_opening_a_writer(installation):
    path = installation.app / 'meta/snap.yaml'
    path.unlink()
    os.mkfifo(path)
    with pytest.raises(runtime.SnapRuntimeError):
        runtime.resolve_snap_runtime(str(installation.launcher))


def test_metadata_over_cap_is_refused(installation):
    (installation.app / 'meta/snap.yaml').write_text('x' * (runtime._METADATA_CAP + 1))
    with pytest.raises(runtime.SnapRuntimeError):
        runtime.resolve_snap_runtime(str(installation.launcher))


def test_writable_ancestor_is_not_runtime_authority(tmp_path):
    tmp_path.chmod(0o777)
    with pytest.raises(runtime.SnapRuntimeError, match='Untrusted'):
        runtime._trusted_path(tmp_path)


@pytest.mark.parametrize('uid,mode,acl_write,message', [
    (12345, 0o755, False, 'Untrusted'),
    (0, 0o775, False, 'Untrusted'),
    (0, 0o757, False, 'Untrusted'),
    (0, 0o755, True, 'Writable'),
])
def test_trust_rejects_each_owner_mode_and_acl_boundary_independently(
        tmp_path, uid, mode, acl_write, message):
    import stat
    from types import ModuleType
    from core.testing.module_views import module_function_view

    accesses = []
    private_os = ModuleType('owned_runtime_os')
    vars(private_os).update(vars(os))
    private_os.stat = lambda path: SimpleNamespace(st_uid=uid, st_mode=stat.S_IFDIR | mode)
    private_os.geteuid = lambda: 2600

    def access(path, flags):
        accesses.append((path, flags))
        return acl_write

    private_os.access = access
    view = module_function_view(runtime, bindings={'os': private_os})
    with pytest.raises(runtime.SnapRuntimeError, match=message):
        view._trusted_path(tmp_path)
    assert bool(accesses) is acl_write


def test_snap_unknown_custom_runner_fails_without_calling_it(installation, monkeypatch, tmp_path):
    monkeypatch.setattr(runner.shutil, 'which', lambda name: str(installation.launcher))
    result = runner.run_rule(tmp_path, '/owned/rule.yaml',
                             subprocess_runner=lambda *a, **k: pytest.fail('unknown runner called'))
    assert result.returncode == -1
    assert 'runtime-aware subprocess_runner' in result.errors[0]


def test_mismatched_output_version_retains_raw_but_no_coverage(installation, monkeypatch, tmp_path):
    monkeypatch.setattr(runner.shutil, 'which', lambda name: str(installation.launcher))
    raw = json.dumps({'version': '9.9.9', 'errors': [], 'results': [],
                      'paths': {'scanned': ['untrusted.py']}})

    def execute(command, **kwargs):
        return subprocess.CompletedProcess(command, 0, raw, '')

    setattr(execute, "with_semgrep_runtime", lambda selected_runtime: execute)
    output = tmp_path / 'metadata.json'
    output.write_text('{"stale": true}')
    result = runner.run_rule(tmp_path, '/owned/rule.yaml', subprocess_runner=execute,
                             json_output_path=output)
    assert any('version does not match' in error for error in result.errors)
    assert result.json_output == raw and not result.files_examined
    assert result.semgrep_version == '' and not output.exists()


@pytest.mark.parametrize('outcome', ['unique', 'ambiguous', 'budget'])
def test_distribution_discovery_closes_its_actual_directory_stream(tmp_path, monkeypatch, outcome):
    site = tmp_path / 'site-packages'
    site.mkdir()
    first = site / 'semgrep-1.56.0.dist-info'
    first.mkdir()
    (first / 'METADATA').write_text('Name: semgrep\nVersion: 1.56.0\n')
    if outcome == 'ambiguous':
        (site / 'semgrep-9.9.9.dist-info').mkdir()
    if outcome == 'budget':
        (site / 'another-package').mkdir()
        monkeypatch.setattr(runtime, '_SITE_ENTRY_CAP', 1)
    closed = []
    actual_scandir = os.scandir

    class OwnedDirectoryStream:
        def __init__(self, path):
            self.actual = actual_scandir(path)

        def __enter__(self):
            return self.actual.__enter__()

        def __exit__(self, *failure):
            try:
                return self.actual.__exit__(*failure)
            finally:
                closed.append(True)

    private_os = SimpleNamespace(**vars(os))
    private_os.scandir = OwnedDirectoryStream
    monkeypatch.setattr(runtime, 'os', private_os)
    if outcome == 'unique':
        assert runtime._distribution_metadata(site) == first / 'METADATA'
    else:
        with pytest.raises(runtime.SnapRuntimeError):
            runtime._distribution_metadata(site)
    assert closed == [True]

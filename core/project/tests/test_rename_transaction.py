"""Registry and output rename failures preserve the previous project."""
import os
from pathlib import Path

import pytest

from core.project import project as model
from core.project import rename_transaction as transaction
from core.project import sessions
from core.testing.module_bindings import patch_module_attribute


@pytest.fixture
def managed(tmp_path, monkeypatch):
    monkeypatch.setenv('RAPTOR_REGISTRY_HOME', str(tmp_path / 'state'))
    monkeypatch.setattr(model, 'DEFAULT_OUTPUT_BASE', tmp_path / 'output')
    return model.ProjectManager(tmp_path / 'state/projects')


def prepare(manager, tmp_path, state):
    output = tmp_path / 'custom' if state == 'custom' else None
    project = manager.create('before', '/target', output_dir=str(output) if output else None,
                             resolve_target=False)
    if state == 'missing':
        project.output_path.rmdir()
    else:
        (project.output_path / 'keep').write_text('previous output')
    manager.set_active('before')
    sessions.record_session('before', pid=os.getpid())
    record = manager.projects_dir / 'before.json'
    return project, record.read_bytes(), {
        str(p): p.read_bytes() for p in (manager.projects_dir.parent / 'sessions.d').glob('*.json')}


SCENARIOS = [(state, phase) for state in ('default', 'custom', 'missing')
             for phase in ('prepare', 'backup', 'move', 'publish', 'retire')
             if phase != 'move' or state == 'default']


@pytest.mark.parametrize('state,phase', SCENARIOS, ids=['-'.join(row) for row in SCENARIOS])
@pytest.mark.parametrize('failure', [OSError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize('after', [False, True], ids=['before-effect', 'after-effect'])
def test_rename_rolls_back_every_owned_effect(managed, tmp_path, monkeypatch, state, phase, failure, after):
    project, record, bindings = prepare(managed, tmp_path, state)
    called = []
    def fault(original, match):
        def wrapped(*args, **kwargs):
            if not match(*args, **kwargs):
                return original(*args, **kwargs)
            called.append(True)
            if after:
                original(*args, **kwargs)
            raise failure('rename failed')
        return wrapped
    if phase == 'prepare':
        monkeypatch.setattr(transaction, 'save_json', fault(transaction.save_json, lambda *a, **kw: True))
    elif phase == 'backup':
        patch_module_attribute(monkeypatch, transaction, 'os', 'link',
                               fault(os.link, lambda *a, **kw: True))
    elif phase in ('move', 'publish'):
        monkeypatch.setattr(transaction, 'rename_without_replace', fault(
            transaction.rename_without_replace,
            lambda src, dst: src == project.output_path if phase == 'move' else Path(src).name == 'project.json'))
    else:
        class RegistryPath(type(managed.projects_dir)):
            def unlink(self, *args, **kwargs):
                if self.name == 'before.json' and not called:
                    called.append(True)
                    if after:
                        super().unlink(*args, **kwargs)
                    raise failure('rename failed')
                return super().unlink(*args, **kwargs)
        managed.projects_dir = RegistryPath(managed.projects_dir)
    with pytest.raises(failure, match='rename failed'):
        managed.rename('before', 'after')
    assert called
    assert (managed.projects_dir / 'before.json').read_bytes() == record
    assert not (managed.projects_dir / 'after.json').exists()
    assert os.readlink(managed.projects_dir / '.active') == 'before.json'
    for path, data in bindings.items():
        assert Path(path).read_bytes() == data
    if state != 'missing':
        assert (project.output_path / 'keep').read_text() == 'previous output'
    else:
        assert not project.output_path.exists()
    assert not (model.DEFAULT_OUTPUT_BASE / 'after').exists()
    assert not list(managed.projects_dir.glob('.rename-*'))


@pytest.mark.parametrize('state', ['default', 'custom', 'missing'])
def test_success_repoints_registration_and_bindings_without_backups(managed, tmp_path, state):
    original, _, _ = prepare(managed, tmp_path, state)
    result = managed.rename('before', 'after')
    assert managed.load('before') is None
    assert managed.load('after').output_dir == result.output_dir
    assert os.readlink(managed.projects_dir / '.active') == 'after.json'
    if state == 'custom':
        assert result.output_dir == original.output_dir
    if state != 'missing':
        assert (result.output_path / 'keep').read_text() == 'previous output'
    assert not list(managed.projects_dir.glob('.rename-*'))


@pytest.mark.parametrize('phase', ['output', 'registration'])
def test_late_contender_never_replaced_and_previous_output_restored(managed, tmp_path, monkeypatch, phase):
    from core.project.tests.test_directory_relocation import occupy
    project, record, _ = prepare(managed, tmp_path, 'default')
    original = transaction.rename_without_replace
    contenders = []
    def race(src, dst):
        if ((phase == 'output' and src == project.output_path)
                or (phase == 'registration' and Path(src).name == 'project.json')):
            contenders.append((dst, occupy(dst, 'empty' if phase == 'output' else 'file', tmp_path)))
        return original(src, dst)
    monkeypatch.setattr(transaction, 'rename_without_replace', race)
    with pytest.raises(OSError):
        managed.rename('before', 'after')
    assert (managed.projects_dir / 'before.json').read_bytes() == record
    assert (project.output_path / 'keep').read_text() == 'previous output'
    path, identity = contenders[0]
    assert path.lstat().st_ino == identity


@pytest.mark.parametrize('failure', [OSError, KeyboardInterrupt, SystemExit])
def test_output_rollback_failure_retains_data_and_original_error(managed, tmp_path, monkeypatch, caplog, failure):
    project, record, _ = prepare(managed, tmp_path, 'default')
    original = transaction.rename_without_replace
    moved = model.DEFAULT_OUTPUT_BASE / 'after'
    def rename(src, dst):
        if Path(src).name == 'project.json':
            raise failure('primary publication failure')
        if src == moved:
            raise OSError('cannot restore output')
        return original(src, dst)
    monkeypatch.setattr(transaction, 'rename_without_replace', rename)
    with pytest.raises(failure, match='primary publication failure'):
        managed.rename('before', 'after')
    assert (moved / 'keep').read_text() == 'previous output'
    assert (managed.projects_dir / 'before.json').read_bytes() == record
    assert str(moved) in caplog.text
    assert not (managed.projects_dir / 'after.json').exists()
    assert not project.output_path.exists()


@pytest.mark.parametrize('failure', [OSError, KeyboardInterrupt, SystemExit])
def test_registry_restore_failure_keeps_recovery_record_outside_scratch(managed, tmp_path, monkeypatch, caplog, failure):
    _, record, _ = prepare(managed, tmp_path, 'default')
    original = transaction.rename_without_replace
    class RegistryPath(type(managed.projects_dir)):
        def unlink(self, *args, **kwargs):
            if self.name == 'before.json':
                super().unlink(*args, **kwargs)
                raise failure('primary retirement failure')
            return super().unlink(*args, **kwargs)
    managed.projects_dir = RegistryPath(managed.projects_dir)
    def rename(src, dst):
        if Path(src).name.startswith('.rename-backup-'):
            raise OSError('registration restore denied')
        return original(src, dst)
    monkeypatch.setattr(transaction, 'rename_without_replace', rename)
    with pytest.raises(failure, match='primary retirement failure'):
        managed.rename('before', 'after')
    backups = list(managed.projects_dir.glob('.rename-backup-*.record'))
    assert len(backups) == 1 and backups[0].read_bytes() == record
    assert str(backups[0]) in caplog.text
    assert (model.DEFAULT_OUTPUT_BASE / 'after/keep').read_text() == 'previous output'
    assert managed.load('after') is not None
    assert not list(managed.projects_dir.glob('.rename-record-*'))


@pytest.mark.parametrize('mode', [0o400, 0o600, 0o640, 0o644])
def test_rename_retains_registry_mode(managed, tmp_path, mode):
    prepare(managed, tmp_path, 'default')
    (managed.projects_dir / 'before.json').chmod(mode)
    managed.rename('before', 'after')
    assert (managed.projects_dir / 'after.json').stat().st_mode & 0o777 == mode


@pytest.mark.parametrize('kind', ['fifo', 'symlink', 'directory'])
@pytest.mark.parametrize('name', ['before.json.lock', 'after.json.lock', '.output-claims.lock'])
def test_rename_refuses_unusable_required_lock_before_moving(managed, tmp_path, kind, name):
    from core.project.tests.test_directory_relocation import occupy
    project, record, _ = prepare(managed, tmp_path, 'default')
    path = managed.projects_dir / name
    path.unlink(missing_ok=True)  # Discard only an idle test-owned sidecar.
    occupy(path, 'empty' if kind == 'directory' else kind, tmp_path)
    with pytest.raises(OSError):
        managed.rename('before', 'after')
    assert (managed.projects_dir / 'before.json').read_bytes() == record
    assert (project.output_path / 'keep').read_text() == 'previous output'
    assert managed.load('after') is None

"""Import publication failures keep the previous data, record and bindings."""
import json
import os
from pathlib import Path
from types import SimpleNamespace
import zipfile

import pytest
from core.project import export as archives
from core.project import import_transaction as transaction
from core.project import project as model
from core.project import sessions
from core.testing.module_bindings import patch_module_attribute


def prepare(tmp_path, monkeypatch, state='registered'):
    home = tmp_path / 'state'
    monkeypatch.setenv('RAPTOR_REGISTRY_HOME', str(home))
    output_base = tmp_path / 'output'
    monkeypatch.setattr(model, 'DEFAULT_OUTPUT_BASE', output_base)
    manager = model.ProjectManager(home / 'projects')
    output = output_base / 'demo'
    record = manager.projects_dir / 'demo.json'
    if state == 'registered':
        manager.create('demo', '/old-target', output_dir=str(output), resolve_target=False)
        manager.update_notes('demo', 'old notes')
        (manager.projects_dir / '.active').symlink_to('demo.json')
        sessions.record_session('demo', pid=os.getpid())
    elif state == 'orphan':
        output.mkdir(parents=True)
    if state != 'new':
        (output / 'old-data').write_text('old output')
    archive = tmp_path / 'incoming.zip'
    with zipfile.ZipFile(archive, 'w') as target:
        target.writestr('demo/.project.json', json.dumps({
            'name': 'demo', 'target': '/imported-target', 'notes': 'new notes',
            'description': 'new description', 'created': '2025-01-01T00:00:00+00:00',
        }))
        target.writestr('demo/new-data', 'new output')
    return SimpleNamespace(manager=manager, output=output, record=record, archive=archive,
                           base=output_base, state=state, home=home,
                           old_record=record.read_bytes() if record.exists() else None,
                           old_id=output.stat().st_ino if output.exists() else None,
                           bindings={str(p): p.read_bytes() for p in (home / 'sessions.d').glob('*.json')})


def run(case, **kwargs):
    return archives.import_project(case.archive, case.manager.projects_dir,
                                   output_base=case.base, force=case.state != 'new', **kwargs)


def assert_previous(case):
    if case.old_record is None:
        assert not case.record.exists()
    else:
        assert case.record.read_bytes() == case.old_record
        assert os.readlink(case.manager.projects_dir / '.active') == 'demo.json'
    if case.old_id is None:
        assert not case.output.exists()
    else:
        assert case.output.stat().st_ino == case.old_id
        assert (case.output / 'old-data').read_text() == 'old output'
        assert not (case.output / 'new-data').exists()
    for path, value in case.bindings.items():
        assert Path(path).read_bytes() == value
    assert not list(case.base.glob('.import-*'))
    assert not list(case.manager.projects_dir.glob('.import-*'))


SCENARIOS = [(state, phase) for state in ('registered', 'orphan', 'new')
             for phase in ('backup-record', 'backup-output', 'publish-output', 'publish-record')
             if (state == 'registered' or phase != 'backup-record')
             and (state != 'new' or phase != 'backup-output')]


@pytest.mark.parametrize('state,phase', SCENARIOS, ids=['-'.join(row) for row in SCENARIOS])
@pytest.mark.parametrize('after', [False, True], ids=['before-effect', 'after-effect'])
@pytest.mark.parametrize('failure', [OSError, KeyboardInterrupt, SystemExit])
def test_publication_failure_rolls_back_every_owned_effect(tmp_path, monkeypatch, state, phase, after, failure):
    case = prepare(tmp_path, monkeypatch, state)
    called = []
    def fault(original, match):
        def wrapped(*args, **kwargs):
            if not match(*args, **kwargs):
                return original(*args, **kwargs)
            called.append(True)
            if after:
                original(*args, **kwargs)
            raise failure('publication failed')
        return wrapped
    if phase == 'backup-record':
        patch_module_attribute(monkeypatch, transaction, 'os', 'link', fault(
            transaction.os.link, lambda src, dst, **kw: str(dst).endswith('.record')))
    elif phase == 'backup-output':
        monkeypatch.setattr(transaction, 'rename_without_replace', fault(
            transaction.rename_without_replace,
            lambda src, dst: Path(dst).name.startswith('.import-backup-')))
    elif phase == 'publish-output':
        monkeypatch.setattr(transaction, 'publish_new_directory', fault(
            transaction.publish_new_directory, lambda *args, **kwargs: True))
    else:
        patch_module_attribute(monkeypatch, transaction, 'os', 'replace', fault(
            transaction.os.replace, lambda src, dst: Path(src).name == 'project.json'))
    with pytest.raises(failure, match='publication failed'):
        run(case)
    assert called == [True]
    assert_previous(case)


@pytest.mark.parametrize('state', ['registered', 'orphan', 'new'])
@pytest.mark.parametrize('failure', [OSError, KeyboardInterrupt, SystemExit])
def test_registration_preparation_fails_before_replacing_data(tmp_path, monkeypatch, state, failure):
    case = prepare(tmp_path, monkeypatch, state)
    original = transaction.save_json
    def failed(*args, **kwargs):
        original(*args, **kwargs)
        raise failure('prepare record failed')
    monkeypatch.setattr(transaction, 'save_json', failed)
    with pytest.raises(failure, match='prepare record failed'):
        run(case)
    assert_previous(case)


@pytest.mark.parametrize('state', ['registered', 'orphan', 'new'])
def test_success_publishes_one_complete_record_without_unbinding_sessions(tmp_path, monkeypatch, state):
    case = prepare(tmp_path, monkeypatch, state)
    result = run(case)
    assert result['output_dir'] == str(case.output)
    assert (case.output / 'new-data').read_text() == 'new output'
    assert not (case.output / 'old-data').exists()
    project = case.manager.load('demo')
    assert project.notes == 'new notes' and project.target == '/imported-target'
    assert project.created == '2025-01-01T00:00:00+00:00'
    if state == 'registered':
        assert os.readlink(case.manager.projects_dir / '.active') == 'demo.json'
    for path, value in case.bindings.items():
        assert Path(path).read_bytes() == value
    assert not list(case.base.glob('.import-*'))
    assert not list(case.manager.projects_dir.glob('.import-*'))


@pytest.mark.parametrize('phase', ['registration', 'output'])
def test_failed_rollback_retains_old_data_outside_disposable_staging(tmp_path, monkeypatch, phase):
    case = prepare(tmp_path, monkeypatch)
    replace, rename = transaction.os.replace, transaction.rename_without_replace
    def fail_record(src, dst):
        if Path(src).name == 'project.json':
            if phase == 'registration':
                replace(src, dst)
            raise OSError('original publication failure')
        if phase == 'registration' and Path(src).suffix == '.record':
            raise OSError('registration rollback unavailable')
        return replace(src, dst)
    def fail_output(src, dst):
        if phase == 'output' and Path(src).name.startswith('.import-backup-'):
            raise OSError('output rollback unavailable')
        return rename(src, dst)
    patch_module_attribute(monkeypatch, transaction, 'os', 'replace', fail_record)
    monkeypatch.setattr(transaction, 'rename_without_replace', fail_output)
    with pytest.raises(OSError, match='original publication failure'):
        run(case)
    backups = list(case.base.glob('.import-backup-*'))
    assert len(backups) == 1 and (backups[0] / 'old-data').read_text() == 'old output'
    if phase == 'registration':
        records = list(case.manager.projects_dir.glob('.import-backup-*.record'))
        assert len(records) == 1 and records[0].read_bytes() == case.old_record
        assert (case.output / 'new-data').read_text() == 'new output'
    else:
        assert case.record.read_bytes() == case.old_record
        assert not case.output.exists()


def test_unknown_output_replacement_is_never_removed_during_rollback(tmp_path, monkeypatch):
    case = prepare(tmp_path, monkeypatch)
    def occupied(src, dst):
        dst.mkdir()
        (dst / 'unrelated').write_text('other owner')
        raise OSError('publication refused')
    monkeypatch.setattr(transaction, 'publish_new_directory', occupied)
    with pytest.raises(OSError, match='publication refused'):
        run(case)
    assert (case.output / 'unrelated').read_text() == 'other owner'
    backups = list(case.base.glob('.import-backup-*'))
    assert len(backups) == 1 and (backups[0] / 'old-data').read_text() == 'old output'
    assert case.record.read_bytes() == case.old_record


def test_unknown_registry_replacement_is_never_overwritten_during_rollback(tmp_path, monkeypatch):
    case = prepare(tmp_path, monkeypatch)
    original = transaction.os.replace
    payload = json.loads(case.old_record)
    payload['description'] = 'other owner'
    changed = json.dumps(payload).encode()
    def replaced(src, dst):
        result = original(src, dst)
        if Path(src).name == 'project.json':
            other = case.manager.projects_dir / 'other-record'
            other.write_bytes(changed)
            original(other, dst)
            raise OSError('record changed')
        return result
    patch_module_attribute(monkeypatch, transaction, 'os', 'replace', replaced)
    with pytest.raises(OSError, match='record changed'):
        run(case)
    assert case.record.read_bytes() == changed
    assert (case.output / 'new-data').read_text() == 'new output'
    assert len(list(case.base.glob('.import-backup-*'))) == 1
    assert list(case.manager.projects_dir.glob('.import-backup-*.record'))[0].read_bytes() == case.old_record


def test_cleanup_refusal_is_reported_after_successful_commit(tmp_path, monkeypatch):
    case = prepare(tmp_path, monkeypatch)
    original = transaction.rmtree_hardened
    monkeypatch.setattr(transaction, 'rmtree_hardened',
                        lambda path: False if path.name.startswith('.import-backup-') else original(path))
    result = run(case)
    assert (case.output / 'new-data').read_text() == 'new output'
    assert (Path(result['retained_backup']) / 'old-data').read_text() == 'old output'
    assert case.manager.load('demo').notes == 'new notes'


def test_operation_lock_inode_survives_the_output_swap(tmp_path, monkeypatch):
    import fcntl
    case = prepare(tmp_path, monkeypatch)
    original = transaction.os.replace
    checked = []
    def check(src, dst):
        if Path(src).name == 'project.json':
            with (case.output / '.op.lock').open('rb') as stream:
                with pytest.raises(BlockingIOError):
                    fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            checked.append(True)
        return original(src, dst)
    patch_module_attribute(monkeypatch, transaction, 'os', 'replace', check)
    run(case)
    assert checked == [True]


@pytest.mark.parametrize('alias', ['relative', 'parent-symlink'])
def test_aliases_of_the_same_output_do_not_self_deadlock(tmp_path, monkeypatch, alias):
    case = prepare(tmp_path, monkeypatch)
    project = case.manager.load('demo')
    if alias == 'relative':
        monkeypatch.chdir(tmp_path)
        project.output_dir = 'output/demo'
    else:
        link = tmp_path / 'output-alias'
        link.symlink_to(case.base, target_is_directory=True)
        project.output_dir = str(link / 'demo')
    case.manager._save(project)
    run(case)
    assert (case.output / 'new-data').read_text() == 'new output'


def test_live_run_refusal_happens_before_any_backup_or_replacement(tmp_path, monkeypatch):
    case = prepare(tmp_path, monkeypatch)
    def live(self, project, **kwargs):
        raise ValueError('live run must finish')
    monkeypatch.setattr(model.ProjectManager, '_refuse_live_delete', live)
    with pytest.raises(ValueError, match='live run must finish'):
        run(case)
    assert_previous(case)


@pytest.mark.parametrize('shape', ['file', 'fifo', 'directory-link', 'dangling-link'])
def test_non_directory_destination_is_never_replaced_even_with_force(tmp_path, monkeypatch, shape):
    case = prepare(tmp_path, monkeypatch, 'new')
    case.base.mkdir()
    target = case.base / 'borrowed'
    target.mkdir()
    (target / 'keep').write_text('operator data')
    if shape == 'file':
        case.output.write_text('operator file')
    elif shape == 'fifo':
        os.mkfifo(case.output)
    else:
        case.output.symlink_to(target if shape == 'directory-link' else case.base / 'absent')
    before = case.output.lstat().st_ino
    with pytest.raises((ValueError, OSError)):
        archives.import_project(case.archive, case.manager.projects_dir, output_base=case.base, force=True)
    assert case.output.lstat().st_ino == before
    assert (target / 'keep').read_text() == 'operator data'
    assert not case.record.exists()


@pytest.mark.parametrize('shape', ['fifo', 'directory', 'symlink', 'dangling'])
def test_non_regular_registration_is_never_overwritten(tmp_path, monkeypatch, shape):
    case = prepare(tmp_path, monkeypatch, 'orphan')
    target = tmp_path / 'borrowed-record'
    target.write_text('operator data')
    if shape == 'fifo':
        os.mkfifo(case.record)
    elif shape == 'directory':
        case.record.mkdir()
    else:
        case.record.symlink_to(target if shape == 'symlink' else tmp_path / 'absent')
    before = case.record.lstat().st_ino
    with pytest.raises((ValueError, OSError)):
        run(case)
    assert case.record.lstat().st_ino == before
    assert target.read_text() == 'operator data'
    assert (case.output / 'old-data').read_text() == 'old output'
    assert not list(case.base.glob('.import-*'))


@pytest.mark.parametrize('previous', ['parent', 'child'])
def test_retarget_import_cannot_overlap_its_previous_output(tmp_path, monkeypatch, previous):
    case = prepare(tmp_path, monkeypatch)
    project = case.manager.load('demo')
    project.output_dir = str(case.base if previous == 'parent' else case.output / 'nested')
    case.manager._save(project)
    before = case.record.read_bytes()
    with pytest.raises(ValueError, match='overlaps previous output'):
        run(case)
    assert case.record.read_bytes() == before
    assert (case.output / 'old-data').read_text() == 'old output'
    assert not list(case.base.glob('.import-*'))


@pytest.mark.parametrize('mode', [0o000, 0o400, 0o600, 0o640])
def test_import_registration_retains_readable_modes_and_repairs_unreadable_ones(tmp_path, monkeypatch, mode):
    case = prepare(tmp_path, monkeypatch)
    case.record.chmod(mode)
    run(case)
    assert case.manager.load('demo').notes == 'new notes'
    assert case.record.stat().st_mode & 0o777 == (mode if mode & 0o400 else 0o600)


def test_registry_backup_cleanup_failure_is_reported_without_losing_commit(tmp_path, monkeypatch):
    case = prepare(tmp_path, monkeypatch)
    class RecordPath(type(case.manager.projects_dir)):
        def unlink(self, *args, **kwargs):
            if self.suffix == '.record':
                raise PermissionError('cannot remove recovery link')
            return super().unlink(*args, **kwargs)
    class RecordManager(model.ProjectManager):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.projects_dir = RecordPath(self.projects_dir)
    monkeypatch.setattr(model, 'ProjectManager', RecordManager)
    result = run(case)
    assert Path(result['retained_registry_backup']).read_bytes() == case.old_record
    assert case.manager.load('demo').notes == 'new notes'
    assert (case.output / 'new-data').read_text() == 'new output'


def test_custom_previous_output_remains_available_as_reported_orphan(tmp_path, monkeypatch):
    case = prepare(tmp_path, monkeypatch)
    previous = tmp_path / 'custom-output'
    case.output.rename(previous)
    project = case.manager.load('demo')
    project.output_dir = str(previous)
    case.manager._save(project)
    result = run(case)
    assert result['orphaned_output'] == str(previous)
    assert (previous / 'old-data').read_text() == 'old output'
    assert (case.output / 'new-data').read_text() == 'new output'


def test_transaction_pins_close_after_failed_publication(tmp_path, monkeypatch):
    case = prepare(tmp_path, monkeypatch)
    real_open = transaction.os.open
    opened = []
    def open_fd(*args, **kwargs):
        fd = real_open(*args, **kwargs)
        opened.append(fd)
        return fd
    def failed(*args):
        raise RuntimeError('stop publication')
    patch_module_attribute(monkeypatch, transaction, 'os', 'open', open_fd)
    monkeypatch.setattr(transaction, 'publish_new_directory', failed)
    with pytest.raises(RuntimeError, match='stop publication'):
        run(case)
    assert len(opened) == 3
    for fd in opened:
        with pytest.raises(OSError):
            os.fstat(fd)
    assert_previous(case)


@pytest.mark.parametrize('kind', ['output', 'registration'])
def test_successful_import_never_cleans_an_unknown_backup_replacement(tmp_path, monkeypatch, kind):
    case = prepare(tmp_path, monkeypatch)
    original = transaction.os.replace
    saved = tmp_path / 'preserved-original'
    changed = []
    def replace(src, dst):
        if Path(src).name == 'project.json':
            if kind == 'output':
                backup = list(case.base.glob('.import-backup-*'))[0]
                backup.rename(saved)
                backup.mkdir()
                (backup / 'keep').write_text('other owner')
            else:
                backup = list(case.manager.projects_dir.glob('.import-backup-*.record'))[0]
                backup.rename(saved)
                backup.write_text('other owner')
            changed.append(backup)
        return original(src, dst)
    patch_module_attribute(monkeypatch, transaction, 'os', 'replace', replace)
    result = run(case)
    assert (case.output / 'new-data').read_text() == 'new output'
    if kind == 'output':
        assert result['retained_backup'] == str(changed[0])
        assert (changed[0] / 'keep').read_text() == 'other owner'
        assert (saved / 'old-data').read_text() == 'old output'
    else:
        assert result['retained_registry_backup'] == str(changed[0])
        assert changed[0].read_text() == 'other owner'
        assert saved.read_bytes() == case.old_record

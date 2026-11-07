"""Direct merge callers receive complete output or retain their previous directory."""
import os
from concurrent.futures import ThreadPoolExecutor
import threading

import pytest

from core.json import save_json
from core.project import merge
from core.project import merge_transaction as transaction
from core.run import scratch
from core.testing.state_isolation import pin_user_state_dirs


@pytest.fixture
def runs(tmp_path, monkeypatch):
    pin_user_state_dirs(monkeypatch, tmp_path / 'state')
    paths = []
    for index in range(2):
        path = tmp_path / f'scan-20260101-{index:06d}'
        path.mkdir()
        save_json(path / 'findings.json', {'findings': [
            {'id': f'F{index}', 'file': f'f{index}.c', 'function': 'main', 'line': 1}]})
        (path / 'notes.txt').write_text(f'notes {index}')
        paths.append(path)
    return paths


def no_scratch(tmp_path):
    assert not list(tmp_path.glob('.merge-stage-*'))
    assert not list(tmp_path.glob('.merge-backup-*'))


SCENARIOS = [(state, phase) for state in ('missing', 'empty')
             for phase in ('build', 'backup', 'publish')
             if state == 'empty' or phase != 'backup']


@pytest.mark.parametrize('state,phase', SCENARIOS, ids=['-'.join(row) for row in SCENARIOS])
@pytest.mark.parametrize('failure', [OSError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize('after', [False, True], ids=['before-effect', 'after-effect'])
def test_failed_merge_restores_previous_directory_and_reclaims_staging(runs, tmp_path, monkeypatch, state, phase, failure, after):
    output = tmp_path / 'merged'
    identity = None
    if state == 'empty':
        output.mkdir()
        identity = output.stat().st_ino
    seen = []
    def fail(original, matches):
        def call(*args, **kwargs):
            if not matches(*args, **kwargs):
                return original(*args, **kwargs)
            seen.append(True)
            if after:
                original(*args, **kwargs)
            raise failure('merge failed')
        return call
    if phase == 'build':
        monkeypatch.setattr(merge, '_merge_runs', fail(merge._merge_runs, lambda *a, **kw: True))
    elif phase == 'backup':
        monkeypatch.setattr(transaction, 'rename_without_replace', fail(
            transaction.rename_without_replace, lambda src, dst: src == output))
    else:
        monkeypatch.setattr(transaction, 'publish_new_directory', fail(
            transaction.publish_new_directory, lambda *a, **kw: True))
    with pytest.raises(failure, match='merge failed'):
        merge.merge_runs(runs, output)
    assert seen
    if identity is None:
        assert not output.exists()
    else:
        assert output.stat().st_ino == identity and list(output.iterdir()) == []
    assert [(p / 'notes.txt').read_text() for p in runs] == ['notes 0', 'notes 1']
    no_scratch(tmp_path)


@pytest.mark.parametrize('state', ['missing', 'empty'])
def test_output_remains_unpublished_until_all_build_steps_finish(runs, tmp_path, monkeypatch, state):
    output = tmp_path / 'merged'
    if state == 'empty':
        output.mkdir()
    original = merge._merge_runs
    def build(sources, destination):
        assert str(destination.parent) in scratch._keepalive_paths
        assert output.exists() == (state == 'empty')
        stats = original(sources, destination)
        assert output.exists() == (state == 'empty')
        if state == 'empty':
            assert list(output.iterdir()) == []
        return stats
    monkeypatch.setattr(merge, '_merge_runs', build)
    assert merge.merge_runs(runs, output)['runs_merged'] == 2
    assert (output / 'findings.json').is_file()
    no_scratch(tmp_path)


@pytest.mark.parametrize('relation', ['same', 'ancestor', 'child', 'alias-child'])
def test_overlapping_output_never_recurses_into_source(runs, tmp_path, relation):
    source = runs[0]
    if relation == 'same':
        output = source
    elif relation == 'ancestor':
        output = source.parent
    elif relation == 'child':
        output = source / 'nested/deeper'
    else:
        alias = tmp_path / 'alias'
        alias.symlink_to(source, target_is_directory=True)
        output = alias / 'nested/deeper'
    with pytest.raises(ValueError, match='overlap'):
        merge.merge_runs(runs, output)
    assert not (source / 'nested').exists()
    assert (source / 'notes.txt').read_text() == 'notes 0'
    no_scratch(tmp_path)


@pytest.mark.parametrize('kind', ['file', 'fifo', 'symlink', 'dangling', 'nonempty', 'hidden-only'])
def test_existing_output_data_or_special_node_never_modified(runs, tmp_path, kind):
    output = tmp_path / 'merged'
    if kind == 'file':
        output.write_text('bystander')
    elif kind == 'fifo':
        os.mkfifo(output)
    elif kind in ('symlink', 'dangling'):
        target = tmp_path / 'outside'
        if kind == 'symlink':
            target.mkdir()
        output.symlink_to(target)
    else:
        output.mkdir()
        (output / ('.hidden' if kind == 'hidden-only' else 'keep')).write_text('bystander')
    identity = output.lstat().st_ino
    with pytest.raises(ValueError):
        merge.merge_runs(runs, output)
    assert output.lstat().st_ino == identity
    no_scratch(tmp_path)


@pytest.mark.parametrize('kind', ['empty', 'file', 'symlink', 'dangling', 'fifo'])
def test_late_publication_contender_is_not_overwritten(runs, tmp_path, monkeypatch, kind):
    from core.project.tests.test_directory_relocation import occupy
    output = tmp_path / 'merged'
    original = transaction.publish_new_directory
    identity = []
    def race(src, dst):
        identity.append(occupy(dst, kind, tmp_path))
        return original(src, dst)
    monkeypatch.setattr(transaction, 'publish_new_directory', race)
    with pytest.raises(OSError):
        merge.merge_runs(runs, output)
    assert output.lstat().st_ino == identity[0]
    assert all(path.is_dir() for path in runs)
    no_scratch(tmp_path)


@pytest.mark.parametrize('failure', [OSError, KeyboardInterrupt, SystemExit])
def test_failed_rollback_retains_previous_directory_outside_disposable_staging(runs, tmp_path, monkeypatch, caplog, failure):
    output = tmp_path / 'merged'
    output.mkdir()
    previous = output.stat().st_ino
    rename = transaction.rename_without_replace
    def publish(*args):
        raise failure('primary failure')
    def restore(src, dst):
        if src.name.startswith('.merge-backup-'):
            raise OSError('restore denied')
        return rename(src, dst)
    monkeypatch.setattr(transaction, 'publish_new_directory', publish)
    monkeypatch.setattr(transaction, 'rename_without_replace', restore)
    with pytest.raises(failure, match='primary failure'):
        merge.merge_runs(runs, output)
    backups = list(tmp_path.glob('.merge-backup-*'))
    assert len(backups) == 1 and backups[0].stat().st_ino == previous
    assert str(backups[0]) in caplog.text
    assert not list(tmp_path.glob('.merge-stage-*'))
    assert all(path.is_dir() for path in runs)


def test_new_data_in_retired_empty_directory_is_never_recursively_cleaned(runs, tmp_path, monkeypatch, caplog):
    output = tmp_path / 'merged'
    output.mkdir()
    original = transaction.publish_new_directory
    backups = []
    def publish(src, dst):
        backup = list(tmp_path.glob('.merge-backup-*'))[0]
        (backup / 'late-data').write_text('another writer')
        backups.append(backup)
        return original(src, dst)
    monkeypatch.setattr(transaction, 'publish_new_directory', publish)
    assert merge.merge_runs(runs, output)['runs_merged'] == 2
    assert (backups[0] / 'late-data').read_text() == 'another writer'
    assert str(backups[0]) in caplog.text


def test_concurrent_merges_publish_one_complete_output(runs, tmp_path):
    output = tmp_path / 'merged'
    ready = threading.Barrier(2)
    def build(_):
        ready.wait(timeout=10)
        try:
            merge.merge_runs(runs, output)
            return True
        except ValueError:
            return False
    with ThreadPoolExecutor(max_workers=2) as workers:
        assert sorted(workers.map(build, range(2))) == [False, True]
    assert (output / 'notes.txt').read_text() == 'notes 0'
    no_scratch(tmp_path)


@pytest.mark.parametrize('mode', [0o700, 0o711, 0o750, 0o755])
def test_success_keeps_the_existing_empty_directory_mode(runs, tmp_path, mode):
    output = tmp_path / 'merged'
    output.mkdir(mode=mode)
    merge.merge_runs(runs, output)
    assert output.stat().st_mode & 0o777 == mode


@pytest.mark.parametrize('kind', ['missing', 'file', 'fifo', 'dangling', 'file-link', 'loop'])
def test_invalid_source_refuses_before_creating_output_parents(runs, tmp_path, kind):
    source = tmp_path / 'invalid-source'
    if kind == 'file':
        source.write_text('file')
    elif kind == 'fifo':
        os.mkfifo(source)
    elif kind == 'dangling':
        source.symlink_to(tmp_path / 'absent')
    elif kind == 'file-link':
        target = tmp_path / 'file'
        target.write_text('file')
        source.symlink_to(target)
    elif kind == 'loop':
        source.symlink_to(source)
    output = tmp_path / 'new-parent/merged'
    with pytest.raises(ValueError, match='directory'):
        merge.merge_runs([runs[0], source], output)
    assert not output.parent.exists()
    no_scratch(tmp_path)


@pytest.mark.parametrize('failure', [OSError, KeyboardInterrupt, SystemExit])
def test_partial_final_rollback_failure_preserves_new_and_previous_data(runs, tmp_path, monkeypatch, caplog, failure):
    output = tmp_path / 'merged'
    output.mkdir()
    previous = output.stat().st_ino
    publish = transaction.publish_new_directory
    rename = transaction.rename_without_replace
    def interrupted(src, dst):
        publish(src, dst)
        raise failure('primary failure after publication')
    def restore(src, dst):
        if src == output and dst.parent.name.startswith('.merge-stage-'):
            raise OSError('cannot retire published output')
        return rename(src, dst)
    monkeypatch.setattr(transaction, 'publish_new_directory', interrupted)
    monkeypatch.setattr(transaction, 'rename_without_replace', restore)
    with pytest.raises(failure, match='primary failure after publication'):
        merge.merge_runs(runs, output)
    assert (output / 'findings.json').is_file()
    backups = list(tmp_path.glob('.merge-backup-*'))
    assert len(backups) == 1 and backups[0].stat().st_ino == previous
    assert str(output) in caplog.text and str(backups[0]) in caplog.text
    assert all(source.is_dir() for source in runs)
    assert not list(tmp_path.glob('.merge-stage-*'))


def test_data_added_before_retirement_is_restored_without_deletion(runs, tmp_path, monkeypatch):
    output = tmp_path / 'merged'
    output.mkdir()
    original = transaction.rename_without_replace
    def retire(src, dst):
        if src == output:
            (src / 'new-data').write_text('concurrent writer')
        return original(src, dst)
    monkeypatch.setattr(transaction, 'rename_without_replace', retire)
    with pytest.raises(OSError, match='changed before publication'):
        merge.merge_runs(runs, output)
    assert (output / 'new-data').read_text() == 'concurrent writer'
    assert not (output / 'findings.json').exists()
    no_scratch(tmp_path)


@pytest.mark.parametrize('state', ['missing', 'empty'])
def test_unknown_output_replacement_is_never_removed_during_rollback(runs, tmp_path, monkeypatch, state):
    output = tmp_path / 'merged'
    if state == 'empty':
        output.mkdir()
    published = tmp_path / 'preserved-merge'
    original = transaction.publish_new_directory
    def publish(src, dst):
        original(src, dst)
        dst.rename(published)
        dst.mkdir()
        (dst / 'keep').write_text('bystander')
    monkeypatch.setattr(transaction, 'publish_new_directory', publish)
    with pytest.raises(OSError, match='changed during publication'):
        merge.merge_runs(runs, output)
    assert (output / 'keep').read_text() == 'bystander'
    assert (published / 'findings.json').is_file()
    assert all(source.is_dir() for source in runs)
    assert not list(tmp_path.glob('.merge-stage-*'))


def test_unknown_recovery_entry_never_cleaned(runs, tmp_path, monkeypatch, caplog):
    output = tmp_path / 'merged'
    output.mkdir()
    original = transaction.rename_without_replace
    backups = []
    def backup(src, dst):
        if src == output:
            dst.mkdir()
            (dst / 'keep').write_text('bystander')
            backups.append(dst)
        return original(src, dst)
    monkeypatch.setattr(transaction, 'rename_without_replace', backup)
    with pytest.raises(OSError):
        merge.merge_runs(runs, output)
    assert list(output.iterdir()) == []
    assert (backups[0] / 'keep').read_text() == 'bystander'
    assert str(backups[0]) in caplog.text
    assert not list(tmp_path.glob('.merge-stage-*'))

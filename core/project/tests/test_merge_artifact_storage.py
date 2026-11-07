"""Artifact preservation is bounded, nonblocking and does not duplicate hardlinks."""
import os
import sys

import pytest

from core.project import merge
from core.project.tests.test_merge_publication_transaction import runs as runs
from core.testing.module_bindings import patch_module_attribute
from core.testing.standalone_cli import run_standalone_cli


@pytest.mark.parametrize('aliases', [False, True], ids=['repeated-path', 'symlink-alias'])
def test_duplicate_sources_do_not_duplicate_artifacts_or_findings(runs, tmp_path, aliases):
    source = runs[0]
    other = source
    if aliases:
        other = tmp_path / 'alias'
        other.symlink_to(source, target_is_directory=True)
    output = tmp_path / 'merged'
    stats = merge.merge_runs([source, other, source], output)
    assert stats['runs_merged'] == 1
    assert stats['total_findings'] == 1
    assert list(output.glob('notes*.txt')) == [output / 'notes.txt']


@pytest.mark.parametrize('location', ['root', 'nested', 'sarif', 'sca-sarif', 'history'])
def test_fifo_nodes_are_skipped_without_blocking(runs, tmp_path, location):
    source = runs[0]
    if location == 'root':
        node = source / 'pipe'
    elif location == 'nested':
        node = source / 'artifacts/pipe'
    elif location == 'sarif':
        node = source / 'pipe.sarif'
    elif location == 'sca-sarif':
        node = source / 'sca/pipe.sarif'
    else:
        node = source / '.reporting/pipe'
    node.parent.mkdir(exist_ok=True)
    os.mkfifo(node)
    output = tmp_path / 'merged'
    script = '''
import sys
from pathlib import Path
from core.project.merge import merge_runs
merge_runs([Path(sys.argv[1])], Path(sys.argv[2]))
'''
    result = run_standalone_cli([sys.executable, '-c', script, str(source), str(output)],
                                capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    assert (output / 'notes.txt').read_text() == 'notes 0'
    assert not any(p.name == node.name for p in output.rglob('*'))


@pytest.mark.parametrize('location', ['root', 'nested', 'history'])
@pytest.mark.parametrize('name', ['data.lock', '.annotation-test.tmp'])
def test_disposable_lock_and_temp_files_are_not_copied(runs, tmp_path, location, name):
    parent = runs[0] / {'root': '', 'nested': 'artifacts', 'history': '.reporting'}[location]
    parent.mkdir(exist_ok=True)
    (parent / name).write_text('disposable')
    (parent / 'keep').write_text('keep')
    output = tmp_path / 'merged'
    merge.merge_runs([runs[0]], output)
    assert not any(path.name == name for path in output.rglob('*'))
    assert any(path.name == 'keep' for path in output.rglob('*'))


@pytest.mark.parametrize('location', ['root', 'nested', 'across-roots', 'history'])
def test_hardlinks_keep_one_copy_of_file_contents(runs, tmp_path, location):
    source = runs[0]
    if location == 'root':
        first, second = source / 'first.bin', source / 'second.bin'
    elif location == 'nested':
        parent = source / 'artifacts'
        parent.mkdir()
        first, second = parent / 'first.bin', parent / 'second.bin'
    elif location == 'across-roots':
        first, second = source / 'first.bin', runs[1] / 'second.bin'
    else:
        parent = source / '.reporting'
        parent.mkdir()
        first, second = parent / 'first.bin', parent / 'second.bin'
    first.write_bytes(b'linked data')
    os.link(first, second)
    output = tmp_path / 'merged'
    merge.merge_runs(runs, output)
    copied = [path for path in output.rglob('*.bin') if path.is_file()]
    assert len(copied) == 2
    assert copied[0].stat().st_ino == copied[1].stat().st_ino
    assert copied[0].read_bytes() == b'linked data'


NAMES = ['a' * 250 + '.txt', 'é' * 120 + '.txt', '🙂' * 60 + '.txt',
         'a.' + 'x' * 248, '.' + 'a' * 250]


@pytest.mark.parametrize('kind', ['file', 'directory'])
@pytest.mark.parametrize('name', NAMES, ids=['ascii', 'accented', 'emoji', 'long-extension', 'hidden'])
def test_long_collision_names_fit_encoded_filesystem_limit(runs, tmp_path, kind, name):
    for index, source in enumerate(runs):
        path = source / name
        if kind == 'file':
            path.write_text(str(index))
        else:
            path.mkdir()
            (path / 'data').write_text(str(index))
    output = tmp_path / 'merged'
    merge.merge_runs(runs, output)
    if kind == 'directory' and name.startswith('.'):
        assert not (output / name).exists()
        return
    if kind == 'file':
        values = [path.read_text() for path in output.iterdir()
                  if path.is_file() and path.name != 'findings.json' and not path.name.startswith('notes')]
    else:
        values = [(path / 'data').read_text() for path in output.iterdir() if path.is_dir()]
    assert sorted(values) == ['0', '1']
    assert all(len(os.fsencode(path.name)) <= os.pathconf(output, 'PC_NAME_MAX')
               for path in output.iterdir())


@pytest.mark.parametrize('suffix', ['', '.txt', '.' + 'x' * 200])
@pytest.mark.parametrize('limit', [64, 128, 255])
def test_collision_names_respect_mount_byte_limits(tmp_path, monkeypatch, limit, suffix):
    patch_module_attribute(monkeypatch, merge, 'os', 'pathconf', lambda *args: limit)
    path = merge._uniquify(tmp_path, 'é' * 120, '20260101-010203', suffix)
    assert len(os.fsencode(path.name)) <= limit
    assert path.name == merge._uniquify(tmp_path, 'é' * 120, '20260101-010203', suffix).name


def test_dangling_collision_name_is_an_occupied_entry(tmp_path):
    occupied = tmp_path / 'notes-20260101.txt'
    occupied.symlink_to(tmp_path / 'absent')
    selected = merge._uniquify(tmp_path, 'notes', '20260101', '.txt')
    assert selected == tmp_path / 'notes-20260101.1.txt'
    assert occupied.is_symlink()


def test_pathological_collisions_stop_after_bounded_work(tmp_path, monkeypatch):
    calls = []
    def occupied(path):
        calls.append(path)
        return True
    patch_module_attribute(monkeypatch, merge, 'os.path', 'lexists', occupied)
    with pytest.raises(RuntimeError, match='1000 collisions'):
        merge._uniquify(tmp_path, 'notes', '20260101', '.txt')
    assert len(calls) == 1001


@pytest.mark.parametrize('failure', [OSError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize('after', [False, True], ids=['before-copy', 'after-copy'])
def test_failed_artifact_copy_leaves_no_partial_final_output(runs, tmp_path, monkeypatch, failure, after):
    original = merge._regular_copier
    def factory():
        copy = original()
        def failed(src, dst):
            if after:
                copy(src, dst)
            raise failure('artifact copy failed')
        return failed
    monkeypatch.setattr(merge, '_regular_copier', factory)
    output = tmp_path / 'merged'
    with pytest.raises(failure, match='artifact copy failed'):
        merge.merge_runs(runs, output)
    assert not output.exists()
    assert not list(tmp_path.glob('.merge-stage-*'))
    assert all(path.is_dir() for path in runs)


@pytest.mark.parametrize('name', ['data.lock', '.annotation-test.tmp'])
@pytest.mark.parametrize('nested', [False, True], ids=['root', 'nested'])
def test_directory_names_resembling_disposable_files_keep_their_contents(runs, tmp_path, name, nested):
    parent = runs[0] / 'artifacts' if nested else runs[0]
    directory = parent / name
    directory.mkdir(parents=True)
    (directory / 'keep').write_text('directory data')
    output = tmp_path / 'merged'
    merge.merge_runs([runs[0]], output)
    if not nested and name.startswith('.'):
        assert not (output / name).exists()  # Existing hidden-directory policy.
    else:
        expected = output / 'artifacts' / name if nested else output / name
        assert (expected / 'keep').read_text() == 'directory data'

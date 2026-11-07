"""Cooperating project claims serialize overlapping output trees across names."""
from concurrent.futures import ThreadPoolExecutor
import os
import threading

import pytest
from core.project import project as model


@pytest.fixture
def managed(tmp_path, monkeypatch):
    monkeypatch.setenv('RAPTOR_REGISTRY_HOME', str(tmp_path / 'state'))
    monkeypatch.setattr(model, 'DEFAULT_OUTPUT_BASE', tmp_path / 'out')
    manager = model.ProjectManager(tmp_path / 'state/projects')
    project = manager.create('first', '/target', resolve_target=False)
    (project.output_path / 'keep').write_text('existing output')
    return manager, project


@pytest.mark.parametrize('relation', ['same', 'parent', 'child', 'alias'])
def test_create_refuses_all_output_overlap_shapes(managed, tmp_path, relation):
    manager, project = managed
    target = project.output_path
    if relation == 'parent':
        target = target.parent
    elif relation == 'child':
        target = target / 'nested'
    elif relation == 'alias':
        alias = tmp_path / 'alias'
        alias.symlink_to(target, target_is_directory=True)
        target = alias
    with pytest.raises(ValueError, match='already belongs'):
        manager.create('second', '/target', output_dir=str(target), resolve_target=False)
    assert manager.load('second') is None
    assert (project.output_path / 'keep').read_text() == 'existing output'


def test_similar_lexical_prefixes_are_distinct_output_trees(managed):
    manager, project = managed
    other = project.output_path.with_name(project.output_path.name + '-sibling')
    manager.create('second', '/target', output_dir=str(other), resolve_target=False)
    assert len(manager.list_projects()) == 2
    assert (project.output_path / 'keep').read_text() == 'existing output'


@pytest.mark.parametrize('relationship', ['same', 'nested'])
def test_concurrent_different_name_creates_never_claim_overlapping_paths(tmp_path, monkeypatch, relationship):
    monkeypatch.setenv('RAPTOR_REGISTRY_HOME', str(tmp_path / 'state'))
    manager = model.ProjectManager(tmp_path / 'state/projects')
    parent = tmp_path / 'output'
    outputs = [parent, parent if relationship == 'same' else parent / 'nested']
    ready = threading.Barrier(2)
    def create(index):
        ready.wait(timeout=10)
        try:
            manager.create(f'project{index}', '/target', output_dir=str(outputs[index]), resolve_target=False)
            return True
        except ValueError:
            return False
    with ThreadPoolExecutor(max_workers=2) as workers:
        result = list(workers.map(create, range(2)))
    assert sorted(result) == [False, True]
    assert len(manager.list_projects()) == 1


@pytest.mark.parametrize('relationship', ['parent', 'child'])
@pytest.mark.parametrize('force', [False, True])
def test_rename_refuses_other_projects_overlapping_the_destination(tmp_path, monkeypatch, relationship, force):
    monkeypatch.setenv('RAPTOR_REGISTRY_HOME', str(tmp_path / 'state'))
    monkeypatch.setattr(model, 'DEFAULT_OUTPUT_BASE', tmp_path / 'out')
    manager = model.ProjectManager(tmp_path / 'state/projects')
    original = manager.create('before', '/target', resolve_target=False)
    (original.output_path / 'keep').write_text('original data')
    other = manager.create('other', '/target', resolve_target=False)
    destination = model.DEFAULT_OUTPUT_BASE / 'after'
    other.output_dir = str(destination.parent if relationship == 'parent' else destination / 'nested')
    manager._save(other)  # Model a legacy or manually edited overlapping claim.
    before = (manager.projects_dir / 'before.json').read_bytes()
    with pytest.raises(ValueError, match='registered'):
        manager.rename('before', 'after', force=force)
    assert (original.output_path / 'keep').read_text() == 'original data'
    assert (manager.projects_dir / 'before.json').read_bytes() == before
    assert manager.load('after') is None


@pytest.mark.parametrize('kind', ['fifo', 'symlink', 'directory'])
def test_required_claim_lock_refuses_tampered_control_state(tmp_path, kind):
    manager = model.ProjectManager(tmp_path / 'state/projects')
    path = manager.projects_dir / '.output-claims.lock'
    target = tmp_path / 'borrowed'
    target.write_text('operator data')
    if kind == 'fifo':
        os.mkfifo(path)
    elif kind == 'directory':
        path.mkdir()
    else:
        path.symlink_to(target)
    with pytest.raises(OSError):
        with manager._output_dir_claim_lock(tmp_path / 'output', required=True):
            pytest.fail('invalid required claim must not enter')
    assert target.read_text() == 'operator data'

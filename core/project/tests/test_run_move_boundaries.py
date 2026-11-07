"""Adoption and removal must never nest runs or mutate name-collision bystanders."""
import errno

import pytest
from core.json import load_json, save_json
from core.project import project as model
from core.project import relocate
from core.project.tests.test_directory_relocation import occupy


@pytest.fixture
def managed(tmp_path, monkeypatch):
    monkeypatch.setenv('RAPTOR_REGISTRY_HOME', str(tmp_path / 'state'))
    manager = model.ProjectManager(tmp_path / 'state/projects')
    project = manager.create('demo', str(tmp_path / 'absent-target'),
                             output_dir=str(tmp_path / 'output'), resolve_target=False)
    return manager, project


def run_at(path, project, pin):
    path.mkdir(parents=True)
    (path / 'findings.json').write_text('[]')
    save_json(path / '.raptor-run.json', {
        'version': 2, 'command': 'scan', 'status': 'completed',
        'target_path': project.target, 'project': pin, 'project_source': 'argv'})
    return path


@pytest.mark.parametrize('operation', ['adopt', 'remove'])
@pytest.mark.parametrize('late', [False, True], ids=['preexisting', 'late'])
@pytest.mark.parametrize('kind', ['empty', 'populated', 'file', 'fifo', 'symlink', 'dangling'])
def test_exact_destination_collisions_preserve_both_sides(managed, tmp_path, monkeypatch, operation, late, kind):
    manager, project = managed
    source = run_at((tmp_path / 'external' if operation == 'adopt' else project.output_path)
                    / 'scan-example', project, 'demo' if operation == 'remove' else None)
    base = project.output_path if operation == 'adopt' else tmp_path / 'removed'
    base.mkdir(exist_ok=True)
    destination = base / source.name
    before = (source / '.raptor-run.json').read_bytes()
    identities = []
    if late:
        original = relocate.publish_new_directory
        def race(src, dst):
            identities.append(occupy(dst, kind, tmp_path))
            return original(src, dst)
        monkeypatch.setattr(relocate, 'publish_new_directory', race)
    else:
        identities.append(occupy(destination, kind, tmp_path))
    if operation == 'adopt':
        assert manager.add_directory('demo', str(source)) == 0
    else:
        with pytest.raises(OSError):
            manager.remove_run('demo', source.name, to_path=str(base))
    assert destination.lstat().st_ino == identities[0]
    assert (source / '.raptor-run.json').read_bytes() == before
    assert (source / 'findings.json').read_text() == '[]'
    assert not list(base.glob('.move-*'))


def test_outside_name_collision_never_repairs_the_bystanders_stale_pin(managed, tmp_path):
    manager, project = managed
    source = run_at(tmp_path / 'external/scan-example', project, None)
    bystander = run_at(project.output_path / source.name, project, 'missing-project')
    before = (bystander / '.raptor-run.json').read_bytes()
    assert manager.add_directory('demo', str(source)) == 0
    assert (bystander / '.raptor-run.json').read_bytes() == before
    assert source.is_dir()


@pytest.mark.parametrize('operation', ['adopt', 'remove'])
def test_cross_filesystem_success_updates_the_published_runs_pin(managed, tmp_path, monkeypatch, operation):
    manager, project = managed
    source = run_at((tmp_path / 'external' if operation == 'adopt' else project.output_path)
                    / 'scan-example', project, 'demo' if operation == 'remove' else None)
    destination = (project.output_path if operation == 'adopt' else tmp_path / 'removed') / source.name
    original = relocate.publish_new_directory
    def publish(src, dst):
        if src == source:
            raise OSError(errno.EXDEV, 'different filesystems')
        return original(src, dst)
    monkeypatch.setattr(relocate, 'publish_new_directory', publish)
    if operation == 'adopt':
        assert manager.add_directory('demo', str(source)) == 1
    else:
        manager.remove_run('demo', source.name, to_path=str(destination.parent))
    assert not source.exists()
    assert load_json(destination / '.raptor-run.json')['project'] == ('demo' if operation == 'adopt' else None)
    assert not (destination / source.name).exists()


def test_remove_into_source_subtree_refuses_before_creating_directories(managed, tmp_path):
    manager, project = managed
    source = run_at(project.output_path / 'scan-example', project, 'demo')
    before = sorted(p.name for p in source.iterdir())
    with pytest.raises(ValueError, match='overlap'):
        manager.remove_run('demo', source.name, to_path=str(source / 'nested/deeper'))
    assert sorted(p.name for p in source.iterdir()) == before

"""Deletion receipts account for linked data and effects preceding an error."""
import os
import time

import pytest

from core.project import clean, cli
from core.project import disk_usage as disk
from core.project.project import ProjectManager
from core.project.tests.test_clean_execution_receipts import run, archive
from core.project.tests.test_disk_usage_accounting import allocated
from core.testing.state_isolation import pin_user_state_dirs


@pytest.fixture
def project(tmp_path, monkeypatch):
    pin_user_state_dirs(monkeypatch, tmp_path / 'state')
    root = tmp_path / 'project'
    return ProjectManager(tmp_path / 'state/projects').create(
        'demo', str(tmp_path / 'missing-target'), output_dir=str(root), resolve_target=False)


def prepared(project):
    root = project.output_path
    first = run(root, 'scan-first', age=30)
    second = run(root, 'scan-second', age=60)
    newest = run(root, 'scan-new')
    (second / 'payload').unlink()
    os.link(first / 'payload', second / 'payload')
    now = time.time()
    for path, age in ((first, 30), (second, 60), (newest, 0)):
        os.utime(path, (now - age, now - age))
    return first, second, newest


@pytest.mark.parametrize('retained', [False, True], ids=['all-links-deleted', 'surviving-link'])
def test_planned_and_completed_cleanup_count_linked_data_only_once(project, retained):
    first, second, newest = prepared(project)
    if retained:
        os.link(first / 'payload', newest / 'retained-link')
    plan = clean.plan_clean(project)
    expected = (allocated(first) + allocated(second)
                + allocated(first / '.raptor-run.json') + allocated(second / '.raptor-run.json')
                + (0 if retained else allocated(first / 'payload')))
    assert plan['freed_bytes'] == expected
    clean.execute_clean(plan, output_path=project.output_path)
    assert plan['freed_bytes'] == expected
    assert plan['by_type']['scan']['freed_bytes'] == expected
    assert set(plan['deleted']) == {first.name, second.name}
    assert newest.exists()


@pytest.mark.parametrize('failure', [OSError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize('phase', ['before', 'partial', 'complete', 'false-after-complete'])
def test_failed_removal_receipts_match_effects_and_preserve_error(project, monkeypatch, failure, phase):
    first, second, newest = prepared(project)
    plan = clean.plan_clean(project)
    plan['delete_dirs'] = [first]
    before = disk.scan_usage(first)
    expected_payload = 0  # Its other hardlink is in the retained second run.
    remove = clean.rmtree_hardened
    def faulty(path):
        if phase == 'partial':
            (path / '.raptor-run.json').unlink()
        elif phase in ('complete', 'false-after-complete'):
            remove(path)
        if phase == 'false-after-complete':
            return False
        raise failure('primary removal failure')
    monkeypatch.setattr(clean, 'rmtree_hardened', faulty)
    expected_error = OSError if phase == 'false-after-complete' else failure
    with pytest.raises(expected_error):
        clean.execute_clean(plan, output_path=project.output_path)
    assert second.exists() and newest.exists()
    if phase in ('complete', 'false-after-complete'):
        assert plan['deleted'] == [first.name]
        assert plan['freed_bytes'] == before.reclaimable_bytes
    elif phase == 'partial':
        assert plan['deleted'] == []
        assert plan['partially_removed'] == [first.name]
        assert plan['freed_bytes'] == before.removed_bytes(disk.scan_usage(first)) + expected_payload
        assert plan['freed_bytes'] > 0
        assert plan['by_type']['scan']['freed_bytes'] == plan['freed_bytes']
    else:
        assert plan['deleted'] == [] and plan['freed_bytes'] == 0
        assert not plan.get('partially_removed')


@pytest.mark.parametrize('failure', [OSError, KeyboardInterrupt, SystemExit])
def test_incomplete_after_scan_cannot_turn_unobserved_files_into_freed_bytes(project, monkeypatch, failure):
    first, _, _ = prepared(project)
    plan = clean.plan_clean(project)
    plan['delete_dirs'] = [first]
    observed = iter([disk.scan_usage(first), disk.Usage(incomplete=True)])
    monkeypatch.setattr(clean, '_run_inventory', lambda path: next(observed))
    def remove(path):
        raise failure('primary removal failure')
    monkeypatch.setattr(clean, 'rmtree_hardened', remove)
    with pytest.raises(failure, match='primary removal failure'):
        clean.execute_clean(plan, output_path=project.output_path)
    assert plan['freed_bytes'] == 0 and plan['deleted'] == []
    assert not plan.get('partially_removed')
    assert plan['size_incomplete']
    assert first.exists()


@pytest.mark.parametrize('failure', [OSError, KeyboardInterrupt, SystemExit])
def test_secondary_measurement_failure_keeps_original_removal_error(project, monkeypatch, failure):
    first, _, _ = prepared(project)
    plan = clean.plan_clean(project)
    plan['delete_dirs'] = [first]
    original = clean._run_inventory
    calls = []
    def inventory(path):
        calls.append(path)
        if len(calls) > 1:
            raise SystemExit('secondary measurement failure')
        return original(path)
    def remove(path):
        raise failure('primary removal failure')
    monkeypatch.setattr(clean, '_run_inventory', inventory)
    monkeypatch.setattr(clean, 'rmtree_hardened', remove)
    with pytest.raises(failure, match='primary removal failure'):
        clean.execute_clean(plan, output_path=project.output_path)
    assert plan['freed_bytes'] == 0 and first.exists()


@pytest.mark.parametrize('failure', [OSError, KeyboardInterrupt, SystemExit])
def test_cli_reports_proven_partial_progress_before_propagating_error(project, monkeypatch, capsys, failure):
    first, _, _ = prepared(project)
    def remove(path):
        (path / '.raptor-run.json').unlink()
        raise failure('cleanup stopped')
    monkeypatch.setattr(clean, 'rmtree_hardened', remove)
    with pytest.raises(failure, match='cleanup stopped'):
        cli._do_clean(project, keep=1, dry_run=False, yes=True)
    output = capsys.readouterr().out
    assert 'Partially removed:' in output and first.name in output
    assert 'Inspect the remaining directories' in output


def test_cache_sweep_uses_the_same_forest_accounting(project):
    first = archive(project.output_path, 'a' * 64)
    second = archive(project.output_path, 'b' * 64)
    (second / 'payload').unlink()
    os.link(first / 'payload', second / 'payload')
    old = time.time() - 86400
    for path in (first, second):
        os.utime(path, (old, old))
    expected = allocated(first) + allocated(second) + allocated(first / 'payload')
    plan = clean.plan_sources_sweep(project)
    assert plan['freed_bytes'] == expected
    result = clean.execute_sources_sweep(project, plan)
    assert result['freed_bytes'] == expected
    assert not first.exists() and not second.exists()


@pytest.mark.parametrize('primary', [OSError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize('report_error', [BrokenPipeError, KeyboardInterrupt, SystemExit])
def test_progress_reporting_failure_never_masks_cleanup_error(project, monkeypatch, primary, report_error):
    prepared(project)
    def remove(path):
        raise primary('primary cleanup failure')
    def report(plan):
        raise report_error('secondary progress failure')
    monkeypatch.setattr(clean, 'rmtree_hardened', remove)
    monkeypatch.setattr(cli, '_print_interrupted_clean', report)
    with pytest.raises(primary, match='primary cleanup failure'):
        cli._do_clean(project, keep=1, dry_run=False, yes=True)


def test_progress_receipts_escape_directory_names(capsys):
    cli._print_interrupted_clean({'deleted': ['old-\x1b[31m'], 'partially_removed': ['partial-\x1b[2J']})
    output = capsys.readouterr().out
    assert '\x1b' not in output
    assert 'Deleted before stopping:' in output and 'Partially removed:' in output
    assert 'Inspect the remaining directories' in output

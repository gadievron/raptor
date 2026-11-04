"""Isolation remains per test while allocations avoid numbered sibling scans."""
from pathlib import Path

from core.testing.tempdirs import isolated_test_dir


def test_state_directories_are_private_fresh_and_retained(tmp_path_factory):
    first = isolated_test_dir(tmp_path_factory, 'keys')
    (first / 'key').write_text('first test')
    second = isolated_test_dir(tmp_path_factory, 'keys')
    assert first != second
    assert first.is_dir() and second.is_dir()
    assert not list(second.iterdir())
    assert first.parent == second.parent == tmp_path_factory.getbasetemp() / 'isolated-state'
    assert first.stat().st_mode & 0o777 == 0o700


def test_state_allocation_does_not_scan_numbered_directories(tmp_path_factory, monkeypatch):
    def refuse_scan(*args, **kwargs):
        raise AssertionError('isolated state must not enumerate sibling directories')

    # Resolve the retained base before forbidding directory scans.
    tmp_path_factory.getbasetemp()
    with monkeypatch.context() as patch:
        patch.setattr(Path, 'iterdir', refuse_scan)
        patch.setattr(tmp_path_factory, 'mktemp', refuse_scan)
        state = isolated_test_dir(tmp_path_factory, 'scorecard')
    assert state.is_dir()

"""Explicit project cleanup reclaims closed runs with tool-owned modes."""

import pytest
from core.project import clean
from core.testing.restricted_tree import restricted_tree


@pytest.mark.parametrize("mode", [0o000, 0o500, 0o555])
def test_project_cleanup_reclaims_restricted_closed_run(tmp_path, monkeypatch, mode):
    with restricted_tree(tmp_path / "old-run", mode) as tree:
        monkeypatch.setattr(clean, "run_is_live", lambda path: False)
        clean.execute_clean({"delete_dirs": [tree]}, output_path=tmp_path)
        assert not tree.exists()


def test_project_cleanup_preserves_live_restricted_run(tmp_path, monkeypatch):
    with restricted_tree(tmp_path / "live-run") as tree:
        monkeypatch.setattr(clean, "run_is_live", lambda path: True)
        plan = {"delete_dirs": [tree]}
        clean.execute_clean(plan, output_path=tmp_path)
        assert tree.exists()
        assert plan["skipped_live"] == [tree.name]


def test_failed_project_cleanup_still_reports_failure(tmp_path, monkeypatch):
    with restricted_tree(tmp_path / "old-run", 0o555) as tree:
        monkeypatch.setattr(clean, "run_is_live", lambda path: False)
        with monkeypatch.context() as fault:
            fault.setattr("shutil.rmtree", lambda *args, **kwargs: None)
            with pytest.raises(OSError, match="could not remove run directory"):
                clean.execute_clean({"delete_dirs": [tree]}, output_path=tmp_path)
        assert tree.exists()

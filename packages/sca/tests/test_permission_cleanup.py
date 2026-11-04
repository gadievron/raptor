"""Whole-project cache eviction must cope with tool-created permissions."""

import os
import time
import pytest
from packages.sca import cache_budget
from core.testing.restricted_tree import restricted_tree


@pytest.mark.parametrize("mode", [0o500, 0o555])
@pytest.mark.parametrize("namespace", ["inventory/target", "stress/clones/target"])
@pytest.mark.parametrize("policy", ["age", "size"])
def test_directory_cache_eviction_reclaims_restricted_tree(
    tmp_path, mode, namespace, policy
):
    state = tmp_path / "fingerprints" / "baseline.json"
    state.parent.mkdir()
    state.write_text("persistent")
    with restricted_tree(tmp_path / namespace, mode) as tree:
        if policy == "age":
            old = time.time() - 60 * 86400
            (tree / "locked").chmod(0o700)
            for parent, dirs, files in os.walk(tree):
                for name in files:
                    os.utime(os.path.join(parent, name), (old, old))
                os.utime(parent, (old, old))
            (tree / "locked").chmod(mode)
            os.utime(tree, (old, old))
        result = cache_budget.prune_cache(
            tmp_path, max_bytes=0 if policy == "size" else None
        )
        assert not tree.exists()
        assert result.errors == 0
        assert result.files_removed == 1
        assert result.bytes_freed == 4096
        assert state.read_text() == "persistent"


def test_failed_eviction_keeps_bytes_and_reports_error(tmp_path, monkeypatch):
    with restricted_tree(tmp_path / "inventory" / "target", 0o555) as tree:
        with monkeypatch.context() as fault:
            fault.setattr("shutil.rmtree", lambda *args, **kwargs: None)
            result = cache_budget.prune_cache(tmp_path, max_bytes=0)
        assert tree.exists()
        assert result.errors == 1
        assert result.bytes_freed == result.files_removed == 0
        assert result.bytes_remaining == 4096
        assert result.budget_exceeded

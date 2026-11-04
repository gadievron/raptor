"""Compose teardown owns every file in its staging tree."""

import pytest
from core.container import compose
from core.run import scratch
from core.testing.restricted_tree import restricted_tree


@pytest.mark.parametrize("mode", [0o000, 0o500, 0o555])
def test_staging_cleanup_reclaims_restricted_output(tmp_path, mode):
    with restricted_tree(tmp_path / "staging", mode) as tree:
        scratch.keepalive_register(tree)
        try:
            compose.cleanup_staging(tree)
            assert not tree.exists()
            assert str(tree) not in scratch._keepalive_paths
        finally:
            scratch.keepalive_unregister(tree)

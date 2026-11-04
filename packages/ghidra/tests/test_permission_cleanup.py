"""Working database copies are disposable even with restricted modes."""

import pytest
from packages.ghidra import server, session
from core.testing.restricted_tree import restricted_tree


@pytest.mark.parametrize("mode", [0o000, 0o500, 0o555])
@pytest.mark.parametrize("owner", ["session", "server"])
def test_closed_owner_reclaims_restricted_database(tmp_path, monkeypatch, mode, owner):
    with restricted_tree(tmp_path / "copy", mode) as tree:
        if owner == "session":
            instance = session.GhidraSession()
            instance._work_dir = str(tree)
            close = instance.close
        else:
            monkeypatch.setattr(server, "pyghidra_available", lambda: True)
            instance = server.GhidraServer(tmp_path / "source.gpr")
            instance._work_dir = tree
            close = instance.stop
        close()
        assert not tree.exists()
        assert instance._work_dir is None

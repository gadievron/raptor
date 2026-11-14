"""Transfer inventories must not silently omit unreadable directories."""

import os
from pathlib import Path

import pytest

from packages.codeql import offline


@pytest.mark.parametrize("location", ["root", "nested"])
def test_transfer_tree_refuses_enumeration_failure(tmp_path, monkeypatch, location):
    source = tmp_path / "source"
    blocked = source / "blocked"
    blocked.mkdir(parents=True)
    (blocked / "query.ql").write_text("// inert source marker\n")
    (source / "visible.ql").write_text("// inert sibling\n")
    unreadable = source if location == "root" else blocked
    original = os.scandir
    denied = []

    def scandir(path):
        if Path(path) == unreadable:
            denied.append(path)
            raise PermissionError(13, "owned read refusal", str(path))
        return original(path)

    # os.walk resolves scandir in the stdlib module; restrict the fault to
    # this owned path and restore the binding through monkeypatch.
    monkeypatch.setattr(os, "scandir", scandir)
    with pytest.raises(ValueError, match="cannot enumerate transfer tree") as error:
        offline._tree(source)
    assert denied
    assert isinstance(error.value.__cause__, PermissionError)
    assert str(unreadable) in str(error.value)


def test_transfer_tree_keeps_readable_nested_inventory(tmp_path):
    source = tmp_path / "source"
    (source / "nested").mkdir(parents=True)
    (source / "nested" / "query.ql").write_bytes(b"query")
    records = offline._tree(source)
    assert set(records) == {"nested/query.ql"}
    assert records["nested/query.ql"]["size"] == 5

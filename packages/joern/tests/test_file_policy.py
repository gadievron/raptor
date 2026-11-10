"""Joern readers retain their distinct confidentiality and integrity policies."""

import errno
import os

import pytest

from core.source import gated
from packages.joern import broker, heap_ledger


def write_record(path, body, mode):
    path.write_text(body)
    path.chmod(mode)
    return path


def test_controller_private_record_rejects_before_consumption(tmp_path, monkeypatch):
    path = write_record(tmp_path / "controller.json", '{"v":1}', 0o640)

    def unexpected_adoption(*args, **kwargs):
        raise AssertionError("unsafe controller record reached stream adoption")

    monkeypatch.setattr(gated, "adopt_fd", unexpected_adoption)
    with pytest.raises(ValueError, match="unsafe Joern controller record"):
        broker._record(path)


def test_controller_record_requires_single_link(tmp_path):
    path = write_record(tmp_path / "controller.json", '{"v":1}', 0o600)
    assert broker._record(path) == {"v": 1}
    os.link(path, tmp_path / "alias")
    with pytest.raises(ValueError, match="unsafe Joern controller record"):
        broker._record(path)


def test_heap_ledger_allows_reads_and_links_but_refuses_foreign_writes(tmp_path):
    path = write_record(tmp_path / "ledger.json", '{"rows":[]}', 0o644)
    os.link(path, tmp_path / "alias")
    assert heap_ledger._read_rows(path) == []
    path.chmod(0o664)
    with pytest.raises(OSError) as error:
        heap_ledger._read_rows(path)
    assert error.value.errno == errno.EINVAL


def test_heap_ledger_still_distinguishes_missing_and_invalid(tmp_path):
    path = tmp_path / "ledger.json"
    assert heap_ledger._read_rows(path) == []
    write_record(path, "invalid-json", 0o600)
    with pytest.raises(OSError) as error:
        heap_ledger._read_rows(path)
    assert error.value.errno == errno.EINVAL


def test_controller_directory_policy_is_unchanged(tmp_path):
    path = tmp_path / "runtime"
    path.mkdir(mode=0o700)
    broker._private(path)
    path.chmod(0o750)
    with pytest.raises(ValueError, match="private and owned by this user"):
        broker._private(path)

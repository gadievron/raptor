"""Metadata hooks validate the opened inode before adoption and consumption."""

import errno
import os

import pytest

from core.source import gated
from core.testing.module_bindings import patch_module_attribute


def read_with(reader, path, policy=None):
    if reader == "open":
        with gated.open_regular_gated(path, stat_validator=policy) as stream:
            return stream.read()
    if reader == "bytes":
        return gated.read_bytes_gated(path, 64, stat_validator=policy)
    return gated.read_text_gated(path, 64, stat_validator=policy)


@pytest.mark.parametrize("reader", ["open", "bytes", "text"])
def test_policy_uses_single_fstat_and_the_same_opened_inode(tmp_path, monkeypatch, reader):
    path = tmp_path / "file"
    path.write_bytes(b"original")
    snapshots = []
    original_fstat = os.fstat

    def fstat(fd):
        metadata = original_fstat(fd)
        snapshots.append(metadata)
        return metadata

    patch_module_attribute(monkeypatch, gated, "os", "fstat", fstat)

    def policy(metadata):
        assert snapshots == [metadata]
        assert snapshots[0] is metadata
        path.rename(tmp_path / "original")
        path.write_bytes(b"replacement")

    actual = read_with(reader, path, policy)
    assert actual == ("original" if reader == "text" else b"original")
    assert len(snapshots) == 1


@pytest.mark.parametrize("reader", ["open", "bytes", "text"])
def test_default_has_no_implicit_private_file_policy(tmp_path, reader):
    path = tmp_path / "public"
    path.write_bytes(b"readable")
    path.chmod(0o666)
    assert read_with(reader, path) == ("readable" if reader == "text" else b"readable")


@pytest.mark.parametrize("primary_type", [ValueError, OSError, KeyboardInterrupt, SystemExit, MemoryError])
@pytest.mark.parametrize("cleanup_type", [OSError, KeyboardInterrupt])
def test_policy_failure_closes_fd_without_consuming_or_masking_primary(
    tmp_path, monkeypatch, primary_type, cleanup_type,
):
    path = tmp_path / "file"
    path.write_bytes(b"private body")
    opened, closed = [], []
    primary = primary_type("policy refused")

    def opening(*args, **kwargs):
        fd = os.open(*args, **kwargs)
        opened.append(fd)
        return fd

    def closing(fd):
        os.close(fd)
        closed.append(fd)
        raise cleanup_type("close failed after consuming fd")

    def adopt(*args, **kwargs):
        raise AssertionError("refused fd reached stream adoption")

    def policy(metadata):
        raise primary

    patch_module_attribute(monkeypatch, gated, "os", "open", opening)
    patch_module_attribute(monkeypatch, gated, "os", "close", closing)
    monkeypatch.setattr(gated, "adopt_fd", adopt)
    with pytest.raises(primary_type) as error:
        gated.open_regular_gated(path, stat_validator=policy)
    assert error.value is primary
    assert len(opened) == 1 and closed == opened
    with pytest.raises(OSError) as retired:
        os.fstat(opened[0])
    assert retired.value.errno == errno.EBADF


def test_policy_does_not_replace_custom_budget_error(tmp_path):
    path = tmp_path / "file"
    path.write_bytes(b"oversized")
    validated = []

    class BudgetError(ValueError):
        pass

    with pytest.raises(BudgetError):
        gated.read_bytes_gated(path, 1, budget_error=BudgetError,
                              stat_validator=validated.append)
    assert len(validated) == 1

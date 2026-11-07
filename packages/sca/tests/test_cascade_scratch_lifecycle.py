"""Cascade parsers consume lockfiles while their complete workspace is owned."""

from contextlib import contextmanager
from pathlib import Path

import pytest

from core.run import scratch
from core.testing.module_bindings import patch_module_attribute
from packages.sca import transitive


@pytest.fixture
def placed_scratch(tmp_path, monkeypatch):
    original = scratch.tempfile.mkdtemp
    roots = []
    def allocate(*a, **kw):
        assert kw.get("dir") is None
        kw["dir"] = tmp_path
        result = original(*a, **kw)
        roots.append(Path(result))
        return result
    patch_module_attribute(monkeypatch, scratch, "tempfile", "mkdtemp", allocate)
    return roots


@pytest.mark.parametrize("ecosystem", list(transitive._CASCADE_LOCKFILE_NAMES))
def test_parser_consumed_inside_owned_workspace(tmp_path, placed_scratch, ecosystem):
    manifest = tmp_path / "host-manifest"
    manifest.write_bytes(b"borrowed")
    def parser(path):
        assert path.name == transitive._CASCADE_LOCKFILE_NAMES[ecosystem]
        assert path.read_bytes() == b"lockfile bytes"
        assert str(path.parent) in scratch._keepalive_paths
        yield "first"
        assert path.exists() and str(path.parent) in scratch._keepalive_paths
        child = path.parent / "restricted"
        child.mkdir()
        (child / "extra").write_bytes(b"temporary")
        child.chmod(0)
        yield "second"
    result = transitive._parse_lockfile_bytes(ecosystem, b"lockfile bytes", parser, manifest)
    assert result == ["first", "second"]
    assert manifest.read_bytes() == b"borrowed"
    assert len(placed_scratch) == 1 and not placed_scratch[0].exists()


@pytest.mark.parametrize("error", [OSError, RuntimeError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("after_yield", [False, True], ids=["call", "iteration"])
def test_parser_failure_reclaims_partial_outputs(tmp_path, placed_scratch, error, after_yield):
    def items(path):
        yield "partial result"
        raise error("parser fault")
    def parser(path):
        (path.parent / "sidecar").write_bytes(b"temporary")
        if after_yield:
            return items(path)
        raise error("parser fault")
    if issubclass(error, Exception):
        assert transitive._parse_lockfile_bytes("PyPI", b"bytes", parser, tmp_path / "host") is None
    else:
        with pytest.raises(error, match="parser fault"):
            transitive._parse_lockfile_bytes("PyPI", b"bytes", parser, tmp_path / "host")
    assert len(placed_scratch) == 1 and not placed_scratch[0].exists()


@pytest.mark.parametrize("error", [OSError, RuntimeError, KeyboardInterrupt, SystemExit])
def test_partial_lockfile_write_is_reclaimed(tmp_path, placed_scratch, monkeypatch, error):
    owner = transitive.scratch_dir
    class FaultPath(type(Path())):
        def write_bytes(self, data):
            super().write_bytes(data[:1])
            raise error("write fault")
    @contextmanager
    def workspace(*a, **kw):
        with owner(*a, **kw) as root:
            yield FaultPath(root)
    monkeypatch.setattr(transitive, "scratch_dir", workspace)
    def parser(path):
        pytest.fail("parser reached after failed input write")
    if issubclass(error, Exception):
        assert transitive._parse_lockfile_bytes("PyPI", b"bytes", parser, tmp_path / "host") is None
    else:
        with pytest.raises(error, match="write fault"):
            transitive._parse_lockfile_bytes("PyPI", b"bytes", parser, tmp_path / "host")
    assert len(placed_scratch) == 1 and not placed_scratch[0].exists()

"""Rendered axes own partial files before yielding to the scanner."""

from contextlib import contextmanager
from pathlib import Path

import pytest

from core.run import scratch
from engine.coccinelle import api_pack_renderer as renderer
import importlib

analyzer = importlib.import_module("packages.source_intel.analyze")


@pytest.fixture
def axis_case(tmp_path, monkeypatch):
    axis = tmp_path / "axis"
    axis.mkdir()
    (axis / "a.cocci").write_text("// @api-packs: packs crypto\n")
    (axis / "b.cocci").write_text("plain rule")
    roots = []

    @contextmanager
    def workspace(prefix):
        with scratch.scratch_dir(prefix, dir=tmp_path / "scratch", keepalive=True) as root:
            roots.append(root)
            yield root

    monkeypatch.setattr(analyzer, "scratch_dir", workspace)
    monkeypatch.setattr(renderer, "render_text", lambda path: "rendered rule")
    return axis, roots


@pytest.mark.parametrize("stage", ["write", "scan"])
@pytest.mark.parametrize("error_type", [OSError, ValueError, KeyboardInterrupt, SystemExit])
def test_failed_rule_preparation_or_scan_reclaims_axis(axis_case, monkeypatch, stage, error_type):
    axis, roots = axis_case
    primary = error_type("axis failed")
    write = Path.write_text

    def fail_write(path, *args, **kwargs):
        result = write(path, *args, **kwargs)
        if roots and path.parent == roots[0]:
            raise primary
        return result

    if stage == "write":
        monkeypatch.setattr(Path, "write_text", fail_write)
    with pytest.raises(error_type) as caught:
        with analyzer._materialize_rules_dir(axis) as effective:
            assert stage == "scan"
            assert str(effective) in scratch._keepalive_paths
            assert (effective / "a.cocci").read_text() == "rendered rule"
            assert (effective / "b.cocci").read_text() == "plain rule"
            raise primary
    assert caught.value is primary
    assert roots and all(not root.exists() for root in roots)
    assert not scratch._keepalive_paths
    assert (axis / "b.cocci").read_text() == "plain rule"


@pytest.mark.parametrize("error_type", [OSError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("cleanup_type", [OSError, KeyboardInterrupt])
def test_rule_cleanup_preserves_scan_failure(axis_case, monkeypatch, error_type, cleanup_type):
    axis, roots = axis_case
    primary = error_type("scan failed")
    remove = scratch.rmtree_hardened

    def cleanup(root):
        assert remove(root)
        raise cleanup_type("cleanup failed")

    monkeypatch.setattr(scratch, "rmtree_hardened", cleanup)
    with pytest.raises(error_type) as caught:
        with analyzer._materialize_rules_dir(axis):
            raise primary
    assert caught.value is primary
    assert all(not root.exists() for root in roots)
    assert not scratch._keepalive_paths


def test_failed_verbatim_copy_reclaims_prior_rendered_file(axis_case):
    axis, roots = axis_case
    (axis / "b.cocci").unlink()
    (axis / "b.cocci").mkdir()
    with pytest.raises(IsADirectoryError):
        with analyzer._materialize_rules_dir(axis):
            pytest.fail("partial preparation must not be yielded")
    assert all(not root.exists() for root in roots)
    assert not scratch._keepalive_paths
    assert (axis / "b.cocci").is_dir()

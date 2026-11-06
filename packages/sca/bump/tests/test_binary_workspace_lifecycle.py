"""Comparison ownership covers both extractions and the consumer."""

from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path

import pytest

from core.run import scratch
from packages.sca.bump import binary_capability_delta as detector
from packages.sca.bump import image_binary_extract as extraction
from packages.sca.bump import orchestrator as orch
from packages.sca.bump.tests.test_image_binary_extract import _stub_client_with_binary


@pytest.fixture
def comparison(monkeypatch, tmp_path):
    roots = []

    @contextmanager
    def owned_workspace(prefix):
        with scratch.scratch_dir(prefix, dir=tmp_path, keepalive=True) as root:
            roots.append(root)
            yield root

    monkeypatch.setattr(orch, "scratch_dir", owned_workspace)
    monkeypatch.setattr(orch, "_resolve_gha_image_refs", lambda *a, **kw: ("old", "new"))
    return roots


def candidate(kind):
    return orch.BumpCandidate(
        kind=kind, locator="docker.io/library/test", file=Path("Dockerfile"),
        current_version="1", target_version="2",
    )


@pytest.mark.parametrize("kind", ["from_image", "yaml_image", "gha_uses"])
@pytest.mark.parametrize("stage", ["first", "second", "compare"])
@pytest.mark.parametrize("error_type", [OSError, KeyboardInterrupt, SystemExit])
def test_interruptions_release_entire_comparison(
    kind, stage, error_type, comparison, monkeypatch, tmp_path,
):
    error = error_type("original failure")
    calls = []
    outside = tmp_path / "outside"
    outside.write_bytes(b"preserve")

    def fetch(ref, *, client, out_dir):
        assert str(out_dir) in scratch._keepalive_paths
        assert comparison == [out_dir]
        index = len(calls)
        calls.append(out_dir)
        (out_dir / f"nested-{index}").mkdir()
        (out_dir / f"nested-{index}" / "partial").write_bytes(b"partial")
        (out_dir / f"link-{index}").symlink_to(outside)
        if stage == ("first" if index == 0 else "second"):
            raise error
        path = out_dir / str(index)
        path.write_bytes(b"binary")
        return path

    def compare(**kwargs):
        assert kwargs["current_binary"].exists()
        assert kwargs["target_binary"].exists()
        assert str(comparison[0]) in scratch._keepalive_paths
        raise error

    monkeypatch.setattr(extraction, "fetch_image_binary", fetch)
    monkeypatch.setattr(detector, "binary_capability_delta_finding", compare)
    with pytest.raises(error_type) as caught:
        orch._binary_capability_delta_for_candidate(candidate(kind), oci_client=object(), http=object())
    assert caught.value is error
    assert len(calls) == (1 if stage == "first" else 2)
    assert not comparison[0].exists()
    assert str(comparison[0]) not in scratch._keepalive_paths
    assert outside.read_bytes() == b"preserve"


@pytest.mark.parametrize("kind", ["from_image", "yaml_image", "gha_uses"])
@pytest.mark.parametrize("missing", [0, 1, None], ids=["current-missing", "target-missing", "success"])
def test_returns_clean_all_artifacts(kind, missing, comparison, monkeypatch):
    paths = []
    result = object()

    def fetch(ref, *, client, out_dir):
        assert str(out_dir) in scratch._keepalive_paths
        path = out_dir / str(len(paths))
        path.write_bytes(b"binary")
        paths.append(path)
        return None if len(paths) - 1 == missing else path

    def compare(**kwargs):
        assert kwargs["current_binary"] == paths[0]
        assert kwargs["target_binary"] == paths[1]
        assert all(p.exists() for p in paths)
        assert paths[0].parent == paths[1].parent
        return result

    monkeypatch.setattr(extraction, "fetch_image_binary", fetch)
    monkeypatch.setattr(detector, "binary_capability_delta_finding", compare)
    actual = orch._binary_capability_delta_for_candidate(candidate(kind), oci_client=object(), http=object())
    assert actual is (result if missing is None else None)
    assert not comparison[0].exists()
    assert str(comparison[0]) not in scratch._keepalive_paths


def test_identical_binaries_use_one_real_extraction(comparison, monkeypatch):
    cand = replace(candidate("from_image"), target_version="1")
    client = _stub_client_with_binary(b"\x7fELF" + b"x" * 200)
    result = object()

    def compare(**kwargs):
        current = kwargs["current_binary"]
        target = kwargs["target_binary"]
        assert current == target
        assert list(comparison[0].iterdir()) == [current]
        assert current.read_bytes() == b"\x7fELF" + b"x" * 200
        assert str(comparison[0]) in scratch._keepalive_paths
        return result

    monkeypatch.setattr(detector, "binary_capability_delta_finding", compare)
    assert orch._binary_capability_delta_for_candidate(cand, oci_client=client) is result
    assert not comparison[0].exists()


@pytest.mark.parametrize("cleanup_type", [OSError, KeyboardInterrupt, SystemExit])
def test_cleanup_failure_preserves_comparison_error(comparison, monkeypatch, cleanup_type):
    primary = ValueError("comparison failed")
    remove = scratch.rmtree_hardened

    def fetch(ref, *, client, out_dir):
        path = out_dir / ref.rsplit(":", 1)[-1]
        path.write_bytes(b"binary")
        return path

    def compare(**kwargs):
        raise primary

    def remove_then_fail(path):
        assert remove(path)
        raise cleanup_type("cleanup failed")

    monkeypatch.setattr(extraction, "fetch_image_binary", fetch)
    monkeypatch.setattr(detector, "binary_capability_delta_finding", compare)
    monkeypatch.setattr(scratch, "rmtree_hardened", remove_then_fail)
    with pytest.raises(ValueError) as caught:
        orch._binary_capability_delta_for_candidate(candidate("from_image"), oci_client=object())
    assert caught.value is primary
    assert not comparison[0].exists()
    assert str(comparison[0]) not in scratch._keepalive_paths

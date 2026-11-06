"""Expanded scanner input is private, pinned, and reclaimed on failure."""

import importlib
import sys
from unittest.mock import patch

import pytest

from core.audit import expanded_semgrep as expanded
from core.run import scratch


@pytest.fixture
def scan_case(tmp_path, monkeypatch):
    # The script's launcher bootstrap owns a temporary path-list object.
    with patch.object(sys, "path", sys.path.copy()):
        scanner = importlib.import_module("packages.static-analysis.scanner")
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "main.c").write_text("int main(void) { return 0; }\n")
        out = tmp_path / "out"
        out.mkdir()
        sentinel = out / "caller-file"
        sentinel.write_bytes(b"preserve")
        monkeypatch.setattr("packages.semgrep.runner.is_available", lambda: True)
        roots = []

        def build(target, root, **kwargs):
            roots.append(root)
            assert root.parent == out
            assert str(root) in scratch._keepalive_paths
            nested = root / "restricted"
            nested.mkdir()
            (nested / "large-view.c").write_bytes(b"partial view")
            nested.chmod(0)
            return expanded.ExpandedCorpus(root=root, expanded=1, candidates_total=1)

        monkeypatch.setattr(expanded, "build_expanded_corpus", build)
        yield scanner, repo, out, roots, build


def reclaimed(out, roots):
    assert roots and all(not root.exists() for root in roots)
    assert all(str(root) not in scratch._keepalive_paths for root in roots)
    assert (out / "caller-file").read_bytes() == b"preserve"


@pytest.mark.parametrize("stage", ["build", "report"])
@pytest.mark.parametrize("error_type", [OSError, ValueError, KeyboardInterrupt, SystemExit])
def test_expanded_stage_error_reclaims_views(scan_case, monkeypatch, stage, error_type):
    scanner, repo, out, roots, build = scan_case
    primary = error_type("stage failed")

    def fail(*args, **kwargs):
        if stage == "build":
            build(*args, **kwargs)
        assert str(roots[0]) in scratch._keepalive_paths
        raise primary

    monkeypatch.setattr(expanded if stage == "build" else scanner,
                        "build_expanded_corpus" if stage == "build" else "_write_stage_report", fail)
    with pytest.raises(error_type) as caught:
        scanner.run_expanded_semgrep_stage(repo, out, [], [])
    assert caught.value is primary
    reclaimed(out, roots)


@pytest.mark.parametrize("error_type", [OSError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("cleanup_type", [OSError, KeyboardInterrupt])
def test_expanded_cleanup_preserves_preparation_error(scan_case, monkeypatch, error_type, cleanup_type):
    scanner, repo, out, roots, build = scan_case
    primary = error_type("preparation failed")
    remove = scratch.rmtree_hardened

    def fail(*args, **kwargs):
        build(*args, **kwargs)
        raise primary

    def cleanup(root):
        assert remove(root)
        raise cleanup_type("cleanup failed")

    monkeypatch.setattr(expanded, "build_expanded_corpus", fail)
    monkeypatch.setattr(scratch, "rmtree_hardened", cleanup)
    with pytest.raises(error_type) as caught:
        scanner.run_expanded_semgrep_stage(repo, out, [], [])
    assert caught.value is primary
    reclaimed(out, roots)


@pytest.mark.parametrize("expanded_count", [0, 1], ids=["empty", "report"])
def test_expanded_returns_reclaim_views(scan_case, monkeypatch, expanded_count):
    scanner, repo, out, roots, build = scan_case

    def prepare(*args, **kwargs):
        corpus = build(*args, **kwargs)
        corpus.expanded = expanded_count
        return corpus

    monkeypatch.setattr(expanded, "build_expanded_corpus", prepare)
    paths = scanner.run_expanded_semgrep_stage(repo, out, [], [])
    assert bool(paths) is bool(expanded_count)
    reclaimed(out, roots)

"""Corpus jobs only reclaim their own invocation's complete scratch tree."""

from pathlib import Path

import pytest

from core.atomic_fs import rmtree_hardened
from core.dataflow import cvefix_bridge as bridge, cvefix_walk as walk
from core.dataflow.cvefix_loader import CveFixPair


def _pair(lang="Python"):
    return CveFixPair("CVE-X", "CWE-89", "https://example.invalid/repo",
                      lang, "a" * 40, "b" * 40)


def _invoke(engine, pair, work):
    if engine == "walk":
        return walk.process_pair(pair, work_dir=work)
    return bridge.synthesize_one(pair, work_dir=work, proposer=lambda *a: "")


@pytest.mark.parametrize("engine", ["walk", "bridge"])
@pytest.mark.parametrize("mode", [0o000, 0o500, 0o555])
def test_failed_pair_reclaims_restricted_build_tree(tmp_path, monkeypatch, engine, mode):
    work = tmp_path / "work"
    work.mkdir()
    marker = work / "unrelated"
    marker.write_text("keep")
    roots = []

    def fetch(url, fix, dest, timeout):
        roots.append(dest.parent)
        nested = dest / "locked" / "nested"
        nested.mkdir(parents=True)
        (nested / "payload").write_bytes(b"payload")
        (dest / "locked").chmod(mode)
        return False

    monkeypatch.setattr(walk, "_fetch_pair", fetch)
    try:
        _invoke(engine, _pair(), work)
        assert sorted(p.name for p in work.iterdir()) == ["unrelated"]
        assert roots[0] != work
        assert not roots[0].exists()
        assert marker.read_text() == "keep"
    finally:
        for root in roots:
            if root != work:
                rmtree_hardened(root)
        rmtree_hardened(work / "repo")


def test_go_pair_does_not_remove_shared_cache(tmp_path, monkeypatch):
    cache = tmp_path / "go-mod-cache"
    cache.mkdir()
    marker = cache / "other-worker"
    marker.write_text("active")
    monkeypatch.setattr(walk, "_fetch_pair", lambda *a: False)
    walk.process_pair(_pair("Go"), work_dir=tmp_path)
    assert marker.read_text() == "active"


def test_cleanup_does_not_mask_failed_fetch(tmp_path, monkeypatch):
    roots = []
    unlink = Path.unlink

    def fetch(url, fix, dest, timeout):
        dest.mkdir(parents=True)
        roots.append(dest.parent)
        raise ValueError("primary fetch failure")

    def fail_unlink(path, *args, **kwargs):
        if path.name == "a.sarif":
            raise PermissionError("secondary unlink failure")
        return unlink(path, *args, **kwargs)

    monkeypatch.setattr(walk, "_fetch_pair", fetch)
    monkeypatch.setattr(Path, "unlink", fail_unlink)
    try:
        with pytest.raises(ValueError, match="primary fetch failure"):
            walk.process_pair(_pair(), work_dir=tmp_path)
        assert all(not root.exists() for root in roots)
    finally:
        for root in roots:
            rmtree_hardened(root)


@pytest.mark.parametrize("engine", ["walk", "bridge"])
def test_cancellation_reclaims_unknown_tool_side_files(tmp_path, monkeypatch, engine):
    roots = []

    def fetch(url, fix, dest, timeout):
        roots.append(dest.parent)
        dest.mkdir(parents=True)
        (dest.parent / "unexpected-tool-cache").mkdir()
        (dest.parent / "unexpected-tool-cache" / "large-output").write_bytes(b"x" * 4096)
        raise KeyboardInterrupt("cancelled fetch")

    monkeypatch.setattr(walk, "_fetch_pair", fetch)
    with pytest.raises(KeyboardInterrupt, match="cancelled fetch"):
        _invoke(engine, _pair(), tmp_path)
    assert len(roots) == 1
    assert not roots[0].exists()
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize("engine", ["walk", "bridge"])
@pytest.mark.parametrize("stage", ["build", "analyze"])
def test_late_failure_reclaims_databases_and_caches(tmp_path, monkeypatch, engine, stage):
    roots = []

    def fetch(url, fix, dest, timeout):
        roots.append(dest.parent)
        dest.mkdir(parents=True)
        return True

    def build(repo, commit, database, *args, **kwargs):
        database.mkdir()
        (database / "table").write_bytes(b"database bytes")
        database.chmod(0o555)
        cache = database.parent / "tool-cache"
        cache.mkdir(exist_ok=True)
        (cache / "payload").write_bytes(b"cache")
        return stage != "build"

    def analyze(database, query, output, *args, **kwargs):
        output.write_bytes(b"partial report")
        return None if engine == "walk" else False

    monkeypatch.setattr(walk, "_fetch_pair", fetch)
    monkeypatch.setattr(walk, "_build_db", build)
    monkeypatch.setattr(walk, "_count_query", analyze)
    monkeypatch.setattr(bridge, "_run_query", analyze)
    _invoke(engine, _pair(), tmp_path)
    assert not roots[0].exists()
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize("engine", ["walk", "bridge"])
def test_overlapping_jobs_keep_each_others_scratch(tmp_path, monkeypatch, engine):
    roots = []

    def fetch(url, fix, dest, timeout):
        roots.append(dest.parent)
        dest.mkdir(parents=True)
        marker = dest / "active"
        marker.write_text("in use")
        if len(roots) == 1:
            _invoke(engine, _pair(), tmp_path)
            assert marker.read_text() == "in use"
        return False

    monkeypatch.setattr(walk, "_fetch_pair", fetch)
    _invoke(engine, _pair(), tmp_path)
    assert len(set(roots)) == 2
    assert all(not root.exists() for root in roots)
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize("engine", ["walk", "bridge"])
def test_caller_owned_paths_survive_repeated_jobs(tmp_path, monkeypatch, engine):
    markers = []
    for name in ("repo", "after", "before", "synth", "db-a", "db-b"):
        directory = tmp_path / name
        directory.mkdir()
        marker = directory / "owned-by-caller"
        marker.write_text(name)
        markers.append(marker)
    report = tmp_path / "after.sarif"
    report.write_text("caller report")
    expected = set(tmp_path.iterdir())
    monkeypatch.setattr(walk, "_fetch_pair", lambda *a: False)
    for _ in range(3):
        _invoke(engine, _pair(), tmp_path)
    assert set(tmp_path.iterdir()) == expected
    assert report.read_text() == "caller report"
    assert all(marker.read_text() == marker.parent.name for marker in markers)


@pytest.mark.parametrize("name", ["go-mod-cache", "gopath", "go-build-cache"])
def test_go_cache_links_do_not_change_external_permissions(tmp_path, name):
    outside = tmp_path / "outside"
    outside.mkdir()
    payload = outside / "readonly"
    payload.write_bytes(b"external data")
    payload.chmod(0o400)
    work = tmp_path / "work"
    work.mkdir()
    link = work / name
    link.symlink_to(outside, target_is_directory=True)
    before = payload.stat().st_mode
    walk._clean_go_caches(work)
    assert link.is_symlink()
    assert payload.stat().st_mode == before
    assert payload.read_bytes() == b"external data"


@pytest.mark.parametrize("engine", ["walk", "bridge"])
def test_no_query_creates_no_scratch(tmp_path, monkeypatch, engine):
    work = tmp_path / "unused"
    monkeypatch.setattr(walk, "query_for", lambda *a: None)
    _invoke(engine, _pair(), work)
    assert not work.exists()

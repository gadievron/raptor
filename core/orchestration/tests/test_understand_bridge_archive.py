"""Archive targets resolve through the bridge via their extraction cache.

Runs on an archive target extract to the content-addressed
``_sources/<name>-<sha>/`` cache and record THAT tree as the
checklist ``target_path`` — pre-fix the bridge's string/resolved-path
target matching compared the archive FILE against the extraction DIR
and never matched, so /understand output silently failed to import
into /validate for every zip-target pipeline. The bridge now
normalises an archive target to its cached extraction (beside the
validate run first, then the global out root) before discovery and
freshness checks; a missing cache falls back to the exact pre-fix
no-match behaviour.
"""

from __future__ import annotations

import json
import zipfile
from pathlib import Path

from core.orchestration.understand_bridge import (
    _normalize_archive_target,
    find_understand_output,
)


def _write_json(path: Path, data: object) -> None:
    path.write_text(json.dumps(data, indent=2))


def _make_zip(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("app/main.py", "print('hi')\n")
    return path


def _cache_dir_for(archive: Path, sources_root: Path) -> Path:
    from core.archive import safe_cache_name
    from core.run.provenance import archive_snapshot
    snap = archive_snapshot(archive)
    assert snap is not None
    d = sources_root / safe_cache_name(
        snap["archive_name"], snap["archive_sha256"])
    d.mkdir(parents=True, exist_ok=True)
    return d


def _make_understand_dir(parent: Path, name: str, target_path: str) -> Path:
    d = parent / name
    d.mkdir(parents=True, exist_ok=True)
    _write_json(d / "context-map.json", {"sources": []})
    _write_json(d / ".raptor-run.json",
                {"version": 1, "command": "understand",
                 "status": "completed"})
    _write_json(d / "checklist.json",
                {"target_path": target_path, "files": []})
    return d


class TestNormalizeArchiveTarget:
    def test_directory_target_passes_through(self, tmp_path):
        d = tmp_path / "src"
        d.mkdir()
        assert _normalize_archive_target(tmp_path, str(d)) == str(d)

    def test_url_target_passes_through(self, tmp_path):
        url = "https://example.test/app"
        assert _normalize_archive_target(tmp_path, url) == url

    def test_archive_without_cache_passes_through(self, tmp_path):
        archive = _make_zip(tmp_path / "app.zip")
        validate_dir = tmp_path / "validate-run"
        validate_dir.mkdir()
        assert (_normalize_archive_target(validate_dir, str(archive))
                == str(archive))

    def test_archive_with_sibling_cache_normalises(self, tmp_path):
        archive = _make_zip(tmp_path / "app.zip")
        project_dir = tmp_path / "project"
        validate_dir = project_dir / "validate-20260925-120000"
        validate_dir.mkdir(parents=True)
        cache = _cache_dir_for(archive, project_dir / "_sources")
        assert (_normalize_archive_target(validate_dir, str(archive))
                == str(cache))


class TestBridgeDiscoveryOnArchiveTargets:
    def test_project_sibling_understand_found_for_zip_target(
        self, tmp_path,
    ):
        archive = _make_zip(tmp_path / "app.zip")
        project_dir = tmp_path / "project"
        validate_dir = project_dir / "validate-20260925-120000"
        validate_dir.mkdir(parents=True)
        cache = _cache_dir_for(archive, project_dir / "_sources")
        u = _make_understand_dir(
            project_dir, "understand-20260925-110000", str(cache))

        result_dir, stale = find_understand_output(
            validate_dir, target_path=str(archive))
        assert result_dir == u
        assert stale == set()

    def test_out_root_understand_found_for_zip_target(
        self, tmp_path, monkeypatch,
    ):
        archive = _make_zip(tmp_path / "app.zip")
        out_root = tmp_path / "out"
        out_root.mkdir()
        monkeypatch.setattr("core.config.RaptorConfig.get_out_dir",
                            staticmethod(lambda: out_root))
        cache = _cache_dir_for(archive, out_root / "_sources")
        u = _make_understand_dir(
            out_root, "understand_20260925_110000", str(cache))

        validate_dir = tmp_path / "validate-run"
        validate_dir.mkdir()
        result_dir, _stale = find_understand_output(
            validate_dir, target_path=str(archive))
        assert result_dir == u

    def test_replaced_archive_bytes_do_not_match_old_cache(
        self, tmp_path,
    ):
        # Content binding: the cache dir was built from the OLD bytes;
        # a rewritten archive must miss it and fall back to no-match.
        archive = _make_zip(tmp_path / "app.zip")
        project_dir = tmp_path / "project"
        validate_dir = project_dir / "validate-20260925-120000"
        validate_dir.mkdir(parents=True)
        cache = _cache_dir_for(archive, project_dir / "_sources")
        _make_understand_dir(
            project_dir, "understand-20260925-110000", str(cache))

        with zipfile.ZipFile(archive, "w") as zf:
            zf.writestr("app/other.py", "y = 2\n")

        result_dir, _stale = find_understand_output(
            validate_dir, target_path=str(archive))
        assert result_dir is None

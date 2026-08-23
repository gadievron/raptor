"""Tests for the /cve-diff → /cve-env fix-pointer bridge.

Fixtures synthesize the exact artifact shape
``cve_diff.report.osv_schema.render`` writes (GIT ranges +
``database_specific``) — the bridge is a plain JSON reader, so the
fixture IS the contract.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.orchestration.cvediff_bridge import FixPointer, find_fix_pointer

CVE = "CVE-2021-41773"


def _osv(cve_id: str = CVE, *, repo: str = "https://github.com/apache/httpd",
         fixed: str = "a" * 40, before: str = "b" * 40,
         shape: str = "source", consensus: str | None = "agree",
         files_changed: int = 3) -> dict:
    dbs: dict = {
        "files_changed": files_changed,
        "diff_bytes": 1234,
        "canonical_score": 100,
        "diff_against": before,
        "diff_shape": shape,
        "files": [],
    }
    if consensus is not None:
        dbs["consensus"] = {"verdict": consensus}
    return {
        "schema_version": "1.6.0",
        "id": cve_id,
        "modified": "2026-08-21T00:00:00Z",
        "references": [{"type": "FIX", "url": f"{repo}/commit/{fixed}"}],
        "affected": [{
            "ranges": [{
                "type": "GIT",
                "repo": repo,
                "events": [{"introduced": before}, {"fixed": fixed}],
            }],
        }],
        "database_specific": dbs,
    }


def _write(run_dir: Path, osv: dict) -> Path:
    run_dir.mkdir(parents=True, exist_ok=True)
    p = run_dir / f"{osv['id']}.osv.json"
    p.write_text(json.dumps(osv))
    return p


class TestTier1Explicit:
    def test_pointer_read_from_explicit_dir(self, tmp_path):
        _write(tmp_path, _osv())
        ptr = find_fix_pointer(CVE, out_dir=tmp_path)
        assert isinstance(ptr, FixPointer)
        assert ptr.repository_url == "https://github.com/apache/httpd"
        assert ptr.fix_commit == "a" * 40
        assert ptr.commit_before == "b" * 40
        assert ptr.diff_shape == "source"
        assert ptr.consensus_verdict == "agree"
        assert ptr.source_run == str(tmp_path)
        assert ptr.mirror_warning is False

    def test_explicit_dir_wins_over_project(self, tmp_path):
        explicit = tmp_path / "explicit"
        proj = tmp_path / "proj"
        _write(explicit, _osv(fixed="c" * 40))
        _write(proj / "cve-diff_run", _osv())
        ptr = find_fix_pointer(CVE, out_dir=explicit, project_dir=proj)
        assert ptr is not None
        assert ptr.fix_commit == "c" * 40

    def test_missing_everywhere_returns_none(self, tmp_path):
        assert find_fix_pointer(
            CVE, out_dir=tmp_path, project_dir=tmp_path) is None

    def test_invalid_cve_id_returns_none(self, tmp_path):
        _write(tmp_path, _osv())
        assert find_fix_pointer("not-a-cve", out_dir=tmp_path) is None


class TestProjectTier:
    def test_found_in_project_run_subdir(self, tmp_path):
        proj = tmp_path / "proj"
        _write(proj / "cve-diff_CVE-2021-41773_x", _osv())
        ptr = find_fix_pointer(CVE, project_dir=proj)
        assert ptr is not None
        assert ptr.fix_commit == "a" * 40

    def test_clean_candidate_beats_newer_mirror_shape(self, tmp_path):
        proj = tmp_path / "proj"
        old = _write(proj / "run_old", _osv())
        new = _write(proj / "run_new", _osv(shape="packaging_only",
                                            fixed="d" * 40))
        # run_new is newer on mtime but mirror-shaped; the clean
        # source-shaped discovery must win.
        import os
        os.utime(old, ns=(1, 1))
        assert new.stat().st_mtime_ns > 1
        ptr = find_fix_pointer(CVE, project_dir=proj)
        assert ptr is not None
        assert ptr.fix_commit == "a" * 40

    def test_newest_wins_among_clean(self, tmp_path):
        proj = tmp_path / "proj"
        old = _write(proj / "run_old", _osv(fixed="e" * 40))
        _write(proj / "run_new", _osv(fixed="f" * 40))
        import os
        os.utime(old, ns=(1, 1))
        ptr = find_fix_pointer(CVE, project_dir=proj)
        assert ptr is not None
        assert ptr.fix_commit == "f" * 40

    def test_mirror_shape_still_returned_when_only_option(self, tmp_path):
        proj = tmp_path / "proj"
        _write(proj / "run", _osv(shape="packaging_only"))
        ptr = find_fix_pointer(CVE, project_dir=proj)
        assert ptr is not None
        assert ptr.mirror_warning is True

    def test_disagreeing_consensus_ranked_below_clean(self, tmp_path):
        proj = tmp_path / "proj"
        old = _write(proj / "run_old", _osv(fixed="1" * 40))
        _write(proj / "run_new", _osv(fixed="2" * 40, consensus="disagree"))
        import os
        os.utime(old, ns=(1, 1))
        ptr = find_fix_pointer(CVE, project_dir=proj)
        assert ptr is not None
        assert ptr.fix_commit == "1" * 40


class TestArtifactRobustness:
    @pytest.mark.parametrize("mutate", [
        lambda o: o.__setitem__("affected", []),
        lambda o: o["database_specific"].pop("diff_against"),
        lambda o: o["affected"][0]["ranges"][0].__setitem__("events", []),
    ])
    def test_pointer_incomplete_artifact_skipped(self, tmp_path, mutate):
        osv = _osv()
        mutate(osv)
        _write(tmp_path, osv)
        assert find_fix_pointer(CVE, out_dir=tmp_path) is None

    def test_malformed_json_skipped(self, tmp_path):
        (tmp_path / f"{CVE}.osv.json").write_text("{not json")
        assert find_fix_pointer(CVE, out_dir=tmp_path) is None

    def test_consensus_absent_is_clean(self, tmp_path):
        _write(tmp_path, _osv(consensus=None))
        ptr = find_fix_pointer(CVE, out_dir=tmp_path)
        assert ptr is not None
        assert ptr.consensus_verdict == ""

    def test_to_dict_round_trip(self, tmp_path):
        _write(tmp_path, _osv())
        ptr = find_fix_pointer(CVE, out_dir=tmp_path)
        assert ptr is not None
        d = ptr.to_dict()
        assert d["cve_id"] == CVE
        assert d["source_run"] == str(tmp_path)


class TestLayering:
    def test_no_cve_diff_import(self):
        """The bridge reads JSON only — core must not import packages."""
        import ast

        import core.orchestration.cvediff_bridge as mod
        tree = ast.parse(Path(mod.__file__).read_text())
        imported: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(a.name for a in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module)
        assert not any(m.split(".")[0] in ("cve_diff", "cve_env", "packages")
                       for m in imported), imported


class TestWriterRoundTrip:
    def test_writer_output_reads_back_identically(self, tmp_path):
        from core.orchestration.cvediff_bridge import (
            write_fix_pointer_artifact,
        )

        original = FixPointer(
            cve_id=CVE,
            repository_url="https://github.com/apache/httpd",
            fix_commit="a" * 40,
            commit_before="b" * 40,
            diff_shape="source",
            consensus_verdict="agree",
            files_changed=3,
        )
        path = write_fix_pointer_artifact(original, tmp_path)
        assert path.name == f"{CVE}.osv.json"
        ptr = find_fix_pointer(CVE, out_dir=tmp_path)
        assert ptr is not None
        for field in ("cve_id", "repository_url", "fix_commit",
                      "commit_before", "diff_shape",
                      "consensus_verdict", "files_changed"):
            assert getattr(ptr, field) == getattr(original, field), field

    def test_writer_refuses_incomplete_pointer(self, tmp_path):
        import pytest as _pytest

        from core.orchestration.cvediff_bridge import (
            write_fix_pointer_artifact,
        )

        with _pytest.raises(ValueError):
            write_fix_pointer_artifact(
                FixPointer(cve_id=CVE, repository_url="",
                           fix_commit="a" * 40, commit_before="b" * 40),
                tmp_path)

    def test_synthesized_marker_present(self, tmp_path):
        import json as _json

        from core.orchestration.cvediff_bridge import (
            write_fix_pointer_artifact,
        )

        path = write_fix_pointer_artifact(
            FixPointer(cve_id=CVE, repository_url="https://github.com/x/y",
                       fix_commit="a" * 40, commit_before="b" * 40,
                       source_run="cvefix-spec"),
            tmp_path)
        data = _json.loads(path.read_text())
        assert data["database_specific"]["synthesized_by"] == "cvefix-spec"

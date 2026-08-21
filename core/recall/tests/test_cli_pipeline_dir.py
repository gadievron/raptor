"""--pipeline-dir selects which detector build runs the profile."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from core.recall.cli import main


def _manifest(tmp_path: Path) -> Path:
    import json

    target = tmp_path / "target"
    target.mkdir()
    m = tmp_path / "m.json"
    m.write_text(json.dumps({
        "schema_version": 1,
        "name": "pipeline-dir-fixture",
        "target": {"repo_url": "https://x/y",
                   "pinned_sha": "a" * 40,
                   "local_path": str(target)},
        "language": "java",
        "profile": "scan",
        "tolerance": {"line_drift": 2, "cwe_family_match": True},
        "expected": [{
            "id": "e1", "file": "src/A.java",
            "line_start": None, "line_end": None,
            "cwe": "CWE-89",
            "provenance": {"kind": "benchmark",
                           "suite": "owasp-benchmark",
                           "case": "BenchmarkTest00001"},
        }],
        "clean_regions": [],
    }), encoding="utf-8")
    return m


class TestPipelineDirFlag:
    def test_rejects_dir_without_raptor_py(self, tmp_path, capsys):
        m = _manifest(tmp_path)
        empty = tmp_path / "not-a-raptor-tree"
        empty.mkdir()
        rc = main(["run", "--manifest", str(m),
                   "--out", str(tmp_path / "out"),
                   "--pipeline-dir", str(empty)])
        assert rc == 2
        assert "does not contain raptor.py" in capsys.readouterr().err

    def test_pipeline_dir_reaches_run_pipeline(self, tmp_path):
        m = _manifest(tmp_path)
        ext = tmp_path / "other-tree"
        ext.mkdir()
        (ext / "raptor.py").write_text("# stub\n", encoding="utf-8")
        seen = {}

        def fake_run_pipeline(manifest, target, repo_root, log_path,
                              timeout_s):
            seen["repo_root"] = repo_root
            out = log_path.parent / "pipeline-run"
            out.mkdir(parents=True, exist_ok=True)
            (out / "x.sarif").write_text(
                '{"runs": []}', encoding="utf-8")
            return out

        with patch("core.recall.cli.verify_pinned_clone",
                   return_value=tmp_path / "target"), \
             patch("core.recall.cli.run_pipeline", fake_run_pipeline), \
             patch("core.recall.cli.collect_findings", return_value=[]):
            rc = main(["run", "--manifest", str(m),
                       "--out", str(tmp_path / "out"),
                       "--pipeline-dir", str(ext)])
        assert rc == 0
        assert seen["repo_root"] == ext.resolve()

    def test_default_is_harness_tree(self, tmp_path):
        m = _manifest(tmp_path)
        seen = {}

        def fake_run_pipeline(manifest, target, repo_root, log_path,
                              timeout_s):
            seen["repo_root"] = repo_root
            out = log_path.parent / "pipeline-run"
            out.mkdir(parents=True, exist_ok=True)
            (out / "x.sarif").write_text('{"runs": []}', encoding="utf-8")
            return out

        with patch("core.recall.cli.verify_pinned_clone",
                   return_value=tmp_path / "target"), \
             patch("core.recall.cli.run_pipeline", fake_run_pipeline), \
             patch("core.recall.cli.collect_findings", return_value=[]):
            rc = main(["run", "--manifest", str(m),
                       "--out", str(tmp_path / "out")])
        assert rc == 0
        assert (seen["repo_root"] / "core" / "recall").is_dir()

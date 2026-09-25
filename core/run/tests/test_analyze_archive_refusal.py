"""analyze refuses archive --repo targets with the canonical hint.

analyze bypasses the run lifecycle (mode_llm_analysis dispatches the
agent directly), so a zip --repo pre-fix reached agent.py unextracted
and the containment gate dropped EVERY SARIF finding as "path
traversal" with exit 0 — a silently-wrong empty analysis. The mode
now refuses archives up front, naming the extracted-tree remedy and
the cached extraction when one exists.
"""

from __future__ import annotations

import sys
import zipfile
from pathlib import Path
from unittest.mock import patch

_RAPTOR_ROOT = Path(__file__).resolve().parents[3]


def _import_raptor():
    if "raptor" not in sys.modules:
        sys.path.insert(0, str(_RAPTOR_ROOT))
    import raptor
    return raptor


def _make_zip(path: Path) -> Path:
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("app/main.py", "print('hi')\n")
    return path


class TestAnalyzeArchiveRefusal:
    def test_zip_repo_refused_without_dispatch(self, tmp_path, capsys):
        raptor = _import_raptor()
        zippath = _make_zip(tmp_path / "app.zip")
        with patch.object(raptor, "_run_script",
                          return_value=0) as run_script:
            rc = raptor.mode_llm_analysis(["--repo", str(zippath)])
        assert rc == 2
        assert not run_script.called
        err = capsys.readouterr().err
        assert "archive" in err
        assert "python3 raptor.py scan --repo" in err

    def test_equals_form_also_refused(self, tmp_path):
        raptor = _import_raptor()
        zippath = _make_zip(tmp_path / "app.zip")
        with patch.object(raptor, "_run_script",
                          return_value=0) as run_script:
            rc = raptor.mode_llm_analysis([f"--repo={zippath}"])
        assert rc == 2
        assert not run_script.called

    def test_cached_extraction_is_named(self, tmp_path, capsys):
        raptor = _import_raptor()
        zippath = _make_zip(tmp_path / "app.zip")
        cached = tmp_path / "out" / "_sources" / "app.zip-abc"
        with patch.object(raptor, "_run_script", return_value=0), \
                patch("packages.describe.cli._find_cached_extraction",
                      return_value=cached):
            rc = raptor.mode_llm_analysis(["--repo", str(zippath)])
        assert rc == 2
        assert str(cached) in capsys.readouterr().err

    def test_directory_repo_dispatches(self, tmp_path):
        raptor = _import_raptor()
        d = tmp_path / "src"
        d.mkdir()
        with patch.object(raptor, "_run_script",
                          return_value=0) as run_script:
            rc = raptor.mode_llm_analysis(["--repo", str(d)])
        assert rc == 0
        assert run_script.called

    def test_non_archive_file_repo_dispatches(self, tmp_path):
        # A plain file --repo is the child's own error to render —
        # the refusal is archive-specific.
        raptor = _import_raptor()
        f = tmp_path / "findings.sarif"
        f.write_text("{}", encoding="utf-8")
        with patch.object(raptor, "_run_script",
                          return_value=0) as run_script:
            raptor.mode_llm_analysis(["--repo", str(f)])
        assert run_script.called

    def test_help_short_circuits_the_refusal(self, tmp_path):
        raptor = _import_raptor()
        zippath = _make_zip(tmp_path / "app.zip")
        with patch.object(raptor, "_run_script",
                          return_value=0) as run_script:
            rc = raptor.mode_llm_analysis(
                ["--help", "--repo", str(zippath)])
        assert rc == 0
        assert run_script.called

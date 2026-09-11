"""Location resolution across finding key shapes.

Two consumers under test:

* ``VulnerabilityContext.read_vulnerable_code`` — SARIF's endLine is
  optional (the parser coerces a missing value to None); a finding
  with only startLine must still show the finding's actual location,
  not the first 100 lines of the file.
* ``_finding_coords`` — the shared (path, function, line) resolver the
  pre-flight chokepoints and the SAGE verdict loop read through. The
  SARIF shape carries ``file`` + ``startLine`` and the inventory
  enrichment stores the function under ``metadata["name"]``.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from packages.llm_analysis.agent import (  # noqa: E402
    VulnerabilityContext,
    _finding_coords,
)


class TestReadVulnerableCodeEndLineFallback:

    @staticmethod
    def _repo_with_big_file(tmp_path: Path) -> Path:
        repo = tmp_path / "repo"
        repo.mkdir()
        lines = [f"// line {i}\n" for i in range(1, 301)]
        lines.append("gets(buf); // line 301\n")
        (repo / "big.c").write_text("".join(lines))
        return repo

    def test_missing_end_line_uses_start_line(self, tmp_path):
        repo = self._repo_with_big_file(tmp_path)
        vuln = VulnerabilityContext(
            {"file": "big.c", "startLine": 301, "endLine": None},
            repo,
        )
        assert vuln.read_vulnerable_code() is True
        assert "gets(buf)" in vuln.full_code
        assert "// line 1\n" not in vuln.full_code
        # Context window is anchored on the finding, not the file head.
        assert "gets(buf)" in vuln.surrounding_context

    def test_both_lines_present_unchanged(self, tmp_path):
        repo = self._repo_with_big_file(tmp_path)
        vuln = VulnerabilityContext(
            {"file": "big.c", "startLine": 2, "endLine": 3},
            repo,
        )
        assert vuln.read_vulnerable_code() is True
        assert vuln.full_code == "// line 2\n// line 3\n"

    def test_no_line_numbers_still_head_fallback(self, tmp_path):
        repo = self._repo_with_big_file(tmp_path)
        vuln = VulnerabilityContext({"file": "big.c"}, repo)
        assert vuln.read_vulnerable_code() is True
        assert vuln.full_code.startswith("// line 1")


class TestFindingCoords:

    def test_sarif_shape_with_inventory_metadata(self):
        # parse_sarif_findings emits file/startLine; the checklist
        # enrichment stores the function under metadata["name"].
        rel, fn, line = _finding_coords({
            "file": "src/auth.c",
            "startLine": 42,
            "endLine": 44,
            "metadata": {"name": "check_pw"},
        })
        assert (rel, fn, line) == ("src/auth.c", "check_pw", 42)

    def test_explicit_keys_win(self):
        rel, fn, line = _finding_coords({
            "file_path": "a.c",
            "file": "b.c",
            "function": "outer",
            "metadata": {"name": "inner"},
            "line": 7,
            "startLine": 9,
        })
        assert (rel, fn, line) == ("a.c", "outer", 7)

    def test_metadata_function_name_beats_metadata_name(self):
        _, fn, _ = _finding_coords({
            "file": "x.c",
            "metadata": {"function_name": "fa", "name": "fb"},
        })
        assert fn == "fa"

    def test_missing_everything_resolves_empty(self):
        assert _finding_coords({}) == ("", "", 0)

    def test_non_numeric_line_is_zero(self):
        assert _finding_coords({"file": "x.c", "line": "abc"})[2] == 0

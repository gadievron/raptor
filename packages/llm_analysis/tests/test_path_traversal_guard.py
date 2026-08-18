"""Test that VulnerabilityContext.get_full_file_path blocks path traversal."""

from pathlib import Path

from packages.llm_analysis.agent import VulnerabilityContext


def _make_vuln(file_path: str, repo_path: Path) -> VulnerabilityContext:
    vuln = VulnerabilityContext.__new__(VulnerabilityContext)
    vuln.file_path = file_path
    vuln.repo_path = repo_path
    return vuln


def test_normal_path(tmp_path: Path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "main.c").write_text("int main(){}")
    vuln = _make_vuln("src/main.c", tmp_path)
    result = vuln.get_full_file_path()
    assert result is not None
    assert result == (tmp_path / "src" / "main.c").resolve()


def test_traversal_blocked(tmp_path: Path):
    vuln = _make_vuln("../../../../etc/shadow", tmp_path)
    result = vuln.get_full_file_path()
    assert result is None


def test_file_uri_traversal_blocked(tmp_path: Path):
    vuln = _make_vuln("file://../../../../etc/passwd", tmp_path)
    result = vuln.get_full_file_path()
    assert result is None


def test_mid_string_file_scheme_not_corrupted(tmp_path: Path):
    """A literal ``file://`` mid-path must survive normalisation.

    The pre-fix substring-``replace`` deleted the marker anywhere in
    the string, silently rewriting ``src/file://x.c`` (the directory
    ``src/file:`` — doubled separators collapse) to ``src/x.c``.
    Only a LEADING scheme may be stripped.
    """
    weird_dir = tmp_path / "src" / "file:"
    weird_dir.mkdir(parents=True)
    (weird_dir / "x.c").write_text("int x;")
    vuln = _make_vuln("src/file://x.c", tmp_path)
    result = vuln.get_full_file_path()
    assert result == (weird_dir / "x.c").resolve()


def test_leading_file_scheme_still_stripped(tmp_path: Path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "main.c").write_text("int main(){}")
    vuln = _make_vuln(f"file://{tmp_path}/src/main.c", tmp_path)
    result = vuln.get_full_file_path()
    assert result == (tmp_path / "src" / "main.c").resolve()


def test_read_code_at_location_mid_string_file_scheme(tmp_path: Path):
    """_read_code_at_location shares the leading-only strip contract."""
    weird_dir = tmp_path / "src" / "file:"
    weird_dir.mkdir(parents=True)
    (weird_dir / "x.c").write_text("line1\nline2\nline3\n")
    vuln = _make_vuln("src/file://x.c", tmp_path)
    snippet = vuln._read_code_at_location("src/file://x.c", 2,
                                          context_lines=1)
    assert "line2" in snippet
    assert "not found" not in snippet.lower()


def test_empty_path():
    vuln = _make_vuln("", Path("/nonexistent"))
    assert vuln.get_full_file_path() is None


def test_none_path():
    vuln = _make_vuln(None, Path("/nonexistent"))
    assert vuln.get_full_file_path() is None

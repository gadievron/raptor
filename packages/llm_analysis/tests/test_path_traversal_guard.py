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


def test_empty_path():
    vuln = _make_vuln("", Path("/nonexistent"))
    assert vuln.get_full_file_path() is None


def test_none_path():
    vuln = _make_vuln(None, Path("/nonexistent"))
    assert vuln.get_full_file_path() is None

"""Tests for language_detector's build-manifest-aware detection (gh #548).

Regression test for the silent-skip bug where ``min_files=3`` dropped
tiny-but-real modules (e.g. a Go API with 2 ``.go`` files + ``go.mod``).
The fix: a matching build manifest counts as evidence on its own,
provided per-language confidence still passes — ``min_confidence``
continues to protect against stray manifests alone.
"""

from pathlib import Path
from unittest.mock import MagicMock

from packages.codeql import language_detector as ld_mod
from packages.codeql.language_detector import LanguageDetector


def _write(repo: Path, rel: str, content: str = "") -> None:
    p = repo / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")


class TestBuildManifestPromotion:
    """A matching build manifest forces detection regardless of file_count."""

    def test_tiny_go_module_with_gomod(self, tmp_path: Path):
        # 1 .go file + go.mod — pre-fix dropped by min_files=3.
        _write(tmp_path, "go.mod", "module tiny\n\ngo 1.21\n")
        _write(tmp_path, "cmd/main.go", "package main\nfunc main() {}\n")

        detected = LanguageDetector(tmp_path).detect_languages()

        assert "go" in detected
        assert detected["go"].file_count == 1
        assert "go.mod" in detected["go"].build_files_found

    def test_tiny_java_module_with_pom(self, tmp_path: Path):
        _write(tmp_path, "pom.xml", "<project/>")
        _write(tmp_path, "src/Main.java", "class Main {}")

        detected = LanguageDetector(tmp_path).detect_languages()

        assert "java" in detected
        assert detected["java"].file_count == 1

    def test_python_pyproject_only(self, tmp_path: Path):
        _write(tmp_path, "pyproject.toml", "[project]\nname='x'\n")
        _write(tmp_path, "x.py", "")

        detected = LanguageDetector(tmp_path).detect_languages()

        assert "python" in detected


class TestStrayManifestRejection:
    """A manifest alone (no matching sources) must NOT trigger detection.

    Closes the inverse failure mode in gh #548 — dev-only Node ingest
    scripts with a stray ``package.json`` would force a JS scan that
    surfaces noise rather than real findings.
    """

    def test_pom_without_java_sources(self, tmp_path: Path):
        _write(tmp_path, "pom.xml", "<project/>")
        _write(tmp_path, "README.md", "")

        detected = LanguageDetector(tmp_path).detect_languages()

        assert "java" not in detected

    def test_package_json_without_js_or_ts(self, tmp_path: Path):
        _write(tmp_path, "package.json", "{}")
        _write(tmp_path, "README.md", "")

        detected = LanguageDetector(tmp_path).detect_languages()

        assert "javascript" not in detected
        assert "typescript" not in detected


class TestFileCountAloneStillWorks:
    """Existing path (file_count >= min_files, no manifest) keeps working."""

    def test_many_python_files_no_manifest(self, tmp_path: Path):
        for i in range(5):
            _write(tmp_path, f"mod_{i}.py", "")

        detected = LanguageDetector(tmp_path).detect_languages()

        assert "python" in detected
        assert detected["python"].file_count == 5

    def test_single_go_file_no_manifest_rejected(self, tmp_path: Path):
        # No build signal AND below file threshold — must NOT detect.
        _write(tmp_path, "scratch.go", "package main\n")

        detected = LanguageDetector(tmp_path).detect_languages()

        assert "go" not in detected


class TestPolyglotMonorepo:
    """The real-world clydehq case: Go API + JS frontend, each module
    too small to clear the old ``min_files=3`` gate. Pre-fix dropped
    both silently; post-fix detects both via their respective build
    manifests, while NOT promoting typescript (no ``.ts`` files even
    though ``package.json`` is in both JS and TS build-file sets).
    """

    def test_go_api_and_js_frontend_both_detected(self, tmp_path: Path):
        # Go API
        _write(tmp_path, "api/go.mod", "module api\n")
        _write(tmp_path, "api/main.go", "package main\n")
        # JS frontend
        _write(tmp_path, "web/package.json", "{}")
        _write(tmp_path, "web/index.js", "// js\n")

        detected = LanguageDetector(tmp_path).detect_languages()

        assert "go" in detected, "Go module must be detected via go.mod"
        assert "javascript" in detected, "JS module must be detected via package.json"
        assert "typescript" not in detected, (
            "typescript shares package.json but has no .ts files; "
            "confidence must keep it out"
        )


class TestSkipLogging:
    """Languages with *some* signal that fail the gates must log at WARN.

    Closes the "operator thinks /agentic succeeded but a language got
    dropped" class of bug — silent skips are the surprise; loud skips
    are operator-actionable. Equally important: languages with *no*
    signal at all stay quiet — otherwise every detection run would
    emit ~10 WARN lines for every absent language.
    """

    def test_low_signal_language_warns(self, tmp_path: Path, monkeypatch):
        # One stray .rb with no Gemfile — below file threshold, no
        # manifest, but file_count > 0 so the WARN branch fires.
        _write(tmp_path, "scratch.rb", "")

        # core.logging's "raptor" wrapper installs a StreamHandler
        # against the *original* sys.stderr at import time and sets
        # propagate=False, so neither caplog nor capsys captures it
        # mid-test. Mock the module-level logger to inspect the call
        # directly — this is the cleanest unit-level assertion.
        mock_logger = MagicMock()
        monkeypatch.setattr(ld_mod, "logger", mock_logger)

        LanguageDetector(tmp_path).detect_languages()

        warning_calls = [c.args[0] for c in mock_logger.warning.call_args_list]
        assert any(
            "Skipping ruby" in msg for msg in warning_calls
        ), f"expected ruby-skip WARN; got warnings: {warning_calls}"

    def test_completely_absent_languages_do_not_warn(self, tmp_path: Path, monkeypatch):
        # Just Python source — no ruby, no go, no java, no js etc.
        # The WARN branch must stay quiet for every absent language;
        # otherwise every clean detection run would emit ~10 spurious
        # "Skipping <lang>" lines for every language NOT in the repo.
        _write(tmp_path, "a.py", "")
        _write(tmp_path, "b.py", "")
        _write(tmp_path, "c.py", "")

        mock_logger = MagicMock()
        monkeypatch.setattr(ld_mod, "logger", mock_logger)

        LanguageDetector(tmp_path).detect_languages()

        spurious = [
            c.args[0] for c in mock_logger.warning.call_args_list
            if "Skipping" in c.args[0]
        ]
        assert spurious == [], (
            f"expected no skip-WARNs for absent languages; "
            f"got noisy warnings: {spurious}"
        )

"""Tests for language_detector's build-manifest-aware detection (gh #548).

Regression test for the silent-skip bug where ``min_files=3`` dropped
tiny-but-real modules (e.g. a Go API with 2 ``.go`` files + ``go.mod``).
The fix: a matching build manifest counts as evidence on its own,
provided per-language confidence still passes — ``min_confidence``
continues to protect against stray manifests alone.

Also covers the structural-indicator mechanics: pruned ignore-dirs
(``node_modules/``, ``dist/``, ``bin/``, ``obj/``) still count as
structural evidence even though their contents never enter the walk,
indicator matching is anchored on path-segment boundaries so lookalike
names (``redist/``, ``sbin/``, ``domain.go``) don't match, every
language pattern declares ``build_file_suffixes``, and declared build
files ending in ``.lock`` (``poetry.lock``, ``yarn.lock``,
``Gemfile.lock``) are not swallowed by IGNORE_SUFFIXES.
"""

from pathlib import Path
from unittest.mock import MagicMock

import pytest

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

        warning_calls = [
            c.args[0] % c.args[1:] if c.args[1:] else c.args[0]
            for c in mock_logger.warning.call_args_list
        ]
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


class TestFloorFallback:
    """detect_languages_floor() is the last-resort tier for repos with
    real source code but no build manifests — multi-language minimal
    repros, fixture trees, vendored reference snapshots. It
    bypasses the confidence gate and admits any language above the
    file-count floor. Caller (agent.py) only invokes it when the two
    confidence-gated tiers have already returned empty.
    """

    def test_multilang_no_manifests_all_admitted(self, tmp_path: Path):
        # mixed-language shape: 4 py + 2 js + 6 go + 4 cpp + non-source
        # files (README, LICENSE, docs, images) that dilute the per-
        # language ratio below the confidence threshold. Zero build
        # files. Every language clears file_count >= 2 under floor.
        for i in range(4):
            _write(tmp_path, f"python/a{i}.py", "")
        for i in range(2):
            _write(tmp_path, f"js/a{i}.js", "")
        for i in range(6):
            _write(tmp_path, f"go/a{i}.go", "")
        for i in range(4):
            _write(tmp_path, f"c/a{i}.c", "")
        # Filler non-source files — README/LICENSE/docs/images bulk.
        # Need enough to push every language's
        # ratio below its min_confidence gate (cap +0.3 on ratio
        # means ratio < 0.2 keeps cpp/python/js below 0.5; go is
        # gated at 0.6 so needs ratio < 0.3). 26 fillers + 16 sources
        # = 42 total; go gets 6/42 = 0.14, well under the gate.
        for i in range(26):
            _write(tmp_path, f"docs/note{i}.md", "")

        det = LanguageDetector(tmp_path)
        # Confidence tiers return empty (no build files, ratios diluted).
        assert det.detect_languages(min_files=3) == {}, (
            "strict tier must reject — no build files, low ratios"
        )
        assert det.detect_languages(min_files=1) == {}, (
            "min_files=1 retry must also reject — confidence still gates"
        )

        floor = det.detect_languages_floor(floor=2)
        assert set(floor.keys()) >= {"python", "javascript", "go", "cpp"}, (
            f"floor tier must admit all four; got {sorted(floor.keys())}"
        )

    def test_single_file_below_floor_rejected(self, tmp_path: Path):
        # One .go file is below floor=2 — must NOT be admitted even
        # in floor tier, otherwise true-empty repos or single-stray-
        # file trees would silently trigger a scan.
        _write(tmp_path, "scratch.go", "package main\n")

        floor = LanguageDetector(tmp_path).detect_languages_floor(floor=2)
        assert "go" not in floor

    def test_floor_logs_per_language_warning(self, tmp_path: Path, monkeypatch):
        # Operator must see a loud WARNING per admitted language so
        # they know the scan is running on low-confidence detection.
        # Silent low-confidence admission would defeat the whole point
        # of having a confidence gate in the strict tiers.
        for i in range(3):
            _write(tmp_path, f"a{i}.py", "")

        mock_logger = MagicMock()
        monkeypatch.setattr(ld_mod, "logger", mock_logger)

        LanguageDetector(tmp_path).detect_languages_floor(floor=2)

        warns = [
            c.args[0] % c.args[1:] if c.args[1:] else c.args[0]
            for c in mock_logger.warning.call_args_list
        ]
        assert any(
            "Floor-tier include python" in w for w in warns
        ), f"expected loud floor-include WARN for python; got: {warns}"


class TestPrunedDirIndicators:
    """Ignored dirs still count as structural evidence.

    Indicators naming IGNORE_DIRS members were dead for their intended
    case — the walk pruned those dirs before any file under them could
    be yielded. Pruned-dir presence now registers the indicator while
    the contents stay unscanned.
    """

    def test_node_modules_presence_matches_indicator(self, tmp_path: Path):
        _write(tmp_path, "index.js", "// js\n")
        _write(tmp_path, "app.js", "// js\n")
        _write(tmp_path, "node_modules/lodash/lodash.js", "// vendored\n")

        stats = LanguageDetector(tmp_path)._scan_repository()

        assert "node_modules/" in stats["indicators"], (
            "a real node_modules/ dir must register the indicator "
            "even though its contents are pruned from the walk"
        )
        # Pruned contents must still NOT be scanned.
        assert stats["scanned_files"] == 2

    def test_dist_bin_obj_presence_matches_indicators(self, tmp_path: Path):
        _write(tmp_path, "Program.cs", "class P {}\n")
        _write(tmp_path, "bin/Debug/app.dll", "")
        _write(tmp_path, "obj/project.assets.json", "{}")
        _write(tmp_path, "dist/bundle.out", "")

        stats = LanguageDetector(tmp_path)._scan_repository()

        assert {"bin/", "obj/", "dist/"} <= stats["indicators"]

    def test_nested_pruned_dir_matches(self, tmp_path: Path):
        _write(tmp_path, "web/index.js", "// js\n")
        _write(tmp_path, "web/node_modules/pkg/a.js", "")

        stats = LanguageDetector(tmp_path)._scan_repository()

        assert "node_modules/" in stats["indicators"]

    def test_indicator_boost_reaches_confidence(self, tmp_path: Path):
        # JS repo whose only structural evidence besides sources is
        # node_modules/ + dist/ — with dead indicators this shape
        # scored 0.3 base + 0.3 ratio-cap = 0.6; the boost itself is
        # the regression target: indicators_found must carry the
        # pruned dirs.
        _write(tmp_path, "a.js", "")
        _write(tmp_path, "b.js", "")
        _write(tmp_path, "c.js", "")
        _write(tmp_path, "node_modules/x/y.js", "")
        _write(tmp_path, "dist/a.out.js", "")

        detected = LanguageDetector(tmp_path).detect_languages()

        assert "javascript" in detected
        assert {"node_modules/", "dist/"} <= set(detected["javascript"].indicators_found)


class TestSegmentBoundaryMatching:
    """Indicator matching is anchored on path-segment boundaries;
    plain substring lookalikes no longer match."""

    def test_redist_does_not_match_dist(self, tmp_path: Path):
        _write(tmp_path, "redist/readme.txt", "")
        _write(tmp_path, "a.py", "")

        stats = LanguageDetector(tmp_path)._scan_repository()

        assert "dist/" not in stats["indicators"]

    def test_sbin_does_not_match_bin(self, tmp_path: Path):
        _write(tmp_path, "sbin/tool.sh", "")

        stats = LanguageDetector(tmp_path)._scan_repository()

        assert "bin/" not in stats["indicators"]

    def test_domain_go_does_not_match_main_go(self, tmp_path: Path):
        _write(tmp_path, "pkg2/domain.go", "package pkg2\n")

        stats = LanguageDetector(tmp_path)._scan_repository()

        assert "main.go" not in stats["indicators"]

    def test_mysrc_does_not_match_src(self, tmp_path: Path):
        _write(tmp_path, "mysrc/a.c", "")

        stats = LanguageDetector(tmp_path)._scan_repository()

        assert "src/" not in stats["indicators"]

    def test_real_segments_still_match(self, tmp_path: Path):
        _write(tmp_path, "app/src/main/java/Main.java", "class Main {}\n")
        _write(tmp_path, "cmd/main.go", "package main\n")
        _write(tmp_path, "pkg/__init__.py", "")

        stats = LanguageDetector(tmp_path)._scan_repository()

        assert {"src/main/java/", "src/", "main.go", "cmd/", "__init__.py"} <= stats["indicators"]

    def test_root_level_file_indicator_matches(self, tmp_path: Path):
        _write(tmp_path, "main.go", "package main\n")

        stats = LanguageDetector(tmp_path)._scan_repository()

        assert "main.go" in stats["indicators"]


class TestBuildFileSuffixSchemaUniformity:
    """Every language pattern declares build_file_suffixes."""

    def test_all_languages_declare_build_file_suffixes(self):
        missing = [
            lang for lang, patterns in LanguageDetector.LANGUAGE_PATTERNS.items()
            if "build_file_suffixes" not in patterns
        ]
        assert missing == [], f"patterns missing build_file_suffixes: {missing}"

    def test_suffix_values_are_tuples(self):
        # endswith() requires str or tuple; a stray list would raise at
        # scan time, so pin the type here.
        for lang, patterns in LanguageDetector.LANGUAGE_PATTERNS.items():
            assert isinstance(patterns["build_file_suffixes"], tuple), lang

    def test_csproj_suffix_still_detected(self, tmp_path: Path):
        _write(tmp_path, "App.csproj", "<Project/>")
        _write(tmp_path, "Program.cs", "class P {}\n")

        detected = LanguageDetector(tmp_path).detect_languages()

        assert "csharp" in detected
        assert "App.csproj" in detected["csharp"].build_files_found


class TestLockBuildFilesNotSwallowed:
    """Declared *.lock build manifests survive the IGNORE_SUFFIXES
    filter; undeclared lock files stay ignored."""

    def test_poetry_lock_counts_as_build_evidence(self, tmp_path: Path):
        _write(tmp_path, "poetry.lock", "[[package]]\n")
        _write(tmp_path, "app.py", "")

        detected = LanguageDetector(tmp_path).detect_languages()

        assert "python" in detected
        assert "poetry.lock" in detected["python"].build_files_found

    def test_yarn_lock_counts_as_build_evidence(self, tmp_path: Path):
        _write(tmp_path, "yarn.lock", "")
        _write(tmp_path, "index.js", "")

        detected = LanguageDetector(tmp_path).detect_languages()

        assert "javascript" in detected
        assert "yarn.lock" in detected["javascript"].build_files_found

    def test_gemfile_lock_counts_as_build_evidence(self, tmp_path: Path):
        _write(tmp_path, "Gemfile.lock", "")
        _write(tmp_path, "app.rb", "")

        stats = LanguageDetector(tmp_path)._scan_repository()

        assert "Gemfile.lock" in stats["build_files"]

    def test_undeclared_lock_files_still_ignored(self, tmp_path: Path):
        _write(tmp_path, "flake.lock", "{}")
        _write(tmp_path, "a.py", "")

        stats = LanguageDetector(tmp_path)._scan_repository()

        assert "flake.lock" not in stats["build_files"]
        assert stats["scanned_files"] == 1


class TestManifestOnlyCeiling:
    """With ZERO source files, confidence is capped at ~0.2 (build-file
    boost only — no base, no indicator boost, no ratio). A crafted
    manifests-plus-indicators repo must stay below every language's
    ``min_confidence`` so hostile zero-source repos cannot force a
    detection."""

    def test_manifests_plus_indicators_zero_source_stay_capped(self, tmp_path: Path):
        # Two Java build files (+0.4 if ungated) + both structural
        # indicators (+0.3 if ungated) but zero .java sources —
        # ungated boosts scored ~0.7 and cleared min_confidence 0.5.
        _write(tmp_path, "pom.xml", "<project/>")
        _write(tmp_path, "build.gradle", "")
        _write(tmp_path, "src/main/java/keep.txt", "")
        _write(tmp_path, "src/test/java/keep.txt", "")

        detector = LanguageDetector(tmp_path)
        stats = detector._scan_repository()
        info = detector._analyze_language(
            "java", LanguageDetector.LANGUAGE_PATTERNS["java"], stats,
        )

        assert info.file_count == 0
        assert info.confidence <= 0.2
        assert "java" not in detector.detect_languages()

    def test_single_manifest_zero_source_scores_point_two(self, tmp_path: Path):
        _write(tmp_path, "go.mod", "module x\n")
        _write(tmp_path, "README.md", "")

        detector = LanguageDetector(tmp_path)
        stats = detector._scan_repository()
        info = detector._analyze_language(
            "go", LanguageDetector.LANGUAGE_PATTERNS["go"], stats,
        )

        assert info.file_count == 0
        assert info.confidence == pytest.approx(0.2)
        assert "go" not in detector.detect_languages()

    def test_ceiling_stays_below_every_min_confidence(self):
        # The manifest-only ceiling (0.2) must sit below the smallest
        # per-language threshold, otherwise the gate is decorative.
        smallest = min(
            p["min_confidence"]
            for p in LanguageDetector.LANGUAGE_PATTERNS.values()
        )
        assert 0.2 < smallest

    def test_source_present_keeps_indicator_and_build_boosts(self, tmp_path: Path):
        # Regression guard: the ceiling only applies at file_count==0;
        # a real repo keeps base + build + indicator + ratio boosts.
        _write(tmp_path, "go.mod", "module x\n")
        _write(tmp_path, "main.go", "package main\n")
        _write(tmp_path, "cmd/run.go", "package main\n")

        detected = LanguageDetector(tmp_path).detect_languages()

        assert "go" in detected
        assert detected["go"].confidence >= 0.6


class TestRustDetection:
    """Rust routes to CodeQL only when the CLI ships the extractor."""

    def _rust_repo(self, tmp_path: Path) -> Path:
        _write(tmp_path, "Cargo.toml", "[package]\nname = \"x\"\n")
        _write(tmp_path, "src/main.rs", "fn main() {}\n")
        _write(tmp_path, "src/lib.rs", "pub fn f() {}\n")
        _write(tmp_path, "src/util.rs", "pub fn g() {}\n")
        return tmp_path

    def _reset_probe_cache(self):
        LanguageDetector._extractor_langs = None

    def test_rust_detected(self, tmp_path: Path):
        detected = LanguageDetector(self._rust_repo(tmp_path)).detect_languages()
        assert "rust" in detected
        assert "Cargo.toml" in detected["rust"].build_files_found

    def test_rust_kept_when_extractor_present(self, tmp_path: Path, monkeypatch):
        self._reset_probe_cache()
        monkeypatch.setattr(
            LanguageDetector, "_extractor_langs", frozenset({"rust", "cpp"}),
        )
        det = LanguageDetector(self._rust_repo(tmp_path))
        supported = det.filter_codeql_supported(det.detect_languages())
        assert "rust" in supported

    def test_rust_dropped_when_extractor_absent(self, tmp_path: Path, monkeypatch):
        self._reset_probe_cache()
        monkeypatch.setattr(
            LanguageDetector, "_extractor_langs", frozenset({"cpp"}),
        )
        mock_logger = MagicMock()
        monkeypatch.setattr(ld_mod, "logger", mock_logger)
        det = LanguageDetector(self._rust_repo(tmp_path))
        supported = det.filter_codeql_supported(det.detect_languages())
        assert "rust" not in supported
        warns = [str(c.args[0]) for c in mock_logger.warning.call_args_list]
        assert any("extractor" in w for w in warns)

    def test_probe_failure_reads_as_unavailable(self, tmp_path: Path, monkeypatch):
        # A failed probe caches frozenset() — probed languages drop,
        # statically-supported languages are unaffected.
        self._reset_probe_cache()
        import shutil as _shutil
        monkeypatch.setattr(_shutil, "which", lambda _name: None)
        _write(tmp_path, "go.mod", "module m\n")
        _write(tmp_path, "a.go", "package m\n")
        det = LanguageDetector(self._rust_repo(tmp_path))
        try:
            supported = det.filter_codeql_supported(det.detect_languages())
            assert "rust" not in supported
            assert "go" in supported
        finally:
            self._reset_probe_cache()

    def test_non_probed_languages_bypass_probe(self, tmp_path: Path, monkeypatch):
        # No probe should even run for a repo with no probed language.
        self._reset_probe_cache()
        called = []
        monkeypatch.setattr(
            LanguageDetector, "_extractor_available",
            lambda self, lang: called.append(lang) or True,
        )
        _write(tmp_path, "go.mod", "module m\n")
        _write(tmp_path, "a.go", "package m\n")
        _write(tmp_path, "b.go", "package m\n")
        det = LanguageDetector(tmp_path)
        det.filter_codeql_supported(det.detect_languages())
        assert called == []


class TestExtractorProbeCliResolution:
    """The probe must consult the SAME binary the run will spawn:
    CODEQL_CLI first (documented operator override), then PATH — a
    bare PATH lookup dropped rust on multi-install hosts where only
    the CODEQL_CLI bundle ships the extractor."""

    def _reset_probe_cache(self):
        LanguageDetector._extractor_langs = None

    def _stub_cli(self, tmp_path: Path) -> Path:
        stub = tmp_path / "codeql-stub"
        stub.write_text(
            "#!/bin/sh\n"
            'if [ "$1" = "resolve" ] && [ "$2" = "languages" ]; then\n'
            '  echo "rust (/opt/bundle/rust)"\n'
            '  echo "cpp (/opt/bundle/cpp)"\n'
            "fi\n"
        )
        stub.chmod(0o755)
        return stub

    def test_codeql_cli_env_binary_consulted(self, tmp_path: Path, monkeypatch):
        self._reset_probe_cache()
        try:
            import shutil as _shutil
            # No codeql on PATH — only the operator override exists.
            monkeypatch.setattr(_shutil, "which", lambda _name: None)
            monkeypatch.setenv("CODEQL_CLI", str(self._stub_cli(tmp_path)))
            det = LanguageDetector(tmp_path)
            assert det._extractor_available("rust") is True
            assert det._extractor_available("go") is False
        finally:
            self._reset_probe_cache()

    def test_without_override_path_miss_reads_unavailable(
        self, tmp_path: Path, monkeypatch,
    ):
        # Two-direction: no CODEQL_CLI and no PATH binary -> probe
        # degrades to unavailable, never crashes.
        self._reset_probe_cache()
        try:
            import shutil as _shutil
            monkeypatch.setattr(_shutil, "which", lambda _name: None)
            monkeypatch.delenv("CODEQL_CLI", raising=False)
            det = LanguageDetector(tmp_path)
            assert det._extractor_available("rust") is False
        finally:
            self._reset_probe_cache()


class TestHumanBranchScrub:
    def test_human_branch_escapes_hostile_build_file_names(
            self, tmp_path: Path, capsys, monkeypatch):
        """The --json lane was given ensure_ascii for exactly these
        scanned-repo names; the human branch prints the same
        build_files_found field and must escape it too (suffix-match
        admission keeps the full hostile basename on .csproj hits)."""
        from packages.codeql.language_detector import main
        _write(tmp_path, "evil\x1b]0;pwned\x07.csproj", "<Project/>\n")
        _write(tmp_path, "a.cs", "class A {}\n")
        _write(tmp_path, "b.cs", "class B {}\n")
        _write(tmp_path, "c.cs", "class C {}\n")
        monkeypatch.setattr(
            "sys.argv",
            ["language_detector", "--repo", str(tmp_path)])
        main()
        out = capsys.readouterr().out
        assert "Build files:" in out
        for raw in ("\x1b", "\x07"):
            assert raw not in out


class TestUnsupportedPrimaryBanner:
    """A repo dominated by a language CodeQL cannot extract must say
    so: the per-language Detected/Skipping lines only ever mention
    extractor languages, so a PHP or Perl codebase read as
    clean-by-silence otherwise."""

    def _warnings(self, mock_logger):
        return [
            c.args[0] % tuple(c.args[1:]) if c.args[1:] else c.args[0]
            for c in mock_logger.warning.call_args_list
        ]

    def test_php_majority_warns_and_names_covered_sliver(
            self, tmp_path: Path, monkeypatch):
        for i in range(12):
            _write(tmp_path, f"src/page{i}.php", "<?php\n")
        for i in range(3):
            _write(tmp_path, f"native/helper{i}.c", "int f(void){}\n")
        mock_logger = MagicMock()
        monkeypatch.setattr(ld_mod, "logger", mock_logger)

        LanguageDetector(tmp_path).detect_languages()

        msgs = self._warnings(mock_logger)
        banner = [m for m in msgs if "no extractor" in m]
        assert banner, f"expected unsupported-primary banner; got {msgs}"
        assert "php (12 files)" in banner[0]
        assert "cpp (3 files)" in banner[0]

    def test_detected_majority_stays_quiet(
            self, tmp_path: Path, monkeypatch):
        for i in range(5):
            _write(tmp_path, f"src/mod{i}.py", "x = 1\n")
        _write(tmp_path, "tools/one.php", "<?php\n")
        mock_logger = MagicMock()
        monkeypatch.setattr(ld_mod, "logger", mock_logger)

        LanguageDetector(tmp_path).detect_languages()

        msgs = self._warnings(mock_logger)
        assert not any("no extractor" in m for m in msgs), msgs

    def test_no_unsupported_files_stays_quiet(
            self, tmp_path: Path, monkeypatch):
        for i in range(4):
            _write(tmp_path, f"src/mod{i}.py", "x = 1\n")
        mock_logger = MagicMock()
        monkeypatch.setattr(ld_mod, "logger", mock_logger)

        LanguageDetector(tmp_path).detect_languages()

        msgs = self._warnings(mock_logger)
        assert not any("no extractor" in m for m in msgs), msgs


class TestScanReuseAcrossTiers:
    """A walk shared via ``scan=`` must not re-walk or re-announce; an
    independent call (separate run) must keep doing both — repo state
    can change between runs, so nothing may be memoised past the
    caller's own dict."""

    def _sparse_php_repo(self, tmp_path: Path) -> Path:
        # Unsupported-primary shape: no extractor language passes any
        # tier, so a caller runs all three tiers back to back.
        for i in range(12):
            _write(tmp_path, f"src/page{i}.php", "<?php\n")
        return tmp_path

    def _instrument(self, detector, monkeypatch):
        walks = []
        original = detector._scan_repository

        def counting():
            walks.append(1)
            return original()

        monkeypatch.setattr(detector, "_scan_repository", counting)
        mock_logger = MagicMock()
        monkeypatch.setattr(ld_mod, "logger", mock_logger)
        return walks, mock_logger

    def _banners(self, mock_logger):
        msgs = [
            c.args[0] % tuple(c.args[1:]) if c.args[1:] else c.args[0]
            for c in mock_logger.warning.call_args_list
        ]
        return [m for m in msgs if "no extractor" in m]

    def test_shared_scan_walks_once_and_announces_once(
            self, tmp_path: Path, monkeypatch):
        detector = LanguageDetector(self._sparse_php_repo(tmp_path))
        walks, mock_logger = self._instrument(detector, monkeypatch)

        scan = detector.scan_repository()
        assert not detector.detect_languages(min_files=3, scan=scan)
        assert not detector.detect_languages(min_files=1, scan=scan)
        assert not detector.detect_languages_floor(floor=2, scan=scan)

        assert len(walks) == 1, "shared scan must not re-walk the repo"
        assert len(self._banners(mock_logger)) == 1, (
            "unsupported-primary banner must announce once per walk"
        )

    def test_independent_calls_each_walk_and_announce(
            self, tmp_path: Path, monkeypatch):
        detector = LanguageDetector(self._sparse_php_repo(tmp_path))
        walks, mock_logger = self._instrument(detector, monkeypatch)

        assert not detector.detect_languages(min_files=3)
        assert not detector.detect_languages(min_files=3)

        assert len(walks) == 2, (
            "independent runs must re-walk — repo state can change"
        )
        assert len(self._banners(mock_logger)) == 2

class TestSuffixCaseFolding:
    """Extension counting is case-folded: uppercase spellings
    (.C/.CPP/.PY — legacy C++ and Windows-authored trees) must be
    visible to detection; the membership tests against
    LANGUAGE_PATTERNS are case-sensitive on lowercase keys."""

    def test_pure_uppercase_c_repo_detects_cpp(self, tmp_path: Path):
        for i in range(3):
            _write(tmp_path, f"src/mod{i}.C", "int f() { return 0; }\n")
        detected = LanguageDetector(tmp_path).detect_languages(min_files=1)
        assert "cpp" in detected

    def test_uppercase_c_repo_clears_floor_tier(self, tmp_path: Path):
        for i in range(3):
            _write(tmp_path, f"src/mod{i}.C", "int f() { return 0; }\n")
        floor = LanguageDetector(tmp_path).detect_languages_floor(floor=2)
        assert "cpp" in floor

    def test_mixed_repo_keeps_the_cpp_bulk(self, tmp_path: Path):
        """Worst pre-fix case: the CodeQL lane silently omitted the
        C++ bulk of a mixed repo AND no unsupported-primary warning
        could fire — coverage read clean."""
        for i in range(3):
            _write(tmp_path, f"native/mod{i}.C", "int f() { return 0; }\n")
        for i in range(3):
            _write(tmp_path, f"py/mod{i}.py", "x = 1\n")
        detected = LanguageDetector(tmp_path).detect_languages(min_files=1)
        assert "python" in detected
        assert "cpp" in detected


class TestModernTsJsSpellings:
    def test_mts_cts_count_as_typescript(self, tmp_path: Path):
        _write(tmp_path, "package.json", "{}")
        _write(tmp_path, "tsconfig.json", "{}")
        for i in range(2):
            _write(tmp_path, f"src/m{i}.mts", "export const x = 1;\n")
        _write(tmp_path, "src/c.cts", "export const y = 2;\n")
        detected = LanguageDetector(tmp_path).detect_languages(min_files=1)
        assert "typescript" in detected

    def test_vue_counts_as_javascript(self, tmp_path: Path):
        _write(tmp_path, "package.json", "{}")
        for i in range(3):
            _write(tmp_path, f"src/App{i}.vue", "<template></template>\n")
        detected = LanguageDetector(tmp_path).detect_languages(min_files=1)
        assert "javascript" in detected


class TestExtractorProbeFailureNotCached:
    """A transient `codeql resolve languages` failure must not lock
    in an empty extractor set for the process lifetime — pre-fix a
    single failed probe silently dropped rust for the whole run."""

    def _reset(self):
        LanguageDetector._extractor_langs = None

    def _cli(self, tmp_path: Path, ok: bool) -> Path:
        stub = tmp_path / ("codeql-ok" if ok else "codeql-bad")
        if ok:
            stub.write_text(
                "#!/bin/sh\necho 'rust (/opt/bundle/rust)'\n",
            )
        else:
            stub.write_text("#!/bin/sh\nexit 1\n")
        stub.chmod(0o755)
        return stub

    def test_failed_probe_reprobes_next_call(
        self, tmp_path: Path, monkeypatch,
    ):
        self._reset()
        try:
            det = LanguageDetector(tmp_path)
            monkeypatch.setenv("CODEQL_CLI", str(self._cli(tmp_path, ok=False)))
            # Failed probe: conservative answer, nothing cached.
            assert det._extractor_available("rust") is False
            assert LanguageDetector._extractor_langs is None
            # Transient failure cleared — the next call recovers.
            monkeypatch.setenv("CODEQL_CLI", str(self._cli(tmp_path, ok=True)))
            assert det._extractor_available("rust") is True
            assert LanguageDetector._extractor_langs == frozenset({"rust"})
        finally:
            self._reset()

    def test_successful_probe_still_cached(
        self, tmp_path: Path, monkeypatch,
    ):
        self._reset()
        try:
            good = self._cli(tmp_path, ok=True)
            monkeypatch.setenv("CODEQL_CLI", str(good))
            det = LanguageDetector(tmp_path)
            assert det._extractor_available("rust") is True
            # Cached — swapping the CLI away no longer changes the answer.
            monkeypatch.setenv("CODEQL_CLI", str(self._cli(tmp_path, ok=False)))
            assert det._extractor_available("rust") is True
        finally:
            self._reset()

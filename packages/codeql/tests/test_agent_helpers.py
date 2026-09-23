"""Agent workflow helpers: shared-extractor collapse + success rule."""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

# packages/codeql/tests/ -> repo root
sys.path.insert(0, str(Path(__file__).parents[3]))

from packages.codeql.agent import (
    _collapse_shared_extractor_languages,
    _workflow_success,
)
from packages.codeql.language_detector import LanguageInfo


def _info(lang: str, files: int, exts: set[str],
          confidence: float = 0.8) -> LanguageInfo:
    return LanguageInfo(
        language=lang,
        confidence=confidence,
        file_count=files,
        extensions_found=set(exts),
        build_files_found=[],
        indicators_found=[],
    )


class TestSharedExtractorCollapse:
    """javascript + typescript resolve to one extractor and one query
    pack — building both duplicated every finding on mixed repos."""

    def test_js_plus_ts_collapse_to_one_javascript_build(self):
        detected = {
            "javascript": _info("javascript", 10, {".js"}, 0.7),
            "typescript": _info("typescript", 20, {".ts"}, 0.9),
        }
        _collapse_shared_extractor_languages(detected)
        assert set(detected) == {"javascript"}
        js = detected["javascript"]
        # Evidence folds — reporting still reflects both.
        assert js.file_count == 30
        assert js.extensions_found == {".js", ".ts"}
        assert js.confidence == 0.9

    def test_sole_typescript_untouched(self):
        detected = {"typescript": _info("typescript", 5, {".ts"})}
        _collapse_shared_extractor_languages(detected)
        assert set(detected) == {"typescript"}

    def test_unrelated_languages_untouched(self):
        detected = {
            "python": _info("python", 3, {".py"}),
            "cpp": _info("cpp", 4, {".c"}),
        }
        _collapse_shared_extractor_languages(detected)
        assert set(detected) == {"python", "cpp"}


class TestWorkflowSuccess:
    """Success requires at least one language's ANALYSIS to succeed —
    additive lanes (IRIS, curated packs, learned models) contribute
    SARIFs but must not turn a run whose every analyze failed into
    exit 0."""

    def test_all_analyses_failed_is_failure(self):
        results = {"python": SimpleNamespace(success=False)}
        assert _workflow_success(results) is False

    def test_one_success_is_success(self):
        results = {
            "python": SimpleNamespace(success=False),
            "cpp": SimpleNamespace(success=True),
        }
        assert _workflow_success(results) is True

    def test_no_analyses_is_failure(self):
        assert _workflow_success({}) is False

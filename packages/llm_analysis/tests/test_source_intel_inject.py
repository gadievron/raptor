"""Tests for ``packages.llm_analysis.source_intel_inject``.

Phase D PR1: source_intel structural evidence flows into Stage D
LLM prompts for memory-corruption findings only.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from core.security.prompt_envelope import UntrustedBlock
from packages.llm_analysis.source_intel_inject import (
    clear_cache_for_tests,
    evidence_blocks_for_finding,
    prepare_source_intel,
)
from packages.source_intel.analyze import (
    AttributeEvidence,
    KIND_NORETURN,
    SourceIntelResult,
)


@pytest.fixture(autouse=True)
def _reset():
    clear_cache_for_tests()
    yield
    clear_cache_for_tests()


def _finding(**kw):
    base = {
        "rule_id": "cpp/null-dereference",
        "file_path": "src/a.c",
        "start_line": 10,
        "end_line": 10,
        "repo_path": "src",
        "function": "panic",
    }
    base.update(kw)
    return base


def _result_with_evidence():
    return SourceIntelResult(
        target="src",
        attributes=(
            AttributeEvidence(
                kind=KIND_NORETURN,
                function_name="panic",
                location=("src/a.c", 10),
                match_source="literal",
                raw_match="noreturn",
            ),
        ),
    )


# ---- prepare_source_intel ---------------------------------------------


class TestPrepare:
    def test_caches_result_for_target(self, tmp_path):
        result = _result_with_evidence()
        with patch(
            "packages.llm_analysis.source_intel_inject._analyze",
            return_value=result,
        ):
            prepare_source_intel(tmp_path)
        from packages.llm_analysis.source_intel_inject import (
            _SI_RESULT_CACHE,
        )
        # Cache values are (signature, result) tuples — index [1]
        # is the stored result. Signature is content-derived; the
        # exact value isn't relevant to this test, only that it
        # was stored alongside the result.
        assert str(tmp_path.resolve()) in _SI_RESULT_CACHE
        assert _SI_RESULT_CACHE[str(tmp_path.resolve())][1] is result

    def test_idempotent_skips_second_call(self, tmp_path):
        result = _result_with_evidence()
        calls = []

        def _spy(target):
            calls.append(target)
            return result

        with patch(
            "packages.llm_analysis.source_intel_inject._analyze",
            side_effect=_spy,
        ):
            prepare_source_intel(tmp_path)
            prepare_source_intel(tmp_path)  # second call no-op
        assert len(calls) == 1

    def test_swallows_exceptions_caches_failure(self, tmp_path):
        with patch(
            "packages.llm_analysis.source_intel_inject._analyze",
            side_effect=RuntimeError("boom"),
        ):
            prepare_source_intel(tmp_path)
        from packages.llm_analysis.source_intel_inject import (
            _SI_RESULT_CACHE,
        )
        # Cache stores (signature, None) on failure — the entry
        # exists (so we don't retry this target this process) but
        # its result-slot is None.
        entry = _SI_RESULT_CACHE.get(str(tmp_path.resolve()))
        assert entry is not None
        assert entry[1] is None

    def test_handles_unresolvable_path(self):
        """A bogus path that can't be resolved must not raise."""
        prepare_source_intel(Path("/not/a/real/path/probably"))
        # No raise = pass

    def test_module_level_analyze_none_skips_gracefully(self, tmp_path):
        """When ``packages.source_intel`` isn't importable
        (minimal install), ``_analyze`` is None and prepare caches
        ``None`` without calling anything."""
        with patch(
            "packages.llm_analysis.source_intel_inject._analyze",
            None,
        ):
            prepare_source_intel(tmp_path)
        from packages.llm_analysis.source_intel_inject import (
            _SI_RESULT_CACHE,
        )
        # Cache stores (signature, None) — entry exists, result-slot None.
        entry = _SI_RESULT_CACHE.get(str(tmp_path.resolve()))
        assert entry is not None
        assert entry[1] is None


# ---- evidence_blocks_for_finding --------------------------------------


class TestEvidenceBlocks:
    def test_returns_empty_when_no_repo_path(self):
        f = _finding(repo_path=None)
        assert evidence_blocks_for_finding(f) == ()

    def test_returns_empty_when_irrelevant_rule_id(self, tmp_path):
        result = _result_with_evidence()
        with patch(
            "packages.llm_analysis.source_intel_inject._analyze",
            return_value=result,
        ):
            prepare_source_intel(tmp_path)
        f = _finding(rule_id="py/sql-injection", repo_path=str(tmp_path))
        assert evidence_blocks_for_finding(f) == ()

    def test_returns_empty_when_cache_miss(self, tmp_path):
        f = _finding(repo_path=str(tmp_path))
        # no prepare → cache miss
        assert evidence_blocks_for_finding(f) == ()

    def test_returns_block_for_memory_corruption_finding(self, tmp_path):
        result = _result_with_evidence()
        with patch(
            "packages.llm_analysis.source_intel_inject._analyze",
            return_value=result,
        ):
            prepare_source_intel(tmp_path)
        f = _finding(repo_path=str(tmp_path), function="panic")
        with patch(
            "packages.llm_analysis.source_intel_inject._extract_flags",
            return_value=None,
        ):
            blocks = evidence_blocks_for_finding(f)
        assert len(blocks) == 1
        assert isinstance(blocks[0], UntrustedBlock)
        assert blocks[0].kind == "source-intel-evidence"
        assert blocks[0].origin == "cocci-structural-evidence"
        assert "panic" in blocks[0].content

    def test_returns_empty_when_skipped_result_no_observations(self, tmp_path):
        skipped = SourceIntelResult(
            target=str(tmp_path), skipped_reason="spatch_not_available",
        )
        with patch(
            "packages.llm_analysis.source_intel_inject._analyze",
            return_value=skipped,
        ):
            prepare_source_intel(tmp_path)
        f = _finding(repo_path=str(tmp_path))
        assert evidence_blocks_for_finding(f) == ()

    def test_function_name_from_metadata_dict(self, tmp_path):
        """``finding["metadata"]["name"]`` takes precedence over
        ``finding["function"]`` (matches the prompt-builder's own
        precedence in ``build_analysis_prompt_bundle_from_finding``)."""
        result = _result_with_evidence()
        with patch(
            "packages.llm_analysis.source_intel_inject._analyze",
            return_value=result,
        ):
            prepare_source_intel(tmp_path)
        f = _finding(
            repo_path=str(tmp_path),
            metadata={"name": "panic"},
            function="should_be_ignored",
        )
        with patch(
            "packages.llm_analysis.source_intel_inject._extract_flags",
            return_value=None,
        ):
            blocks = evidence_blocks_for_finding(f)
        assert len(blocks) == 1
        # Evidence was filtered to fn=panic so the block has the
        # noreturn observation.
        assert "panic" in blocks[0].content

    def test_cwe_fallback_gate_fires_for_external_scanner(self, tmp_path):
        """External scanners use rule_id prefixes that don't match
        _DEFAULT_RULE_PREFIXES (CodeQL-centric).  The CWE-based
        fallback gate should still allow source-intel evidence when
        the finding's cwe_id is in the memory-corruption set."""
        result = _result_with_evidence()
        with patch(
            "packages.llm_analysis.source_intel_inject._analyze",
            return_value=result,
        ):
            prepare_source_intel(tmp_path)
        f = _finding(
            rule_id="coverity-CID-12345",
            cwe_id="CWE-476",
            repo_path=str(tmp_path),
            function="panic",
        )
        with patch(
            "packages.llm_analysis.source_intel_inject._extract_flags",
            return_value=None,
        ):
            blocks = evidence_blocks_for_finding(f)
        assert len(blocks) == 1
        assert blocks[0].kind == "source-intel-evidence"

    def test_cwe_fallback_gate_rejects_non_memory_corruption(self, tmp_path):
        """CWE fallback gate should reject findings whose CWE is
        outside the memory-corruption set."""
        result = _result_with_evidence()
        with patch(
            "packages.llm_analysis.source_intel_inject._analyze",
            return_value=result,
        ):
            prepare_source_intel(tmp_path)
        f = _finding(
            rule_id="coverity-CID-99999",
            cwe_id="CWE-89",
            repo_path=str(tmp_path),
        )
        assert evidence_blocks_for_finding(f) == ()

    def test_render_failure_returns_empty_not_raise(self, tmp_path):
        """When the renderer raises, return ``()`` rather than
        propagating — Stage D must never fail over an evidence
        issue."""
        result = _result_with_evidence()
        with patch(
            "packages.llm_analysis.source_intel_inject._analyze",
            return_value=result,
        ):
            prepare_source_intel(tmp_path)
        f = _finding(repo_path=str(tmp_path))
        with (
            patch(
                "packages.llm_analysis.source_intel_inject._extract_flags",
                return_value=None,
            ),
            patch(
                "packages.llm_analysis.source_intel_inject._derive_evidence_strings",
                side_effect=RuntimeError("renderer blew up"),
            ),
        ):
            blocks = evidence_blocks_for_finding(f)
        assert blocks == ()

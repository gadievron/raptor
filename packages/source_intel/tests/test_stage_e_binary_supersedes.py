"""Tests for Stage E binary-supersedes (Phase C PR2).

  > "Binary observation supersedes source intent when both
  > available (Stage E binary wins)."

When ``packages.exploit_feasibility`` reports a binary verdict that
says the bug isn't reachable as a viable exploit (``"blocked"`` or
``"requires_environment"``), the rendered source_intel evidence
gets a SUPERSEDED prefix telling the LLM to weigh the binary side
over any source_intel EXPLOITABLE signal.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


from core.security.prompt_envelope import UntrustedBlock
from packages.source_intel.analyze import (
    AttributeEvidence,
    KIND_NORETURN,
    SourceIntelResult,
)
from packages.source_intel.llm_bridge import make_source_intel_collector
from packages.source_intel.render import (
    _BINARY_SUPERSEDING_VERDICTS,
    _supersession_prefix,
    derive_evidence_strings,
)


# ---- _supersession_prefix unit ----------------------------------------


class TestSupersessionPrefix:
    def test_none_when_verdict_none(self):
        assert _supersession_prefix(None) is None

    def test_none_on_exploitable_verdict(self):
        assert _supersession_prefix("exploitable") is None

    def test_none_on_likely_exploitable_verdict(self):
        assert _supersession_prefix("likely_exploitable") is None

    def test_prefix_on_blocked(self):
        p = _supersession_prefix("blocked")
        assert p is not None
        assert "SUPERSEDED" in p
        assert "blocked" in p

    def test_prefix_on_requires_environment(self):
        p = _supersession_prefix("requires_environment")
        assert p is not None
        assert "SUPERSEDED" in p
        assert "requires_environment" in p

    def test_prefix_says_evidence_is_structurally_correct(self):
        """LLM must not conclude 'source_intel was wrong' — only that
        it doesn't override the binary verdict."""
        p = _supersession_prefix("blocked")
        assert "STRUCTURALLY CORRECT" in p

    def test_prefix_warns_not_evidence_for_or_against(self):
        """The prefix should explicitly tell the LLM not to use the
        observations as exploitability evidence either way."""
        p = _supersession_prefix("blocked")
        assert "not as evidence" in p.lower()

    def test_superseding_set_includes_blocked_and_requires_env(self):
        assert "blocked" in _BINARY_SUPERSEDING_VERDICTS
        assert "requires_environment" in _BINARY_SUPERSEDING_VERDICTS

    def test_unknown_verdict_no_prefix(self):
        """Unknown verdicts (typo, new tier) → fail safe (no prefix).
        The renderer doesn't second-guess the verdict vocabulary."""
        assert _supersession_prefix("totally_unknown_verdict") is None


# ---- derive_evidence_strings integration ------------------------------


class TestRenderWithBinaryVerdict:
    def _result(self):
        return SourceIntelResult(
            target="/tmp/x",
            attributes=(
                AttributeEvidence(
                    kind=KIND_NORETURN,
                    function_name="panic",
                    location=("/tmp/x/f.c", 50),
                    match_source="literal",
                    raw_match="noreturn",
                ),
            ),
        )

    def test_no_verdict_unchanged_output(self):
        lines = derive_evidence_strings(
            self._result(),
            finding_function="panic",
            style="stage_d",
        )
        joined = "\n".join(lines)
        assert "SUPERSEDED" not in joined

    def test_exploitable_verdict_no_supersession(self):
        lines = derive_evidence_strings(
            self._result(),
            finding_function="panic",
            style="stage_d",
            binary_verdict="exploitable",
        )
        joined = "\n".join(lines)
        assert "SUPERSEDED" not in joined

    def test_blocked_verdict_prepends_supersession(self):
        lines = derive_evidence_strings(
            self._result(),
            finding_function="panic",
            style="stage_d",
            binary_verdict="blocked",
        )
        joined = "\n".join(lines)
        assert "SUPERSEDED" in joined
        assert lines[0].startswith("SUPERSEDED")

    def test_blocked_verdict_keeps_evidence_below(self):
        """The structural evidence MUST still appear — the prefix
        reframes it, doesn't suppress it."""
        lines = derive_evidence_strings(
            self._result(),
            finding_function="panic",
            style="stage_d",
            binary_verdict="blocked",
        )
        joined = "\n".join(lines)
        assert "panic" in joined
        # The noreturn observation should still render below the prefix.
        assert "noreturn" in joined.lower() or "never returns" in joined.lower()

    def test_supersession_applies_even_to_no_signal_branch(self):
        """When source_intel found nothing AND binary blocks: the
        prefix STILL fires so consumer sees the disposition."""
        empty = SourceIntelResult(target="/tmp/x")
        lines = derive_evidence_strings(
            empty,
            finding_function="foo",
            style="stage_d",
            binary_verdict="blocked",
        )
        joined = "\n".join(lines)
        assert "SUPERSEDED" in joined
        assert "no attribute or proximity evidence" in joined

    def test_supersession_applies_to_skipped_run(self):
        """When source_intel was skipped AND binary blocks: prefix
        still leads, so the LLM understands the binary disposition
        regardless of source_intel state."""
        skipped = SourceIntelResult(
            target="/tmp/x", skipped_reason="spatch_not_available",
        )
        lines = derive_evidence_strings(
            skipped,
            style="stage_d",
            binary_verdict="blocked",
        )
        joined = "\n".join(lines)
        assert "SUPERSEDED" in joined
        # Skip explanation still surfaces below.
        assert "Source_intel skipped" in joined


# ---- collector wiring -------------------------------------------------


def _path(rule_id: str = "cpp/null-dereference", file_path: str = "a.c"):
    return SimpleNamespace(
        rule_id=rule_id,
        sink=SimpleNamespace(file_path=file_path, line=10),
        source=SimpleNamespace(file_path=file_path, line=1),
    )


class TestCollectorBinaryVerdict:
    def _setup_result(self):
        return SourceIntelResult(
            target="/tmp/x",
            attributes=(
                AttributeEvidence(
                    kind=KIND_NORETURN,
                    function_name="panic",
                    location=("/tmp/x/a.c", 10),
                    match_source="literal",
                    raw_match="noreturn",
                ),
            ),
        )

    def test_resolver_called_with_dataflow_and_target(self):
        seen = {}

        def _resolver(dataflow, target):
            seen["dataflow"] = dataflow
            seen["target"] = target
            return "blocked"

        collector = make_source_intel_collector(
            binary_verdict_resolver=_resolver,
        )
        with (
            patch("packages.source_intel.analyze.analyze",
                  return_value=self._setup_result()),
            patch("packages.source_intel.llm_bridge._safe_extract_flags",
                  return_value=None),
            patch("packages.source_intel.llm_bridge._safe_enclosing_function",
                  return_value="panic"),
        ):
            block = collector(_path(), Path("/tmp/x"))
        assert seen["dataflow"] is not None
        assert seen["target"] == Path("/tmp/x")
        assert isinstance(block, UntrustedBlock)
        assert "SUPERSEDED" in block.content

    def test_resolver_returning_none_renders_unchanged(self):
        collector = make_source_intel_collector(
            binary_verdict_resolver=lambda d, t: None,
        )
        with (
            patch("packages.source_intel.analyze.analyze",
                  return_value=self._setup_result()),
            patch("packages.source_intel.llm_bridge._safe_extract_flags",
                  return_value=None),
            patch("packages.source_intel.llm_bridge._safe_enclosing_function",
                  return_value="panic"),
        ):
            block = collector(_path(), Path("/tmp/x"))
        assert isinstance(block, UntrustedBlock)
        assert "SUPERSEDED" not in block.content

    def test_resolver_raising_is_swallowed(self):
        """Resolver exception must NOT fail the collector — log + None."""
        def _bad_resolver(d, t):
            raise RuntimeError("oracle is down")

        collector = make_source_intel_collector(
            binary_verdict_resolver=_bad_resolver,
        )
        with (
            patch("packages.source_intel.analyze.analyze",
                  return_value=self._setup_result()),
            patch("packages.source_intel.llm_bridge._safe_extract_flags",
                  return_value=None),
            patch("packages.source_intel.llm_bridge._safe_enclosing_function",
                  return_value="panic"),
        ):
            block = collector(_path(), Path("/tmp/x"))
        assert isinstance(block, UntrustedBlock)
        # Resolver crashed → no supersession applied; evidence renders
        # unchanged. NOT skipped.
        assert "SUPERSEDED" not in block.content

    def test_no_resolver_means_no_supersession(self):
        """Default behaviour (no resolver) = legacy non-Stage-E rendering."""
        collector = make_source_intel_collector()
        with (
            patch("packages.source_intel.analyze.analyze",
                  return_value=self._setup_result()),
            patch("packages.source_intel.llm_bridge._safe_extract_flags",
                  return_value=None),
            patch("packages.source_intel.llm_bridge._safe_enclosing_function",
                  return_value="panic"),
        ):
            block = collector(_path(), Path("/tmp/x"))
        assert isinstance(block, UntrustedBlock)
        assert "SUPERSEDED" not in block.content

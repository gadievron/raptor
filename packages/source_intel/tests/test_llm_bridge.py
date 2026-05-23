"""Tests for ``packages.source_intel.llm_bridge``.

Validates the evidence-collector factory + CWE-prefix dispatcher
that wire source_intel into ``DataflowValidator(evidence_collector=)``.
Tests run against synthetic ``DataflowPath`` objects so no spatch
subprocess is required.
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
from packages.source_intel.llm_bridge import (
    DEFAULT_SOURCE_INTEL_RULE_PREFIXES,
    make_cwe_dispatched_collector,
    make_source_intel_collector,
)


# ---- DataflowPath stub ------------------------------------------------


def _path(rule_id: str = "cpp/null-dereference", file_path: str = "a.c"):
    """Build a minimal stand-in for the validator's DataflowPath."""
    return SimpleNamespace(
        rule_id=rule_id,
        sink=SimpleNamespace(file_path=file_path, line=10),
        source=SimpleNamespace(file_path=file_path, line=1),
    )


# ---- make_source_intel_collector --------------------------------------


def test_collector_skipped_run_with_no_observations_returns_none():
    skipped = SourceIntelResult(
        target="/tmp/x",
        skipped_reason="spatch_not_available",
    )
    collector = make_source_intel_collector()
    with patch(
        "packages.source_intel.analyze.analyze",
        return_value=skipped,
    ):
        block = collector(_path(), Path("/tmp/x"))
    assert block is None


def test_collector_runs_analyze_and_returns_untrusted_block():
    """analyze() returns a result with one observation; collector
    renders it as an UntrustedBlock."""
    result = SourceIntelResult(
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
    collector = make_source_intel_collector()
    with (
        patch("packages.source_intel.analyze.analyze", return_value=result),
        patch(
            "packages.source_intel.llm_bridge._safe_extract_flags",
            return_value=None,
        ),
        patch(
            "packages.source_intel.llm_bridge._safe_enclosing_function",
            return_value="panic",
        ),
    ):
        block = collector(_path(), Path("/tmp/x"))
    assert isinstance(block, UntrustedBlock)
    assert block.kind == "source-intel-evidence"
    assert block.origin == "cocci-structural-evidence"
    assert "panic" in block.content


def test_collector_empty_render_returns_none():
    """Result is non-empty but the renderer filters everything out
    (e.g. attributes scoped to a different function)."""
    result = SourceIntelResult(
        target="/tmp/x",
        attributes=(
            AttributeEvidence(
                kind=KIND_NORETURN,
                function_name="some_other_function",
                location=("/tmp/x/a.c", 10),
                match_source="literal",
                raw_match="noreturn",
            ),
        ),
    )
    collector = make_source_intel_collector()
    with (
        patch("packages.source_intel.analyze.analyze", return_value=result),
        patch(
            "packages.source_intel.llm_bridge._safe_extract_flags",
            return_value=None,
        ),
        patch(
            "packages.source_intel.llm_bridge._safe_enclosing_function",
            return_value="caller_function",
        ),
    ):
        block = collector(_path(), Path("/tmp/x"))
    # render emits an explicit "no signal" line for the requested
    # function — that IS still a useful block (carries the absence).
    # So we expect a block, not None.
    assert isinstance(block, UntrustedBlock)
    assert "no attribute or proximity evidence" in block.content


def test_collector_swallows_exceptions():
    """Any exception in the collector pipeline must be swallowed —
    validate_path must never fail over an evidence issue."""
    collector = make_source_intel_collector()
    with patch(
        "packages.source_intel.analyze.analyze",
        side_effect=RuntimeError("boom"),
    ):
        block = collector(_path(), Path("/tmp/x"))
    assert block is None


def test_collector_uses_cache_when_provided():
    """When cache.get() hits, analyze() is not invoked again."""
    cached = SourceIntelResult(
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

    class _DummyCache:
        def __init__(self):
            self.gets = 0
            self.puts = 0

        def get(self, target, rules_dir=None):
            self.gets += 1
            return cached

        def put(self, target, rules_dir, result):
            self.puts += 1

    cache = _DummyCache()
    collector = make_source_intel_collector(cache=cache)
    with (
        patch(
            "packages.source_intel.analyze.analyze",
            side_effect=AssertionError("should not be called"),
        ),
        patch(
            "packages.source_intel.llm_bridge._safe_extract_flags",
            return_value=None,
        ),
        patch(
            "packages.source_intel.llm_bridge._safe_enclosing_function",
            return_value="panic",
        ),
    ):
        block = collector(_path(), Path("/tmp/x"))
    assert isinstance(block, UntrustedBlock)
    assert cache.gets == 1
    assert cache.puts == 0


def test_repo_path_resolver_invoked():
    """When provided, the resolver gets first crack at picking the
    scan target (kernel-scale targets may want to narrow)."""
    seen = {}

    def _resolver(dataflow, repo_path):
        seen["called"] = True
        return repo_path / "subtree"

    result = SourceIntelResult(target="/tmp/x", skipped_reason="x")
    collector = make_source_intel_collector(repo_path_resolver=_resolver)
    with patch(
        "packages.source_intel.analyze.analyze",
        return_value=result,
    ) as analyze_mock:
        collector(_path(), Path("/tmp/x"))
    assert seen.get("called") is True
    assert analyze_mock.call_args.args[0] == Path("/tmp/x/subtree")


# ---- make_cwe_dispatched_collector ------------------------------------


def test_dispatcher_routes_memory_corruption_to_source_intel():
    calls = []

    def _sanitizer(d, r):
        calls.append(("sanitizer", d.rule_id))
        return None

    def _source_intel(d, r):
        calls.append(("source_intel", d.rule_id))
        return UntrustedBlock(
            content="x", kind="source-intel-evidence",
            origin="cocci-structural-evidence",
        )

    dispatcher = make_cwe_dispatched_collector(
        sanitizer_collector=_sanitizer,
        source_intel_collector=_source_intel,
    )

    block = dispatcher(_path(rule_id="cpp/null-dereference"), Path("/tmp/x"))
    assert isinstance(block, UntrustedBlock)
    assert calls == [("source_intel", "cpp/null-dereference")]


def test_dispatcher_routes_injection_to_sanitizer():
    calls = []

    def _sanitizer(d, r):
        calls.append(("sanitizer", d.rule_id))
        return None

    def _source_intel(d, r):
        calls.append(("source_intel", d.rule_id))
        return None

    dispatcher = make_cwe_dispatched_collector(
        sanitizer_collector=_sanitizer,
        source_intel_collector=_source_intel,
    )
    dispatcher(_path(rule_id="py/sql-injection"), Path("/tmp/x"))
    assert calls == [("sanitizer", "py/sql-injection")]


def test_dispatcher_handles_missing_branches():
    """With one branch unwired, dispatcher returns None for the
    rule_id that would route to the missing branch."""
    def _sanitizer(d, r):
        return UntrustedBlock(
            content="s", kind="sanitizer-evidence",
            origin="project-source-extracted",
        )

    dispatcher = make_cwe_dispatched_collector(
        sanitizer_collector=_sanitizer,
        source_intel_collector=None,
    )
    # memory-corruption → source_intel branch missing → None
    assert dispatcher(_path(rule_id="cpp/double-free"), Path("/tmp/x")) is None
    # injection → sanitizer branch wired → returns block
    block = dispatcher(_path(rule_id="py/sql-injection"), Path("/tmp/x"))
    assert isinstance(block, UntrustedBlock)


def test_dispatcher_custom_prefixes_override_default():
    seen = []

    def _source_intel(d, r):
        seen.append(d.rule_id)
        return None

    dispatcher = make_cwe_dispatched_collector(
        sanitizer_collector=lambda d, r: None,
        source_intel_collector=_source_intel,
        source_intel_rule_prefixes={"foo/bar-"},
    )
    dispatcher(_path(rule_id="foo/bar-baz"), Path("/tmp/x"))
    dispatcher(_path(rule_id="cpp/null-dereference"), Path("/tmp/x"))
    # Only the matching prefix routed to source_intel; the previously-
    # default cpp/null-dereference went to sanitizer (no source_intel hit)
    assert seen == ["foo/bar-baz"]


def test_default_prefixes_cover_design_cwes():
    """Sanity: the default prefix set hits at least one rule_id from
    each CWE class the design specifies (CWE-120/122/190/415/416/476/787)."""
    rules = [
        "cpp/unbounded-write",          # CWE-120
        "cpp/uncontrolled-allocation-size",  # CWE-122 / CWE-190
        "cpp/uncontrolled-arithmetic",  # CWE-190
        "cpp/double-free",              # CWE-415
        "cpp/use-after-free",           # CWE-416
        "cpp/null-dereference",         # CWE-476
        "c/null-dereference",           # CWE-476
        "cpp/out-of-bounds-write",      # CWE-787
    ]
    for r in rules:
        assert any(
            r.startswith(p) for p in DEFAULT_SOURCE_INTEL_RULE_PREFIXES
        ), f"rule {r} not covered by default prefixes"

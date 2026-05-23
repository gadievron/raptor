"""Tests for the SourceIntelAdapter — pre-computed source_intel KB
exposed to hypothesis validation. Mocks SourceIntelResult so no spatch
subprocess is required."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))


from packages.hypothesis_validation.adapters import SourceIntelAdapter
from packages.source_intel.analyze import (
    AbortEvidence,
    AllocationEvidence,
    AttributeEvidence,
    GRADE_DOMINATES,
    KIND_NORETURN,
    KIND_WUR,
    SourceIntelResult,
)


# ---- helpers ----------------------------------------------------------


def _q(**kwargs) -> str:
    return json.dumps(kwargs)


def _attr_result(*attrs) -> SourceIntelResult:
    return SourceIntelResult(target="/tmp/x", attributes=tuple(attrs))


def _abort_result(*aborts) -> SourceIntelResult:
    return SourceIntelResult(target="/tmp/x", aborts=tuple(aborts))


def _alloc_result(*allocs) -> SourceIntelResult:
    return SourceIntelResult(target="/tmp/x", allocations=tuple(allocs))


# ---- describe / availability ------------------------------------------


class TestSourceIntelAdapterMeta:
    def test_name(self):
        assert SourceIntelAdapter().name == "source_intel"

    def test_describe_languages(self):
        cap = SourceIntelAdapter().describe()
        assert cap.languages == ["c", "cpp"]
        assert cap.syntax_example

    def test_describe_lists_axes(self):
        text = SourceIntelAdapter().describe().render_for_prompt()
        # Each major axis is mentioned in the capability description
        assert "attribute" in text.lower()
        assert "abort" in text.lower()
        assert "allocation" in text.lower() or "alloc" in text.lower()

    def test_unavailable_when_coccinelle_missing(self, tmp_path):
        a = SourceIntelAdapter()
        with patch.object(a, "is_available", return_value=False):
            ev = a.run('{"function":"x"}', tmp_path)
        assert not ev.success
        assert "spatch is not installed" in ev.error


# ---- query validation -------------------------------------------------


class TestQueryValidation:
    def setup_method(self):
        self.adapter = SourceIntelAdapter()
        self.target = Path("/tmp/x")

    def test_empty_rule(self):
        ev = self.adapter.run("", self.target)
        assert not ev.success
        assert "empty rule" in ev.error

    def test_bad_json(self):
        ev = self.adapter.run("{not json", self.target)
        assert not ev.success
        assert "not valid JSON" in ev.error

    def test_non_object(self):
        ev = self.adapter.run('["a", "b"]', self.target)
        assert not ev.success
        assert "must be an object" in ev.error

    def test_unknown_field(self):
        ev = self.adapter.run(
            _q(function="x", evil="payload"), self.target
        )
        assert not ev.success
        assert "unknown query field" in ev.error
        assert "evil" in ev.error

    def test_missing_function(self):
        ev = self.adapter.run(_q(axes=["attrs"]), self.target)
        assert not ev.success
        assert "missing required 'function'" in ev.error

    def test_unknown_axis(self):
        with patch.object(self.adapter, "is_available", return_value=True):
            ev = self.adapter.run(
                _q(function="x", axes=["nope"]), self.target
            )
        assert not ev.success
        assert "unknown axis" in ev.error
        assert "nope" in ev.error

    def test_axes_must_be_list(self):
        with patch.object(self.adapter, "is_available", return_value=True):
            ev = self.adapter.run(
                _q(function="x", axes="attrs"), self.target
            )
        assert not ev.success
        assert "'axes' must be a list" in ev.error


# ---- per-axis behaviour -----------------------------------------------


class TestAttrsAxis:
    def test_attribute_match_by_function(self, tmp_path):
        result = _attr_result(
            AttributeEvidence(
                kind=KIND_WUR, function_name="kmalloc",
                location=("/tmp/x/mm/slab.c", 100),
                match_source="literal", raw_match="warn_unused_result",
            ),
            AttributeEvidence(
                kind=KIND_NORETURN, function_name="panic",
                location=("/tmp/x/kernel/panic.c", 50),
                match_source="literal", raw_match="noreturn",
            ),
        )
        adapter = SourceIntelAdapter()
        with (
            patch.object(adapter, "is_available", return_value=True),
            patch(
                "packages.source_intel.analyze.analyze",
                return_value=result,
            ),
        ):
            ev = adapter.run(
                _q(function="kmalloc", axes=["attrs"]), tmp_path
            )
        assert ev.success
        assert len(ev.matches) == 1
        m = ev.matches[0]
        assert m["axis"] == "attrs"
        assert m["kind"] == KIND_WUR
        assert m["function"] == "kmalloc"
        assert m["line"] == 100

    def test_kind_filter_narrows(self, tmp_path):
        result = _attr_result(
            AttributeEvidence(
                kind=KIND_WUR, function_name="kmalloc",
                location=("/tmp/x/mm/slab.c", 100),
                match_source="literal", raw_match="warn_unused_result",
            ),
            AttributeEvidence(
                kind=KIND_NORETURN, function_name="kmalloc",
                location=("/tmp/x/mm/slab.c", 100),
                match_source="literal", raw_match="noreturn",
            ),
        )
        adapter = SourceIntelAdapter()
        with (
            patch.object(adapter, "is_available", return_value=True),
            patch(
                "packages.source_intel.analyze.analyze",
                return_value=result,
            ),
        ):
            ev = adapter.run(
                _q(function="kmalloc", axes=["attrs"], kind=KIND_WUR),
                tmp_path,
            )
        assert ev.success
        assert len(ev.matches) == 1
        assert ev.matches[0]["kind"] == KIND_WUR

    def test_file_filter_narrows(self, tmp_path):
        result = _attr_result(
            AttributeEvidence(
                kind=KIND_WUR, function_name="kmalloc",
                location=("/tmp/x/mm/slab.c", 100),
                match_source="literal", raw_match="x",
            ),
            AttributeEvidence(
                kind=KIND_WUR, function_name="kmalloc",
                location=("/tmp/x/other/file.c", 10),
                match_source="literal", raw_match="x",
            ),
        )
        adapter = SourceIntelAdapter()
        with (
            patch.object(adapter, "is_available", return_value=True),
            patch(
                "packages.source_intel.analyze.analyze",
                return_value=result,
            ),
        ):
            ev = adapter.run(
                _q(function="kmalloc", axes=["attrs"], file="mm/slab.c"),
                tmp_path,
            )
        assert ev.success
        assert len(ev.matches) == 1
        assert ev.matches[0]["file"].endswith("mm/slab.c")


class TestAbortsAxis:
    def test_abort_match(self, tmp_path):
        result = _abort_result(
            AbortEvidence(
                macro="panic", location=("/tmp/x/f.c", 50),
                enclosing_function="do_thing", grade=GRADE_DOMINATES,
            ),
        )
        adapter = SourceIntelAdapter()
        with (
            patch.object(adapter, "is_available", return_value=True),
            patch(
                "packages.source_intel.analyze.analyze",
                return_value=result,
            ),
        ):
            ev = adapter.run(
                _q(function="do_thing", axes=["aborts"]), tmp_path
            )
        assert ev.success
        assert len(ev.matches) == 1
        assert ev.matches[0]["macro"] == "panic"
        assert ev.matches[0]["grade"] == GRADE_DOMINATES


class TestAllocationsAxis:
    def test_unchecked_alloc_match(self, tmp_path):
        result = _alloc_result(
            AllocationEvidence(
                allocator="kmalloc",
                location=("/tmp/x/f.c", 200),
                shape="field",
                enclosing_function="do_thing",
                target_field="data",
            ),
        )
        adapter = SourceIntelAdapter()
        with (
            patch.object(adapter, "is_available", return_value=True),
            patch(
                "packages.source_intel.analyze.analyze",
                return_value=result,
            ),
        ):
            ev = adapter.run(
                _q(function="do_thing", axes=["allocations"]), tmp_path
            )
        assert ev.success
        assert len(ev.matches) == 1
        assert ev.matches[0]["allocator"] == "kmalloc"
        assert ev.matches[0]["target_field"] == "data"


class TestNoMatches:
    def test_no_match_reports_clear_summary(self, tmp_path):
        result = _attr_result()
        adapter = SourceIntelAdapter()
        with (
            patch.object(adapter, "is_available", return_value=True),
            patch(
                "packages.source_intel.analyze.analyze",
                return_value=result,
            ),
        ):
            ev = adapter.run(
                _q(function="missing_fn", axes=["attrs"]), tmp_path
            )
        assert ev.success
        assert ev.matches == []
        assert "no source_intel observation" in ev.summary


# ---- caching ----------------------------------------------------------


class TestCaching:
    def test_cache_hit_skips_analyze(self, tmp_path):
        cached = _attr_result(
            AttributeEvidence(
                kind=KIND_WUR, function_name="kmalloc",
                location=("/tmp/x/f.c", 1),
                match_source="literal", raw_match="x",
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
        adapter = SourceIntelAdapter(cache=cache)
        with (
            patch.object(adapter, "is_available", return_value=True),
            patch(
                "packages.source_intel.analyze.analyze",
                side_effect=AssertionError("must not be called"),
            ),
        ):
            ev = adapter.run(
                _q(function="kmalloc", axes=["attrs"]), tmp_path
            )
        assert ev.success
        assert cache.gets == 1
        assert cache.puts == 0


# ---- skip semantics ---------------------------------------------------


class TestSkipReason:
    def test_skipped_result_returns_error_evidence(self, tmp_path):
        result = SourceIntelResult(
            target="/tmp/x", skipped_reason="spatch_not_available",
        )
        adapter = SourceIntelAdapter()
        with (
            patch.object(adapter, "is_available", return_value=True),
            patch(
                "packages.source_intel.analyze.analyze",
                return_value=result,
            ),
        ):
            ev = adapter.run(
                _q(function="x", axes=["attrs"]), tmp_path
            )
        assert not ev.success
        assert "source_intel skipped" in ev.error
        assert "spatch_not_available" in ev.error

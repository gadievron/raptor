"""Per-file failure isolation in the consistency extractors, plus the
prepass dimension-failure counter.

One bad file (grammar edge case, hostile input) used to abort a whole
extractor pass, and the prepass's dimension-level ``except`` swallowed
detector crashes at debug level — "0 deviations" was
indistinguishable from "dimension failed". The extractors now skip and
count the failing file; the prepass surfaces detector crashes in
``telemetry["dimension_failures"]``.
"""

from __future__ import annotations

import pytest

pytest.importorskip("tree_sitter", reason="extractors need tree-sitter")
pytest.importorskip("tree_sitter_python",
                    reason="extractors need the python grammar")

from core.audit import consistency_dimensions as cd  # noqa: E402
from core.audit.callsite_consistency import parse_source_cached  # noqa: E402

_GOOD = (
    "def f():\n"
    "    foo(1, 2)\n"
    "    bar(3)\n"
)


@pytest.fixture()
def poisoned_parse(monkeypatch):
    """parse_source_cached that raises for bad.py only."""

    def _parse(file_path, source):
        if file_path == "bad.py":
            raise RuntimeError("simulated grammar crash")
        return parse_source_cached(file_path, source)

    monkeypatch.setattr(cd, "parse_source_cached", _parse)


class TestPerFileIsolation:
    def test_arg_sites_survive_bad_file(self, poisoned_parse):
        by_callee = cd._extract_arg_sites(
            {"bad.py": "x = 1\n", "good.py": _GOOD},
        )
        assert "foo" in by_callee
        assert by_callee["foo"][0].file == "good.py"

    def test_function_spans_survive_bad_file(self, poisoned_parse):
        spans = cd._function_spans(
            {"bad.py": "x = 1\n", "good.py": _GOOD},
        )
        assert any(fp == "good.py" and name == "f"
                   for fp, name, _start, _body in spans)

    def test_shape_sites_survive_bad_file(self, poisoned_parse):
        by_key = cd._extract_shape_sites(
            {"bad.py": "x = 1\n", "good.py": _GOOD},
        )
        assert ("foo", 0) in by_key

    def test_call_events_survive_bad_file(self, poisoned_parse):
        events = cd._extract_call_events(
            {"bad.py": "x = 1\n", "good.py": _GOOD},
        )
        assert ("good.py", "f") in events
        assert {e.callee for e in events[("good.py", "f")]} \
            >= {"foo", "bar"}


class TestDimensionFailureTelemetry:
    def test_detector_crash_is_counted(self, monkeypatch):
        from core.audit.consistency_prepass import run_consistency_prepass

        def _boom(*_a, **_k):
            raise RuntimeError("simulated detector crash")

        monkeypatch.setattr(
            cd, "detect_flag_mode_deviations", _boom,
        )
        result = run_consistency_prepass(
            {"a.py": _GOOD},
        )
        failures = result["telemetry"]["dimension_failures"]
        assert failures.get("flag-mode") == 1

    def test_clean_run_reports_no_failures(self):
        from core.audit.consistency_prepass import run_consistency_prepass

        result = run_consistency_prepass({"a.py": _GOOD})
        assert result["telemetry"]["dimension_failures"] == {}

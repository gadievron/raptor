"""FN census: construct classification, coverage split, rendering."""

from __future__ import annotations

import json
from pathlib import Path

from core.recall.fn_census import (
    COVERAGE_FIRED_ELSEWHERE,
    COVERAGE_NO_FINDINGS,
    UNCLASSIFIED,
    build_fn_census,
    classify_fn_source,
    render_fn_census_markdown,
)

_COLLECTION = """
java.util.HashMap<String, Object> map1 = new java.util.HashMap<String, Object>();
map1.put("keyA-1", "a");
map1.put("keyB-1", param);
bar = (String) map1.get("keyB-1");
"""

_HELPER = """
new org.owasp.benchmark.helpers.SeparateClassRequest(request);
String param = scr.getTheParameter("x");
"""

_CONFIG = """
benchmarkprops.load(stream);
String algorithm = benchmarkprops.getProperty("hashAlg1", "SHA512");
"""


class TestClassify:
    def test_collection_indirection(self):
        primary, matched = classify_fn_source(_COLLECTION)
        assert primary == "collection_indirection"
        assert "collection_indirection" in matched

    def test_helper_class_source(self):
        primary, _ = classify_fn_source(_HELPER)
        assert primary == "helper_class_source"

    def test_config_outranks_helper(self):
        primary, matched = classify_fn_source(_CONFIG + _HELPER)
        assert primary == "config_indirection"
        assert "helper_class_source" in matched

    def test_unmatched_is_unclassified(self):
        primary, matched = classify_fn_source("int x = 1;\n")
        assert primary == UNCLASSIFIED
        assert matched == []

    def test_decorations_are_not_probes(self):
        # URL decoding and encoder calls ride along most flows; they
        # must never be classified as the chain-breaking construct.
        text = 'java.net.URLDecoder.decode(v, "UTF-8");\nESAPI.encoder()'
        primary, matched = classify_fn_source(text)
        assert primary == UNCLASSIFIED
        assert matched == []


def _missed_entry(tmp_path: Path, case_id: str, cwe: str,
                  source: str) -> dict:
    f = tmp_path / f"{case_id}.java"
    f.write_text(source, encoding="utf-8")
    return {"id": case_id, "file": f.name, "cwe": cwe,
            "line_start": None, "line_end": None}


class TestBuildCensus:
    def test_aggregates_and_coverage_split(self, tmp_path):
        missed = [
            _missed_entry(tmp_path, "A", "CWE-89", _COLLECTION),
            _missed_entry(tmp_path, "B", "CWE-89", _HELPER),
            _missed_entry(tmp_path, "C", "CWE-328", _CONFIG),
        ]
        per_cwe = [
            {"cwe": "CWE-89", "expected": 10, "found": 8},
            {"cwe": "CWE-328", "expected": 5, "found": 0},
        ]
        census = build_fn_census(missed, source_root=tmp_path,
                                 per_cwe=per_cwe)
        assert census["fn_total"] == 3
        idioms = {r["idiom"]: r["count"] for r in census["by_idiom"]}
        assert idioms == {"collection_indirection": 1,
                          "helper_class_source": 1,
                          "config_indirection": 1}
        cov = {r["coverage"]: r["count"] for r in census["by_coverage"]}
        assert cov[COVERAGE_FIRED_ELSEWHERE] == 2  # CWE-89 found > 0
        assert cov[COVERAGE_NO_FINDINGS] == 1      # CWE-328 found == 0

    def test_unreadable_sources_counted_not_fatal(self, tmp_path):
        missed = [{"id": "gone", "file": "missing.java",
                   "cwe": "CWE-79"}]
        census = build_fn_census(missed, source_root=tmp_path)
        assert census["unreadable_sources"] == 1
        assert census["by_idiom"][0]["idiom"] == UNCLASSIFIED

    def test_rules_per_cwe_family_matched(self, tmp_path):
        missed = [_missed_entry(tmp_path, "A", "CWE-79", _HELPER)]
        produced = [
            {"rule_id": "xss-a", "cwe": "CWE-79"},
            {"rule_id": "xss-b", "cwe": "CWE-80"},   # family sibling
            {"rule_id": "sqli", "cwe": "CWE-89"},    # unrelated
        ]
        census = build_fn_census(missed, source_root=tmp_path,
                                 produced=produced)
        assert census["rules_firing_per_cwe"]["CWE-79"] == [
            "xss-a", "xss-b"]

    def test_label_class_and_render(self, tmp_path):
        missed = [_missed_entry(tmp_path, "A", "CWE-89", _COLLECTION)]
        census = build_fn_census(missed, source_root=tmp_path,
                                 per_cwe=[])
        assert census["label_class"] == "recall-ground-truth"
        md = render_fn_census_markdown(census)
        assert "chain-breaking construct" in md
        assert "collection_indirection" in md
        json.dumps(census)  # serialisable

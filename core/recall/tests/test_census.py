"""Tests for the clean-region FP census."""

from __future__ import annotations

import json

from core.recall.census import (
    UNCLASSIFIED,
    build_census,
    classify_source,
    render_census_markdown,
)

ESAPI_SRC = """
import org.owasp.esapi.ESAPI;
String bar = ESAPI.encoder().encodeForHTML(param);
switch (param) { default: break; }
"""

ENCODER_SRC = """
import org.owasp.encoder.Encode;
out.println(Encode.forHtml(param));
"""

PREPARED_SRC = """
PreparedStatement ps = conn.prepareStatement(sql);
ps.setString(1, param);
"""

TABLE_SRC = """
java.util.ArrayList<String> valuesList = new java.util.ArrayList<String>();
switch (param) { case "a": break; }
"""

PLAIN_SRC = "String x = doSomething(param);\n"


class TestClassifySource:
    def test_esapi_outranks_allowlist(self):
        primary, matched = classify_source(ESAPI_SRC)
        assert primary == "esapi_encoder"
        assert "allowlist_or_table" in matched

    def test_owasp_encoder(self):
        assert classify_source(ENCODER_SRC)[0] == "owasp_java_encoder"

    def test_prepared_statement(self):
        assert classify_source(PREPARED_SRC)[0] == "prepared_statement"

    def test_table_lookup(self):
        assert classify_source(TABLE_SRC)[0] == "allowlist_or_table"

    def test_unclassified_is_honest(self):
        primary, matched = classify_source(PLAIN_SRC)
        assert primary == UNCLASSIFIED
        assert matched == []


def _fp(case_id, cwe, path, rules=None):
    entry = {"id": case_id, "cwe": cwe, "file": path}
    if rules is not None:
        entry["rules"] = rules
    return entry


class TestBuildCensus:
    def test_rankings_and_rule_attribution(self, tmp_path):
        (tmp_path / "a.java").write_text(ESAPI_SRC, encoding="utf-8")
        (tmp_path / "b.java").write_text(ENCODER_SRC, encoding="utf-8")
        (tmp_path / "c.java").write_text(PLAIN_SRC, encoding="utf-8")
        fps = [
            _fp("A", "CWE-79", "a.java", rules=["r.xss"]),
            _fp("B", "CWE-79", "b.java", rules=["r.xss"]),
            _fp("C", "CWE-89", "c.java", rules=["r.sqli"]),
        ]
        census = build_census(fps, source_root=tmp_path)
        assert census["fp_total"] == 3
        assert census["by_rule"][0] == {"rule": "r.xss", "count": 2}
        idioms = {r["idiom"]: r["count"] for r in census["by_idiom"]}
        assert idioms["esapi_encoder"] == 1
        assert idioms[UNCLASSIFIED] == 1
        cross = {(r["rule"], r["idiom"]) for r in census["rule_x_idiom"]}
        assert ("r.xss", "esapi_encoder") in cross

    def test_rules_by_id_fallback(self, tmp_path):
        (tmp_path / "a.java").write_text(ESAPI_SRC, encoding="utf-8")
        fps = [_fp("A", "CWE-79", "a.java")]  # no rules field
        census = build_census(
            fps, source_root=tmp_path,
            rules_by_id={"A": ["r.late"]})
        assert census["by_rule"][0]["rule"] == "r.late"

    def test_missing_source_counts_unreadable(self, tmp_path):
        fps = [_fp("A", "CWE-79", "nope.java", rules=["r"])]
        census = build_census(fps, source_root=tmp_path)
        assert census["unreadable_sources"] == 1
        assert census["by_idiom"][0]["idiom"] == UNCLASSIFIED

    def test_no_rule_attribution_bucket(self, tmp_path):
        (tmp_path / "a.java").write_text(PLAIN_SRC, encoding="utf-8")
        census = build_census([_fp("A", "CWE-79", "a.java")],
                              source_root=tmp_path)
        assert census["by_rule"][0]["rule"] == "(no-rule-attribution)"

    def test_markdown_and_json_roundtrip(self, tmp_path):
        (tmp_path / "a.java").write_text(ESAPI_SRC, encoding="utf-8")
        census = build_census([_fp("A", "CWE-79", "a.java", rules=["r"])],
                              source_root=tmp_path)
        md = render_census_markdown(census)
        assert "esapi_encoder" in md and "| r |" in md
        json.dumps(census)  # JSON-serialisable


class TestCweAwareIdiomPrimary:
    def test_encoder_not_primary_for_pathtrav(self):
        from core.recall.census import classify_source
        text = ('bar = cond ? "safe" : param;\n'
                'switch (c) { case 1: x = "a"; }\n'
                'out.println(ESAPI.encoder().encodeForHTML(fileName));')
        primary, matched = classify_source(text, "CWE-22")
        assert "esapi_encoder" in matched
        assert primary == "allowlist_or_table"

    def test_encoder_primary_for_xss(self):
        from core.recall.census import classify_source
        text = 'out.println(ESAPI.encoder().encodeForHTML(param));'
        primary, _ = classify_source(text, "CWE-79")
        assert primary == "esapi_encoder"

    def test_prepared_statement_demoted_below_selection(self):
        from core.recall.census import classify_source
        text = ('java.util.HashMap<String, Object> map = null;\n'
                'switch (c) { case 1: break; }\n'
                'st = conn.prepareStatement(sql);')
        primary, matched = classify_source(text, "CWE-89")
        assert "prepared_statement" in matched
        assert primary == "allowlist_or_table"

    def test_prepared_statement_still_primary_when_alone(self):
        from core.recall.census import classify_source
        primary, _ = classify_source("conn.prepareStatement(sql);", "CWE-89")
        assert primary == "prepared_statement"


class TestJulietProbeAndWindow:
    def test_juliet_constant_source_probe(self):
        from core.recall.census import classify_source
        primary, matched = classify_source(
            "/* goodG2B1() - use goodsource and badsink */\n"
            'String data = "foo"; stmt.execute("SELECT " + data);',
            "CWE-89")
        assert primary == "juliet_constant_source_g2b"
        assert "juliet_constant_source_g2b" in matched

    def test_probe_inert_without_marker(self):
        from core.recall.census import classify_source
        primary, _ = classify_source(
            'stmt.execute("SELECT " + data);', "CWE-89")
        assert primary != "juliet_constant_source_g2b"

    def test_region_window_slices_by_lines(self, tmp_path):
        from core.recall.census import _read_clean_source
        f = tmp_path / "T.java"
        f.write_text("\n".join(f"line{i}" for i in range(1, 201)))
        text = _read_clean_source(
            {"file": str(f), "line_start": 100, "line_end": 100}, None)
        assert "line100" in text and "line60" in text
        assert "line1\n" not in text and "line190" not in text

    def test_no_line_info_reads_whole_file(self, tmp_path):
        from core.recall.census import _read_clean_source
        f = tmp_path / "T.java"
        f.write_text("alpha\nomega")
        assert _read_clean_source({"file": str(f)}, None) == "alpha\nomega"

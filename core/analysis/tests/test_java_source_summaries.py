"""Source-wrapper summary derivation: qualification proofs and the
refusal battery (detection-side mirror of the sanitizer summaries)."""

from __future__ import annotations

from pathlib import Path

import json

import pytest

pytest.importorskip("tree_sitter_java")

from core.analysis.java_source_summaries import (  # noqa: E402
    derive_source_summaries,
    rows_from_source_summaries,
    scan_tree,
)


def _summaries(src: str):
    r = derive_source_summaries(src)
    return {(s.owner, s.name): s for s in r.summaries}, r.refusals


_PKG = "package demo.helpers;\nimport javax.servlet.http.HttpServletRequest;\n"


class TestQualifies:
    def test_param_receiver(self):
        s, _ = _summaries(_PKG + """
public class H {
    public String grab(HttpServletRequest req, String p) {
        return req.getParameter(p);
    }
}""")
        assert ("H", "grab") in s
        assert s[("H", "grab")].via == "param"
        assert s[("H", "grab")].signature == "(HttpServletRequest,String)"

    def test_constructor_frozen_field(self):
        s, _ = _summaries(_PKG + """
public class H {
    private HttpServletRequest request;
    public H(HttpServletRequest request) { this.request = request; }
    public String getIt(String p) { return request.getParameter(p); }
}""")
        assert s[("H", "getIt")].via == "field"

    def test_local_hop(self):
        s, _ = _summaries(_PKG + """
public class H {
    public String grab(HttpServletRequest req, String p) {
        String v = req.getParameter(p);
        return v;
    }
}""")
        assert ("H", "grab") in s

    def test_depth_two_composition(self):
        s, _ = _summaries(_PKG + """
public class H {
    private HttpServletRequest request;
    public H(HttpServletRequest request) { this.request = request; }
    public String inner(String p) { return request.getParameter(p); }
    public String outer(String p) { return inner(p); }
}""")
        assert s[("H", "inner")].via == "field"
        assert s[("H", "outer")].via == "compose"

    def test_real_benchmark_shape(self):
        src = _PKG + """
public class SeparateClassRequest {
    private HttpServletRequest request;
    public SeparateClassRequest(HttpServletRequest request) {
        this.request = request;
    }
    public String getTheParameter(String p) {
        return request.getParameter(p);
    }
    public String getTheValue(String p) { return "bar"; }
}"""
        s, refusals = _summaries(src)
        assert ("SeparateClassRequest", "getTheParameter") in s
        assert ("SeparateClassRequest", "getTheValue") not in s


class TestRefusals:
    def test_constant_return_refused(self):
        s, r = _summaries(_PKG + """
public class H {
    public String safe(String p) { return "bar"; }
}""")
        assert not s
        assert any("string_literal" in k for k in r)

    def test_sanitizing_wrapper_refused(self):
        # validates/encodes-then-returns: NOT a raw source (wrapped_call)
        s, r = _summaries(_PKG + """
public class H {
    public String clean(HttpServletRequest req, String p) {
        return org.owasp.encoder.Encode.forHtml(req.getParameter(p));
    }
}""")
        assert not s
        assert r.get("wrapped_call")

    def test_branchy_body_refused(self):
        s, r = _summaries(_PKG + """
public class H {
    public String grab(HttpServletRequest req, String p) {
        if (p == null) { return ""; }
        return req.getParameter(p);
    }
}""")
        assert not s

    def test_field_reassigned_elsewhere_refused(self):
        # the receiver field is mutable after construction: not frozen
        s, r = _summaries(_PKG + """
public class H {
    private HttpServletRequest request;
    public H(HttpServletRequest request) { this.request = request; }
    public void swap(HttpServletRequest other) { this.request = other; }
    public String getIt(String p) { return request.getParameter(p); }
}""")
        assert not s
        assert r.get("source call on unproven receiver")

    def test_field_not_ctor_param_refused(self):
        s, r = _summaries(_PKG + """
public class H {
    private HttpServletRequest request;
    public H() { this.request = null; }
    public String getIt(String p) { return request.getParameter(p); }
}""")
        assert not s

    def test_string_field_mediation_refused(self):
        # taint parked in a mutable String field between methods
        s, r = _summaries(_PKG + """
public class H {
    private String stash;
    public void put(HttpServletRequest req) {
        stash = req.getParameter("x");
    }
    public String getIt() { return stash; }
}""")
        assert not s

    def test_overload_ambiguity_refused(self):
        s, r = _summaries(_PKG + """
public class H {
    public String g(HttpServletRequest req, String p) {
        return req.getParameter(p);
    }
    public String g(HttpServletRequest req, String p) {
        return req.getParameter(p);
    }
}""")
        assert not s
        assert r.get("overload_ambiguity")

    def test_unknown_receiver_method_refused(self):
        s, r = _summaries(_PKG + """
public class H {
    public String grab(HttpServletRequest req, String p) {
        return req.getAttribute(p).toString();
    }
}""")
        assert not s

    def test_two_level_cycle_refused(self):
        s, r = _summaries(_PKG + """
public class H {
    public String a(String p) { return b(p); }
    public String b(String p) { return a(p); }
}""")
        assert not s


class TestRowsAndScan:
    def test_rows_validate_for_java(self):
        from core.dataflow.extension_pack import _validate
        s, _ = _summaries(_PKG + """
public class H {
    public String grab(HttpServletRequest req, String p) {
        return req.getParameter(p);
    }
}""")
        rows = rows_from_source_summaries(s.values())
        assert rows and all(_validate(r, "java") is None for r in rows)
        assert rows[0].model_kind == "remote"
        assert rows[0].access_output == "ReturnValue"
        assert rows[0].provenance == "mechanical"

    def test_scan_tree_caps_and_filters(self, tmp_path):
        good = tmp_path / "src" / "H.java"
        good.parent.mkdir(parents=True)
        good.write_text(_PKG + """
public class H {
    public String grab(HttpServletRequest req, String p) {
        return req.getParameter(p);
    }
}""", encoding="utf-8")
        skipped = tmp_path / "test" / "T.java"
        skipped.parent.mkdir(parents=True)
        skipped.write_text(good.read_text(), encoding="utf-8")
        summaries, refusals, scanned = scan_tree(tmp_path)
        assert [x.owner for x in summaries] == ["H"]
        assert scanned == 1  # test/ dir skipped

    def test_pack_emission_end_to_end(self, tmp_path):
        from core.dataflow.extension_pack import write_extension_pack
        s, _ = _summaries(_PKG + """
public class H {
    public String grab(HttpServletRequest req, String p) {
        return req.getParameter(p);
    }
}""")
        res = write_extension_pack(
            rows_from_source_summaries(s.values()),
            language="java", out_dir=tmp_path,
        )
        assert res.rows_written == 1 and not res.rejected
        text = res.model_file.read_text()
        assert "codeql/java-all" in text and "sourceModel" in text
        assert '"(HttpServletRequest,String)"' in text


class TestSemgrepProjectionSync:
    """The generated semgrep rules mirror the in-repo rule blocks —
    drift between them must break the build."""

    def _origin(self, rel: str) -> str:
        root = Path(__file__).resolve().parents[3]
        return (root / rel).read_text(encoding="utf-8")

    def test_xss_blocks_match_origin_rule(self):
        from packages.semgrep.source_wrapper_rules import (
            XSS_SANITIZERS,
            XSS_SINKS,
        )
        origin = self._origin("engine/semgrep/rules/injection/xss.yaml")
        for pat in list(XSS_SINKS) + list(XSS_SANITIZERS):
            assert pat in origin, f"pattern drifted from origin rule: {pat}"

    def test_collection_propagators_match_origin_rule(self):
        from packages.semgrep.source_wrapper_rules import (
            COLLECTION_PROPAGATORS,
        )
        origin = self._origin("engine/semgrep/rules/injection/xss.yaml")
        for prop in COLLECTION_PROPAGATORS:
            assert prop["pattern"] in origin, (
                f"propagator drifted from origin rule: {prop['pattern']}"
            )

    def test_every_generated_rule_has_scanner_cwe_mapping(self):
        # The recall matcher never credits CWE-less findings; the scan
        # stage stamps CWE onto SARIF rule properties from a suffix
        # map. A generated rule missing from that map ships findings
        # that mechanically score zero (observed live: the sqli rule).
        from packages.semgrep import source_wrapper_rules as swr
        scanner_src = self._origin("packages/static-analysis/scanner.py")
        s, _ = _summaries(_PKG + """
public class H {
    public String grab(HttpServletRequest req, String p) {
        return req.getParameter(p);
    }
}""")
        doc = json.loads(swr.generate_rules_yaml(list(s.values())))
        for rule in doc["rules"]:
            suffix = "." + rule["id"].rsplit(".", 1)[-1]
            assert f'"{suffix}"' in scanner_src, (
                f"generated rule {rule['id']} has no cwe_by_suffix "
                f"entry in the scan stage — its findings score zero")

    def test_sqli_blocks_match_origin_rule(self):
        from packages.semgrep.source_wrapper_rules import (
            SQLI_SINK_BLOCKS,
            SQLI_SINKS,
        )
        origin = self._origin("engine/semgrep/rules/injection/sql-taint.yaml")

        def _strings(node):
            if isinstance(node, dict):
                for key, val in node.items():
                    if key == "pattern" and isinstance(val, str):
                        yield val
                    elif key == "metavariable-regex":
                        yield val["regex"]
                    else:
                        yield from _strings(val)
            elif isinstance(node, (list, tuple)):
                for item in node:
                    yield from _strings(item)

        for pat in list(SQLI_SINKS) + list(_strings(list(SQLI_SINK_BLOCKS))):
            assert pat in origin, f"pattern drifted from origin rule: {pat}"

    def test_trust_boundary_blocks_match_origin_rule(self):
        from packages.semgrep.source_wrapper_rules import TRUST_BOUNDARY_SINKS
        origin = self._origin("engine/semgrep/rules/java/trust-boundary.yaml")
        for pat in TRUST_BOUNDARY_SINKS:
            assert pat in origin, f"pattern drifted from origin rule: {pat}"

    def test_generated_yaml_shape(self):
        from packages.semgrep.source_wrapper_rules import generate_rules_yaml
        s, _ = _summaries(_PKG + """
public class H {
    public String grab(HttpServletRequest req, String p) {
        return req.getParameter(p);
    }
}""")
        text = generate_rules_yaml(s.values())
        import json
        doc = json.loads(text)
        ids = [r["id"] for r in doc["rules"]]
        assert "raptor.generated.source-wrapper.xss" in ids
        srcs = doc["rules"][0]["pattern-sources"][0]["pattern-either"]
        assert {"pattern": "(H $W).grab(...)"} in srcs
        assert generate_rules_yaml([]) is None

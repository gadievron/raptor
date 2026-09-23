"""Tests for nosemgrep inline-suppression extraction and SARIF annotation."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from packages.semgrep.nosemgrep import annotate_sarif, extract_nosemgrep


# ── extract_nosemgrep ────────────────────────────────────────────────────────


class TestExtractNosemgrep:
    def test_inline_same_line(self, tmp_path):
        src = tmp_path / "a.py"
        src.write_text("x = eval(inp)  # nosemgrep: python.eval-usage\n")
        result = extract_nosemgrep(src, 1)
        assert result is not None
        assert result["suppressed"] is True
        assert result["rule_ids"] == ["python.eval-usage"]
        assert result["comment_line"] == 1

    def test_comment_line_above(self, tmp_path):
        src = tmp_path / "a.py"
        src.write_text("# nosemgrep: rule-id reason text\nx = eval(inp)\n")
        result = extract_nosemgrep(src, 2)
        assert result is not None
        assert result["rule_ids"] == ["rule-id"]
        assert result["justification"] == "reason text"
        assert result["comment_line"] == 1

    def test_blanket_suppression(self, tmp_path):
        src = tmp_path / "a.py"
        src.write_text("x = eval(inp)  # nosemgrep\n")
        result = extract_nosemgrep(src, 1)
        assert result is not None
        assert result["rule_ids"] == []
        assert result["justification"] is None

    def test_multiple_rule_ids(self, tmp_path):
        src = tmp_path / "a.py"
        src.write_text("x = eval(inp)  # nosemgrep: rule-a,rule-b,rule-c\n")
        result = extract_nosemgrep(src, 1)
        assert result["rule_ids"] == ["rule-a", "rule-b", "rule-c"]

    def test_c_style_comment(self, tmp_path):
        src = tmp_path / "a.c"
        src.write_text("strcpy(dst, src); // nosemgrep: cwe-120\n")
        result = extract_nosemgrep(src, 1)
        assert result is not None
        assert result["rule_ids"] == ["cwe-120"]

    def test_block_comment(self, tmp_path):
        src = tmp_path / "a.c"
        src.write_text("strcpy(dst, src); /* nosemgrep: cwe-120 */\n")
        result = extract_nosemgrep(src, 1)
        assert result is not None

    def test_no_nosemgrep(self, tmp_path):
        src = tmp_path / "a.py"
        src.write_text("x = eval(inp)\ny = 42\n")
        assert extract_nosemgrep(src, 1) is None
        assert extract_nosemgrep(src, 2) is None

    def test_missing_file(self, tmp_path):
        assert extract_nosemgrep(tmp_path / "missing.py", 1) is None

    def test_line_out_of_range(self, tmp_path):
        src = tmp_path / "a.py"
        src.write_text("x = 1\n")
        assert extract_nosemgrep(src, 100) is None

    def test_justification_with_colon_in_rule(self, tmp_path):
        src = tmp_path / "a.py"
        src.write_text(
            "x = eval(inp)  # nosemgrep: python.lang.eval-usage safe constant\n"
        )
        result = extract_nosemgrep(src, 1)
        assert result["rule_ids"] == ["python.lang.eval-usage"]
        assert result["justification"] == "safe constant"

    def test_preloaded_lines(self, tmp_path):
        lines = ["x = eval(inp)  # nosemgrep: rule-id reason"]
        result = extract_nosemgrep(tmp_path / "unused.py", 1, _lines=lines)
        assert result is not None
        assert result["rule_ids"] == ["rule-id"]


# ── annotate_sarif ───────────────────────────────────────────────────────────


def _make_sarif_data(results, tool_name=None):
    run = {"results": results}
    if tool_name:
        run["tool"] = {"driver": {"name": tool_name}}
    return {"runs": [run]}


def _make_result(uri, line):
    return {
        "ruleId": "test.rule",
        "message": {"text": "test"},
        "level": "warning",
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": uri},
                "region": {"startLine": line},
            },
        }],
    }


class TestAnnotateSarif:
    def test_annotates_suppressed_result(self, tmp_path):
        src = tmp_path / "a.py"
        src.write_text("x = eval(inp)  # nosemgrep: test.rule safe use\n")
        result = _make_result("a.py", 1)
        sarif = _make_sarif_data([result])

        count = annotate_sarif(sarif, str(tmp_path))

        assert count == 1
        nosem = result["properties"]["nosemgrep"]
        assert nosem["suppressed"] is True
        assert nosem["rule_ids"] == ["test.rule"]
        assert nosem["justification"] == "safe use"

    def test_skips_unsuppressed_result(self, tmp_path):
        src = tmp_path / "a.py"
        src.write_text("x = eval(inp)\n")
        result = _make_result("a.py", 1)
        sarif = _make_sarif_data([result])

        count = annotate_sarif(sarif, str(tmp_path))

        assert count == 0
        assert "properties" not in result or "nosemgrep" not in result.get("properties", {})

    def test_mixed_results(self, tmp_path):
        src = tmp_path / "a.py"
        src.write_text("x = eval(inp)  # nosemgrep\ny = eval(inp)\n")
        r1 = _make_result("a.py", 1)
        r2 = _make_result("a.py", 2)
        sarif = _make_sarif_data([r1, r2])

        count = annotate_sarif(sarif, str(tmp_path))

        assert count == 1
        assert "nosemgrep" in r1.get("properties", {})
        assert "nosemgrep" not in r2.get("properties", {})

    def test_missing_file_graceful(self, tmp_path):
        result = _make_result("missing.py", 1)
        sarif = _make_sarif_data([result])

        count = annotate_sarif(sarif, str(tmp_path))
        assert count == 0

    def test_preserves_existing_properties(self, tmp_path):
        src = tmp_path / "a.py"
        src.write_text("x = eval(inp)  # nosemgrep\n")
        result = _make_result("a.py", 1)
        result["properties"] = {"cwe": "CWE-94"}
        sarif = _make_sarif_data([result])

        annotate_sarif(sarif, str(tmp_path))

        assert result["properties"]["cwe"] == "CWE-94"
        assert result["properties"]["nosemgrep"]["suppressed"] is True

    def test_file_uri_prefix(self, tmp_path):
        src = tmp_path / "a.py"
        src.write_text("x = eval(inp)  # nosemgrep\n")
        abs_path = str(src)
        result = _make_result(f"file://{abs_path}", 1)
        sarif = _make_sarif_data([result])

        count = annotate_sarif(sarif, str(tmp_path))
        assert count == 1

    def test_skips_codeql_run(self, tmp_path):
        src = tmp_path / "a.py"
        src.write_text("x = eval(inp)  # nosemgrep\n")
        result = _make_result("a.py", 1)
        sarif = _make_sarif_data([result], tool_name="CodeQL")

        count = annotate_sarif(sarif, str(tmp_path))
        assert count == 0
        assert "nosemgrep" not in result.get("properties", {})

    def test_skips_coccinelle_run(self, tmp_path):
        src = tmp_path / "a.c"
        src.write_text("strcpy(dst, src); // nosemgrep\n")
        result = _make_result("a.c", 1)
        sarif = _make_sarif_data([result], tool_name="coccinelle")

        count = annotate_sarif(sarif, str(tmp_path))
        assert count == 0

    def test_annotates_semgrep_run(self, tmp_path):
        src = tmp_path / "a.py"
        src.write_text("x = eval(inp)  # nosemgrep\n")
        result = _make_result("a.py", 1)
        sarif = _make_sarif_data([result], tool_name="Semgrep OSS")

        count = annotate_sarif(sarif, str(tmp_path))
        assert count == 1

    def test_annotates_unnamed_tool_run(self, tmp_path):
        """Runs without tool.driver.name (legacy SARIF) are assumed semgrep."""
        src = tmp_path / "a.py"
        src.write_text("x = eval(inp)  # nosemgrep\n")
        result = _make_result("a.py", 1)
        sarif = _make_sarif_data([result])  # no tool_name

        count = annotate_sarif(sarif, str(tmp_path))
        assert count == 1

    def test_mixed_tool_runs(self, tmp_path):
        """Only semgrep run annotated, CodeQL run skipped."""
        src = tmp_path / "a.py"
        src.write_text("x = eval(inp)  # nosemgrep\n")
        r_sem = _make_result("a.py", 1)
        r_cql = _make_result("a.py", 1)
        sarif = {
            "runs": [
                {"tool": {"driver": {"name": "Semgrep OSS"}}, "results": [r_sem]},
                {"tool": {"driver": {"name": "CodeQL"}}, "results": [r_cql]},
            ]
        }

        count = annotate_sarif(sarif, str(tmp_path))
        assert count == 1
        assert "nosemgrep" in r_sem.get("properties", {})
        assert "nosemgrep" not in r_cql.get("properties", {})


class TestAnnotateSarifContainment:
    """URIs derive from SARIF over an untrusted repo — reads must stay
    under the repo root (out-of-tree files must never be quoted into
    properties.nosemgrep.justification)."""

    def _outside(self, tmp_path):
        outside = tmp_path / "outside.py"
        outside.write_text("x = 1  # nosemgrep: test.rule leaked-text\n")
        root = tmp_path / "repo"
        root.mkdir()
        return outside, root

    def test_file_uri_outside_root_refused(self, tmp_path):
        outside, root = self._outside(tmp_path)
        result = _make_result(f"file://{outside}", 1)
        sarif = _make_sarif_data([result])
        assert annotate_sarif(sarif, str(root)) == 0
        assert "properties" not in result

    def test_absolute_uri_outside_root_refused(self, tmp_path):
        outside, root = self._outside(tmp_path)
        result = _make_result(str(outside), 1)
        sarif = _make_sarif_data([result])
        assert annotate_sarif(sarif, str(root)) == 0
        assert "properties" not in result

    def test_traversal_uri_refused(self, tmp_path):
        _outside, root = self._outside(tmp_path)
        result = _make_result("../outside.py", 1)
        sarif = _make_sarif_data([result])
        assert annotate_sarif(sarif, str(root)) == 0
        assert "properties" not in result

    def test_file_uri_inside_root_still_annotates(self, tmp_path):
        src = tmp_path / "a.py"
        src.write_text("x = eval(inp)  # nosemgrep: test.rule ok\n")
        result = _make_result(f"file://{src}", 1)
        sarif = _make_sarif_data([result])
        assert annotate_sarif(sarif, str(tmp_path)) == 1


# ── build_cmd flag ───────────────────────────────────────────────────────────


class TestBuildCmdDisableNosemgrep:
    def test_disable_nosemgrep_in_cmd(self):
        from packages.semgrep.runner import build_cmd
        cmd = build_cmd(Path("/src"), "p/security-audit")
        assert "--disable-nosem" in cmd


class TestAnnotateSarifMalformedShapes:
    """One malformed result must never abort the whole SARIF merge.

    Explicit ``null`` / wrong-typed nodes at any level read as absent;
    well-formed sibling results still get annotated.
    """

    @staticmethod
    def _suppressed_source(tmp_path):
        src = tmp_path / "a.py"
        src.write_text(
            "x = eval(inp)  # nosemgrep: test.rule safe use\n",
        )
        return src

    def _assert_sibling_survives(self, tmp_path, bad_result):
        self._suppressed_source(tmp_path)
        good = _make_result("a.py", 1)
        sarif = _make_sarif_data([bad_result, good])
        assert annotate_sarif(sarif, str(tmp_path)) == 1
        assert good["properties"]["nosemgrep"]["suppressed"] is True

    def test_null_physical_location(self, tmp_path):
        self._assert_sibling_survives(
            tmp_path, {"locations": [{"physicalLocation": None}]},
        )

    def test_null_artifact_location_and_region(self, tmp_path):
        self._assert_sibling_survives(tmp_path, {
            "locations": [{"physicalLocation": {
                "artifactLocation": None, "region": None,
            }}],
        })

    def test_wrong_typed_uri_and_line(self, tmp_path):
        self._assert_sibling_survives(tmp_path, {
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": 7},
                "region": {"startLine": "12"},
            }}],
        })

    def test_null_locations_and_results(self, tmp_path):
        self._suppressed_source(tmp_path)
        good = _make_result("a.py", 1)
        sarif = {"runs": [
            {"results": None},
            {"results": [{"locations": None}, good]},
        ]}
        assert annotate_sarif(sarif, str(tmp_path)) == 1

    def test_null_tool_and_driver(self, tmp_path):
        self._suppressed_source(tmp_path)
        good = _make_result("a.py", 1)
        sarif = {"runs": [{"tool": None, "results": [good]}]}
        assert annotate_sarif(sarif, str(tmp_path)) == 1
        sarif2 = {"runs": [{"tool": {"driver": None},
                            "results": [_make_result("a.py", 1)]}]}
        assert annotate_sarif(sarif2, str(tmp_path)) == 1

    def test_null_runs_returns_zero(self, tmp_path):
        assert annotate_sarif({"runs": None}, str(tmp_path)) == 0

    def test_non_dict_properties_skipped_not_clobbered(self, tmp_path):
        self._suppressed_source(tmp_path)
        bad = _make_result("a.py", 1)
        bad["properties"] = "already-a-string"
        good = _make_result("a.py", 1)
        sarif = _make_sarif_data([bad, good])
        assert annotate_sarif(sarif, str(tmp_path)) == 1
        assert bad["properties"] == "already-a-string"


class TestStandaloneReadIsCapped:
    def test_extract_nosemgrep_routes_through_the_capped_reader(
        self, tmp_path, monkeypatch,
    ):
        """The standalone path (no _lines) must use the same capped
        read as annotate_sarif's _FileCache — it read files
        unbounded."""
        import packages.semgrep.nosemgrep as ns

        f = tmp_path / "a.py"
        f.write_text("x = 1  # nosemgrep: rule1\n")
        calls = {"n": 0}
        real = ns.read_text_capped

        def counting(path, *a, **kw):
            calls["n"] += 1
            return real(path, *a, **kw)

        monkeypatch.setattr(ns, "read_text_capped", counting)

        def _no_unbounded(self, *a, **kw):  # pragma: no cover
            raise AssertionError("unbounded Path.read_text used")

        monkeypatch.setattr(Path, "read_text", _no_unbounded)
        got = extract_nosemgrep(f, 1)
        assert got is not None and got["suppressed"] is True
        assert calls["n"] == 1

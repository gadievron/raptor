"""Tests for SARIF parser reliability and untrusted-input hardening."""

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock


def _write_sarif(dirpath, sarif_dict, name="test.sarif"):
    """Serialize a SARIF dict into dirpath and return the file path."""
    path = Path(dirpath) / name
    path.write_text(json.dumps(sarif_dict))
    return path


def _result(rule_id="R-1", uri="src/main.c", **region):
    """Minimal SARIF result with a single physical location."""
    region = region or {"startLine": 1}
    return {
        "ruleId": rule_id,
        "message": {"text": "finding"},
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": uri},
                "region": region,
            }
        }],
        "level": "error",
    }


def _sarif(results, tool="testtool", rules=None):
    """Minimal single-run SARIF document."""
    return {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": tool, "rules": rules or []}},
            "results": results,
        }],
    }


class TestSarifSizeGuard(unittest.TestCase):
    """Test that oversized SARIF files are rejected."""

    def test_rejects_file_over_100mib(self):
        """Size guard rejects files exceeding 100 MiB."""
        from core.sarif.parser import parse_sarif_findings

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "big.sarif"
            path.write_text('{"runs": []}')

            original_stat = path.stat
            call_count = [0]

            def fake_stat(self_path, **kwargs):
                # Only fake the size check (second stat call), not exists()
                call_count[0] += 1
                real = original_stat(**kwargs)
                if call_count[0] >= 2:
                    mock_result = MagicMock()
                    mock_result.st_size = 200 * 1024 * 1024
                    mock_result.st_mode = real.st_mode
                    return mock_result
                return real

            from unittest.mock import patch
            with patch.object(type(path), 'stat', fake_stat):
                result = parse_sarif_findings(path)

            self.assertEqual(result, [])

    def test_accepts_normal_file(self):
        """Normal SARIF files are parsed correctly."""
        from core.sarif.parser import parse_sarif_findings

        sarif_data = {
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {"name": "test", "rules": []}},
                "results": [{
                    "ruleId": "test-rule",
                    "message": {"text": "test finding"},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": "test.c"},
                            "region": {"startLine": 1}
                        }
                    }],
                    "level": "error"
                }]
            }]
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "normal.sarif"
            path.write_text(json.dumps(sarif_data))

            result = parse_sarif_findings(path)
            self.assertEqual(len(result), 1)
            self.assertEqual(result[0]["rule_id"], "test-rule")

    def test_rejects_nonexistent_file(self):
        from core.sarif.parser import parse_sarif_findings

        result = parse_sarif_findings(Path("/nonexistent/file.sarif"))
        self.assertEqual(result, [])

    def test_rejects_invalid_json(self):
        from core.sarif.parser import parse_sarif_findings

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "bad.sarif"
            path.write_text("not json{{{")

            result = parse_sarif_findings(path)
            self.assertEqual(result, [])


class TestLoadSarif(unittest.TestCase):
    """Test load_sarif — the single I/O entry point for SARIF files."""

    def test_returns_dict_for_valid_file(self):
        from core.sarif.parser import load_sarif

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "valid.sarif"
            path.write_text('{"version": "2.1.0", "runs": []}')

            result = load_sarif(path)
            self.assertIsInstance(result, dict)
            self.assertEqual(result["version"], "2.1.0")

    def test_returns_none_for_nonexistent(self):
        from core.sarif.parser import load_sarif

        self.assertIsNone(load_sarif(Path("/nonexistent.sarif")))

    def test_returns_none_for_invalid_json(self):
        from core.sarif.parser import load_sarif

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "bad.sarif"
            path.write_text("{broken")

            self.assertIsNone(load_sarif(path))

    def test_returns_none_for_non_object(self):
        from core.sarif.parser import load_sarif

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "array.sarif"
            path.write_text('[1, 2, 3]')

            self.assertIsNone(load_sarif(path))


class TestMergeSarif(unittest.TestCase):
    """Test merge_sarif — combines multiple SARIF files."""

    def test_merges_different_tools(self):
        from core.sarif.parser import merge_sarif

        with tempfile.TemporaryDirectory() as tmpdir:
            p1 = Path(tmpdir) / "a.sarif"
            p2 = Path(tmpdir) / "b.sarif"
            p1.write_text(json.dumps({"runs": [{"tool": {"driver": {"name": "ToolA"}}, "results": [{"ruleId": "r1"}]}]}))
            p2.write_text(json.dumps({"runs": [{"tool": {"driver": {"name": "ToolB"}}, "results": [{"ruleId": "r2"}]}]}))

            merged = merge_sarif([str(p1), str(p2)])
            self.assertEqual(len(merged["runs"]), 2)

    def test_dedup_same_tool(self):
        from core.sarif.parser import merge_sarif

        result = {"ruleId": "r1", "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": "a.c"}, "region": {"startLine": 10}}}]}
        with tempfile.TemporaryDirectory() as tmpdir:
            p1 = Path(tmpdir) / "a.sarif"
            p2 = Path(tmpdir) / "b.sarif"
            p1.write_text(json.dumps({"runs": [{"tool": {"driver": {"name": "Semgrep"}}, "results": [result]}]}))
            p2.write_text(json.dumps({"runs": [{"tool": {"driver": {"name": "Semgrep"}}, "results": [result]}]}))

            merged = merge_sarif([str(p1), str(p2)])
            self.assertEqual(len(merged["runs"]), 1)
            self.assertEqual(len(merged["runs"][0]["results"]), 1)

    def test_skips_invalid_files(self):
        from core.sarif.parser import merge_sarif

        with tempfile.TemporaryDirectory() as tmpdir:
            good = Path(tmpdir) / "good.sarif"
            good.write_text(json.dumps({"runs": [{"tool": {"driver": {"name": "T"}}, "results": []}]}))

            merged = merge_sarif([str(good), "/nonexistent.sarif"])
            self.assertEqual(len(merged["runs"]), 1)

    def test_empty_input(self):
        from core.sarif.parser import merge_sarif

        merged = merge_sarif([])
        self.assertEqual(merged["runs"], [])

    def test_merge_skips_non_object_runs_and_results(self):
        from core.sarif.parser import merge_sarif

        sarif = {
            "version": "2.1.0",
            "runs": [
                "bogus",
                {
                    "tool": {"driver": {"name": "t"}},
                    "results": ["bogus", _result()],
                },
            ],
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            path = _write_sarif(tmpdir, sarif)
            merged = merge_sarif([str(path)])
        self.assertEqual(len(merged["runs"]), 1)
        self.assertEqual(len(merged["runs"][0]["results"]), 1)

    def test_merge_null_tool_block(self):
        from core.sarif.parser import merge_sarif

        sarif = {
            "version": "2.1.0",
            "runs": [{"tool": None, "results": [_result()]}],
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            path = _write_sarif(tmpdir, sarif)
            merged = merge_sarif([str(path)])
        self.assertEqual(len(merged["runs"][0]["results"]), 1)

    def test_result_key_malformed_fields_hashable(self):
        from core.sarif.parser import _result_key

        result = {
            "ruleId": {"weird": 1},
            "locations": ["bogus"],
            "partialFingerprints": {"primaryLocationLineHash": {"d": 1}},
        }
        key = _result_key(result)
        hash(key)  # must be usable as a dict key

    def test_result_key_line_coercion(self):
        from core.sarif.parser import _result_key

        r1 = _result(startLine="abc")
        r2 = _result(startLine=1.0)
        self.assertEqual(_result_key(r1)[2], 0)
        self.assertEqual(_result_key(r2)[2], 1)


class TestSarifHelpers(unittest.TestCase):
    """Test get_tool_name and get_rules helpers."""

    def test_get_tool_name(self):
        from core.sarif.parser import get_tool_name

        run = {"tool": {"driver": {"name": "Semgrep OSS"}}}
        self.assertEqual(get_tool_name(run), "Semgrep OSS")

    def test_get_tool_name_missing(self):
        from core.sarif.parser import get_tool_name

        self.assertEqual(get_tool_name({}), "unknown")

    def test_get_rules(self):
        from core.sarif.parser import get_rules

        run = {"tool": {"driver": {"rules": [
            {"id": "rule-1", "shortDescription": {"text": "test"}},
            {"id": "rule-2"},
        ]}}}
        rules = get_rules(run)
        self.assertEqual(len(rules), 2)
        self.assertIn("rule-1", rules)
        self.assertIn("rule-2", rules)

    def test_get_rules_empty(self):
        from core.sarif.parser import get_rules

        self.assertEqual(get_rules({}), {})

    def test_get_rules_skips_no_id(self):
        from core.sarif.parser import get_rules

        run = {"tool": {"driver": {"rules": [
            {"id": "valid"},
            {"shortDescription": {"text": "no id"}},
        ]}}}
        rules = get_rules(run)
        self.assertEqual(len(rules), 1)
        self.assertIn("valid", rules)

    def test_get_tool_name_null_tool(self):
        from core.sarif.parser import get_tool_name

        self.assertEqual(get_tool_name({"tool": None}), "unknown")
        self.assertEqual(get_tool_name({"tool": "bogus"}), "unknown")
        self.assertEqual(
            get_tool_name({"tool": {"driver": {"name": None}}}), "unknown"
        )
        self.assertEqual(
            get_tool_name({"tool": {"driver": {"name": ""}}}), "unknown"
        )
        self.assertEqual(
            get_tool_name({"tool": {"driver": {"name": "x"}}}), "x"
        )

    def test_get_rules_malformed(self):
        from core.sarif.parser import get_rules

        self.assertEqual(get_rules({"tool": None}), {})
        self.assertEqual(
            get_rules({"tool": {"driver": {"rules": "bogus"}}}), {}
        )
        rules = {"tool": {"driver": {"rules": [
            "bogus", {"id": 7}, {"id": "ok"},
        ]}}}
        self.assertEqual(list(get_rules(rules)), ["ok"])

    def test_rule_properties_wrong_type(self):
        from core.sarif.parser import parse_sarif_findings

        rules = [{"id": "R-1", "properties": "bogus"},
                 {"id": "R-2", "properties": {"tags": "bogus"}}]
        results = [_result(rule_id="R-1"), _result(rule_id="R-2")]
        with tempfile.TemporaryDirectory() as tmpdir:
            path = _write_sarif(tmpdir, _sarif(results, rules=rules))
            findings = parse_sarif_findings(path)
        self.assertEqual([f["cwe_id"] for f in findings], [None, None])


class TestFindingsByTool(unittest.TestCase):
    """generate_scan_metrics populates findings_by_tool from SARIF driver names."""

    def test_findings_by_tool_from_sarif_driver_names(self):
        from core.sarif.parser import generate_scan_metrics

        with tempfile.TemporaryDirectory() as tmpdir:
            sem = Path(tmpdir) / "sem.sarif"
            sem.write_text(json.dumps({"runs": [{
                "tool": {"driver": {"name": "Semgrep OSS"}},
                "results": [{"ruleId": "r1"}, {"ruleId": "r2"}],
            }]}))
            cocci = Path(tmpdir) / "cocci.sarif"
            cocci.write_text(json.dumps({"runs": [{
                "tool": {"driver": {"name": "coccinelle"}},
                "results": [{"ruleId": "r3"}],
            }]}))
            cql = Path(tmpdir) / "cql.sarif"
            cql.write_text(json.dumps({"runs": [{
                "tool": {"driver": {"name": "CodeQL"}},
                "results": [{"ruleId": "cpp/r4"}, {"ruleId": "cpp/r5"}, {"ruleId": "cpp/r6"}],
            }]}))
            metrics = generate_scan_metrics([str(sem), str(cocci), str(cql)])

        by_tool = metrics["findings_by_tool"]
        self.assertEqual(by_tool["semgrep"], 2)
        self.assertEqual(by_tool["coccinelle"], 1)
        self.assertEqual(by_tool["codeql"], 3)

    def test_normalise_tool_name(self):
        from core.sarif.parser import _normalise_tool_name

        self.assertEqual(_normalise_tool_name("Semgrep OSS"), "semgrep")
        self.assertEqual(_normalise_tool_name("CodeQL"), "codeql")
        self.assertEqual(_normalise_tool_name("coccinelle"), "coccinelle")
        self.assertEqual(_normalise_tool_name("CustomTool"), "customtool")


class TestMetricsHardening(unittest.TestCase):
    """generate_scan_metrics survives non-object runs/results and
    wrong-typed rule/level fields."""

    def test_metrics_survive_malformed_runs(self):
        from core.sarif.parser import generate_scan_metrics

        sarif = {
            "version": "2.1.0",
            "runs": [
                "bogus",
                {
                    "tool": {"driver": {"name": "t"}},
                    "artifacts": None,
                    "results": [
                        "bogus",
                        {"ruleId": {"weird": 1}, "level": {"weird": 1}},
                        _result(),
                    ],
                },
            ],
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            path = _write_sarif(tmpdir, sarif)
            metrics = generate_scan_metrics([str(path)])
        self.assertEqual(metrics["total_findings"], 3)
        self.assertEqual(metrics["findings_by_rule"]["unknown"], 1)
        self.assertEqual(metrics["findings_by_rule"]["R-1"], 1)
        self.assertEqual(metrics["findings_by_severity"]["error"], 1)


class TestNullPhysicalLocation(unittest.TestCase):
    """SARIF allows explicit null values for location fields."""

    def test_null_physical_location_does_not_crash(self):
        from core.sarif.parser import parse_sarif_findings

        sarif = {
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {"name": "test", "rules": []}},
                "results": [{
                    "ruleId": "test-rule",
                    "message": {"text": "finding"},
                    "locations": [{
                        "physicalLocation": None,
                    }],
                }],
            }],
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "null-loc.sarif"
            path.write_text(json.dumps(sarif))
            findings = parse_sarif_findings(path)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["rule_id"], "test-rule")
        self.assertIsNone(findings[0]["file"])

    def test_null_artifact_location_does_not_crash(self):
        from core.sarif.parser import parse_sarif_findings

        sarif = {
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {"name": "test", "rules": []}},
                "results": [{
                    "ruleId": "test-rule",
                    "message": {"text": "finding"},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": None,
                            "region": None,
                        },
                    }],
                }],
            }],
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "null-artifact.sarif"
            path.write_text(json.dumps(sarif))
            findings = parse_sarif_findings(path)
        self.assertEqual(len(findings), 1)
        self.assertIsNone(findings[0]["file"])


class TestCoerceLine(unittest.TestCase):
    """_coerce_line — the gate on untrusted numeric line fields."""

    def test_int_passes(self):
        from core.sarif.parser import _coerce_line

        self.assertEqual(_coerce_line(42), 42)

    def test_zero_and_negative_kept_as_ints(self):
        from core.sarif.parser import _coerce_line

        self.assertEqual(_coerce_line(0), 0)
        self.assertEqual(_coerce_line(-3), -3)

    def test_integral_float_coerced(self):
        from core.sarif.parser import _coerce_line

        self.assertEqual(_coerce_line(12.0), 12)

    def test_string_rejected(self):
        from core.sarif.parser import _coerce_line

        self.assertIsNone(_coerce_line("abc"))
        self.assertIsNone(_coerce_line("12"))

    def test_infinity_and_nan_rejected(self):
        from core.sarif.parser import _coerce_line

        self.assertIsNone(_coerce_line(float("inf")))
        self.assertIsNone(_coerce_line(float("-inf")))
        self.assertIsNone(_coerce_line(float("nan")))

    def test_non_integral_float_rejected(self):
        from core.sarif.parser import _coerce_line

        self.assertIsNone(_coerce_line(1.5))

    def test_bool_rejected(self):
        from core.sarif.parser import _coerce_line

        self.assertIsNone(_coerce_line(True))
        self.assertIsNone(_coerce_line(False))

    def test_none_and_objects_rejected(self):
        from core.sarif.parser import _coerce_line

        self.assertIsNone(_coerce_line(None))
        self.assertIsNone(_coerce_line({"x": 1}))
        self.assertIsNone(_coerce_line([1]))


class TestParserLineCoercion(unittest.TestCase):
    """Crafted SARIF with string / Infinity line numbers must not crash
    the import — invalid values come out as None."""

    def test_string_startline_becomes_none(self):
        from core.sarif.parser import parse_sarif_findings

        with tempfile.TemporaryDirectory() as tmpdir:
            path = _write_sarif(
                tmpdir, _sarif([_result(startLine="abc", endLine="def")])
            )
            findings = parse_sarif_findings(path)
        self.assertEqual(len(findings), 1)
        self.assertIsNone(findings[0]["startLine"])
        self.assertIsNone(findings[0]["endLine"])

    def test_infinity_startline_becomes_none(self):
        # json.dumps(allow_nan=True) emits bare Infinity, which
        # CPython's json.loads accepts by default.
        from core.sarif.parser import parse_sarif_findings

        with tempfile.TemporaryDirectory() as tmpdir:
            path = _write_sarif(
                tmpdir, _sarif([_result(startLine=float("inf"))])
            )
            findings = parse_sarif_findings(path)
        self.assertIsNone(findings[0]["startLine"])

    def test_integral_float_startline_coerced_to_int(self):
        from core.sarif.parser import parse_sarif_findings

        with tempfile.TemporaryDirectory() as tmpdir:
            path = _write_sarif(
                tmpdir, _sarif([_result(startLine=7.0, endLine=9.0)])
            )
            findings = parse_sarif_findings(path)
        self.assertEqual(findings[0]["startLine"], 7)
        self.assertEqual(findings[0]["endLine"], 9)

    def test_valid_lines_unchanged(self):
        from core.sarif.parser import parse_sarif_findings

        with tempfile.TemporaryDirectory() as tmpdir:
            path = _write_sarif(
                tmpdir, _sarif([_result(startLine=3, endLine=5)])
            )
            findings = parse_sarif_findings(path)
        self.assertEqual(findings[0]["startLine"], 3)
        self.assertEqual(findings[0]["endLine"], 5)

    def test_dataflow_step_line_coerced(self):
        from core.sarif.parser import extract_dataflow_path

        flows = [{
            "threadFlows": [{
                "locations": [
                    {"location": {"physicalLocation": {
                        "artifactLocation": {"uri": "a.c"},
                        "region": {"startLine": "evil", "startColumn": 2},
                    }}},
                    {"location": {"physicalLocation": {
                        "artifactLocation": {"uri": "b.c"},
                        "region": {"startLine": 9},
                    }}},
                ]
            }]
        }]
        path = extract_dataflow_path(flows)
        self.assertIsNotNone(path)
        self.assertEqual(path["source"]["line"], 0)
        self.assertEqual(path["source"]["column"], 2)
        self.assertEqual(path["sink"]["line"], 9)


class TestMalformedShapes(unittest.TestCase):
    """Untrusted-shape hardening in parse_sarif_findings: non-object
    runs/results, null or wrong-typed nesting."""

    def test_non_object_run_skipped(self):
        from core.sarif.parser import parse_sarif_findings

        sarif = {"version": "2.1.0", "runs": ["bogus", 42, None]}
        with tempfile.TemporaryDirectory() as tmpdir:
            path = _write_sarif(tmpdir, sarif)
            self.assertEqual(parse_sarif_findings(path), [])

    def test_non_object_result_skipped(self):
        from core.sarif.parser import parse_sarif_findings

        sarif = _sarif(["bogus", _result(), 17])
        with tempfile.TemporaryDirectory() as tmpdir:
            path = _write_sarif(tmpdir, sarif)
            findings = parse_sarif_findings(path)
        self.assertEqual(len(findings), 1)

    def test_non_array_results_skipped(self):
        from core.sarif.parser import parse_sarif_findings

        sarif = {
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "t"}}, "results": "oops"}],
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            path = _write_sarif(tmpdir, sarif)
            self.assertEqual(parse_sarif_findings(path), [])

    def test_null_message_and_level(self):
        from core.sarif.parser import parse_sarif_findings

        result = _result()
        result["message"] = None
        result["level"] = None
        with tempfile.TemporaryDirectory() as tmpdir:
            path = _write_sarif(tmpdir, _sarif([result]))
            findings = parse_sarif_findings(path)
        self.assertIsNone(findings[0]["message"])
        self.assertEqual(findings[0]["level"], "warning")

    def test_wrong_typed_nesting(self):
        from core.sarif.parser import parse_sarif_findings

        result = {
            "ruleId": {"not": "a-string"},
            "message": "bare string not object",
            "locations": ["bogus"],
            "fingerprints": "bogus",
            "level": 3,
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            path = _write_sarif(tmpdir, _sarif([result]))
            findings = parse_sarif_findings(path)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertIsNone(f["rule_id"])
        self.assertIsNone(f["message"])
        self.assertIsNone(f["file"])
        self.assertEqual(f["level"], "warning")
        # finding_id falls back to the deterministic hash
        self.assertIsInstance(f["finding_id"], str)
        self.assertEqual(len(f["finding_id"]), 64)

    def test_non_string_snippet_text(self):
        from core.sarif.parser import parse_sarif_findings

        result = _result()
        result["locations"][0]["physicalLocation"]["region"]["snippet"] = {
            "text": {"nested": True}
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            path = _write_sarif(tmpdir, _sarif([result]))
            findings = parse_sarif_findings(path)
        self.assertEqual(findings[0]["snippet"], "")

    def test_non_string_uri_dropped(self):
        from core.sarif.parser import parse_sarif_findings

        result = _result()
        result["locations"][0]["physicalLocation"]["artifactLocation"] = {
            "uri": ["not-a-string"]
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            path = _write_sarif(tmpdir, _sarif([result]))
            findings = parse_sarif_findings(path)
        self.assertIsNone(findings[0]["file"])

    def test_non_string_uri_base_id_ignored(self):
        from core.sarif.parser import parse_sarif_findings

        result = _result()
        result["locations"][0]["physicalLocation"]["artifactLocation"][
            "uriBaseId"
        ] = {"weird": 1}
        sarif = _sarif([result])
        sarif["runs"][0]["originalUriBaseIds"] = "bogus"
        with tempfile.TemporaryDirectory() as tmpdir:
            path = _write_sarif(tmpdir, sarif)
            findings = parse_sarif_findings(path)
        self.assertEqual(findings[0]["file"], "src/main.c")

    def test_non_dict_rule_entries_ignored(self):
        from core.sarif.parser import parse_sarif_findings

        rules = ["bogus", {"id": {"weird": 1}}, {"id": "R-1",
                 "properties": {"cwe": "CWE-89"}}]
        with tempfile.TemporaryDirectory() as tmpdir:
            path = _write_sarif(tmpdir, _sarif([_result()], rules=rules))
            findings = parse_sarif_findings(path)
        self.assertEqual(findings[0]["cwe_id"], "CWE-89")


class TestSourceRootContainment(unittest.TestCase):
    """Opt-in containment check at the parse boundary: with a known
    source root, artifact URIs resolving outside it are skipped —
    matching how import_normalizer treats unmappable URIs."""

    @staticmethod
    def _sarif_with_uris(uris, uri_bases=None):
        run = {
            "tool": {"driver": {"name": "test", "rules": []}},
            "results": [
                {
                    "ruleId": f"rule-{i}",
                    "message": {"text": "finding"},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": art,
                            "region": {"startLine": 1},
                        }
                    }],
                }
                for i, art in enumerate(uris)
            ],
        }
        if uri_bases:
            run["originalUriBaseIds"] = uri_bases
        return {"version": "2.1.0", "runs": [run]}

    def _parse(self, sarif, source_root=None):
        from core.sarif.parser import parse_sarif_findings

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "t.sarif"
            path.write_text(json.dumps(sarif))
            return parse_sarif_findings(path, source_root=source_root)

    def test_in_root_relative_uri_kept_identical(self):
        """With a root, in-root findings come out exactly as without."""
        sarif = self._sarif_with_uris([{"uri": "src/foo.c"}])
        with tempfile.TemporaryDirectory() as root:
            with_root = self._parse(sarif, source_root=Path(root))
        without_root = self._parse(sarif)
        self.assertEqual(with_root, without_root)
        self.assertEqual(with_root[0]["file"], "src/foo.c")

    def test_traversal_uri_skipped_when_root_known(self):
        sarif = self._sarif_with_uris([
            {"uri": "../../etc/passwd"},
            {"uri": "src/ok.c"},
        ])
        with tempfile.TemporaryDirectory() as root:
            findings = self._parse(sarif, source_root=Path(root))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["file"], "src/ok.c")

    def test_percent_encoded_traversal_skipped(self):
        sarif = self._sarif_with_uris([{"uri": "%2e%2e/%2e%2e/etc/passwd"}])
        with tempfile.TemporaryDirectory() as root:
            findings = self._parse(sarif, source_root=Path(root))
        self.assertEqual(findings, [])

    def test_absolute_uri_outside_root_skipped(self):
        sarif = self._sarif_with_uris([{"uri": "file:///etc/passwd"}])
        with tempfile.TemporaryDirectory() as root:
            findings = self._parse(sarif, source_root=Path(root))
        self.assertEqual(findings, [])

    def test_absolute_uri_inside_root_kept(self):
        with tempfile.TemporaryDirectory() as root:
            resolved_root = Path(root).resolve()
            sarif = self._sarif_with_uris(
                [{"uri": f"file://{resolved_root}/src/foo.c"}]
            )
            findings = self._parse(sarif, source_root=Path(root))
        self.assertEqual(len(findings), 1)

    def test_base_joined_uri_escaping_root_skipped(self):
        """A benign-looking relative URI can still escape via a hostile
        originalUriBaseIds entry — the check runs AFTER base joining."""
        sarif = self._sarif_with_uris(
            [{"uri": "passwd", "uriBaseId": "EVIL"}],
            uri_bases={"EVIL": {"uri": "../../../etc/"}},
        )
        with tempfile.TemporaryDirectory() as root:
            findings = self._parse(sarif, source_root=Path(root))
        self.assertEqual(findings, [])

    def test_no_root_keeps_all_findings(self):
        """Back-compat: without source_root nothing is filtered."""
        sarif = self._sarif_with_uris([
            {"uri": "../../etc/passwd"},
            {"uri": "src/ok.c"},
        ])
        findings = self._parse(sarif)
        self.assertEqual(len(findings), 2)

    def test_missing_uri_not_filtered(self):
        """A result with no artifact URI is neither in- nor out-of-root;
        it passes through as before (file=None)."""
        sarif = self._sarif_with_uris([{}])
        with tempfile.TemporaryDirectory() as root:
            findings = self._parse(sarif, source_root=Path(root))
        self.assertEqual(len(findings), 1)
        self.assertIsNone(findings[0]["file"])


class TestValidateSchemaError(unittest.TestCase):
    """A structurally-invalid local schema file must not crash
    validate_sarif."""

    def test_invalid_schema_returns_none(self):
        if importlib.util.find_spec("jsonschema") is None:
            self.skipTest("jsonschema not installed")
        from core.sarif.parser import validate_sarif

        with tempfile.TemporaryDirectory() as tmpdir:
            sarif_path = _write_sarif(tmpdir, _sarif([_result()]))
            schema_path = Path(tmpdir) / "schema.json"
            # Structurally-invalid JSON Schema: "type" must not be an int.
            schema_path.write_text(json.dumps({"type": 12}))
            self.assertIsNone(
                validate_sarif(sarif_path, schema_path=schema_path)
            )


if __name__ == "__main__":
    unittest.main()

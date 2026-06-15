"""Tests for the SARIF import normalizer."""

import json
from pathlib import Path

from core.sarif.import_normalizer import (
    _infer_cwe,
    _is_sca_finding,
    _resolve_uri,
    _strip_file_scheme,
    findings_to_sarif,
    normalize_imported_findings,
    format_import_summary,
    import_provenance_block,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_finding(**overrides):
    """Minimal finding dict (same shape as parse_sarif_findings output)."""
    base = {
        "finding_id": "test-001",
        "rule_id": "test-rule",
        "message": "test finding",
        "file": "src/auth.c",
        "startLine": 42,
        "endLine": 42,
        "snippet": "",
        "level": "warning",
        "cwe_id": None,
        "tool": "TestScanner",
        "has_dataflow": False,
        "dataflow_path": None,
    }
    base.update(overrides)
    return base


def _source_tree(tmp_path):
    """Create a minimal source tree and return its root."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "auth.c").write_text(
        "int check_password(const char *pw) {\n"
        "    // line 2\n"
        "    // line 3\n"
        "    return strcmp(pw, stored);\n"
        "    // line 5\n"
        "}\n"
    )
    (tmp_path / "src" / "main.c").write_text("int main() { return 0; }\n")
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "utils.c").write_text("void helper() {}\n")
    return tmp_path


# ---------------------------------------------------------------------------
# _strip_file_scheme
# ---------------------------------------------------------------------------

class TestStripFileScheme:
    def test_triple_slash(self):
        assert _strip_file_scheme("file:///home/user/src/foo.c") == "home/user/src/foo.c"

    def test_double_slash(self):
        assert _strip_file_scheme("file://src/foo.c") == "src/foo.c"

    def test_no_scheme(self):
        assert _strip_file_scheme("src/foo.c") == "src/foo.c"

    def test_empty(self):
        assert _strip_file_scheme("") == ""


# ---------------------------------------------------------------------------
# _infer_cwe
# ---------------------------------------------------------------------------

class TestInferCwe:
    def test_sql_injection_in_message(self):
        assert _infer_cwe("generic-rule", "Possible SQL injection") == "CWE-89"

    def test_buffer_overflow_in_rule_id(self):
        assert _infer_cwe("buffer-overflow-check", "") == "CWE-120"

    def test_xss_in_message(self):
        assert _infer_cwe("web-001", "Cross-site scripting vulnerability") == "CWE-79"

    def test_explicit_cwe_in_message(self):
        assert _infer_cwe("generic", "Violation of CWE-416") == "CWE-416"

    def test_explicit_cwe_in_rule_id(self):
        assert _infer_cwe("CWE-787-oob-write", "some message") == "CWE-787"

    def test_use_after_free(self):
        assert _infer_cwe("memory-safety", "use after free detected") == "CWE-416"

    def test_null_deref(self):
        assert _infer_cwe("null-pointer-deref", "") == "CWE-476"

    def test_format_string(self):
        assert _infer_cwe("fmt", "format string vulnerability") == "CWE-134"

    def test_no_match(self):
        assert _infer_cwe("RULE-12345", "something happened") is None

    def test_command_injection(self):
        assert _infer_cwe("os-command", "OS command injection") == "CWE-78"

    def test_deserialization(self):
        assert _infer_cwe("deser", "unsafe deserialization") == "CWE-502"

    def test_ssrf(self):
        assert _infer_cwe("web", "server-side request forgery") == "CWE-918"

    def test_hardcoded_secret(self):
        assert _infer_cwe("cred", "hardcoded password in source") == "CWE-798"


# ---------------------------------------------------------------------------
# _resolve_uri
# ---------------------------------------------------------------------------

class TestResolveUri:
    def test_relative_path_direct_match(self, tmp_path):
        root = _source_tree(tmp_path)
        idx = {"auth.c": [Path("src/auth.c")]}
        cache = [None]
        assert _resolve_uri("src/auth.c", root, idx, cache) == "src/auth.c"

    def test_absolute_path_strip(self, tmp_path):
        root = _source_tree(tmp_path)
        idx = {"auth.c": [Path("src/auth.c")]}
        cache = [None]
        result = _resolve_uri("src/auth.c", root, idx, cache)
        assert result == "src/auth.c"

    def test_file_scheme_uri(self, tmp_path):
        root = _source_tree(tmp_path)
        idx = {"auth.c": [Path("src/auth.c")]}
        cache = [None]
        result = _resolve_uri(f"file:///{root}/src/auth.c", root, idx, cache)
        assert result == "src/auth.c"

    def test_url_encoded_path(self, tmp_path):
        root = _source_tree(tmp_path)
        (root / "src" / "my file.c").write_text("int x;")
        idx = {"my file.c": [Path("src/my file.c")]}
        cache = [None]
        result = _resolve_uri("src/my%20file.c", root, idx, cache)
        assert result == "src/my file.c"

    def test_basename_only_unique(self, tmp_path):
        root = _source_tree(tmp_path)
        idx = {"utils.c": [Path("lib/utils.c")]}
        cache = [None]
        result = _resolve_uri("/some/ci/path/utils.c", root, idx, cache)
        assert result == "lib/utils.c"

    def test_path_traversal_rejected(self, tmp_path):
        """SARIF URIs with ``..`` must not escape source_root."""
        root = _source_tree(tmp_path)
        idx = {}
        cache = [None]
        assert _resolve_uri("../../etc/passwd", root, idx, cache) is None
        assert _resolve_uri("src/../../../etc/shadow", root, idx, cache) is None

    def test_basename_ambiguous_returns_none(self, tmp_path):
        root = _source_tree(tmp_path)
        # auth.c only in src/, but simulate ambiguity
        (root / "lib" / "auth.c").write_text("int other;")
        idx = {"auth.c": [Path("src/auth.c"), Path("lib/auth.c")]}
        cache = [None]
        result = _resolve_uri("/unknown/path/auth.c", root, idx, cache)
        assert result is None

    def test_depth_cache_speedup(self, tmp_path):
        root = _source_tree(tmp_path)
        idx = {"auth.c": [Path("src/auth.c")], "main.c": [Path("src/main.c")]}
        cache = [None]
        # First resolution discovers depth
        _resolve_uri("/ci/workspace/src/auth.c", root, idx, cache)
        assert cache[0] is not None
        saved_depth = cache[0]
        # Second resolution uses cached depth
        result = _resolve_uri("/ci/workspace/src/main.c", root, idx, cache)
        assert result == "src/main.c"
        assert cache[0] == saved_depth

    def test_no_match_returns_none(self, tmp_path):
        root = _source_tree(tmp_path)
        idx = {}
        cache = [None]
        assert _resolve_uri("nonexistent.c", root, idx, cache) is None


# ---------------------------------------------------------------------------
# normalize_imported_findings
# ---------------------------------------------------------------------------

class TestNormalizeImportedFindings:
    def test_basic_passthrough(self, tmp_path):
        root = _source_tree(tmp_path)
        findings = [_make_finding(snippet="existing snippet")]
        result = normalize_imported_findings(findings, root)
        assert result.stats.total_imported == 1
        assert result.findings[0]["file"] == "src/auth.c"
        assert result.findings[0]["snippet"] == "existing snippet"

    def test_snippet_synthesis(self, tmp_path):
        root = _source_tree(tmp_path)
        findings = [_make_finding(snippet="", startLine=1)]
        result = normalize_imported_findings(findings, root)
        assert result.stats.snippet_synthesized == 1
        assert "check_password" in result.findings[0]["snippet"]

    def test_cwe_inference(self, tmp_path):
        root = _source_tree(tmp_path)
        findings = [_make_finding(
            rule_id="buffer-overflow-check",
            cwe_id=None,
        )]
        result = normalize_imported_findings(findings, root)
        assert result.stats.cwe_inferred == 1
        assert result.findings[0]["cwe_id"] == "CWE-120"
        assert result.findings[0].get("_cwe_inferred") is True

    def test_cwe_not_overwritten(self, tmp_path):
        root = _source_tree(tmp_path)
        findings = [_make_finding(cwe_id="CWE-89")]
        result = normalize_imported_findings(findings, root)
        assert result.stats.cwe_inferred == 0
        assert result.findings[0]["cwe_id"] == "CWE-89"

    def test_path_traversal_skipped(self, tmp_path):
        root = _source_tree(tmp_path)
        findings = [_make_finding(file="../../etc/passwd")]
        result = normalize_imported_findings(findings, root)
        assert result.stats.findings_skipped == 1
        assert result.stats.total_imported == 0

    def test_unresolvable_uri_skipped(self, tmp_path):
        root = _source_tree(tmp_path)
        findings = [_make_finding(file="/nonexistent/path/foo.c")]
        result = normalize_imported_findings(findings, root)
        assert result.stats.findings_skipped == 1
        assert result.stats.total_imported == 0
        assert len(result.findings) == 0
        assert any("cannot map URI" in w.message for w in result.warnings)

    def test_missing_startline_skipped(self, tmp_path):
        root = _source_tree(tmp_path)
        findings = [_make_finding(startLine=None)]
        result = normalize_imported_findings(findings, root)
        assert result.stats.findings_skipped == 1

    def test_endline_defaults_to_startline(self, tmp_path):
        root = _source_tree(tmp_path)
        findings = [_make_finding(endLine=None)]
        result = normalize_imported_findings(findings, root)
        assert result.findings[0]["endLine"] == 42

    def test_message_fallback(self, tmp_path):
        root = _source_tree(tmp_path)
        findings = [_make_finding(message=None, message_override=True)]
        findings[0]["message"] = None
        result = normalize_imported_findings(findings, root)
        assert "test-rule" in result.findings[0]["message"]
        assert "src/auth.c" in result.findings[0]["message"]

    def test_level_defaults_to_warning(self, tmp_path):
        root = _source_tree(tmp_path)
        findings = [_make_finding(level=None)]
        result = normalize_imported_findings(findings, root)
        assert result.findings[0]["level"] == "warning"

    def test_tool_preservation(self, tmp_path):
        root = _source_tree(tmp_path)
        findings = [_make_finding(tool="Coverity")]
        result = normalize_imported_findings(findings, root)
        assert result.findings[0]["tool"] == "Coverity"

    def test_unknown_tool_replaced(self, tmp_path):
        root = _source_tree(tmp_path)
        findings = [_make_finding(tool="unknown")]
        result = normalize_imported_findings(findings, root, original_tool="Bandit")
        assert result.findings[0]["tool"] == "Bandit"

    def test_uri_rebasing(self, tmp_path):
        root = _source_tree(tmp_path)
        findings = [_make_finding(file=f"file:///{root}/src/auth.c")]
        result = normalize_imported_findings(findings, root)
        assert result.findings[0]["file"] == "src/auth.c"
        assert result.stats.uri_rebased == 1

    def test_multiple_findings_mixed(self, tmp_path):
        root = _source_tree(tmp_path)
        findings = [
            _make_finding(finding_id="f1", file="src/auth.c", cwe_id="CWE-89"),
            _make_finding(finding_id="f2", file="src/main.c", cwe_id=None,
                          rule_id="null-pointer-deref"),
            _make_finding(finding_id="f3", file="/bad/path.c"),
        ]
        result = normalize_imported_findings(findings, root)
        assert result.stats.total_imported == 2
        assert result.stats.findings_skipped == 1
        assert result.stats.cwe_inferred == 1


# ---------------------------------------------------------------------------
# format_import_summary
# ---------------------------------------------------------------------------

class TestFormatImportSummary:
    def test_basic_summary(self, tmp_path):
        root = _source_tree(tmp_path)
        findings = [_make_finding()]
        result = normalize_imported_findings(findings, root)
        text = format_import_summary(result, ["test.sarif"])
        assert "1 findings imported" in text
        assert "test.sarif" in text

    def test_summary_with_skips(self, tmp_path):
        root = _source_tree(tmp_path)
        findings = [_make_finding(file="/bad/path.c")]
        result = normalize_imported_findings(findings, root)
        text = format_import_summary(result, ["test.sarif"])
        assert "skipped" in text

    def test_no_dataflow_message(self, tmp_path):
        root = _source_tree(tmp_path)
        findings = [_make_finding(has_dataflow=False)]
        result = normalize_imported_findings(findings, root)
        text = format_import_summary(result, ["test.sarif"])
        assert "0 dataflow paths" in text


# ---------------------------------------------------------------------------
# import_provenance_block
# ---------------------------------------------------------------------------

class TestImportProvenanceBlock:
    def test_basic_block(self, tmp_path):
        root = _source_tree(tmp_path)
        findings = [_make_finding()]
        result = normalize_imported_findings(findings, root)
        block = import_provenance_block(
            result,
            sarif_files=["coverity.sarif"],
            tools=["Coverity"],
        )
        assert block["tools"] == ["Coverity"]
        assert block["total_imported"] == 1
        assert block["source"] == "directory"

    def test_archive_block(self, tmp_path):
        root = _source_tree(tmp_path)
        findings = [_make_finding()]
        result = normalize_imported_findings(findings, root)
        block = import_provenance_block(
            result,
            sarif_files=["test.sarif"],
            tools=["external"],
            source_type="archive",
            archive_sha256="abc123",
        )
        assert block["source"] == "archive"
        assert block["archive_sha256"] == "abc123"


# ---------------------------------------------------------------------------
# Synthetic SARIF fixtures — end-to-end through parse + normalize
# ---------------------------------------------------------------------------

class TestEndToEndSyntheticSarif:
    """Parse a synthetic SARIF file, then normalize against a source tree."""

    def _write_sarif(self, tmp_path, sarif_dict):
        p = tmp_path / "test.sarif"
        p.write_text(json.dumps(sarif_dict))
        return p

    def _minimal_sarif(self, **result_overrides):
        result = {
            "ruleId": "test-rule",
            "level": "warning",
            "message": {"text": "test finding"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": "src/auth.c"},
                    "region": {"startLine": 1},
                }
            }],
        }
        result.update(result_overrides)
        return {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [{
                "tool": {"driver": {"name": "TestTool", "rules": []}},
                "results": [result],
            }],
        }

    def test_minimal_sarif_roundtrip(self, tmp_path):
        root = _source_tree(tmp_path)
        sarif_path = self._write_sarif(tmp_path, self._minimal_sarif())

        from core.sarif.parser import parse_sarif_findings
        findings = parse_sarif_findings(sarif_path)
        assert len(findings) == 1

        result = normalize_imported_findings(findings, root)
        assert result.stats.total_imported == 1
        assert result.findings[0]["file"] == "src/auth.c"

    def test_no_rules_block(self, tmp_path):
        root = _source_tree(tmp_path)
        sarif = self._minimal_sarif()
        del sarif["runs"][0]["tool"]["driver"]["rules"]
        sarif_path = self._write_sarif(tmp_path, sarif)

        from core.sarif.parser import parse_sarif_findings
        findings = parse_sarif_findings(sarif_path)
        result = normalize_imported_findings(findings, root)
        assert result.stats.total_imported == 1
        assert result.findings[0]["cwe_id"] is None

    def test_cwe_in_relationships(self, tmp_path):
        _source_tree(tmp_path)
        sarif = self._minimal_sarif()
        sarif["runs"][0]["tool"]["driver"]["rules"] = [{
            "id": "test-rule",
            "shortDescription": {"text": "Test"},
            "relationships": [{
                "target": {
                    "id": "CWE-89",
                    "toolComponent": {"name": "CWE"},
                },
            }],
        }]
        sarif_path = self._write_sarif(tmp_path, sarif)

        from core.sarif.parser import parse_sarif_findings
        findings = parse_sarif_findings(sarif_path)
        assert findings[0]["cwe_id"] == "CWE-89"

    def test_null_fields_handled(self, tmp_path):
        root = _source_tree(tmp_path)
        sarif = self._minimal_sarif()
        sarif["runs"][0]["results"][0]["codeFlows"] = None
        sarif_path = self._write_sarif(tmp_path, sarif)

        from core.sarif.parser import parse_sarif_findings
        findings = parse_sarif_findings(sarif_path)
        result = normalize_imported_findings(findings, root)
        assert result.stats.total_imported == 1

    def test_original_uri_base_ids(self, tmp_path):
        root = _source_tree(tmp_path)
        sarif = {
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {"name": "ExtTool", "rules": []}},
                "originalUriBaseIds": {
                    "%SRCROOT%": {"uri": f"file:///{root}/"},
                },
                "results": [{
                    "ruleId": "ext-001",
                    "level": "warning",
                    "message": {"text": "issue"},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": "src/auth.c",
                                "uriBaseId": "%SRCROOT%",
                            },
                            "region": {"startLine": 1},
                        }
                    }],
                }],
            }],
        }
        sarif_path = self._write_sarif(tmp_path, sarif)

        from core.sarif.parser import parse_sarif_findings
        findings = parse_sarif_findings(sarif_path)
        result = normalize_imported_findings(findings, root)
        assert result.stats.total_imported == 1
        assert result.findings[0]["file"] == "src/auth.c"

    def test_multi_run_sarif(self, tmp_path):
        root = _source_tree(tmp_path)
        sarif = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "SAST", "rules": []}},
                    "results": [{
                        "ruleId": "sast-001",
                        "message": {"text": "SAST finding"},
                        "locations": [{
                            "physicalLocation": {
                                "artifactLocation": {"uri": "src/auth.c"},
                                "region": {"startLine": 1},
                            }
                        }],
                    }],
                },
                {
                    "tool": {"driver": {"name": "SCA", "rules": []}},
                    "results": [{
                        "ruleId": "sca-001",
                        "message": {"text": "SCA finding"},
                        "locations": [{
                            "physicalLocation": {
                                "artifactLocation": {"uri": "src/main.c"},
                                "region": {"startLine": 1},
                            }
                        }],
                    }],
                },
            ],
        }
        sarif_path = self._write_sarif(tmp_path, sarif)

        from core.sarif.parser import parse_sarif_findings
        findings = parse_sarif_findings(sarif_path)
        assert len(findings) == 2

        result = normalize_imported_findings(findings, root)
        assert result.stats.total_imported == 2
        tools = {f["tool"] for f in result.findings}
        assert tools == {"SAST", "SCA"}

    def test_empty_results(self, tmp_path):
        root = _source_tree(tmp_path)
        sarif = {
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {"name": "EmptyTool", "rules": []}},
                "results": [],
            }],
        }
        sarif_path = self._write_sarif(tmp_path, sarif)

        from core.sarif.parser import parse_sarif_findings
        findings = parse_sarif_findings(sarif_path)
        result = normalize_imported_findings(findings, root)
        assert result.stats.total_imported == 0
        assert result.findings == []


class TestFindingsToSarif:
    """Unit tests for findings_to_sarif."""

    def test_empty_findings(self):
        sarif = findings_to_sarif([])
        assert sarif["version"] == "2.1.0"
        assert sarif["runs"] == []

    def test_single_finding_structure(self):
        f = _make_finding(
            tool="MyScanner",
            rule_id="RULE-1",
            file="src/main.c",
            startLine=10,
            endLine=15,
            snippet="int x = 0;",
            message="found issue",
            level="error",
            cwe_id="CWE-120",
        )
        sarif = findings_to_sarif([f])
        assert len(sarif["runs"]) == 1

        run = sarif["runs"][0]
        assert run["tool"]["driver"]["name"] == "MyScanner"
        assert len(run["tool"]["driver"]["rules"]) == 1
        assert run["tool"]["driver"]["rules"][0]["id"] == "RULE-1"
        assert run["tool"]["driver"]["rules"][0]["properties"]["cwe"] == ["CWE-120"]

        result = run["results"][0]
        assert result["ruleId"] == "RULE-1"
        assert result["level"] == "error"
        assert result["message"]["text"] == "found issue"

        loc = result["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"] == "src/main.c"
        assert loc["region"]["startLine"] == 10
        assert loc["region"]["endLine"] == 15
        assert loc["region"]["snippet"]["text"] == "int x = 0;"

    def test_groups_by_tool(self):
        findings = [
            _make_finding(tool="ToolA", rule_id="A-1", file="a.c", startLine=1),
            _make_finding(tool="ToolB", rule_id="B-1", file="b.c", startLine=1),
            _make_finding(tool="ToolA", rule_id="A-2", file="c.c", startLine=1),
        ]
        sarif = findings_to_sarif(findings)
        assert len(sarif["runs"]) == 2

        tool_names = {r["tool"]["driver"]["name"] for r in sarif["runs"]}
        assert tool_names == {"ToolA", "ToolB"}

        tool_a_run = [r for r in sarif["runs"]
                      if r["tool"]["driver"]["name"] == "ToolA"][0]
        assert len(tool_a_run["results"]) == 2
        assert len(tool_a_run["tool"]["driver"]["rules"]) == 2

    def test_deduplicates_rules(self):
        findings = [
            _make_finding(tool="T", rule_id="R-1", file="a.c", startLine=1),
            _make_finding(tool="T", rule_id="R-1", file="b.c", startLine=5),
        ]
        sarif = findings_to_sarif(findings)
        run = sarif["runs"][0]
        assert len(run["results"]) == 2
        assert len(run["tool"]["driver"]["rules"]) == 1

    def test_no_cwe_omits_properties(self):
        f = _make_finding(tool="T", rule_id="R-1", file="a.c", startLine=1)
        f.pop("cwe_id", None)
        sarif = findings_to_sarif([f])
        rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
        assert "properties" not in rule

    def test_missing_tool_defaults_to_external(self):
        f = _make_finding(file="a.c", startLine=1)
        f.pop("tool", None)
        sarif = findings_to_sarif([f])
        assert sarif["runs"][0]["tool"]["driver"]["name"] == "external"

    def test_finding_id_emitted_as_fingerprint(self):
        f = _make_finding(
            finding_id="SARIF-0042", file="a.c", startLine=1, tool="T",
        )
        sarif = findings_to_sarif([f])
        result = sarif["runs"][0]["results"][0]
        assert result["fingerprints"]["matchBasedId/v1"] == "SARIF-0042"

    def test_no_finding_id_omits_fingerprint(self):
        f = _make_finding(file="a.c", startLine=1, tool="T")
        f.pop("finding_id", None)
        sarif = findings_to_sarif([f])
        result = sarif["runs"][0]["results"][0]
        assert "fingerprints" not in result

    def test_dataflow_path_emitted_as_codeflows(self):
        flow = [{"threadFlows": [{"locations": []}]}]
        f = _make_finding(
            file="a.c", startLine=1, tool="T",
            has_dataflow=True, dataflow_path=flow,
        )
        sarif = findings_to_sarif([f])
        result = sarif["runs"][0]["results"][0]
        assert result["codeFlows"] == flow

    def test_no_dataflow_omits_codeflows(self):
        f = _make_finding(
            file="a.c", startLine=1, tool="T",
            has_dataflow=False,
        )
        sarif = findings_to_sarif([f])
        result = sarif["runs"][0]["results"][0]
        assert "codeFlows" not in result


class TestIsScaFinding:
    """Unit tests for SCA finding detection."""

    def test_known_sca_tool_snyk(self):
        assert _is_sca_finding({"tool": "Snyk", "file": "src/main.c"})

    def test_known_sca_tool_grype(self):
        assert _is_sca_finding({"tool": "grype", "file": "src/main.c"})

    def test_known_sca_tool_trivy(self):
        assert _is_sca_finding({"tool": "trivy", "file": "src/main.c"})

    def test_dependency_manifest_package_json(self):
        assert _is_sca_finding({"tool": "CustomTool", "file": "package.json"})

    def test_dependency_manifest_requirements_txt(self):
        assert _is_sca_finding({"tool": "CustomTool", "file": "requirements.txt"})

    def test_dependency_manifest_cargo_lock(self):
        assert _is_sca_finding({"tool": "CustomTool", "file": "Cargo.lock"})

    def test_dependency_manifest_nested_path(self):
        assert _is_sca_finding({"tool": "CustomTool", "file": "frontend/package.json"})

    def test_code_file_not_sca(self):
        assert not _is_sca_finding({"tool": "Coverity", "file": "src/auth.c"})

    def test_non_sca_tool_code_file(self):
        assert not _is_sca_finding({"tool": "CodeQL", "file": "src/main.py"})

    def test_empty_tool_code_file(self):
        assert not _is_sca_finding({"tool": "", "file": "src/main.c"})

    def test_none_tool(self):
        assert not _is_sca_finding({"tool": None, "file": "src/main.c"})

    def test_setup_py_unknown_tool_is_sca(self):
        assert _is_sca_finding({"tool": "CustomTool", "file": "setup.py"})

    def test_setup_py_sast_tool_not_sca(self):
        assert not _is_sca_finding({"tool": "Bandit", "file": "setup.py"})

    def test_setup_py_coverity_not_sca(self):
        assert not _is_sca_finding({"tool": "Coverity Static Analysis", "file": "setup.py"})

    def test_pom_xml_is_sca(self):
        assert _is_sca_finding({"tool": "CustomTool", "file": "pom.xml"})

    def test_tool_name_substring_match(self):
        assert _is_sca_finding({"tool": "Snyk Open Source", "file": "src/main.c"})

    def test_tool_name_variant_trivy(self):
        assert _is_sca_finding({"tool": "Trivy Vulnerability Scanner", "file": "src/main.c"})

    def test_sast_tool_on_manifest_not_sca(self):
        assert not _is_sca_finding({"tool": "Semgrep", "file": "build.gradle"})


class TestScaTaggingInNormalize:
    """SCA findings get tagged with _source_type=dependency."""

    def test_sca_tool_tagged(self, tmp_path):
        root = tmp_path / "repo"
        root.mkdir()
        (root / "package.json").write_text('{"name": "test"}')

        f = _make_finding(
            tool="Snyk", file="package.json", startLine=1,
        )
        result = normalize_imported_findings([f], root)
        assert result.stats.total_imported == 1
        assert result.stats.sca_tagged == 1
        assert result.findings[0]["source_type"] == "dependency"

    def test_code_finding_not_tagged(self, tmp_path):
        root = tmp_path / "repo"
        root.mkdir()
        (root / "src").mkdir()
        (root / "src" / "main.c").write_text("int main() { return 0; }\n")

        f = _make_finding(
            tool="Coverity", file="src/main.c", startLine=1,
        )
        result = normalize_imported_findings([f], root)
        assert result.stats.total_imported == 1
        assert result.stats.sca_tagged == 0
        assert "source_type" not in result.findings[0]

    def test_sca_warning_in_summary(self, tmp_path):
        root = tmp_path / "repo"
        root.mkdir()
        (root / "package.json").write_text('{"name": "test"}')

        f = _make_finding(
            tool="Snyk", file="package.json", startLine=1,
        )
        result = normalize_imported_findings([f], root)
        summary = format_import_summary(result, ["snyk.sarif"])
        assert "dependency (SCA)" in summary
        assert "consider --also-scan" in summary

    def test_mixed_sca_and_code(self, tmp_path):
        root = tmp_path / "repo"
        root.mkdir()
        (root / "src").mkdir()
        (root / "src" / "main.c").write_text("int main() { return 0; }\n")
        (root / "package.json").write_text('{"name": "test"}')

        findings = [
            _make_finding(
                finding_id="code-1",
                tool="Coverity", file="src/main.c", startLine=1,
            ),
            _make_finding(
                finding_id="sca-1",
                tool="Snyk", file="package.json", startLine=1,
            ),
        ]
        result = normalize_imported_findings(findings, root)
        assert result.stats.total_imported == 2
        assert result.stats.sca_tagged == 1
        code_f = [f for f in result.findings if f["finding_id"] == "code-1"][0]
        sca_f = [f for f in result.findings if f["finding_id"] == "sca-1"][0]
        assert "source_type" not in code_f
        assert sca_f["source_type"] == "dependency"

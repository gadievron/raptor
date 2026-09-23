"""Tests for the SARIF import normalizer."""

import json
from pathlib import Path

from core.sarif.import_normalizer import (
    _MAX_DEPTH_CACHE,
    _MAX_FULL_SCAN_SECONDS,
    _infer_cwe,
    _is_sca_finding,
    _remember_depth,
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


def _df_step(file, line, label, snippet=""):
    """One step in the parser's INTERNAL dataflow shape."""
    return {
        "file": file, "line": line, "column": 0,
        "label": label, "snippet": snippet,
    }


def _internal_dataflow(alternatives=0):
    """dataflow_path exactly as parse_sarif_findings produces it —
    the internal dict, not a SARIF-shaped list."""
    def _path():
        return {
            "source": _df_step("a.c", 1, "source"),
            "sink": _df_step("c.c", 9, "sink", snippet="run(x)"),
            "steps": [_df_step("b.c", 5, "propagate")],
            "total_steps": 3,
        }
    primary = _path()
    primary["alternative_paths"] = [_path() for _ in range(alternatives)]
    return primary


def _sarif_tf_location(uri, line, label):
    """One SARIF threadFlow location for producer-side fixtures."""
    return {
        "location": {
            "message": {"text": label},
            "physicalLocation": {
                "artifactLocation": {"uri": uri},
                "region": {"startLine": line},
            },
        }
    }


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


def _lines_source_tree(tmp_path):
    """Source tree whose src/main.c holds 20 numbered lines, so snippet
    synthesis output is predictable line-by-line."""
    root = tmp_path / "src_root"
    (root / "src").mkdir(parents=True)
    (root / "src" / "main.c").write_text(
        "\n".join(f"line {i}" for i in range(1, 21))
    )
    return root


def _lines_finding(**overrides):
    """Finding pointing into the numbered-lines source tree."""
    base = {"file": "src/main.c", "startLine": 5, "endLine": None}
    base.update(overrides)
    return _make_finding(**base)


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
# Depth-cache cost containment
# ---------------------------------------------------------------------------

class TestDepthCacheCap:
    """The cached-depth loop runs BEFORE every budget gate, so its
    per-URI cost must not be a document-controlled multiplier: a SARIF
    that seeds one cache entry per strip depth must not make every
    later unresolvable URI pay one ``_is_under_root`` resolve per
    seeded depth after the scan budgets are spent."""

    def _seed_cache(self, root, cache, depths):
        """Cache one strip depth per member of *depths* via real
        resolutions (junk prefix of that length ending in a real
        file), with fresh budgets."""
        idx: dict = {}
        for d in depths:
            uri = "/".join(f"s{j}" for j in range(d)) + "/x.c"
            budget = [64]
            clock = [0.0]
            assert _resolve_uri(
                uri, root, idx, cache,
                scan_budget=budget, scan_clock=clock,
            ) == "x.c"

    def test_remember_depth_caps_cache(self):
        cache: list = [None]
        for d in range(1, 21):
            _remember_depth(cache, d)
        assert len(cache) == _MAX_DEPTH_CACHE
        # Most-recent-first, oldest evicted.
        assert cache[0] == 20
        assert 1 not in cache

    def test_seeded_cache_cannot_multiply_post_budget_cost(
        self, tmp_path, monkeypatch,
    ):
        """After the scan budgets are spent, one unresolvable URI's
        cached-depth cost is bounded by the cache cap — not by how
        many depths the document managed to seed."""
        (tmp_path / "x.c").write_text("int x;\n")
        cache: list = [None]
        self._seed_cache(tmp_path, cache, range(1, 33))

        import core.sarif.import_normalizer as _mod
        real = _mod._is_under_root
        calls = [0]

        def _counting(root, candidate):
            calls[0] += 1
            return real(root, candidate)

        monkeypatch.setattr(_mod, "_is_under_root", _counting)
        # Budgets spent: the full-scan lane is closed, only the
        # cached-depth loop and the basename index run.
        result = _resolve_uri(
            "/".join(f"h{j}" for j in range(64)), tmp_path, {}, cache,
            scan_budget=[0],
            scan_clock=[_MAX_FULL_SCAN_SECONDS],
        )
        assert result is None
        assert calls[0] <= _MAX_DEPTH_CACHE

    def test_cached_shapes_survive_post_budget(self, tmp_path):
        """Resolved scanner shapes keep the cached-depth fast path
        after budget exhaustion (the documented post-budget contract)."""
        (tmp_path / "x.c").write_text("int x;\n")
        (tmp_path / "y.c").write_text("int y;\n")
        cache: list = [None]
        # Three alternating scanner shapes — all must stay cached.
        self._seed_cache(tmp_path, cache, (1, 2, 3))
        for d in (1, 2, 3):
            uri = "/".join(f"p{j}" for j in range(d)) + "/y.c"
            assert _resolve_uri(
                uri, tmp_path, {}, cache,
                scan_budget=[0],
                scan_clock=[_MAX_FULL_SCAN_SECONDS],
            ) == "y.c"

    def test_evicted_depth_rediscovered_e2e(self, tmp_path):
        """LRU eviction never loses findings: a shape whose depth was
        evicted re-resolves through the (budgeted) full scan."""
        (tmp_path / "real.c").write_text("int r;\n")
        findings = []
        for d in range(1, _MAX_DEPTH_CACHE + 5):
            uri = "/".join(f"s{j}" for j in range(d)) + "/real.c"
            findings.append(_make_finding(
                finding_id=f"f{d}", file=uri, startLine=1, endLine=1,
            ))
        # Re-visit the first (now evicted) shape at the end.
        findings.append(_make_finding(
            finding_id="revisit", file="s0/real.c", startLine=1, endLine=1,
        ))
        result = normalize_imported_findings(findings, tmp_path)
        assert result.stats.findings_skipped == 0
        assert all(f["file"] == "real.c" for f in result.findings)


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
# Untrusted numeric fields
# ---------------------------------------------------------------------------

class TestNumericFieldValidation:
    """Non-integer startLine/endLine from untrusted SARIF must not crash
    snippet synthesis — invalid values skip the finding (with a warning)
    instead of raising TypeError mid-import."""

    def test_string_startline_skipped_not_crash(self, tmp_path):
        root = _lines_source_tree(tmp_path)
        result = normalize_imported_findings(
            [_lines_finding(startLine="abc")], root
        )
        assert result.stats.findings_skipped == 1
        assert result.stats.total_imported == 0
        assert result.warnings and "invalid" in result.warnings[0].message

    def test_infinity_startline_skipped_not_crash(self, tmp_path):
        root = _lines_source_tree(tmp_path)
        result = normalize_imported_findings(
            [_lines_finding(startLine=float("inf"))], root
        )
        assert result.stats.findings_skipped == 1

    def test_nan_endline_falls_back_to_startline(self, tmp_path):
        root = _lines_source_tree(tmp_path)
        result = normalize_imported_findings(
            [_lines_finding(endLine=float("nan"))], root
        )
        assert result.stats.total_imported == 1
        assert result.findings[0]["endLine"] == 5

    def test_string_endline_falls_back_and_snippet_synthesized(self, tmp_path):
        root = _lines_source_tree(tmp_path)
        result = normalize_imported_findings(
            [_lines_finding(endLine="zzz")], root
        )
        f = result.findings[0]
        assert f["endLine"] == 5
        assert f["snippet"].startswith("line 5")

    def test_endline_before_startline_clamped(self, tmp_path):
        root = _lines_source_tree(tmp_path)
        result = normalize_imported_findings(
            [_lines_finding(startLine=5, endLine=-2)], root
        )
        assert result.findings[0]["endLine"] == 5

    def test_negative_startline_skipped(self, tmp_path):
        root = _lines_source_tree(tmp_path)
        result = normalize_imported_findings(
            [_lines_finding(startLine=-4)], root
        )
        assert result.stats.findings_skipped == 1

    def test_integral_float_lines_coerced(self, tmp_path):
        root = _lines_source_tree(tmp_path)
        result = normalize_imported_findings(
            [_lines_finding(startLine=5.0, endLine=6.0)], root
        )
        f = result.findings[0]
        assert f["startLine"] == 5
        assert f["endLine"] == 6
        assert f["snippet"]

    def test_non_string_file_skipped(self, tmp_path):
        root = _lines_source_tree(tmp_path)
        result = normalize_imported_findings(
            [_lines_finding(file={"weird": 1})], root
        )
        assert result.stats.findings_skipped == 1

    def test_crafted_sarif_end_to_end_import_survives(self, tmp_path):
        """Full chain: hostile SARIF file → parse → normalize."""
        from core.sarif.parser import parse_sarif_findings

        root = _lines_source_tree(tmp_path)
        sarif = {
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {"name": "evil", "rules": []}},
                "results": [
                    {
                        "ruleId": "R-bad",
                        "message": {"text": "boom"},
                        "locations": [{
                            "physicalLocation": {
                                "artifactLocation": {"uri": "src/main.c"},
                                "region": {"startLine": "abc"},
                            }
                        }],
                    },
                    {
                        "ruleId": "R-inf",
                        "message": {"text": "boom"},
                        "locations": [{
                            "physicalLocation": {
                                "artifactLocation": {"uri": "src/main.c"},
                                "region": {"startLine": float("inf")},
                            }
                        }],
                    },
                    {
                        "ruleId": "R-ok",
                        "message": {"text": "fine"},
                        "locations": [{
                            "physicalLocation": {
                                "artifactLocation": {"uri": "src/main.c"},
                                "region": {"startLine": 3},
                            }
                        }],
                    },
                ],
            }],
        }
        path = tmp_path / "evil.sarif"
        path.write_text(json.dumps(sarif))
        findings = parse_sarif_findings(path)
        result = normalize_imported_findings(findings, root)
        assert result.stats.total_imported == 1
        assert result.stats.findings_skipped == 2
        assert result.findings[0]["rule_id"] == "R-ok"


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

    def test_hostile_uri_escaped_in_warning_and_summary(self, tmp_path):
        # Imported SARIF is untrusted and the summary is printed to
        # the operator terminal by /agentic --sarif: a URI carrying
        # OSC/BEL bytes must not survive raw into either the warning
        # record or the joined summary examples.
        root = _source_tree(tmp_path)
        evil = "/bad/\x1b]0;pwned\x07/path.c"
        findings = [_make_finding(file=evil)]
        result = normalize_imported_findings(findings, root)
        for w in result.warnings:
            assert "\x1b" not in w.message and "\x07" not in w.message
        text = format_import_summary(result, ["test.sarif"])
        assert "\x1b" not in text and "\x07" not in text
        assert "pwned" in text  # escaped content, not silently dropped


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


class TestUriUnresolvedSurfaced:
    """uri_unresolved is surfaced in the operator summary and the
    provenance block, not just counted internally."""

    def _unresolved_result(self, tmp_path):
        root = _lines_source_tree(tmp_path)
        return normalize_imported_findings(
            [_lines_finding(file="no/such/file.c")], root
        )

    def test_counter_still_increments(self, tmp_path):
        result = self._unresolved_result(tmp_path)
        assert result.stats.uri_unresolved == 1
        assert result.stats.findings_skipped == 1

    def test_summary_reports_unresolved_uris(self, tmp_path):
        result = self._unresolved_result(tmp_path)
        text = format_import_summary(result, ["test.sarif"])
        assert "could not be mapped to the source tree" in text
        assert "1 skipped" in text

    def test_summary_omits_line_when_zero(self, tmp_path):
        root = _lines_source_tree(tmp_path)
        # Skipped for a different reason: missing startLine.
        result = normalize_imported_findings(
            [_lines_finding(startLine=None)], root
        )
        assert result.stats.uri_unresolved == 0
        text = format_import_summary(result, ["test.sarif"])
        assert "could not be mapped" not in text

    def test_provenance_block_carries_unresolved_count(self, tmp_path):
        result = self._unresolved_result(tmp_path)
        block = import_provenance_block(
            result, sarif_files=["test.sarif"], tools=["external"],
        )
        assert block["synthesized_fields"]["uri_unresolved"] == 1
        assert block["synthesized_fields"]["findings_skipped"] == 1


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
        # Producer-shaped fixture: parse_sarif_findings stores dataflow
        # as the INTERNAL {source, sink, steps, ...} dict, never as a
        # ready-made SARIF list. The emitter must convert it back to
        # the spec's array-of-codeFlow shape.
        f = _make_finding(
            file="a.c", startLine=1, tool="T",
            has_dataflow=True,
            dataflow_path=_internal_dataflow(),
        )
        sarif = findings_to_sarif([f])
        result = sarif["runs"][0]["results"][0]
        flows = result["codeFlows"]
        assert isinstance(flows, list)
        assert len(flows) == 1
        locations = flows[0]["threadFlows"][0]["locations"]
        assert len(locations) == 3
        first = locations[0]["location"]["physicalLocation"]
        assert first["artifactLocation"]["uri"] == "a.c"
        assert first["region"]["startLine"] == 1
        assert locations[0]["location"]["message"]["text"] == "source"
        last = locations[-1]["location"]["physicalLocation"]
        assert last["artifactLocation"]["uri"] == "c.c"
        assert last["region"]["snippet"]["text"] == "run(x)"

    def test_alternative_paths_emit_extra_codeflows(self):
        f = _make_finding(
            file="a.c", startLine=1, tool="T",
            has_dataflow=True,
            dataflow_path=_internal_dataflow(alternatives=1),
        )
        sarif = findings_to_sarif([f])
        flows = sarif["runs"][0]["results"][0]["codeFlows"]
        assert len(flows) == 2

    def test_sarif_shaped_list_dataflow_passes_through(self):
        # Hand-built findings that never went through the parser may
        # already carry SARIF-shaped codeFlows; those stay verbatim.
        flow = [{"threadFlows": [{"locations": []}]}]
        f = _make_finding(
            file="a.c", startLine=1, tool="T",
            has_dataflow=True, dataflow_path=flow,
        )
        sarif = findings_to_sarif([f])
        assert sarif["runs"][0]["results"][0]["codeFlows"] == flow

    def test_single_location_path_omits_codeflows(self):
        # A degenerate path (< 2 locations) cannot round-trip through
        # the parser, so no codeFlows member is emitted at all —
        # better absent than schema-invalid.
        f = _make_finding(
            file="a.c", startLine=1, tool="T",
            has_dataflow=True,
            dataflow_path={
                "source": _df_step("a.c", 1, "source"),
                "sink": None,
                "steps": [],
                "total_steps": 1,
                "alternative_paths": [],
            },
        )
        sarif = findings_to_sarif([f])
        assert "codeFlows" not in sarif["runs"][0]["results"][0]

    def test_dataflow_round_trips_through_disk(self, tmp_path):
        # produce → import (parse) → emit → re-parse: has_dataflow and
        # the path content must survive the disk hop. Pre-fix the
        # emitter wrote the internal dict verbatim and re-parse lost
        # the dataflow (has_dataflow True → False).
        produced = {
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {"name": "Ext"}},
                "results": [{
                    "ruleId": "R-1",
                    "message": {"text": "tainted flow"},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": "a.c"},
                            "region": {"startLine": 3},
                        }
                    }],
                    "codeFlows": [{
                        "threadFlows": [{
                            "locations": [
                                _sarif_tf_location("a.c", 3, "user input"),
                                _sarif_tf_location("b.c", 7, "propagate"),
                                _sarif_tf_location("c.c", 9, "dangerous sink"),
                            ]
                        }]
                    }],
                }],
            }],
        }
        first = tmp_path / "produced.sarif"
        first.write_text(json.dumps(produced))

        from core.sarif.parser import parse_sarif_findings
        findings = parse_sarif_findings(first)
        assert len(findings) == 1
        assert findings[0]["has_dataflow"] is True
        original_path = findings[0]["dataflow_path"]

        second = tmp_path / "normalized.sarif"
        second.write_text(json.dumps(findings_to_sarif(findings)))

        reparsed = parse_sarif_findings(second)
        assert len(reparsed) == 1
        assert reparsed[0]["has_dataflow"] is True
        rt = reparsed[0]["dataflow_path"]
        assert rt["source"] == original_path["source"]
        assert rt["sink"] == original_path["sink"]
        assert rt["steps"] == original_path["steps"]
        assert rt["total_steps"] == original_path["total_steps"]

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


class TestUntrustedTreeHardening:
    """The scanned tree and the imported SARIF are both untrusted —
    the file index and snippet synthesis must stay bounded."""

    def test_deep_tree_does_not_recurse(self, tmp_path):
        # ~1200 nesting levels blow a recursive walk's Python stack;
        # the iterative index must survive and still find the file.
        # One mkdir per level: pathlib's parents=True is itself
        # recursive and cannot build a 1200-deep tree in one call.
        deep = tmp_path
        for _ in range(1200):
            deep = deep / "d"
            deep.mkdir()
        (deep / "leaf.c").write_text("int x;\n")
        from core.sarif.import_normalizer import _build_file_index
        index = _build_file_index(tmp_path)
        assert "leaf.c" in index

    def test_oversized_source_skips_snippet(self, tmp_path):
        from core.sarif.import_normalizer import (
            _SNIPPET_SOURCE_MAX_BYTES,
            _synthesize_snippet,
        )
        big = tmp_path / "big.c"
        with big.open("wb") as f:
            f.seek(_SNIPPET_SOURCE_MAX_BYTES)
            f.write(b"x")
        assert _synthesize_snippet(tmp_path, "big.c", 1, 1) == ""

    def test_normal_source_still_synthesizes(self, tmp_path):
        from core.sarif.import_normalizer import _synthesize_snippet
        (tmp_path / "ok.c").write_text("line1\nline2\nline3\n")
        snippet = _synthesize_snippet(tmp_path, "ok.c", 2, 2)
        assert "line2" in snippet


class TestResolveUriComponentCap:
    def test_pathological_uri_rejected_fast(self, tmp_path):
        # O(N^2) resolution: 8000 components measured ~62s pre-fix.
        # The cap must reject far past-cap URIs in well under a
        # second (structural bound: the loop never starts). CPU
        # budget, not wall clock: the quadratic loop burns CPU.
        from core.testing.wallclock import cpu_budget

        root = _source_tree(tmp_path)
        evil = "/".join(["d"] * 5000) + "/x.c"
        findings = [_make_finding(file=evil)]
        with cpu_budget(5.0, what="pathological-URI normalisation"):
            result = normalize_imported_findings(findings, root)
        assert result.stats.findings_skipped == 1

    def test_deep_but_real_paths_still_resolve(self, tmp_path):
        # Two-direction: a deep-but-plausible prefix strips fine.
        root = _source_tree(tmp_path)
        prefixed = "/".join(["ci", "build", "workspace", "src"]) + "/main.c"
        findings = [_make_finding(file=prefixed)]
        result = normalize_imported_findings(findings, root)
        assert result.stats.total_imported == 1


# ---------------------------------------------------------------------------
# Aggregate URI-resolution budget + negative memo
# ---------------------------------------------------------------------------

class TestResolveUriAggregateBudget:
    """The per-URI component cap bounds ONE scan, but the document cap
    admits ~147k cap-sized findings — the aggregate axis of the same
    wedge. Structural assertions (counting _is_under_root probes), not
    wall-clock ones."""

    def _counting_root(self, tmp_path, monkeypatch):
        from core.sarif import import_normalizer as mod
        root = _source_tree(tmp_path)
        calls = {"n": 0}
        real = mod._is_under_root

        def counted(source_root, candidate):
            calls["n"] += 1
            return real(source_root, candidate)

        monkeypatch.setattr(mod, "_is_under_root", counted)
        return root, calls

    def test_failed_memo_kills_repeat_scans(self, tmp_path, monkeypatch):
        root, calls = self._counting_root(tmp_path, monkeypatch)
        bad = "/".join(["x"] * 40) + "/nope.c"
        memo: set = set()
        budget = [999]
        cache = [None]
        assert _resolve_uri(bad, root, {}, cache,
                            failed_memo=memo, scan_budget=budget) is None
        first = calls["n"]
        assert first > 0
        # Same URI again: memo answers, zero probes — pre-fix each of
        # 147k identical-URI findings re-paid the full quadratic scan.
        assert _resolve_uri(bad, root, {}, cache,
                            failed_memo=memo, scan_budget=budget) is None
        assert calls["n"] == first

    def test_scan_budget_stops_full_scans(self, tmp_path, monkeypatch):
        root, calls = self._counting_root(tmp_path, monkeypatch)
        memo: set = set()
        budget = [2]
        cache = [None]
        for i in range(2):  # consume the budget with distinct failures
            assert _resolve_uri(f"a/b/c/miss{i}.c", root, {}, cache,
                                failed_memo=memo,
                                scan_budget=budget) is None
        assert budget[0] == 0
        before = calls["n"]
        # New distinct unresolvable URI: no probes spent at all.
        assert _resolve_uri("d/e/f/other.c", root, {}, cache,
                            failed_memo=memo, scan_budget=budget) is None
        assert calls["n"] == before

    def test_cached_depth_survives_budget_exhaustion(
        self, tmp_path, monkeypatch,
    ):
        root, calls = self._counting_root(tmp_path, monkeypatch)
        memo: set = set()
        budget = [1]
        cache = [None]
        # Establish the scanner shape (strips /ci/workspace).
        assert _resolve_uri("/ci/workspace/src/auth.c", root,
                            {"auth.c": [Path("src/auth.c")]}, cache,
                            failed_memo=memo,
                            scan_budget=budget) == "src/auth.c"
        # Exhaust the budget.
        _resolve_uri("a/b/miss.c", root, {}, cache,
                     failed_memo=memo, scan_budget=budget)
        assert budget[0] == 0
        # The established shape still resolves via the cached depth.
        assert _resolve_uri("/ci/workspace/src/auth.c", root, {}, cache,
                            failed_memo=memo,
                            scan_budget=budget) == "src/auth.c"

    def test_successful_scans_never_consume_budget(self, tmp_path):
        root = _source_tree(tmp_path)
        memo: set = set()
        budget = [3]
        for _ in range(10):
            cache = [None]  # force the full scan each time
            assert _resolve_uri("/ci/ws/src/auth.c", root, {}, cache,
                                failed_memo=memo,
                                scan_budget=budget) == "src/auth.c"
        assert budget[0] == 3

    def test_memo_size_is_capped(self, tmp_path):
        from core.sarif import import_normalizer as mod
        root = _source_tree(tmp_path)
        memo: set = set()
        budget = [10 ** 9]
        cap = mod._MAX_FAILED_URI_MEMO
        for i in range(cap + 10):
            _resolve_uri(f"m/{i}.c", root, {}, [None],
                         failed_memo=memo, scan_budget=budget)
        assert len(memo) <= cap

    def test_import_loop_threads_budget(self, tmp_path, monkeypatch):
        """normalize_imported_findings wires memo+budget: a document of
        identical unresolvable URIs costs one scan, and all findings
        still degrade to skipped/unresolved (never a crash)."""
        root, calls = self._counting_root(tmp_path, monkeypatch)
        bad = "/".join(["x"] * 30) + "/nope.c"
        findings = [
            _make_finding(file=bad, finding_id=f"f{i}") for i in range(50)
        ]
        result = normalize_imported_findings(findings, root)
        assert result.stats.uri_unresolved == 50
        # One full scan's worth of probes, not 50 (memo short-circuit).
        assert calls["n"] <= 40


def test_oversized_snippet_warning_escapes_hostile_path(
    tmp_path, monkeypatch, caplog,
):
    """The oversized-file warning prints a filename from the untrusted
    scanned tree to the operator terminal — control bytes must be
    escaped at creation (the ImportWarning sites already are)."""
    import logging

    from core.sarif import import_normalizer as mod

    root = tmp_path
    evil = "src/\x1b]0;pwned\x07big.c"
    (tmp_path / "src").mkdir()
    victim = tmp_path / evil
    victim.write_text("x")
    monkeypatch.setattr(mod, "_SNIPPET_SOURCE_MAX_BYTES", 0)
    with caplog.at_level(logging.WARNING):
        assert mod._synthesize_snippet(root, evil, 1, 1) == ""
    joined = " ".join(r.getMessage() for r in caplog.records)
    assert "big.c" in joined
    assert "\x1b" not in joined and "\x07" not in joined


class TestResolveUriBudgetRecallAndWallCap:
    """Budget exhaustion must degrade the EXPENSIVE lane only: the
    O(1) basename index and the cached-depth path stay live, and
    RESOLVING deep URIs are bounded by depth caching + the aggregate
    wall clock (the failure budget never sees a success)."""

    def _counting_root(self, tmp_path, monkeypatch):
        from core.sarif import import_normalizer as mod
        root = _source_tree(tmp_path)
        calls = {"n": 0}
        real = mod._is_under_root

        def counted(source_root, candidate):
            calls["n"] += 1
            return real(source_root, candidate)

        monkeypatch.setattr(mod, "_is_under_root", counted)
        return root, calls

    def test_basename_index_survives_budget_exhaustion(self, tmp_path):
        """Junk-first exhausts the failed-scan budget BEFORE any depth
        is cached; a later legitimate URI with a unique basename must
        still resolve — the basename lookup is O(1) and not part of
        the wedge (skipping it dropped the finding)."""
        root = _source_tree(tmp_path)
        memo: set = set()
        budget = [1]
        cache = [None]
        idx = {"auth.c": [Path("src/auth.c")]}
        assert _resolve_uri("j/u/n/k/miss.c", root, idx, cache,
                            failed_memo=memo, scan_budget=budget) is None
        assert budget[0] == 0
        assert _resolve_uri("/ci/prefix/wrong/auth.c", root, idx, cache,
                            failed_memo=memo,
                            scan_budget=budget) == "src/auth.c"

    def test_import_junk_first_legit_findings_still_import(self, tmp_path):
        """E2E recall shape: a document whose unmappable URIs
        (generated/vendored paths grouped first) precede the real
        results must still import every real result. Pre-fix the
        exhausted budget skipped the basename index and dropped ALL
        subsequent legitimate findings (imported 0 of 500)."""
        from core.sarif import import_normalizer as mod
        root = _source_tree(tmp_path)
        junk = [
            _make_finding(file=f"gen/out/{i}/nope-{i}.c",
                          finding_id=f"junk-{i}")
            for i in range(mod._MAX_FAILED_URI_SCANS + 36)
        ]
        legit = [
            _make_finding(file="/ci/workspace/elsewhere/auth.c",
                          finding_id=f"legit-{i}", startLine=1)
            for i in range(500)
        ]
        result = normalize_imported_findings(junk + legit, root)
        assert result.stats.findings_skipped == len(junk)
        assert result.stats.uri_unresolved == len(junk)
        imported = len(junk) + len(legit) - result.stats.findings_skipped
        assert imported == 500

    def test_alternating_deep_resolving_uris_bounded(
        self, tmp_path, monkeypatch,
    ):
        """Two alternating deep-but-RESOLVING URIs (junk components
        ending in a real in-repo path) thrashed the single-slot depth
        cache — every finding re-paid the full quadratic scan and
        nothing was charged (successes bypassed budget and memo).
        The depth cache holds every successful depth, so the pair
        costs two full scans total."""
        root, calls = self._counting_root(tmp_path, monkeypatch)
        depth_a, depth_b = 40, 60
        uri_a = "/".join(["a"] * depth_a) + "/src/auth.c"
        uri_b = "/".join(["b"] * depth_b) + "/src/main.c"
        cache: list = [None]
        memo: set = set()
        budget = [999]
        clock = [0.0]
        for _ in range(50):
            assert _resolve_uri(uri_a, root, {}, cache, failed_memo=memo,
                                scan_budget=budget,
                                scan_clock=clock) == "src/auth.c"
            assert _resolve_uri(uri_b, root, {}, cache, failed_memo=memo,
                                scan_budget=budget,
                                scan_clock=clock) == "src/main.c"
        # Two full scans (≤ depth+2 probes each) + ≤2 cached-depth
        # probes per subsequent call — far below 100 full scans.
        assert calls["n"] <= (depth_a + depth_b + 8) + 4 * 100
        assert budget[0] == 999  # successes never touch the budget

    def test_resolved_memo_short_circuits_repeat_successes(
        self, tmp_path, monkeypatch,
    ):
        root, calls = self._counting_root(tmp_path, monkeypatch)
        cache: list = [None]
        rmemo: dict = {}
        assert _resolve_uri("/ci/ws/src/auth.c", root, {}, cache,
                            resolved_memo=rmemo) == "src/auth.c"
        before = calls["n"]
        assert _resolve_uri("/ci/ws/src/auth.c", root, {}, cache,
                            resolved_memo=rmemo) == "src/auth.c"
        assert calls["n"] == before  # memo answered, zero probes

    def test_wall_clock_cap_stops_full_scans_basename_survives(
        self, tmp_path, monkeypatch,
    ):
        """Aggregate wall cap: once full-scan time is spent, unknown
        URIs skip the quadratic loop entirely — but unique basenames
        still resolve. Both directions: under the cap the full scan
        runs (distinct-depth URI resolves without an index)."""
        from core.sarif import import_normalizer as mod
        root, calls = self._counting_root(tmp_path, monkeypatch)
        idx = {"auth.c": [Path("src/auth.c")]}
        clock = [0.0]
        # Under the cap: full scan allowed, resolves with empty index.
        assert _resolve_uri("/p/q/src/main.c", root, {}, [None],
                            scan_clock=clock) == "src/main.c"
        assert clock[0] > 0.0
        # Spent: no full scan probes, basename index still resolves.
        spent = [mod._MAX_FULL_SCAN_SECONDS]
        before = calls["n"]
        assert _resolve_uri("/x/y/z/auth.c", root, idx, [None],
                            scan_clock=spent) == "src/auth.c"
        assert calls["n"] == before + 1  # only the basename probe
        # ... and a non-unique/unknown basename degrades to None.
        assert _resolve_uri("/x/y/z/nope.c", root, idx, [None],
                            scan_clock=spent) is None

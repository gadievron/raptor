"""End-to-end test: external SARIF → parse → normalize → pipeline entry.

Exercises the full path a user's external SARIF would take through
the system, without requiring LLM calls or scanner binaries.
Covers: parse, normalize, URI rebase, CWE inference, snippet synthesis,
source-intel CWE gate, path traversal rejection, dedup, multi-file merge.
"""

import json
from pathlib import Path

from core.sarif.import_normalizer import (
    findings_to_sarif,
    normalize_imported_findings,
    format_import_summary,
    import_provenance_block,
)
from core.sarif.parser import (
    deduplicate_findings,
    merge_sarif,
    parse_sarif_findings,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_source_tree(root: Path) -> None:
    """Create a small C project with multiple files."""
    (root / "src").mkdir(parents=True)
    (root / "src" / "auth.c").write_text(
        '#include <string.h>\n'
        'int check_password(const char *input) {\n'
        '    return strcmp(input, "secret");\n'
        '}\n'
    )
    (root / "src" / "db.c").write_text(
        '#include <stdio.h>\n'
        'void query(const char *sql) {\n'
        '    printf("executing: %s\\n", sql);\n'
        '}\n'
    )
    (root / "src" / "net.c").write_text(
        '#include <stdlib.h>\n'
        'void *alloc_buf(int size) {\n'
        '    return malloc(size);\n'
        '}\n'
    )
    (root / "include").mkdir()
    (root / "include" / "auth.h").write_text(
        'int check_password(const char *input);\n'
    )


def _coverity_style_sarif(source_root: Path) -> dict:
    """Simulate Coverity-style SARIF: absolute CI paths, no codeFlows,
    CWE only in properties.cwe (list form), no snippets."""
    ci_prefix = f"/builds/jenkins/workspace/{source_root.name}"
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Coverity Static Analysis",
                    "version": "2024.3.0",
                    "rules": [
                        {
                            "id": "CID-12345",
                            "shortDescription": {"text": "Buffer overflow"},
                            "properties": {"cwe": ["CWE-120"]},
                        },
                        {
                            "id": "CID-12346",
                            "shortDescription": {"text": "SQL injection"},
                            "properties": {"cwe": ["CWE-89"]},
                        },
                    ],
                }
            },
            "results": [
                {
                    "ruleId": "CID-12345",
                    "level": "error",
                    "message": {"text": "Buffer overflow in check_password"},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": f"file:///{ci_prefix}/src/auth.c",
                            },
                            "region": {"startLine": 3, "endLine": 3},
                        }
                    }],
                },
                {
                    "ruleId": "CID-12346",
                    "level": "error",
                    "message": {"text": "SQL injection in query"},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": f"file:///{ci_prefix}/src/db.c",
                            },
                            "region": {"startLine": 3},
                        }
                    }],
                },
            ],
        }],
    }


def _bandit_style_sarif() -> dict:
    """Simulate Bandit-style SARIF: relative paths, CWE in tags,
    no codeFlows, has snippets."""
    return {
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Bandit",
                    "version": "1.7.9",
                    "rules": [{
                        "id": "B608",
                        "shortDescription": {"text": "Hardcoded SQL"},
                        "properties": {"tags": ["cwe-89", "security"]},
                    }],
                }
            },
            "results": [{
                "ruleId": "B608",
                "level": "warning",
                "message": {"text": "Possible SQL injection via string-based query"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": "src/db.c"},
                        "region": {
                            "startLine": 3,
                            "snippet": {"text": '    printf("executing: %s\\n", sql);'},
                        },
                    }
                }],
            }],
        }],
    }


def _malicious_sarif() -> dict:
    """SARIF with path-traversal URIs — must be rejected."""
    return {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "Evil", "rules": []}},
            "results": [
                {
                    "ruleId": "evil-001",
                    "message": {"text": "traversal attempt"},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": "../../etc/passwd"},
                            "region": {"startLine": 1},
                        }
                    }],
                },
                {
                    "ruleId": "evil-002",
                    "message": {"text": "another traversal"},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": "src/../../../etc/shadow",
                            },
                            "region": {"startLine": 1},
                        }
                    }],
                },
            ],
        }],
    }


def _no_rules_no_cwe_sarif() -> dict:
    """SARIF with no rules block and no CWE anywhere — tests CWE inference
    from message text."""
    return {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "CustomLinter"}},
            "results": [
                {
                    "ruleId": "CUSTOM-001",
                    "message": {"text": "Potential use after free in alloc_buf"},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": "src/net.c"},
                            "region": {"startLine": 3},
                        }
                    }],
                },
                {
                    "ruleId": "CUSTOM-002",
                    "message": {"text": "General code quality issue"},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": "src/net.c"},
                            "region": {"startLine": 1},
                        }
                    }],
                },
            ],
        }],
    }


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestE2ECoverityStyle:
    """Coverity-style: absolute CI paths, CWE in properties.cwe list."""

    def test_full_pipeline(self, tmp_path):
        source = tmp_path / "repo"
        source.mkdir()
        _write_source_tree(source)

        sarif = _coverity_style_sarif(source)
        sarif_path = tmp_path / "coverity.sarif"
        sarif_path.write_text(json.dumps(sarif))

        # Step 1: parse
        findings = parse_sarif_findings(sarif_path)
        assert len(findings) == 2
        assert findings[0]["tool"] == "Coverity Static Analysis"
        assert findings[0]["cwe_id"] == "CWE-120"
        assert findings[1]["cwe_id"] == "CWE-89"

        # Step 2: dedup (no dupes expected)
        unique = deduplicate_findings(findings)
        assert len(unique) == 2

        # Step 3: normalize
        result = normalize_imported_findings(unique, source)
        assert result.stats.total_imported == 2
        assert result.stats.findings_skipped == 0

        # URIs rebased from absolute CI paths
        assert result.findings[0]["file"] == "src/auth.c"
        assert result.findings[1]["file"] == "src/db.c"
        assert result.stats.uri_rebased == 2

        # Snippets synthesized (Coverity didn't provide them)
        assert result.stats.snippet_synthesized == 2
        assert "strcmp" in result.findings[0]["snippet"]
        assert "printf" in result.findings[1]["snippet"]

        # CWEs preserved from parser (not inferred)
        assert result.stats.cwe_inferred == 0
        assert result.findings[0]["cwe_id"] == "CWE-120"

        # endLine defaulted
        assert result.findings[1]["endLine"] == 3

        # Tool name preserved
        assert result.findings[0]["tool"] == "Coverity Static Analysis"

        # Summary
        summary = format_import_summary(result, ["coverity.sarif"])
        assert "2 findings imported" in summary
        assert "2 URIs rebased" in summary
        assert "2 snippets synthesized" in summary

        # Provenance
        prov = import_provenance_block(
            result,
            sarif_files=["coverity.sarif"],
            tools=["Coverity Static Analysis"],
        )
        assert prov["total_imported"] == 2
        assert prov["synthesized_fields"]["uri_rebased"] == 2


class TestE2EBanditStyle:
    """Bandit-style: relative paths, CWE in tags, has snippets."""

    def test_full_pipeline(self, tmp_path):
        source = tmp_path / "repo"
        source.mkdir()
        _write_source_tree(source)

        sarif_path = tmp_path / "bandit.sarif"
        sarif_path.write_text(json.dumps(_bandit_style_sarif()))

        findings = parse_sarif_findings(sarif_path)
        assert len(findings) == 1
        assert findings[0]["cwe_id"] == "CWE-89"

        result = normalize_imported_findings(findings, source)
        assert result.stats.total_imported == 1
        # Path already relative and correct — no rebasing
        assert result.findings[0]["file"] == "src/db.c"
        # Snippet from SARIF preserved (not synthesized)
        assert result.stats.snippet_synthesized == 0
        # CWE from parser preserved
        assert result.stats.cwe_inferred == 0


class TestE2EMultiFileMerge:
    """Merge Coverity + Bandit SARIF, dedup overlapping findings."""

    def test_cross_scanner_merge(self, tmp_path):
        source = tmp_path / "repo"
        source.mkdir()
        _write_source_tree(source)

        coverity_path = tmp_path / "coverity.sarif"
        coverity_path.write_text(json.dumps(_coverity_style_sarif(source)))

        bandit_path = tmp_path / "bandit.sarif"
        bandit_path.write_text(json.dumps(_bandit_style_sarif()))

        # Parse both
        all_findings = []
        for p in [coverity_path, bandit_path]:
            all_findings.extend(parse_sarif_findings(p))
        assert len(all_findings) == 3  # 2 Coverity + 1 Bandit

        # Dedup — Coverity SQL-injection (CID-12346 at db.c:3) and
        # Bandit B608 (at db.c:3) have same file+line but different
        # rule_ids, so both survive standard dedup.
        unique = deduplicate_findings(all_findings)
        assert len(unique) == 3

        # Normalize
        result = normalize_imported_findings(unique, source)
        assert result.stats.total_imported == 3

        # Both tools represented
        tools = {f["tool"] for f in result.findings}
        assert "Coverity Static Analysis" in tools
        assert "Bandit" in tools


class TestE2EPathTraversal:
    """Malicious SARIF with traversal URIs must be fully rejected."""

    def test_traversal_rejected(self, tmp_path):
        source = tmp_path / "repo"
        source.mkdir()
        _write_source_tree(source)

        sarif_path = tmp_path / "evil.sarif"
        sarif_path.write_text(json.dumps(_malicious_sarif()))

        findings = parse_sarif_findings(sarif_path)
        assert len(findings) == 2

        result = normalize_imported_findings(findings, source)
        assert result.stats.total_imported == 0
        assert result.stats.findings_skipped == 2
        assert all("cannot map URI" in w.message for w in result.warnings
                    if w.field == "file")


class TestE2ECweInference:
    """SARIF with no rules block, no CWE — tests inference from message."""

    def test_cwe_inferred_from_message(self, tmp_path):
        source = tmp_path / "repo"
        source.mkdir()
        _write_source_tree(source)

        sarif_path = tmp_path / "custom.sarif"
        sarif_path.write_text(json.dumps(_no_rules_no_cwe_sarif()))

        findings = parse_sarif_findings(sarif_path)
        assert len(findings) == 2
        # Parser finds no CWE (no rules block)
        assert findings[0]["cwe_id"] is None
        assert findings[1]["cwe_id"] is None

        result = normalize_imported_findings(findings, source)
        assert result.stats.total_imported == 2

        # First finding: "use after free" → CWE-416 inferred
        uaf_finding = [f for f in result.findings
                       if f["rule_id"] == "CUSTOM-001"][0]
        assert uaf_finding["cwe_id"] == "CWE-416"
        assert uaf_finding.get("_cwe_inferred") is True

        # Second finding: "general code quality" → no CWE match
        generic_finding = [f for f in result.findings
                           if f["rule_id"] == "CUSTOM-002"][0]
        assert generic_finding["cwe_id"] is None

        assert result.stats.cwe_inferred == 1


class TestE2EMergedSarifPipeline:
    """Test merge_sarif → parse → normalize full chain."""

    def test_merge_then_normalize(self, tmp_path):
        source = tmp_path / "repo"
        source.mkdir()
        _write_source_tree(source)

        coverity_path = tmp_path / "coverity.sarif"
        coverity_path.write_text(json.dumps(_coverity_style_sarif(source)))

        bandit_path = tmp_path / "bandit.sarif"
        bandit_path.write_text(json.dumps(_bandit_style_sarif()))

        # Merge at the SARIF level
        merged = merge_sarif([str(coverity_path), str(bandit_path)])
        assert len(merged["runs"]) == 2  # one run per tool

        # Write merged, re-parse
        merged_path = tmp_path / "merged.sarif"
        merged_path.write_text(json.dumps(merged))

        findings = parse_sarif_findings(merged_path)
        unique = deduplicate_findings(findings)

        result = normalize_imported_findings(unique, source)
        assert result.stats.total_imported == 3
        assert result.stats.findings_skipped == 0

        # All findings have resolved paths
        for f in result.findings:
            assert not f["file"].startswith("file://")
            assert not f["file"].startswith("/")


class TestE2ENormalizedSarifRoundTrip:
    """Verify that writing normalized findings back to SARIF and
    re-parsing produces the same data — this is the fix for the
    validation-phase double-parse problem."""

    def test_coverity_roundtrip_preserves_patches(self, tmp_path):
        source = tmp_path / "repo"
        source.mkdir()
        _write_source_tree(source)

        sarif_path = tmp_path / "coverity.sarif"
        sarif_path.write_text(json.dumps(_coverity_style_sarif(source)))

        # Parse + normalize (first pass — patches applied)
        findings = parse_sarif_findings(sarif_path)
        result = normalize_imported_findings(findings, source)
        assert result.stats.uri_rebased == 2
        assert result.stats.snippet_synthesized == 2

        # Write normalized SARIF back to disk
        normalized = findings_to_sarif(result.findings)
        norm_path = tmp_path / "normalized.sarif"
        norm_path.write_text(json.dumps(normalized))

        # Re-parse from disk (simulates validation phase double-parse)
        reparsed = parse_sarif_findings(norm_path)
        assert len(reparsed) == 2

        # Rebased URIs survived the round-trip
        assert reparsed[0]["file"] == "src/auth.c"
        assert reparsed[1]["file"] == "src/db.c"
        assert not reparsed[0]["file"].startswith("file://")
        assert not reparsed[0]["file"].startswith("/")

        # Synthesized snippets survived
        assert reparsed[0].get("snippet")
        assert "strcmp" in reparsed[0]["snippet"]
        assert reparsed[1].get("snippet")
        assert "printf" in reparsed[1]["snippet"]

        # CWEs survived (from original parser, preserved through SARIF)
        assert reparsed[0]["cwe_id"] == "CWE-120"
        assert reparsed[1]["cwe_id"] == "CWE-89"

        # Tool names survived
        assert reparsed[0]["tool"] == "Coverity Static Analysis"

    def test_inferred_cwe_survives_roundtrip(self, tmp_path):
        source = tmp_path / "repo"
        source.mkdir()
        _write_source_tree(source)

        sarif_path = tmp_path / "custom.sarif"
        sarif_path.write_text(json.dumps(_no_rules_no_cwe_sarif()))

        findings = parse_sarif_findings(sarif_path)
        result = normalize_imported_findings(findings, source)

        # CWE-416 was inferred for "use after free"
        uaf = [f for f in result.findings if f["rule_id"] == "CUSTOM-001"][0]
        assert uaf["cwe_id"] == "CWE-416"

        # Round-trip through SARIF
        normalized = findings_to_sarif(result.findings)
        norm_path = tmp_path / "normalized.sarif"
        norm_path.write_text(json.dumps(normalized))

        reparsed = parse_sarif_findings(norm_path)
        uaf_reparsed = [f for f in reparsed if f["rule_id"] == "CUSTOM-001"][0]
        assert uaf_reparsed["cwe_id"] == "CWE-416"

    def test_multi_tool_roundtrip(self, tmp_path):
        source = tmp_path / "repo"
        source.mkdir()
        _write_source_tree(source)

        # Parse both scanners
        all_findings = []
        for sarif_fn, sarif_gen in [
            ("coverity.sarif", _coverity_style_sarif(source)),
            ("bandit.sarif", _bandit_style_sarif()),
        ]:
            p = tmp_path / sarif_fn
            p.write_text(json.dumps(sarif_gen))
            all_findings.extend(parse_sarif_findings(p))

        result = normalize_imported_findings(
            deduplicate_findings(all_findings), source,
        )
        assert result.stats.total_imported == 3

        # Round-trip
        normalized = findings_to_sarif(result.findings)
        norm_path = tmp_path / "normalized.sarif"
        norm_path.write_text(json.dumps(normalized))

        reparsed = parse_sarif_findings(norm_path)
        assert len(reparsed) == 3

        tools = {f["tool"] for f in reparsed}
        assert "Coverity Static Analysis" in tools
        assert "Bandit" in tools

        # All paths are relative
        for f in reparsed:
            assert not f["file"].startswith("file://")
            assert not f["file"].startswith("/")


class TestE2EScaDetection:
    """SCA-flavour SARIF is detected and tagged."""

    def _snyk_style_sarif(self):
        return {
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "Snyk",
                        "version": "1.1292.0",
                        "rules": [{
                            "id": "SNYK-JS-LODASH-567746",
                            "shortDescription": {
                                "text": "Prototype Pollution",
                            },
                        }],
                    }
                },
                "results": [{
                    "ruleId": "SNYK-JS-LODASH-567746",
                    "level": "error",
                    "message": {"text": "Prototype Pollution in lodash"},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": "package.json"},
                            "region": {"startLine": 5},
                        }
                    }],
                }],
            }],
        }

    def test_snyk_sarif_tagged_as_dependency(self, tmp_path):
        source = tmp_path / "repo"
        source.mkdir()
        _write_source_tree(source)
        (source / "package.json").write_text(
            '{\n  "name": "test",\n  "version": "1.0.0",\n'
            '  "dependencies": {\n    "lodash": "^4.17.20"\n  }\n}\n'
        )

        sarif_path = tmp_path / "snyk.sarif"
        sarif_path.write_text(json.dumps(self._snyk_style_sarif()))

        findings = parse_sarif_findings(sarif_path)
        assert len(findings) == 1
        assert findings[0]["tool"] == "Snyk"

        result = normalize_imported_findings(findings, source)
        assert result.stats.total_imported == 1
        assert result.stats.sca_tagged == 1
        assert result.findings[0]["source_type"] == "dependency"

        summary = format_import_summary(result, ["snyk.sarif"])
        assert "dependency (SCA)" in summary

    def test_mixed_code_and_sca_findings(self, tmp_path):
        source = tmp_path / "repo"
        source.mkdir()
        _write_source_tree(source)
        (source / "package.json").write_text('{"name": "test"}\n')

        # Combine Coverity code finding with Snyk SCA finding
        all_findings = []

        coverity_path = tmp_path / "coverity.sarif"
        coverity_path.write_text(json.dumps(_coverity_style_sarif(source)))
        all_findings.extend(parse_sarif_findings(coverity_path))

        snyk_path = tmp_path / "snyk.sarif"
        snyk_path.write_text(json.dumps(self._snyk_style_sarif()))
        all_findings.extend(parse_sarif_findings(snyk_path))

        result = normalize_imported_findings(
            deduplicate_findings(all_findings), source,
        )
        assert result.stats.total_imported == 3
        assert result.stats.sca_tagged == 1

        sca = [f for f in result.findings if f.get("source_type") == "dependency"]
        code = [f for f in result.findings if "source_type" not in f]
        assert len(sca) == 1
        assert len(code) == 2
        assert sca[0]["tool"] == "Snyk"


class TestE2EProvenanceBlock:
    """Provenance block is correctly populated from import results."""

    def test_provenance_from_coverity_import(self, tmp_path):
        source = tmp_path / "repo"
        source.mkdir()
        _write_source_tree(source)

        sarif_path = tmp_path / "coverity.sarif"
        sarif_path.write_text(json.dumps(_coverity_style_sarif(source)))

        findings = parse_sarif_findings(sarif_path)
        result = normalize_imported_findings(findings, source)

        tools = sorted({f["tool"] for f in result.findings})
        prov = import_provenance_block(
            result,
            sarif_files=["coverity.sarif"],
            tools=tools,
        )

        assert prov["total_imported"] == 2
        assert prov["sarif_files"] == ["coverity.sarif"]
        assert "Coverity Static Analysis" in prov["tools"]
        assert prov["synthesized_fields"]["uri_rebased"] == 2
        assert prov["synthesized_fields"]["snippet_synthesized"] == 2
        assert prov["source"] == "directory"

    def test_provenance_with_archive(self, tmp_path):
        source = tmp_path / "repo"
        source.mkdir()
        _write_source_tree(source)

        sarif_path = tmp_path / "scan.sarif"
        sarif_path.write_text(json.dumps(_bandit_style_sarif()))

        findings = parse_sarif_findings(sarif_path)
        result = normalize_imported_findings(findings, source)

        prov = import_provenance_block(
            result,
            sarif_files=["scan.sarif"],
            tools=["Bandit"],
            source_type="archive",
            archive_sha256="abc123deadbeef",
        )

        assert prov["source"] == "archive"
        assert prov["archive_sha256"] == "abc123deadbeef"


# ---------------------------------------------------------------------------
# E2E: Enriched SARIF writer
# ---------------------------------------------------------------------------

class TestE2EEnrichedSarifWriter:
    """Full pipeline: parse → normalize → analyse (simulated) → enriched SARIF → re-parse."""

    def test_enriched_roundtrip_preserves_verdicts(self, tmp_path):
        from core.sarif.enriched_writer import write_enriched_sarif

        source = tmp_path / "repo"
        source.mkdir()
        _write_source_tree(source)

        sarif_path = tmp_path / "coverity.sarif"
        sarif_path.write_text(json.dumps(_coverity_style_sarif(source)))
        findings = parse_sarif_findings(sarif_path)
        result = normalize_imported_findings(findings, source)

        analysed = []
        for f in result.findings:
            f["exploitable"] = True
            f["exploitability_score"] = 0.85
            f["analysis"] = {
                "is_true_positive": True,
                "is_exploitable": True,
                "reasoning": "Attacker controls input buffer size",
            }
            analysed.append(f)

        out = tmp_path / "enriched.sarif"
        write_enriched_sarif(analysed, out, tool_version="test-1.0")

        doc = json.loads(out.read_text())
        assert doc["version"] == "2.1.0"
        assert len(doc["runs"]) == 1

        result_0 = doc["runs"][0]["results"][0]
        raptor = result_0["properties"]["raptor"]
        assert raptor["verdict"] == "exploitable"
        assert raptor["is_exploitable"] is True
        assert raptor["exploitability_score"] == 0.85
        assert "reasoning" in raptor

        reparsed = parse_sarif_findings(out)
        assert len(reparsed) == 2
        for r in reparsed:
            assert r["rule_id"] in ("CID-12345", "CID-12346")
            assert r["file"].startswith("src/")

    def test_suppressed_findings_in_enriched_sarif(self, tmp_path):
        from core.sarif.enriched_writer import build_enriched_sarif

        findings = [
            {
                "finding_id": "supp1",
                "rule_id": "CWE-120",
                "file_path": "src/dead.c",
                "start_line": 5,
                "message": "Buffer overflow in dead code",
                "level": "warning",
                "tool": "CodeQL",
                "analysis": {
                    "reachability_suppression": True,
                    "reachability_verdict": "absent",
                },
            },
            {
                "finding_id": "live1",
                "rule_id": "CWE-79",
                "file_path": "src/app.py",
                "start_line": 10,
                "message": "XSS",
                "level": "error",
                "tool": "Semgrep",
                "exploitable": True,
                "analysis": {"is_true_positive": True, "is_exploitable": True},
            },
        ]

        doc = build_enriched_sarif(findings, tool_version="test-1.0")
        all_results = []
        for run in doc["runs"]:
            all_results.extend(run["results"])

        suppressed = [r for r in all_results if "suppressions" in r]
        live = [r for r in all_results if "suppressions" not in r]
        assert len(suppressed) == 1
        assert suppressed[0]["ruleId"] == "CWE-120"
        assert len(live) == 1
        assert live[0]["properties"]["raptor"]["verdict"] == "exploitable"

    def test_enriched_sarif_with_mixed_analysis_states(self, tmp_path):
        """Findings with different analysis states: exploitable, confirmed, ruled_out, not_analyzed."""
        from core.sarif.enriched_writer import build_enriched_sarif

        findings = [
            {
                "rule_id": "R1", "file_path": "a.py", "start_line": 1,
                "message": "m", "tool": "T", "exploitable": True,
                "analysis": {"is_true_positive": True},
            },
            {
                "rule_id": "R2", "file_path": "b.py", "start_line": 2,
                "message": "m", "tool": "T",
                "analysis": {"is_true_positive": True},
            },
            {
                "rule_id": "R3", "file_path": "c.py", "start_line": 3,
                "message": "m", "tool": "T",
                "analysis": {"is_true_positive": False},
            },
            {
                "rule_id": "R4", "file_path": "d.py", "start_line": 4,
                "message": "m", "tool": "T",
            },
        ]
        doc = build_enriched_sarif(findings, tool_version="test-1.0")
        results = doc["runs"][0]["results"]
        verdicts = [r["properties"]["raptor"]["verdict"] for r in results]
        assert verdicts == ["exploitable", "confirmed", "ruled_out", "not_analyzed"]

    def test_level_validation_e2e(self, tmp_path):
        """Invalid SARIF levels from external scanners are clamped."""
        from core.sarif.enriched_writer import write_enriched_sarif

        findings = [
            {"rule_id": "R1", "file_path": "a.py", "start_line": 1,
             "message": "m", "tool": "T", "level": "critical"},
            {"rule_id": "R2", "file_path": "b.py", "start_line": 1,
             "message": "m", "tool": "T", "level": "error"},
            {"rule_id": "R3", "file_path": "c.py", "start_line": 1,
             "message": "m", "tool": "T", "level": "HIGH"},
        ]
        out = tmp_path / "levels.sarif"
        write_enriched_sarif(findings, out, tool_version="1.0")

        doc = json.loads(out.read_text())
        levels = [r["level"] for r in doc["runs"][0]["results"]]
        assert levels == ["warning", "error", "warning"]

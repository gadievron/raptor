"""Tests for core.orchestration.audit_bridge."""

from __future__ import annotations

import json
from pathlib import Path

from core.orchestration.audit_bridge import (
    _build_constraint_index,
    enrich_attack_paths,
    enrich_with_summaries,
    find_audit_output,
    inject_chains_as_hypotheses,
    inject_dark_as_hypotheses,
    is_audit_format,
    load_attack_chains,
    load_audit_constraints,
    load_dark_findings,
    load_summaries,
    normalize_audit_findings,
)


def _write_constraints(run_dir: Path, constraints: list) -> None:
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "constraints.json").write_text(json.dumps(constraints), encoding="utf-8")


class TestFindAuditOutput:
    def test_finds_sibling_with_constraints(self, tmp_path):
        _write_constraints(tmp_path / "audit_run", [{"function": "fn"}])
        current = tmp_path / "validate_run"
        current.mkdir()
        result = find_audit_output(current)
        assert result == tmp_path / "audit_run"

    def test_excludes_current_dir(self, tmp_path):
        _write_constraints(tmp_path / "validate_run", [{"function": "fn"}])
        result = find_audit_output(tmp_path / "validate_run")
        assert result is None

    def test_returns_none_without_constraints(self, tmp_path):
        (tmp_path / "other_run").mkdir()
        current = tmp_path / "validate_run"
        current.mkdir()
        result = find_audit_output(current)
        assert result is None

    def test_picks_newest(self, tmp_path):
        import time
        _write_constraints(tmp_path / "old", [{"function": "a"}])
        time.sleep(0.05)
        _write_constraints(tmp_path / "new", [{"function": "b"}])
        current = tmp_path / "validate"
        current.mkdir()
        result = find_audit_output(current)
        assert result == tmp_path / "new"


class TestLoadAuditConstraints:
    def test_loads_and_filters_refuted(self, tmp_path):
        _write_constraints(tmp_path, [
            {"function": "fn1", "status": "open", "kind": "parameter"},
            {"function": "fn2", "status": "refuted", "kind": "parameter"},
            {"function": "fn3", "status": "verified", "kind": "postcondition"},
        ])
        result = load_audit_constraints(tmp_path)
        assert len(result) == 2
        assert all(c["status"] != "refuted" for c in result)

    def test_empty_on_missing_file(self, tmp_path):
        assert load_audit_constraints(tmp_path) == []

    def test_empty_on_malformed_json(self, tmp_path):
        tmp_path.mkdir(exist_ok=True)
        (tmp_path / "constraints.json").write_text("{not valid", encoding="utf-8")
        assert load_audit_constraints(tmp_path) == []

    def test_empty_on_non_list(self, tmp_path):
        tmp_path.mkdir(exist_ok=True)
        (tmp_path / "constraints.json").write_text('{"key": "value"}', encoding="utf-8")
        assert load_audit_constraints(tmp_path) == []


class TestBuildConstraintIndex:
    def test_indexes_by_file_function(self):
        constraints = [
            {"function": "fn", "file": "a.c", "kind": "parameter",
             "target": "buf", "rule": "len <= 1024", "violation": "overflow"},
        ]
        index = _build_constraint_index(constraints)
        assert "a.c:fn" in index
        assert ":fn" in index

    def test_skips_empty_function(self):
        constraints = [{"function": "", "file": "a.c"}]
        index = _build_constraint_index(constraints)
        assert len(index) == 0


class TestEnrichAttackPaths:
    def test_enriches_matching_steps(self, tmp_path):
        paths = [
            {"steps": [
                {"function": "parse_input", "file": "http.c"},
                {"function": "handle_data", "file": "core.c"},
            ]},
        ]
        ap_file = tmp_path / "attack-paths.json"
        ap_file.write_text(json.dumps(paths), encoding="utf-8")

        constraints = [
            {"function": "parse_input", "file": "http.c",
             "kind": "parameter", "target": "buf",
             "rule": "len <= 4096", "violation": "stack overflow",
             "status": "open"},
        ]

        enriched = enrich_attack_paths(ap_file, constraints)
        assert enriched == 1

        data = json.loads(ap_file.read_text(encoding="utf-8"))
        step = data[0]["steps"][0]
        assert "parameter_constraints" in step
        assert step["parameter_constraints"][0]["rule"] == "len <= 4096"

    def test_bare_function_fallback(self, tmp_path):
        paths = [{"steps": [{"function": "fn", "file": "other.c"}]}]
        ap_file = tmp_path / "attack-paths.json"
        ap_file.write_text(json.dumps(paths), encoding="utf-8")

        constraints = [
            {"function": "fn", "file": "original.c",
             "kind": "precondition", "target": "ptr",
             "rule": "not NULL", "violation": "null deref",
             "status": "open"},
        ]

        enriched = enrich_attack_paths(ap_file, constraints)
        assert enriched == 1

    def test_no_enrichment_no_write(self, tmp_path):
        paths = [{"steps": [{"function": "unrelated", "file": "x.c"}]}]
        ap_file = tmp_path / "attack-paths.json"
        ap_file.write_text(json.dumps(paths), encoding="utf-8")
        original = ap_file.read_text(encoding="utf-8")

        constraints = [
            {"function": "fn", "file": "a.c", "kind": "parameter",
             "target": "x", "rule": "r", "violation": "v", "status": "open"},
        ]

        enriched = enrich_attack_paths(ap_file, constraints)
        assert enriched == 0
        assert ap_file.read_text(encoding="utf-8") == original

    def test_missing_file(self, tmp_path):
        constraints = [{"function": "fn", "file": "a.c"}]
        enriched = enrich_attack_paths(tmp_path / "nope.json", constraints)
        assert enriched == 0


class TestLoadAttackChains:
    def test_loads_valid_chains(self, tmp_path):
        chains = [
            {"id": "c1", "goal": "RCE", "findings": [{"finding_id": "F1"}]},
            {"id": "c2", "goal": "info leak", "findings": []},
        ]
        (tmp_path / "attack-chains.json").write_text(json.dumps(chains), encoding="utf-8")
        result = load_attack_chains(tmp_path)
        assert len(result) == 2
        assert result[0]["goal"] == "RCE"

    def test_empty_on_missing_file(self, tmp_path):
        assert load_attack_chains(tmp_path) == []

    def test_empty_on_malformed_json(self, tmp_path):
        (tmp_path / "attack-chains.json").write_text("not json", encoding="utf-8")
        assert load_attack_chains(tmp_path) == []

    def test_filters_non_dict_entries(self, tmp_path):
        (tmp_path / "attack-chains.json").write_text(json.dumps([
            {"id": "c1"}, "not a dict", 42, {"id": "c2"},
        ]), encoding="utf-8")
        result = load_attack_chains(tmp_path)
        assert len(result) == 2


class TestLoadSummaries:
    def test_loads_dict_format(self, tmp_path):
        data = {"src/a.c:parse": {"taint_rules": [], "preconditions": []}}
        (tmp_path / "summaries.json").write_text(json.dumps(data), encoding="utf-8")
        result = load_summaries(tmp_path)
        assert "src/a.c:parse" in result

    def test_loads_list_format(self, tmp_path):
        data = [
            {"file": "a.c", "function": "fn1", "taint_rules": []},
            {"file": "b.c", "function": "fn2", "preconditions": ["x != NULL"]},
        ]
        (tmp_path / "summaries.json").write_text(json.dumps(data), encoding="utf-8")
        result = load_summaries(tmp_path)
        assert "a.c:fn1" in result
        assert "b.c:fn2" in result

    def test_empty_on_missing_file(self, tmp_path):
        assert load_summaries(tmp_path) == {}

    def test_empty_on_non_list_non_dict(self, tmp_path):
        (tmp_path / "summaries.json").write_text('"just a string"', encoding="utf-8")
        assert load_summaries(tmp_path) == {}


class TestInjectChainsAsHypotheses:
    def test_injects_into_existing_surface(self, tmp_path):
        surface = {"entry_points": [], "sinks": [], "hypotheses": []}
        ap_file = tmp_path / "attack-surface.json"
        ap_file.write_text(json.dumps(surface), encoding="utf-8")

        chains = [
            {"description": "heap overflow via parse", "goal": "RCE",
             "primitives": ["write-what-where"],
             "findings": [{"finding_id": "F1"}]},
        ]
        result = inject_chains_as_hypotheses(chains, ap_file)
        assert result == 1

        data = json.loads(ap_file.read_text(encoding="utf-8"))
        assert len(data["hypotheses"]) == 1
        h = data["hypotheses"][0]
        assert h["source"] == "audit_chain"
        assert h["status"] == "imported"
        assert h["goal"] == "RCE"

    def test_returns_zero_on_missing_file(self, tmp_path):
        chains = [{"description": "x"}]
        result = inject_chains_as_hypotheses(chains, tmp_path / "nope.json")
        assert result == 0

    def test_returns_zero_on_empty_chains(self, tmp_path):
        ap_file = tmp_path / "attack-surface.json"
        ap_file.write_text(json.dumps({"hypotheses": []}), encoding="utf-8")
        assert inject_chains_as_hypotheses([], ap_file) == 0


class TestEnrichWithSummaries:
    def test_enriches_matching_steps(self, tmp_path):
        paths = [{"steps": [
            {"function": "parse", "file": "http.c"},
            {"function": "handle", "file": "core.c"},
        ]}]
        ap_file = tmp_path / "attack-paths.json"
        ap_file.write_text(json.dumps(paths), encoding="utf-8")

        summaries = {
            "http.c:parse": {
                "preconditions": [{"param": "buf", "conditions": ["!= NULL"]}],
                "taint_rules": [{"source_param": "buf", "sink_call": "memcpy"}],
                "returns": [],
            },
        }
        result = enrich_with_summaries(ap_file, summaries)
        assert result == 1

        data = json.loads(ap_file.read_text(encoding="utf-8"))
        step = data[0]["steps"][0]
        assert "callee_contract" in step
        assert step["callee_contract"]["preconditions"][0]["param"] == "buf"

    def test_no_enrichment_without_summaries(self, tmp_path):
        paths = [{"steps": [{"function": "fn", "file": "a.c"}]}]
        ap_file = tmp_path / "attack-paths.json"
        ap_file.write_text(json.dumps(paths), encoding="utf-8")
        assert enrich_with_summaries(ap_file, {}) == 0

    def test_missing_file(self, tmp_path):
        summaries = {"a.c:fn": {"preconditions": []}}
        assert enrich_with_summaries(tmp_path / "nope.json", summaries) == 0


class TestIsAuditFormat:
    def test_detects_audit_findings(self):
        findings = [
            {"id": "FIND-001", "file": "a.py", "evidence_tool": "semgrep:x",
             "hypothesis": "path traversal", "provenance_refs": []},
        ]
        assert is_audit_format(findings) is True

    def test_rejects_validate_findings(self):
        findings = [
            {"id": "FIND-001", "file": "a.py", "vuln_type": "path_traversal",
             "status": "not_disproven", "origin": "claude_native"},
        ]
        assert is_audit_format(findings) is False

    def test_empty_list(self):
        assert is_audit_format([]) is False

    def test_non_dict_entries(self):
        assert is_audit_format(["not a dict"]) is False


class TestNormalizeAuditFindings:
    def test_sets_origin(self):
        findings = [{"id": "F1", "source": "audit", "file": "a.py"}]
        result = normalize_audit_findings(findings)
        assert result[0]["origin"] == "audit_import"

    def test_preserves_existing_origin(self):
        findings = [{"id": "F1", "source": "audit", "origin": "pre_existing"}]
        result = normalize_audit_findings(findings)
        assert result[0]["origin"] == "pre_existing"

    def test_maps_description_to_candidate_reasoning(self):
        findings = [{"id": "F1", "description": "buffer overflow via parse"}]
        result = normalize_audit_findings(findings)
        assert result[0]["candidate_reasoning"] == "buffer overflow via parse"

    def test_preserves_existing_candidate_reasoning(self):
        findings = [{"id": "F1", "description": "from audit",
                     "candidate_reasoning": "already set"}]
        result = normalize_audit_findings(findings)
        assert result[0]["candidate_reasoning"] == "already set"

    def test_confidence_from_semgrep(self):
        findings = [{"id": "F1", "evidence_tool": "semgrep:/tmp/rule.yaml"}]
        result = normalize_audit_findings(findings)
        assert result[0]["confidence"] == "medium"

    def test_confidence_from_taint_approx(self):
        findings = [{"id": "F1", "evidence_tool": "taint_approx"}]
        result = normalize_audit_findings(findings)
        assert result[0]["confidence"] == "low"

    def test_confidence_from_smt(self):
        findings = [{"id": "F1", "evidence_tool": "smt:check-overflow"}]
        result = normalize_audit_findings(findings)
        assert result[0]["confidence"] == "medium"

    def test_audit_context_populated(self):
        findings = [{
            "id": "F1",
            "title": "Path traversal in parse_input",
            "description": "Unsanitized input flows to open()",
            "hypothesis": "Attacker-controlled path reaches filesystem",
            "evidence_tool": "semgrep:/tmp/rule.yaml",
            "provenance_refs": [{"run_id": "audit_123"}],
        }]
        result = normalize_audit_findings(findings)
        ctx = result[0]["audit_context"]
        assert ctx["title"] == "Path traversal in parse_input"
        assert ctx["hypothesis"] == "Attacker-controlled path reaches filesystem"
        assert ctx["evidence_tool"] == "semgrep:/tmp/rule.yaml"
        assert ctx["provenance_refs"] == [{"run_id": "audit_123"}]

    def test_hypothesis_same_as_description_omitted(self):
        findings = [{
            "id": "F1",
            "description": "same text",
            "hypothesis": "same text",
        }]
        result = normalize_audit_findings(findings)
        assert "hypothesis" not in result[0].get("audit_context", {})

    def test_skips_non_dict_entries(self):
        findings = [{"id": "F1"}, "not a dict", 42]
        result = normalize_audit_findings(findings)
        assert len(result) == 1

    def test_no_audit_context_when_no_rich_fields(self):
        findings = [{"id": "F1", "file": "a.py", "line": 1}]
        result = normalize_audit_findings(findings)
        assert "audit_context" not in result[0]

    def test_original_fields_preserved(self):
        findings = [{
            "id": "F1", "file": "a.py", "function": "parse",
            "line": 42, "severity": "medium", "source": "audit",
            "title": "vuln", "description": "desc",
            "evidence_tool": "semgrep:x", "hypothesis": "hyp",
            "provenance_refs": [{"run_id": "r1"}],
        }]
        result = normalize_audit_findings(findings)
        f = result[0]
        assert f["file"] == "a.py"
        assert f["function"] == "parse"
        assert f["line"] == 42
        assert f["severity"] == "medium"


class TestInjectChainsIdCollision:
    def test_repeated_inject_no_id_collision(self, tmp_path):
        surface_path = tmp_path / "attack-surface.json"
        surface_path.write_text(json.dumps({"hypotheses": []}))
        chains_a = [{"description": "chain A", "goal": "goal A",
                      "primitives": [], "findings": []}]
        chains_b = [{"description": "chain B", "goal": "goal B",
                      "primitives": [], "findings": []}]

        inject_chains_as_hypotheses(chains_a, surface_path)
        inject_chains_as_hypotheses(chains_b, surface_path)

        data = json.loads(surface_path.read_text())
        ids = [h["id"] for h in data["hypotheses"]]
        assert len(ids) == len(set(ids)), f"duplicate IDs: {ids}"
        assert ids == ["audit_chain_0", "audit_chain_1"]

class TestLoadDarkFindings:
    def test_loads_only_dark(self, tmp_path):
        graded = {
            "findings": [
                {"status": "dark", "title": "idor", "file": "o.py",
                 "function": "get_order", "line": 4,
                 "hypothesis": "order id not scoped to user"},
                {"status": "finding", "title": "overflow", "file": "a.c",
                 "function": "f", "line": 9},
            ],
        }
        (tmp_path / "findings-graded.json").write_text(json.dumps(graded))
        dark = load_dark_findings(tmp_path)
        assert len(dark) == 1
        assert dark[0]["title"] == "idor"

    def test_empty_on_missing_file(self, tmp_path):
        assert load_dark_findings(tmp_path) == []

    def test_empty_on_malformed_json(self, tmp_path):
        (tmp_path / "findings-graded.json").write_text("{not json")
        assert load_dark_findings(tmp_path) == []


class TestInjectDarkAsHypotheses:
    def _dark(self):
        return [{
            "status": "dark", "title": "idor in order lookup",
            "file": "orders.py", "function": "get_order", "line": 4,
            "hypothesis": "order id not scoped to requesting user",
            "cwe_class": "CWE-639", "verification_tier": "speculative",
        }]

    def test_injects_into_surface(self, tmp_path):
        surface_path = tmp_path / "attack-surface.json"
        surface_path.write_text(json.dumps({"hypotheses": []}))
        injected = inject_dark_as_hypotheses(self._dark(), surface_path)
        assert injected == 1
        data = json.loads(surface_path.read_text())
        h = data["hypotheses"][0]
        assert h["source"] == "audit_dark"
        assert h["needs_validation"] is True
        assert h["file"] == "orders.py"
        assert h["function"] == "get_order"
        assert h["description"] == "order id not scoped to requesting user"
        assert h["cwe"] == "CWE-639"

    def test_dedupes_on_reinject(self, tmp_path):
        surface_path = tmp_path / "attack-surface.json"
        surface_path.write_text(json.dumps({"hypotheses": []}))
        inject_dark_as_hypotheses(self._dark(), surface_path)
        injected = inject_dark_as_hypotheses(self._dark(), surface_path)
        assert injected == 0
        data = json.loads(surface_path.read_text())
        assert len(data["hypotheses"]) == 1

    def test_missing_surface_file(self, tmp_path):
        assert inject_dark_as_hypotheses(
            self._dark(), tmp_path / "attack-surface.json",
        ) == 0

    def test_empty_input(self, tmp_path):
        surface_path = tmp_path / "attack-surface.json"
        surface_path.write_text(json.dumps({"hypotheses": []}))
        assert inject_dark_as_hypotheses([], surface_path) == 0

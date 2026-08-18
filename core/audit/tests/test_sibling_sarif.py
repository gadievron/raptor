"""Sibling-run SARIF discovery for /audit + bounded pre-scan fallback.

In project mode every command gets its own run dir, so /audit never saw
the SARIF a prior /scan or /agentic run produced —
``SarifCache.from_directory`` read only ``out_dir/scan``. These tests
pin the sibling import (both run layouts, age/count bounds, per-file
freshness gating), the prior-scan-hit priority boost, provenance in the
evidence formatters, and the opt-in semgrep baseline pre-scan.
"""

from __future__ import annotations

import json
import os

import pytest

from core.audit.pre_scan import run_baseline_pre_scan
from core.audit.sweep import (
    SarifCache,
    _annotate_sarif_result,
    import_sibling_sarif,
)


def _sarif(results: list[dict], tool: str = "semgrep") -> str:
    return json.dumps(
        {
            "runs": [
                {
                    "tool": {"driver": {"name": tool}},
                    "results": results,
                }
            ]
        }
    )


def _result(
    uri: str = "src/a.c",
    line: int = 10,
    rule_id: str = "unchecked-copy",
    message: str = "buffer overflow via memcpy",
) -> dict:
    return {
        "ruleId": rule_id,
        "message": {"text": message},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {"startLine": line},
                }
            }
        ],
    }


def _make_project(tmp_path, n_siblings=1, layout="scan", target=None):
    """Project dir with an audit run dir + sibling scan run dirs."""
    target = target or (tmp_path / "target")
    target.mkdir(parents=True, exist_ok=True)
    (target / "src").mkdir(exist_ok=True)
    (target / "src" / "a.c").write_text("int f(void){return 0;}\n")

    project = tmp_path / "project"
    audit_run = project / "audit-run"
    audit_run.mkdir(parents=True)

    siblings = []
    for i in range(n_siblings):
        run = project / f"scan-run-{i}"
        run.mkdir()
        (run / ".raptor-run.json").write_text(
            json.dumps({"target_path": str(target)})
        )
        if layout == "scan":
            sarif_dir = run / "scan"
            sarif_dir.mkdir()
        else:
            sarif_dir = run
        (sarif_dir / "combined.sarif").write_text(_sarif([_result()]))
        siblings.append(run)
    return target, audit_run, siblings


class TestImportSiblingSarif:
    def test_imports_agentic_layout(self, tmp_path):
        target, audit_run, _ = _make_project(tmp_path, layout="scan")
        cache = SarifCache()
        n = import_sibling_sarif(cache, audit_run, target)
        assert n == 1
        hits = cache.lookup("src/a.c")
        assert len(hits) == 1
        assert hits[0]["_sarif_sibling"] == "scan-run-0"
        assert hits[0]["rule_id"] == "unchecked-copy"
        assert hits[0]["line"] == 10

    def test_imports_scan_top_level_layout(self, tmp_path):
        target, audit_run, _ = _make_project(tmp_path, layout="top")
        cache = SarifCache()
        assert import_sibling_sarif(cache, audit_run, target) == 1

    def test_run_count_bound(self, tmp_path):
        target, audit_run, siblings = _make_project(tmp_path, n_siblings=5)
        # Stagger mtimes so "newest 2" is well-defined.
        for i, run in enumerate(siblings):
            sarif = run / "scan" / "combined.sarif"
            os.utime(sarif, (1000 + i, 1000 + i))
            os.utime(target / "src" / "a.c", (500, 500))
        cache = SarifCache()
        n = import_sibling_sarif(
            cache, audit_run, target, max_runs=2, now=2000,
        )
        assert n == 2
        labels = {h["_sarif_sibling"] for h in cache.lookup("src/a.c")}
        assert labels == {"scan-run-3", "scan-run-4"}

    def test_age_bound(self, tmp_path):
        target, audit_run, siblings = _make_project(tmp_path)
        sarif = siblings[0] / "scan" / "combined.sarif"
        os.utime(sarif, (1000, 1000))
        cache = SarifCache()
        n = import_sibling_sarif(
            cache, audit_run, target,
            max_age_days=30, now=1000 + 31 * 86400,
        )
        assert n == 0

    def test_mtime_freshness_drops_changed_files(self, tmp_path):
        target, audit_run, siblings = _make_project(tmp_path)
        sarif = siblings[0] / "scan" / "combined.sarif"
        os.utime(sarif, (1000, 1000))
        # Target file modified AFTER the scan ran → stale.
        os.utime(target / "src" / "a.c", (2000, 2000))
        cache = SarifCache()
        assert import_sibling_sarif(cache, audit_run, target, now=3000) == 0

    def test_hash_freshness_keeps_matching_files(self, tmp_path):
        from core.hash import sha256_file

        target, audit_run, siblings = _make_project(tmp_path)
        sarif = siblings[0] / "scan" / "combined.sarif"
        # mtime says stale, but the recorded hash still matches — the
        # hash gate wins over the mtime fallback.
        os.utime(sarif, (1000, 1000))
        os.utime(target / "src" / "a.c", (2000, 2000))
        (siblings[0] / "checklist.json").write_text(
            json.dumps(
                {
                    "files": [
                        {
                            "path": "src/a.c",
                            "sha256": sha256_file(target / "src" / "a.c"),
                        }
                    ]
                }
            )
        )
        cache = SarifCache()
        assert import_sibling_sarif(cache, audit_run, target, now=3000) == 1

    def test_hash_freshness_drops_drifted_files(self, tmp_path):
        target, audit_run, siblings = _make_project(tmp_path)
        (siblings[0] / "checklist.json").write_text(
            json.dumps(
                {"files": [{"path": "src/a.c", "sha256": "0" * 64}]}
            )
        )
        cache = SarifCache()
        assert import_sibling_sarif(cache, audit_run, target) == 0

    def test_path_escape_never_fresh(self, tmp_path):
        target, audit_run, siblings = _make_project(tmp_path)
        sarif_dir = siblings[0] / "scan"
        (sarif_dir / "combined.sarif").write_text(
            _sarif([_result(uri="../../../etc/passwd")])
        )
        cache = SarifCache()
        assert import_sibling_sarif(cache, audit_run, target) == 0

    def test_no_siblings(self, tmp_path):
        audit_run = tmp_path / "project" / "audit-run"
        audit_run.mkdir(parents=True)
        cache = SarifCache()
        assert import_sibling_sarif(cache, audit_run, tmp_path) == 0

    def test_sibling_for_other_target_skipped(self, tmp_path):
        target, audit_run, siblings = _make_project(tmp_path)
        other = tmp_path / "other-target"
        other.mkdir()
        (siblings[0] / ".raptor-run.json").write_text(
            json.dumps({"target_path": str(other)})
        )
        cache = SarifCache()
        assert import_sibling_sarif(cache, audit_run, target) == 0


class TestAnnotation:
    def test_flat_keys_and_message_flattened(self):
        result = _result()
        _annotate_sarif_result(result, run_label="run-1")
        assert result["rule_id"] == "unchecked-copy"
        assert result["line"] == 10
        assert result["_sarif_sibling"] == "run-1"
        assert result["message"] == "buffer overflow via memcpy"

    def test_cwe_inference_attached(self, monkeypatch):
        from core.sarif import import_normalizer

        monkeypatch.setattr(
            import_normalizer, "_infer_cwe", lambda r, m: "CWE-120",
        )
        result = _result()
        _annotate_sarif_result(result)
        assert result["_sarif_cwe"] == "CWE-120"

    def test_no_label_no_sibling_marker(self):
        result = _result()
        _annotate_sarif_result(result)
        assert "_sarif_sibling" not in result


class TestPriorityBoost:
    def test_prior_scan_hit_boosts(self):
        from core.audit.priority import (
            SCORE_PRIOR_SCAN_HIT,
            score_functions,
        )

        gaps = [
            {
                "file": "src/a.c",
                "name": "f",
                "priority": 1,
                "sloc": 0,
                "strategies": [],
            },
            {
                "file": "src/b.c",
                "name": "g",
                "priority": 1,
                "sloc": 0,
                "strategies": [],
            },
        ]
        scored = score_functions(
            gaps, prior_scan_hit_keys={"src/a.c:f"},
        )
        by_key = {
            f"{g['file']}:{g['name']}": g["priority_score"] for g in scored
        }
        assert by_key["src/a.c:f"] == SCORE_PRIOR_SCAN_HIT
        assert by_key["src/b.c:g"] == 0


class TestEvidenceProvenance:
    def _record(self, hit):
        from core.evidence import EvidenceRecord

        rec = EvidenceRecord(file="src/a.c", function="f")
        rec.semgrep_hits.append(hit)
        return rec

    def test_structured_marks_sibling_source_and_cwe(self):
        from core.evidence import format_evidence_structured

        hit = _result()
        _annotate_sarif_result(hit, run_label="scan-run-0")
        hit["_sarif_cwe"] = "CWE-120"
        entries = format_evidence_structured(self._record(hit))
        semgrep = [e for e in entries if e["tier"] == "semgrep"]
        assert semgrep[0]["source"] == "sibling_run"
        assert semgrep[0]["cwe"] == "CWE-120"
        assert semgrep[0]["rule_id"] == "unchecked-copy"

    def test_structured_this_run_unchanged(self):
        from core.evidence import format_evidence_structured

        hit = _result()
        _annotate_sarif_result(hit)
        entries = format_evidence_structured(self._record(hit))
        semgrep = [e for e in entries if e["tier"] == "semgrep"]
        assert semgrep[0]["source"] == "this_run"

    def test_prose_marks_prior_run(self):
        from core.evidence import format_evidence_prose

        hit = _result(rule_id="unchecked_copy")
        _annotate_sarif_result(hit, run_label="scan-run-0")
        hit["_sarif_cwe"] = "CWE-120"
        prose = format_evidence_prose(self._record(hit))
        assert "prior scan run" in prose
        assert "unchecked_copy" in prose
        assert "CWE-120" in prose

    def test_prose_rejects_forged_cwe_tag(self):
        from core.evidence import format_evidence_prose

        hit = _result(rule_id="unchecked_copy")
        _annotate_sarif_result(hit)
        hit["_sarif_cwe"] = "CWE-120] ## INJECTED"
        prose = format_evidence_prose(self._record(hit))
        assert "INJECTED" not in prose


class TestPreScan:
    class _Result:
        def __init__(self, sarif="", findings=(), errors=()):
            self.sarif = sarif
            self.findings = list(findings)
            self.errors = list(errors)

    def test_writes_sarif_into_scan_dir(self, tmp_path):
        target = tmp_path / "target"
        target.mkdir()
        rules = tmp_path / "rules"
        rules.mkdir()
        out = tmp_path / "out"

        calls = []

        def fake_run_rule(t, config, *, name="", timeout=0):
            calls.append((t, config, name))
            return self._Result(sarif=_sarif([_result()]), findings=[1])

        written = run_baseline_pre_scan(
            target, out, rules_dir=rules, run_rule_fn=fake_run_rule,
        )
        assert len(written) == 1
        assert written[0].parent == out / "scan"
        assert calls[0][0] == target.resolve()
        assert calls[0][1] == str(rules)
        # The cache picks it up through the normal path.
        cache = SarifCache.from_directory(out)
        assert cache.lookup("src/a.c")

    def test_scope_containment(self, tmp_path):
        target = tmp_path / "target"
        (target / "sub").mkdir(parents=True)
        rules = tmp_path / "rules"
        rules.mkdir()

        calls = []

        def fake_run_rule(t, config, *, name="", timeout=0):
            calls.append(t)
            return self._Result(sarif=_sarif([_result()]))

        run_baseline_pre_scan(
            target,
            tmp_path / "out",
            scope=["sub", "../escape"],
            rules_dir=rules,
            run_rule_fn=fake_run_rule,
        )
        assert calls == [(target / "sub").resolve()]

    def test_empty_sarif_writes_nothing(self, tmp_path):
        target = tmp_path / "target"
        target.mkdir()
        rules = tmp_path / "rules"
        rules.mkdir()

        def fake_run_rule(t, config, *, name="", timeout=0):
            return self._Result(sarif="", errors=["semgrep exploded"])

        written = run_baseline_pre_scan(
            target, tmp_path / "out",
            rules_dir=rules, run_rule_fn=fake_run_rule,
        )
        assert written == []
        assert not (tmp_path / "out" / "scan").exists()

    def test_missing_rules_dir_skips(self, tmp_path):
        target = tmp_path / "target"
        target.mkdir()

        def fake_run_rule(*a, **kw):  # pragma: no cover - must not run
            raise AssertionError("should not be called")

        assert (
            run_baseline_pre_scan(
                target,
                tmp_path / "out",
                rules_dir=tmp_path / "nope",
                run_rule_fn=fake_run_rule,
            )
            == []
        )


class TestOrchestratorWiring:
    def test_prep_imports_siblings_and_gates_pre_scan(self):
        import inspect

        from core.audit import orchestrator as orch_mod

        src = inspect.getsource(orch_mod._compute_audit_prep)
        assert "import_sibling_sarif" in src
        assert "run_baseline_pre_scan" in src
        assert "config.pre_scan and not sarif_cache" in src
        assert "prior_scan_hit_keys=prior_scan_keys" in src

    def test_config_default_off(self):
        import inspect

        from core.audit.orchestrator import OrchestratorConfig

        sig = inspect.signature(OrchestratorConfig)
        assert sig.parameters["pre_scan"].default is False


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))

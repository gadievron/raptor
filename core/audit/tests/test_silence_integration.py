"""Integration: silence admissibility through the whole seam.

The real review loop (``core.audit.orchestrator.run_orchestrator``;
stub transport, canned model ``finding`` verdicts) over a PHP tree
whose run directory holds a POPULATED SARIF cache — the state the
substrate integration test pinned empty because
the sarif_cache phantom-coverage alias made every resolution
undecidable. Real ``_sweep_validate`` → real chain → real
``run_semgrep_sweep`` (semgrep stubbed at the runner boundary: the
binary runs clean, scans the target, matches nothing) → G2 → real
``_resolve_gate_demoted`` → export.

Cells (one function each; every model verdict is an evidence-free
``finding``, so G2 demotes it and the end-of-run resolver decides):

* ``by_alias``     — CWE-89 claim whose chain dispatches no live channel
  (joern down); ONE unrelated stock-rule SARIF hit elsewhere in the
  file. Pre-fix: the file-level alias "covered" it → clean, dropped.
* ``by_keyword``   — CWE-89 claim worded with a hypothesis-keyword table
  phrase: the keyword rule's scanned zero-match. Pre-fix: refuted →
  class coverage → clean, dropped.
* ``by_attr_rule`` — CWE-79 body-context XSS; the dispatched curated
  rule (php/attr-xss.yaml) adjudicates only the attribute-context
  sub-shape. Pre-fix: its silence refuted the class → clean, dropped.
* ``by_argument``  — CWE-88 claim; the curated argument-injection rule
  is confirm-only. Its scanned silence leaves the claim dark and exported.
* ``by_control``   — CONTROL: a claim about a literal fixture-marker call;
  an unmarked fixture rule covers that complete bounded claim. Its scanned
  silence remains a probative refutation → clean.
* ``by_lineless``  — (own file) a CORRELATED SQL-injection SARIF result
  with no placeable line. Pre-fix: placed in every function's range,
  it corroborated the claim → suspicious; now unplaceable → no
  corroboration, no covering channel → dark (still exported).

* ``tiny``         — (own file, declared scanned, zero alerts) resolved
  by the sarif-clean gate without review: clean, journaled with
  ``clean_basis="sarif_clean"`` so reuse re-runs the gate instead of
  importing it.

Pinned flip set (pre-fix → now): by_alias clean→dark, by_keyword
clean→dark, by_attr_rule clean→dark, by_argument clean→dark,
by_lineless suspicious→dark; by_control clean→clean.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import core.audit.orchestrator as orch
import packages.semgrep.runner as semgrep_runner
from core.audit.findings_export import export_findings
from core.audit.orchestrator import (
    OrchestratorConfig,
    ReviewOutcome,
    run_orchestrator,
)
from core.audit.substrate import _reset_substrate_caches
from packages.semgrep.models import SemgrepResult

_APP = (
    "<?php\n"                                                     # 1
    "function by_alias($db, $id) {\n"                             # 2
    "    return $db->fetch_by($id);\n"                            # 3
    "}\n"                                                         # 4
    "function by_keyword($db, $id) {\n"                           # 5
    "    return $db->fetch_by($id);\n"                            # 6
    "}\n"                                                         # 7
    "function by_attr_rule($name) {\n"                            # 8
    "    return \"<p>\" . $name . \"</p>\";\n"                    # 9
    "}\n"                                                         # 10
    "function by_argument($flag) {\n"                             # 11
    "    return $flag;\n"                                         # 12
    "}\n"                                                         # 13
    "function unrelated() {\n"                                    # 14
    "    phpinfo();\n"                                            # 15
    "}\n"                                                         # 16
    "function by_control($flag) {\n"                              # 17
    "    return $flag;\n"                                         # 18
    "}\n"                                                         # 19
)
_TINY = "<?php\nfunction tiny($a) {\n    return $a + 1;\n}\n"
_LINELESS = (
    "<?php\n"
    "function by_lineless($db, $id) {\n"
    "    return $db->fetch_by($id);\n"
    "}\n"
)

# function -> (cwe, hypothesis). by_keyword's wording carries the
# hypothesis-keyword table phrase ("sql injection"); the others are
# worded so no keyword/mechanical-check rule is generated.
_CLAIMS = {
    "by_alias": ("CWE-89", "the id reaches the database lookup unescaped"),
    "by_keyword": ("CWE-89", "SQL injection: id reaches the query unescaped"),
    "by_attr_rule": ("CWE-79", "the name is echoed into the page unescaped"),
    "by_argument": ("CWE-88", "the flag is passed to the command unescaped"),
    "by_control": ("", "the fixture_marker call is present"),
    "by_lineless": ("CWE-89", "the id reaches the database lookup unescaped"),
}

_EXPECTED = {
    "by_alias": "dark",
    "by_keyword": "dark",
    "by_attr_rule": "dark",
    "by_argument": "dark",
    "by_lineless": "dark",
    "by_control": "clean",
}
_PRE_FIX = {
    "by_alias": "clean",
    "by_keyword": "clean",
    "by_attr_rule": "clean",
    "by_argument": "clean",
    "by_lineless": "suspicious",
    "by_control": "clean",
}


def _write_tree(tmp_path: Path) -> tuple[Path, Path]:
    target = tmp_path / "target"
    target.mkdir()
    (target / "app.php").write_text(_APP)
    (target / "lineless.php").write_text(_LINELESS)
    (target / "tiny.php").write_text(_TINY)
    out = tmp_path / "out"
    (out / "scan").mkdir(parents=True)
    items = [
        {"name": "by_alias", "line_start": 2, "line_end": 4},
        {"name": "by_keyword", "line_start": 5, "line_end": 7},
        {"name": "by_attr_rule", "line_start": 8, "line_end": 10},
        {"name": "by_argument", "line_start": 11, "line_end": 13},
        {"name": "unrelated", "line_start": 14, "line_end": 16},
        {"name": "by_control", "line_start": 17, "line_end": 19},
    ]
    checklist = {"files": [
        {"path": "app.php", "language": "php", "items": items},
        {"path": "lineless.php", "language": "php", "items": [
            {"name": "by_lineless", "line_start": 2, "line_end": 4}]},
        {"path": "tiny.php", "language": "php", "items": [
            {"name": "tiny", "line_start": 2, "line_end": 4}]},
    ]}
    (out / "checklist.json").write_text(json.dumps(checklist))
    (out / "context-map.json").write_text(json.dumps({
        "entry_points": [
            {"file": f["path"], "name": i["name"]}
            for f in checklist["files"] for i in f["items"]
            if i["name"] in _CLAIMS
        ],
        "sinks": [], "trust_boundaries": [], "unchecked_flows": [],
    }))

    def _result(rule, uri, region):
        loc = {"artifactLocation": {"uri": uri}}
        if region is not None:
            loc["region"] = region
        return {"ruleId": rule, "message": {"text": "x"},
                "locations": [{"physicalLocation": loc}]}

    # The populated cache: one unrelated stock-rule hit inside
    # ``unrelated`` (app.php) and one correlated SQL-injection hit with
    # no placeable line (lineless.php).
    (out / "scan" / "prior.sarif").write_text(json.dumps({
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "Semgrep OSS"}},
            # tiny.php: declared scanned, zero alerts — the sarif-clean
            # gate's input (a small non-entry function in it resolves
            # clean without review).
            "artifacts": [{"location": {"uri": "tiny.php"}}],
            "results": [
                _result("php.lang.best-practice.phpinfo-use", "app.php",
                        {"startLine": 15}),
                _result("php.lang.security.injection.tainted-sql-string",
                        "lineless.php", None),
            ],
        }],
    }))
    return target, out


def _review_fn(ctx, config):
    fn = ctx["function"]
    cwe, hypothesis = _CLAIMS.get(fn, ("", ""))
    if not hypothesis:
        return ReviewOutcome(
            file=ctx["file"], function=fn, status="clean", body="ok",
            line=ctx.get("line_start", 1) or 1, model="stub-transport",
        )
    return ReviewOutcome(
        file=ctx["file"], function=fn, status="finding",
        body=f"model claim for {fn}", hypothesis=hypothesis,
        review_result={"cwe": cwe, "mechanism": hypothesis},
        line=ctx.get("line_start", 1) or 1, model="stub-transport",
    )


@pytest.mark.slow
class TestPopulatedSarifCacheSeam:
    """End to end through run_orchestrator with a populated SARIF cache:
    each silence shape the fix closes resolves dark, and the probative
    control stays clean."""

    @pytest.fixture()
    def run(self, tmp_path, monkeypatch):
        _reset_substrate_caches()
        target, out = _write_tree(tmp_path)
        # Keep a genuinely probative control independent of curated rule roles.
        # This rule covers only the fixture's literal-call presence claim.
        control_rule = tmp_path / "control.yaml"
        control_rule.write_text(
            "rules:\n  - id: fixture-marker\n    languages: [php]\n"
            "    pattern: fixture_marker(...)\n    message: marker call\n"
            "    severity: WARNING\n",
        )
        original_chain = orch._hypothesis_to_tool_chain

        def tool_chain(hypothesis, *args, **kwargs):
            if hypothesis == _CLAIMS["by_control"][1]:
                return [{"type": "semgrep", "config": {"rule": str(control_rule)}}]
            return original_chain(hypothesis, *args, **kwargs)

        monkeypatch.setattr(orch, "_hypothesis_to_tool_chain", tool_chain)
        # This seam exercises scanner receipts and resolution, not background
        # study, unrelated detectors, or LLM-generated witness probes.
        monkeypatch.setattr(orch, "_run_mechanical_detectors", lambda *a, **k: ({}, set()))
        monkeypatch.setattr(orch, "_study_consumer", lambda *a, **k: None)
        monkeypatch.setattr(orch, "_run_dark_verification", lambda *a, **k: None)
        # No CodeQL channel participates in this Semgrep receipt fixture.
        monkeypatch.setattr(orch, "_resolved_codeql_query", lambda *a, **k: None)
        # semgrep at the runner boundary: available, scans the target
        # (scanned-path witness present), matches nothing.
        monkeypatch.setattr(semgrep_runner, "is_available", lambda: True)
        monkeypatch.setattr(
            semgrep_runner, "run_rule",
            lambda tgt, cfg, **kw: SemgrepResult(
                name="r", config=str(cfg), target=str(tgt),
                findings=[], errors=[], returncode=0,
                files_examined=[str(tgt)]),
        )
        monkeypatch.setattr(
            orch, "_start_joern_server_raw", lambda *a, **kw: None)
        # Hermetic prefilter: no regex stamp may end validation before
        # the chain dispatches (the cells isolate the chain + resolver).
        monkeypatch.setattr(
            orch, "run_prefilter",
            lambda **kw: SimpleNamespace(
                hits=[], skip_llm=False, skip_reason="", language="php",
                sloc=10),
        )
        checklist = json.loads((out / "checklist.json").read_text())
        config = OrchestratorConfig(
            target_path=target, out_dir=out, resume=False,
            inventory=checklist, batch_sloc_threshold=0,
            # Canned synchronous reviews do not need model-derived parallelism.
            max_workers=1,
            verdict_reuse=False,
            immediate_verify=False, on_demand_synthesis=False,
        )
        result = run_orchestrator(config, _review_fn)
        return result, out

    def test_cache_is_populated(self, run):
        """Anti-vacuity: the run really wrote SARIF, so the cache the
        cells rely on is populated."""
        _result, out = run
        assert list(out.rglob("*.sarif"))

    def test_exact_flip_set(self, run):
        """Non-probative claims stay dark; the bounded control stays clean."""
        result, _out = run
        final = {o.function: o.status for o in result.outcomes
                 if o.function in _CLAIMS}
        assert final == _EXPECTED
        flipped = {fn for fn in _CLAIMS if _PRE_FIX[fn] != final[fn]}
        assert flipped == {
            "by_alias", "by_keyword", "by_attr_rule", "by_argument", "by_lineless"}

    def test_flipped_rows_are_exported_and_the_control_is_not(self, run):
        """The flipped rows reach the export; the probatively refuted
        control does not."""
        result, _out = run
        exported = {
            f.get("function") for f in
            export_findings(result.outcomes)["findings"]
        }
        assert {"by_alias", "by_keyword", "by_attr_rule",
                "by_argument", "by_lineless"} <= exported
        assert "by_control" not in exported

    def test_records_name_the_non_probative_channel(self, run):
        """Non-probative rules record inconclusive; the control is resolved."""
        result, _out = run
        by_fn = {o.function: o for o in result.outcomes}
        for fn in ("by_keyword", "by_attr_rule", "by_argument"):
            o = by_fn[fn]
            assert "semgrep" in (o.tools_dispatched or set())
            assert "semgrep" in (o.tools_inconclusive or set())
        control = by_fn["by_control"]
        assert "semgrep" in (control.tools_dispatched or set())
        assert not (control.tools_inconclusive or set())
        assert control.clean_basis == "gate_resolved"


    def test_sarif_clean_gate_row_is_stamped_silence_derived(self, run):
        """The sarif-clean gate's clean is file-level silence: journaled
        ``clean_basis="sarif_clean"`` (refused by cross-run reuse)."""
        from core.coverage.journal import latest_entries

        result, out = run
        by_fn = {o.function: o for o in result.outcomes}
        assert by_fn["tiny"].status == "clean"
        assert by_fn["tiny"].evidence_tool == "sarif:no_alerts", (
            "precondition: the sarif-clean gate resolved it")
        assert by_fn["tiny"].clean_basis == "sarif_clean"
        row = latest_entries(out)["tiny.php:tiny"]
        assert row.clean_basis == "sarif_clean"

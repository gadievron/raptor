"""Silence admissibility: a channel's silence becomes a negative verdict
only when the run completed PROBATIVELY, the rule can ADJUDICATE the
claim, and the silence COVERS the claimed function.

Each class pins one leaf of that contract end to end through the real
producer and the real consumer:

* file-level SARIF presence — a SARIF hit (any rule, anywhere in
  the file) is not a covering channel for a function's class claim;
* unplaceable SARIF results — a result with no placeable line is in
  no function's range (``_match_in_range``'s single policy);
* inconclusive outcomes — an ``inconclusive`` outcome on any
  coverage-mapped channel stays in the dispatch record (the tool
  looked) but is booked in ``tools_inconclusive`` and never earns
  class coverage;
* the booking tripwire — every ``"inconclusive"`` tier increment in
  the record-writing validators also books the channel (the
  ``smt_invariant`` leg used to count it and record nothing);
* keyword rules — a hypothesis-keyword semgrep rule's scanned zero-match is
  inconclusive IN THE SWEEP, so the tier counter, the substrate
  receipt and the refinement prompt agree;
* clean tier and propagation — a clean grades ``tool_backed`` only
  on a probative channel, so propagation never trusts a
  non-probative clean;
* observations — ``[tool-refuted]`` needs a probative refutation.

Isolating controls ride with every leaf: the same record with a
probative (refuted) channel still resolves clean / grades tool_backed,
so the fix never starves a genuine refutation.
"""

from __future__ import annotations

import ast
import inspect
import json
import textwrap
from pathlib import Path
from types import SimpleNamespace

import pytest

import core.audit.orchestrator as orch
from core.audit.findings_export import export_findings
from core.audit.orchestrator import (
    OrchestratorConfig,
    OrchestratorResult,
    ReviewOutcome,
    _check_finding_gates,
    _demote_outcome,
    _resolve_gate_demoted,
)
from core.audit.sweep import SarifCache, SweepResult

_PHP = (
    "<?php\nfunction getUser($db, $id) {\n"
    "  return $db->query(\"SELECT * FROM users WHERE id = \" . $id);\n"
    "}\n\nfunction other() {\n  echo $_GET['x'];\n}\n"
)
_PHP_CK = {"files": [{"path": "app.php", "items": [
    {"name": "getUser", "line_start": 2, "line_end": 4},
    {"name": "other", "line_start": 6, "line_end": 8},
]}]}
_C = (
    "#include <string.h>\n"
    "void cp(char *d, const char *s, int n) {\n"
    "  char b[8];\n  memcpy(b, s, n);\n}\n"
)
_C_CK = {"files": [{"path": "a.c", "items": [
    {"name": "cp", "line_start": 2, "line_end": 5},
]}]}


def _sarif(results, *, tool="Semgrep OSS", declare=None):
    run = {
        "tool": {"driver": {"name": tool}},
        "results": [{
            "ruleId": rid, "message": {"text": "x"},
            "locations": [{"physicalLocation": dict(
                {"artifactLocation": {"uri": f}},
                **({"region": region} if region is not None else {}),
            )}],
        } for (rid, f, region) in results],
    }
    if declare is not None:
        run["artifacts"] = [{"location": {"uri": f}} for f in declare]
    return {"version": "2.1.0", "runs": [run]}


def _target(tmp_path: Path, name: str, src: str) -> tuple[Path, Path]:
    tgt = tmp_path / "tgt"
    tgt.mkdir()
    (tgt / name).write_text(src)
    out = tmp_path / "out"
    (out / "scan").mkdir(parents=True)
    return tgt, out


def _resolve(outcome, config, sarif_cache, checklist, tools):
    result = OrchestratorResult()
    result.outcomes = [outcome]
    result.suspicious = int(outcome.status == "suspicious")
    _resolve_gate_demoted(
        result, config, sarif_cache, checklist,
        domain_model=None, available_tools=tools, mechanical_findings={},
    )
    final = result.outcomes[0]
    return final, len(export_findings(result.outcomes)["findings"])


def _g2_demoted(outcome):
    violations = _check_finding_gates(outcome)
    assert any(v.startswith("G2") for v in violations), violations
    return _demote_outcome(
        outcome, f"[gate violation: {'; '.join(violations)}]",
    )


def _php_claim(**kw):
    return ReviewOutcome(
        file="app.php", function="getUser", status="finding",
        body="model claim", hypothesis="user id concatenated into SQL",
        evidence_tool="",
        review_result={"cwe": "CWE-89", "mechanism": "SQL injection"},
        line=2, **kw,
    )


def _inc(outcome) -> set:
    """The outcome's non-probative channel record (absent → empty)."""
    return set(getattr(outcome, "tools_inconclusive", None) or ())


def _outcome(**kw):
    """ReviewOutcome with the record fields set as attributes, so the
    isolating controls construct identically before and after the
    field exists."""
    record = {k: kw.pop(k) for k in (
        "tools_dispatched", "tools_errored", "tools_skipped",
        "tools_inconclusive") if k in kw}
    outcome = ReviewOutcome(**kw)
    for k, v in record.items():
        setattr(outcome, k, v)
    return outcome


# ------------------------------------------ file-level SARIF presence


class TestFileLevelSarifIsNotCoverage:
    """A SARIF result anywhere in the file used to alias to a semgrep
    run (``ran.add("sarif_cache")``): one unrelated stock-rule hit in
    ANOTHER function resolved this function's class claim clean and
    dropped it from the export. File-level, rule-blind presence never
    covers a function claim — with or without the hit, the claim with
    no covering channel resolves dark."""

    @pytest.fixture(autouse=True)
    def _no_prefilter_corroboration(self, monkeypatch):
        """Hermetic: a prefilter hit on the SQL sink would count as
        mechanical corroboration and keep the claim suspicious whatever
        the SARIF state, so these cells stub it out and isolate the
        SARIF coverage question."""
        monkeypatch.setattr(
            orch, "run_prefilter",
            lambda **kw: SimpleNamespace(
                hits=[], skip_llm=False, skip_reason="", language="",
                sloc=10),
        )

    def _unrelated_hit(self, tmp_path, *, producer="disk", declare=None):
        tgt, out = _target(tmp_path, "app.php", _PHP)
        hit = [("php.lang.best-practice.phpinfo-use", "app.php",
                {"startLine": 7})]
        if producer == "disk":
            (out / "scan" / "s.sarif").write_text(
                json.dumps(_sarif(hit, declare=declare)))
            cache = SarifCache.from_directory(out)
        else:  # the CodeQL pre-sweep write path
            cache = SarifCache.from_directory(out)
            for r in _sarif(hit, tool="CodeQL")["runs"][0]["results"]:
                cache.ingest("app.php", r)
        # Anti-vacuity: the hit is file-level presence only — it is in
        # NO line of the claimed function and corroborates nothing.
        assert cache.lookup("app.php") is not None
        assert cache.lookup("app.php", 2, 4) == []
        return tgt, out, cache

    @pytest.mark.parametrize("producer", ["disk", "ingest"])
    def test_unrelated_same_file_hit_resolves_dark(self, tmp_path, producer):
        """An unrelated hit elsewhere in the file, from disk SARIF or a
        CodeQL ingest, must not cover this claim: it resolves dark
        and stays exported."""
        tgt, out, cache = self._unrelated_hit(tmp_path, producer=producer)
        config = OrchestratorConfig(target_path=tgt, out_dir=out)
        final, exported = _resolve(
            _g2_demoted(_php_claim()), config, cache, _PHP_CK,
            {"joern": False, "semgrep": True},
        )
        assert final.status == "dark"
        assert exported == 1

    def test_plain_suspicious_joern_up_resolves_dark(self, tmp_path):
        """The same holds for a plain suspicious row with joern
        available: file-level presence is never class coverage."""
        tgt, out, cache = self._unrelated_hit(tmp_path)
        config = OrchestratorConfig(target_path=tgt, out_dir=out)
        outcome = _php_claim()
        outcome.status = "suspicious"
        final, exported = _resolve(
            outcome, config, cache, _PHP_CK,
            {"joern": True, "semgrep": True},
        )
        assert final.status == "dark"
        assert exported == 1

    def test_declared_scan_is_monotone_in_unrelated_alerts(self, tmp_path):
        """A declared, silent scan resolves dark; adding ONE
        unrelated alert to the same file used to flip it clean (the
        unrelated alert "disconfirmed" the claim)."""
        finals = []
        for i, hits in enumerate(([], [("unrelated.rule", "app.php",
                                        {"startLine": 7})])):
            sub = tmp_path / f"cell{i}"
            sub.mkdir()
            tgt, out = _target(sub, "app.php", _PHP)
            (out / "scan" / "s.sarif").write_text(
                json.dumps(_sarif(hits, declare=["app.php"])))
            cache = SarifCache.from_directory(out)
            config = OrchestratorConfig(target_path=tgt, out_dir=out)
            final, exported = _resolve(
                _g2_demoted(_php_claim()), config, cache, _PHP_CK,
                {"joern": False, "semgrep": True},
            )
            finals.append((final.status, exported))
        assert finals == [("dark", 1), ("dark", 1)]

    def test_control_probative_dispatch_still_resolves_clean(self, tmp_path):
        """The coverage oracle is the dispatch record: a semgrep run
        that looked and refuted for THIS function still resolves the
        claim clean (the fix removes the alias, not the refutation)."""
        tgt, out, cache = self._unrelated_hit(tmp_path)
        config = OrchestratorConfig(target_path=tgt, out_dir=out)
        outcome = _php_claim()
        outcome.tools_dispatched = {"semgrep"}
        final, exported = _resolve(
            _g2_demoted(outcome), config, cache, _PHP_CK,
            {"joern": False, "semgrep": True},
        )
        assert final.status == "clean"
        assert exported == 0


# --------------------------------------------- unplaceable SARIF results


class TestUnplaceableSarifResult:
    """``_sarif_result_in_range`` placed a result with no startLine in
    EVERY function's range — the opposite of ``_match_in_range``'s
    stated policy ("unplaceable matches are NOT in range")."""

    _SRC = ("def a(x):\n    return x\n\n\ndef b(y):\n    return y\n\n\n"
            "def c(z):\n    return z\n")
    _CK = {"files": [{"path": "m.py", "items": [
        {"name": "a", "line_start": 1, "line_end": 2},
        {"name": "b", "line_start": 5, "line_end": 6},
        {"name": "c", "line_start": 9, "line_end": 10},
    ]}]}

    def _cache(self, tmp_path, region):
        (tmp_path / "m.py").write_text(self._SRC)
        out = tmp_path / "out"
        (out / "scan").mkdir(parents=True)
        (out / "scan" / "x.sarif").write_text(json.dumps(_sarif([(
            "python.lang.security.audit.dangerous-subprocess-use",
            "m.py", region,
        )])))
        return SarifCache.from_directory(out)

    @pytest.mark.parametrize("region", [
        None, {"startLine": 0}, {"charOffset": 120, "charLength": 5},
    ], ids=["no_region", "startLine_0", "offset_only"])
    def test_unplaceable_result_is_in_no_range(self, tmp_path, region):
        """A result with no region, startLine 0 or only a char offset is
        placed in no function, matching _match_in_range's policy."""
        from core.audit.sweep import _match_in_range, _sarif_result_in_range

        cache = self._cache(tmp_path, region)
        placed = [fn for fn, a, b in (("a", 1, 2), ("b", 5, 6), ("c", 9, 10))
                  if cache.lookup("m.py", a, b)]
        assert placed == []
        result = cache.lookup("m.py")[0]
        assert _sarif_result_in_range(result, 5, 6) is False
        # The policy twin agrees.
        assert _match_in_range({"line": 0}, 5, 6) is False

    @pytest.mark.parametrize("region", [None, {"startLine": 0}])
    def test_unplaceable_result_corroborates_nothing(self, tmp_path, region):
        """A line-less result used to corroborate every function in its
        file; it must corroborate none."""
        cache = self._cache(tmp_path, region)
        config = OrchestratorConfig(
            target_path=tmp_path, out_dir=tmp_path / "out")
        outcome = ReviewOutcome(
            file="m.py", function="b", status="suspicious",
            body="x", hypothesis="command injection via subprocess", line=5,
        )
        assert orch._has_mechanical_corroboration(
            outcome, config, cache, self._CK) is False

    def test_control_placed_result_keeps_its_function(self, tmp_path):
        """Control: a placed result still lands in exactly its own
        function."""
        cache = self._cache(tmp_path, {"startLine": 10})
        assert cache.lookup("m.py", 5, 6) == []
        assert len(cache.lookup("m.py", 9, 10)) == 1


# ---------------------------------------------------- inconclusive outcomes


def _stub_result(tool, outcome, matches=None):
    def _make(*_a, **kw):
        return SweepResult(
            tool=tool, file_path=kw.get("file_path", "f"),
            function_name=kw.get("function_name", "g"),
            outcome=outcome, matches=list(matches or []),
            details={"reason": f"stub {outcome}"},
        )
    return _make


def _arm_channel_stubs(monkeypatch, tool, outcome, matches=None):
    """Stub every per-channel runner at its boundary; the real
    ``_run_tool_chain`` leg classifies the result."""
    import core.audit.cocci_flow as cocci_flow
    import core.audit.joern_verify as joern_verify

    mk = _stub_result(tool, outcome, matches)
    monkeypatch.setattr(orch, "run_semgrep_sweep", mk)
    monkeypatch.setattr(
        orch, "_memoized_sweep_step",
        lambda cfg, name, key, fn: mk(file_path="f", function_name="g"),
    )
    monkeypatch.setattr(joern_verify, "run_guard_dominance_check", mk)
    monkeypatch.setattr(joern_verify, "run_flow_reachability_check", mk)
    monkeypatch.setattr(
        joern_verify, "extract_guard_target", lambda h, s: ("n", "memcpy"))
    monkeypatch.setattr(
        joern_verify, "extract_flow_endpoints", lambda h, s: ("n", "memcpy"))
    monkeypatch.setattr(cocci_flow, "run_flow_cocci_sweep", mk)
    monkeypatch.setattr(orch, "_joern_budget_timeout_s", lambda c: 30)
    monkeypatch.setattr(orch, "_joern_dispatch_blocked", lambda c: False)
    # Neutralise the prefilter: a correlated regex hit would stamp
    # evidence and return before the chain dispatches.
    monkeypatch.setattr(
        orch, "run_prefilter",
        lambda **kw: SimpleNamespace(
            hits=[], skip_llm=False, skip_reason="", language="", sloc=10),
    )


# channel -> (file, src, checklist, cwe, hypothesis, chain config, the
# coverage name the resolver's available_tools map keys on)
_CHANNELS = {
    "semgrep": ("app.php", _PHP, _PHP_CK, "CWE-89",
                "user id concatenated into $db->query",
                lambda t: {"rule": str(t / "r.yml")}, "semgrep"),
    "smt": ("a.c", _C, _C_CK, "CWE-190",
            "integer overflow: n * 4 wraps before memcpy",
            lambda t: {"verb": "check-overflow"}, "smt"),
    "codeql": ("a.c", _C, _C_CK, "CWE-787",
               "buffer overflow: memcpy n into b[8] out-of-bounds write",
               lambda t: {"query": str(t / "x.ql")}, "codeql"),
    "coccinelle": ("a.c", _C, _C_CK, "CWE-787",
                   "buffer overflow: memcpy n into b[8] out-of-bounds write",
                   lambda t: {"rule": str(t / "r.cocci")}, "coccinelle"),
    "coccinelle_flow": ("a.c", _C, _C_CK, "CWE-787",
                        "buffer overflow: memcpy n into b[8] out-of-bounds",
                        lambda t: {"cwe": "CWE-787", "sinks": ["memcpy"],
                                   "template": None}, "coccinelle"),
    "joern_guard": ("a.c", _C, _C_CK, "CWE-89",
                    "SQL injection: n flows into memcpy sink",
                    lambda t: {"cwe": "CWE-89", "sinks": ["memcpy"]},
                    "joern"),
    "joern_flow": ("a.c", _C, _C_CK, "CWE-89",
                   "SQL injection: n flows into memcpy sink",
                   lambda t: {"cwe": "CWE-89", "sinks": ["memcpy"]},
                   "joern"),
}


def _sweep_channel(tmp_path, monkeypatch, tool, outcome, *, matches=None,
                   chain=None, memo=None):
    """Real ``_sweep_validate`` (the record writer) over a one-channel
    chain → real G2 → real resolver → export."""
    fname, src, ck, cwe, hyp, cfg_fn, cov = _CHANNELS[tool]
    tgt, out = _target(tmp_path, fname, src)
    (tmp_path / "r.yml").write_text("rules: []\n")
    (tmp_path / "x.ql").write_text("select 1\n")
    (tmp_path / "r.cocci").write_text("@r@\n@@\nmemcpy(...);\n")
    config = OrchestratorConfig(target_path=tgt, out_dir=out)
    if tool == "codeql":
        db = tmp_path / "db"
        db.mkdir()
        config.codeql_db_path = db
    _arm_channel_stubs(monkeypatch, tool, outcome, matches)
    if memo is not None:
        monkeypatch.setattr(orch, "_memoized_sweep_step", memo)
    entries = chain or [{"type": tool, "config": cfg_fn(tmp_path)}]
    monkeypatch.setattr(
        orch, "_hypothesis_to_tool_chain", lambda *a, **k: list(entries))
    claim = ReviewOutcome(
        file=fname, function=ck["files"][0]["items"][0]["name"],
        status="finding", body="model claim", hypothesis=hyp,
        evidence_tool="", review_result={"cwe": cwe, "mechanism": hyp},
        line=2,
    )
    swept = orch._sweep_validate(
        claim, config, SarifCache(), joern_server=object(),
    )
    assert swept.status == "finding" and not swept.evidence_tool, (
        "precondition: the channel confirmed nothing")
    final, exported = _resolve(
        _g2_demoted(swept), config, SarifCache(), ck,
        {"joern": cov == "joern", cov: True},
    )
    return swept, final, exported


class TestInconclusiveNeverCovers:
    """An inconclusive channel stays in the dispatch record but
    never counts as coverage at gate resolution."""

    @pytest.mark.parametrize("tool", sorted(_CHANNELS))
    def test_inconclusive_channel_resolves_dark(
        self, tmp_path, monkeypatch, tool,
    ):
        """For each coverage channel, an inconclusive run through the
        real record writer resolves dark, not clean, and the booking
        survives the resolver."""
        swept, final, exported = _sweep_channel(
            tmp_path, monkeypatch, tool, "inconclusive")
        # Never class coverage: the claim stays visible ...
        assert final.status == "dark"
        assert exported == 1
        # ... the channel stays in the record (it looked) and is
        # booked non-probative.
        assert tool in (swept.tools_dispatched or set())
        assert tool in _inc(swept)
        # The record survives the resolver's replacement object.
        assert tool in _inc(final)

    @pytest.mark.parametrize("tool", sorted(_CHANNELS))
    def test_control_refuted_channel_still_resolves_clean(
        self, tmp_path, monkeypatch, tool,
    ):
        """Control: a probative refutation on the same channel still
        resolves the claim clean."""
        swept, final, exported = _sweep_channel(
            tmp_path, monkeypatch, tool, "refuted")
        assert not _inc(swept)
        assert final.status == "clean"
        assert exported == 0

    def test_capped_in_function_match_resolves_dark(
        self, tmp_path, monkeypatch,
    ):
        """A genuine in-function MATCH capped to inconclusive (identifier
        mismatch / presence detector) is a positive signal — it must
        never become disconfirmation."""
        swept, final, exported = _sweep_channel(
            tmp_path, monkeypatch, "semgrep", "inconclusive",
            matches=[{"start": {"line": 3}, "check_id": "x"}],
        )
        assert final.status == "dark" and exported == 1
        assert "semgrep" in _inc(swept)

    def test_one_probative_entry_keeps_a_multi_entry_type_probative(
        self, tmp_path, monkeypatch,
    ):
        """A chain may carry several entries of one type: the type is
        non-probative only when EVERY entry was inconclusive."""
        for order, expect_dark in ((["inconclusive", "refuted"], False),
                                   (["inconclusive", "inconclusive"], True)):
            outcomes = iter(order)
            sub = tmp_path / "-".join(order)
            sub.mkdir()
            swept, final, exported = _sweep_channel(
                sub, monkeypatch, "semgrep", "refuted", chain=[
                    {"type": "semgrep",
                     "config": {"rule": str(sub / "r.yml")}}] * 2,
                memo=lambda cfg, n, k, fn, _it=outcomes: SweepResult(
                    tool="semgrep", file_path="f", function_name="g",
                    outcome=next(_it), details={"reason": "stub"}),
            )
            assert bool(_inc(swept)) is expect_dark, order
            assert final.status == ("dark" if expect_dark else "clean")

    @pytest.mark.parametrize("leg", ["smt", "coccinelle"])
    def test_proactive_inconclusive_is_booked(self, tmp_path, monkeypatch,
                                              leg):
        """_proactive_validate is the third record writer: its smt and
        coccinelle inconclusive outcomes are booked like the chain's."""
        tgt, out = _target(tmp_path, "a.c", _C)
        config = OrchestratorConfig(target_path=tgt, out_dir=out)
        mk = _stub_result(leg, "inconclusive")
        if leg == "smt":
            monkeypatch.setattr(orch, "run_smt_verb_direct", mk)
            monkeypatch.setattr(
                orch, "run_coccinelle_sweep", _stub_result("c", "skipped"))
            cwe, mech = "CWE-190", "integer overflow in n * 4"
        else:
            monkeypatch.setattr(
                orch, "run_smt_verb_direct", _stub_result("s", "skipped"))
            monkeypatch.setattr(orch, "run_coccinelle_sweep", mk)
            cwe, mech = "CWE-476", "missing null check on d before use"
        outcome = ReviewOutcome(
            file="a.c", function="cp", status="suspicious", body="x",
            hypothesis=mech, evidence_tool="",
            review_result={"cwe": cwe, "mechanism": mech}, line=2,
        )
        res = orch._proactive_validate(outcome, config, None)
        assert leg in (res.tools_dispatched or set()), (
            "precondition: the proactive leg ran")
        assert leg in _inc(res)
        # A clean carrying only this record is not tool-backed.
        res.status = "clean"
        assert res.compute_tier() == "speculative"


class TestInconclusiveRecordSurvivesCopies:
    """Every ReviewOutcome copy site that carries tools_errored /
    tools_skipped carries tools_inconclusive too — otherwise the
    replacement object silently reads as probative coverage."""

    def test_every_errored_copy_site_carries_inconclusive(self):
        """AST pin: every tools_errored copy is followed by a
        tools_inconclusive copy to the same object, so no copy site
        drops the booking."""
        src = inspect.getsource(orch)
        tree = ast.parse(src)
        missing = []
        copies = 0
        blocks = [
            getattr(node, f) for node in ast.walk(tree)
            for f in ("body", "orelse", "finalbody")
            if isinstance(getattr(node, f, None), list)
        ]
        for body in blocks:
            for i, stmt in enumerate(body):
                if not (isinstance(stmt, ast.Assign)
                        and len(stmt.targets) == 1
                        and isinstance(stmt.targets[0], ast.Attribute)
                        and stmt.targets[0].attr == "tools_errored"
                        and isinstance(stmt.value, ast.Attribute)
                        and stmt.value.attr == "tools_errored"):
                    continue
                copies += 1
                dst = ast.unparse(stmt.targets[0].value)
                window = body[i:i + 4]
                if not any(
                    isinstance(s, ast.Assign)
                    and isinstance(s.targets[0], ast.Attribute)
                    and s.targets[0].attr == "tools_inconclusive"
                    and ast.unparse(s.targets[0].value) == dst
                    for s in window
                ):
                    missing.append((stmt.lineno, dst))
        # Anti-vacuity: the ten copy sites the record has today.
        assert copies >= 10
        assert missing == []

    def test_demote_outcome_carries_inconclusive(self):
        """_demote_outcome builds a replacement outcome; it must keep
        the inconclusive booking."""
        outcome = _php_claim()
        outcome.tools_dispatched = {"semgrep"}
        outcome.tools_inconclusive = {"semgrep"}
        demoted = _demote_outcome(outcome, "[gate violation: G2: x]")
        assert _inc(demoted) == {"semgrep"}


class TestRefinementMergeProbativeWins:
    """refinement.merge_outcomes keeps a channel inconclusive only if no
    round that dispatched it was probative."""

    def _o(self, status, dispatched, inconclusive=None, evidence=""):
        return _outcome(
            file="a.c", function="f", status=status, body="b",
            evidence_tool=evidence, tools_dispatched=set(dispatched),
            tools_inconclusive=set(inconclusive) if inconclusive else None,
        )

    def test_inconclusive_in_both_rounds_stays_inconclusive(self):
        """Inconclusive in both rounds: the merged record stays
        inconclusive."""
        from core.audit.refinement import merge_outcomes

        merged = merge_outcomes(
            self._o("suspicious", {"semgrep"}, {"semgrep"}),
            self._o("suspicious", {"semgrep"}, {"semgrep"}),
        )
        assert _inc(merged) == {"semgrep"}

    def test_probative_in_either_round_wins(self):
        """Probative in the refined round clears the original round's
        booking."""
        from core.audit.refinement import merge_outcomes

        merged = merge_outcomes(
            self._o("suspicious", {"semgrep", "smt"}, {"semgrep"}),
            self._o("suspicious", {"semgrep"}, None),
        )
        # semgrep refuted in the refined round; smt stayed probative.
        assert not _inc(merged)
        assert merged.tools_dispatched == {"semgrep", "smt"}

    def test_original_only_inconclusive_survives_refined_winner(self):
        """A channel only the original round ran keeps its booking when
        the refined outcome wins."""
        from core.audit.refinement import merge_outcomes

        merged = merge_outcomes(
            self._o("suspicious", {"smt"}, {"smt"}),
            self._o("suspicious", set(), None),
        )
        assert _inc(merged) == {"smt"}


class TestRefinementPromptReadsTheRecord:
    """The refinement prompt described a dispatched semgrep run with
    no evidence-index hit as "no matches" — a refutation, told to the
    model, for a channel whose every answer was inconclusive."""

    def test_refinement_prompt_does_not_claim_silence(self):
        """The prompt must say the channel ran inconclusive, not that it
        found no matches."""
        from core.audit.refinement import _describe_tool_result

        outcome = _outcome(
            file="a.py", function="q", status="suspicious", body="b",
            tools_dispatched={"semgrep"}, tools_inconclusive={"semgrep"},
        )
        rec = SimpleNamespace(semgrep_hits=[])
        text = _describe_tool_result(
            "semgrep", "a.py:q", {"a.py:q": rec}, outcome=outcome)
        assert "no matches" not in text
        assert "inconclusive" in text


# ------------------------------------------------- booking tripwire


def _is_tier_inconclusive_call(node) -> bool:
    if not (isinstance(node, ast.Call)
            and getattr(node.func, "id", "") == "_increment_tier_dict"):
        return False
    return any(
        isinstance(a, ast.Constant) and a.value == "inconclusive"
        for a in ast.walk(node)
    )


def _is_book_call(node) -> bool:
    return (isinstance(node, ast.Call)
            and getattr(node.func, "id", "") == "_book_inconclusive")


def _guard_only(test) -> bool:
    """``if tier_counters:`` — a counter guard, not an outcome branch."""
    names = {getattr(n, "id", None) for n in ast.walk(test)}
    return names <= {"tier_counters", None}


class TestInconclusiveBookingTripwire:
    """Every branch of a record-writing validator that increments an
    ``"inconclusive"`` tier counter also books the channel. The
    ``smt_invariant`` leg counted its inconclusive in a bare ``else``
    and recorded nothing, so a clean whose only channel was an
    undecidable (LLM-phrased) invariant graded tool_backed."""

    @pytest.mark.parametrize("fn", [
        orch._run_tool_chain, orch._proactive_validate,
    ], ids=["_run_tool_chain", "_proactive_validate"])
    def test_every_inconclusive_increment_books_the_channel(self, fn):
        """AST tripwire: every inconclusive tier increment sits in a
        branch that also calls _book_inconclusive (with a minimum
        site count, so it cannot pass vacuously)."""
        tree = ast.parse(textwrap.dedent(inspect.getsource(fn)))
        parents = {}
        for node in ast.walk(tree):
            for child in ast.iter_child_nodes(node):
                parents[child] = node
        unbooked, sites = [], 0
        for node in ast.walk(tree):
            if not _is_tier_inconclusive_call(node):
                continue
            sites += 1
            # Climb to the outcome branch: the nearest enclosing If
            # whose test is not a bare ``tier_counters`` guard.
            cur, branch = node, None
            while cur in parents:
                par = parents[cur]
                if isinstance(par, ast.If) and not _guard_only(par.test):
                    branch = par.body if cur in par.body else par.orelse
                    break
                cur = par
            assert branch is not None, node.lineno
            if not any(_is_book_call(n) for s in branch
                       for n in ast.walk(s)):
                unbooked.append(node.lineno)
        assert sites >= (17 if fn is orch._run_tool_chain else 2)
        assert unbooked == []

    def test_smt_invariant_inconclusive_is_booked(
        self, tmp_path, monkeypatch,
    ):
        """The smt_invariant leg books its inconclusive outcome, so a
        clean resting on it is speculative, not tool_backed."""
        import core.audit.invariant_smt as inv

        tgt, out = _target(tmp_path, "a.c", _C)
        config = OrchestratorConfig(target_path=tgt, out_dir=out)
        monkeypatch.setattr(
            inv, "check_invariant_preservation",
            lambda invariant, source: SimpleNamespace(
                outcome="inconclusive", invariant=invariant,
                reason="invariant outside the linear fragment"),
        )
        monkeypatch.setattr(
            orch, "_record_invariant_receipt", lambda *a, **k: None)
        monkeypatch.setattr(
            orch, "run_prefilter",
            lambda **kw: SimpleNamespace(
                hits=[], skip_llm=False, skip_reason="", language="",
                sloc=10),
        )
        monkeypatch.setattr(
            orch, "_hypothesis_to_tool_chain",
            lambda *a, **k: [{"type": "smt_invariant",
                              "config": {"invariant": "n <= 8"}}],
        )
        claim = ReviewOutcome(
            file="a.c", function="cp", status="finding", body="x",
            hypothesis="the invariant n <= 8 can be violated",
            evidence_tool="", review_result={"cwe": ""}, line=2,
        )
        swept = orch._sweep_validate(claim, config, SarifCache())
        assert "smt_invariant" in (swept.tools_dispatched or set())
        assert "smt_invariant" in _inc(swept)
        swept.status = "clean"
        assert swept.compute_tier() == "speculative"


# ------------------------------------------------------------ keyword rules


class TestKeywordRuleSilenceIsInconclusive:
    """The hypothesis-keyword table rules are keyword->regex presence
    patterns whose MATCHES were already capped; their scanned
    zero-match still booked ``refuted`` and closed the whole class at
    gate resolution. The sweep now books it inconclusive (same branch
    family and receipt shape as the confirm-only cap)."""

    def _sweep(self, tmp_path, monkeypatch, *, keyword):
        import packages.semgrep.runner as runner_mod
        from packages.semgrep.models import SemgrepResult

        from core.audit.sweep import run_semgrep_sweep

        (tmp_path / "app.py").write_text(
            "def q(c, i):\n    return c.execute('SELECT ' + i)\n")
        monkeypatch.setattr(runner_mod, "is_available", lambda: True)
        monkeypatch.setattr(
            runner_mod, "run_rule",
            lambda *a, **kw: SemgrepResult(
                name="r", config="rule.yaml", target="app.py",
                findings=[], errors=[], returncode=0,
                files_examined=[str(tmp_path / "app.py")]),
        )
        return run_semgrep_sweep(
            target_path=tmp_path, file_path="app.py", function_name="q",
            rule_config="rule.yaml", line_start=1, line_end=2,
            rule_keyword=keyword,
        )

    def test_keyword_zero_match_is_inconclusive(self, tmp_path, monkeypatch):
        """A keyword rule's scanned zero-match is inconclusive with a
        covered=unknown receipt, not a refutation."""
        result = self._sweep(tmp_path, monkeypatch, keyword="sql injection")
        assert result.outcome == "inconclusive"
        assert (result.details or {}).get("reason", "").startswith(
            "keyword rule")
        # The licensed-refutation receipt (covered=True) is gone: the
        # scan's silence carries covered=unknown, like confirm-only.
        receipt = (result.details or {}).get("substrate") or {}
        assert receipt.get("covered") == "unknown"

    def test_control_curated_zero_match_still_refutes(
        self, tmp_path, monkeypatch,
    ):
        """Control: a curated rule (no keyword) still refutes on a
        scanned zero-match."""
        result = self._sweep(tmp_path, monkeypatch, keyword="")
        assert result.outcome == "refuted"

    def test_tier_counter_agrees_with_the_record(self, tmp_path, monkeypatch):
        """Through the real _sweep_validate, the tier counter and the
        dispatch record both say inconclusive."""
        import packages.semgrep.runner as runner_mod
        from packages.semgrep.models import SemgrepResult

        tgt, out = _target(tmp_path, "app.py",
                           "def q(c, i):\n    return c.execute('S' + i)\n")
        monkeypatch.setattr(runner_mod, "is_available", lambda: True)
        monkeypatch.setattr(
            runner_mod, "run_rule",
            lambda *a, **kw: SemgrepResult(
                name="r", config="rule.yaml", target="app.py",
                findings=[], errors=[], returncode=0,
                files_examined=[str(tgt / "app.py")]),
        )
        monkeypatch.setattr(
            orch, "run_prefilter",
            lambda **kw: SimpleNamespace(
                hits=[], skip_llm=False, skip_reason="", language="",
                sloc=10),
        )
        rule = tmp_path / "kw.yaml"
        rule.write_text("rules: []\n")
        monkeypatch.setattr(
            orch, "_hypothesis_to_tool_chain",
            lambda *a, **k: [{"type": "semgrep", "config": {
                "rule": str(rule), "keyword": "sql injection"}}],
        )
        config = OrchestratorConfig(target_path=tgt, out_dir=out)
        counters = OrchestratorResult().tier_counters
        claim = ReviewOutcome(
            file="app.py", function="q", status="finding", body="x",
            hypothesis="SQL injection: i concatenated into execute",
            evidence_tool="",
            review_result={"cwe": "CWE-89", "mechanism": "SQL injection"},
            line=1,
        )
        swept = orch._sweep_validate(
            claim, config, SarifCache(), tier_counters=counters)
        tc = counters["semgrep"]
        assert (tc.inconclusive, tc.refuted) == (1, 0)
        assert "semgrep" in _inc(swept)

# ---------------------------------------------- clean tier and propagation


class TestCleanTierNeedsProbativeChannel:
    """compute_tier grades a clean tool_backed only on a
    probative channel, and propagation trusts only such cleans."""

    @pytest.mark.parametrize("record", [
        {"tools_dispatched": {"smt"}, "tools_inconclusive": {"smt"}},
        {"tools_dispatched": {"smt", "coccinelle"},
         "tools_inconclusive": {"smt"}, "tools_errored": {"coccinelle"}},
        {"tools_dispatched": {"smt_invariant"},
         "tools_inconclusive": {"smt_invariant"}},
    ], ids=["inconclusive", "inconclusive+errored", "smt_invariant"])
    def test_non_probative_clean_is_speculative(self, record):
        """A clean whose channels are all inconclusive or errored is
        speculative."""
        clean = _outcome(
            file="a.c", function="f", status="clean", body="ok", **record)
        assert clean.compute_tier() == "speculative"

    def test_control_probative_clean_is_tool_backed(self):
        """Control: one probative channel next to an inconclusive one
        keeps the clean tool_backed."""
        clean = _outcome(
            file="a.c", function="f", status="clean", body="ok",
            tools_dispatched={"smt", "semgrep"},
            tools_inconclusive={"smt"},
        )
        assert clean.compute_tier() == "tool_backed"

    @pytest.mark.parametrize("inconclusive, demoted", [
        ({"smt"}, False), (None, True),
    ], ids=["non_probative_callee", "control_probative_callee"])
    def test_propagation_trusts_only_probative_clean(
        self, inconclusive, demoted,
    ):
        """A callee clean backed only by an inconclusive channel must
        not demote its caller; a probative one still does."""
        from core.audit.propagation import propagate_confidence

        callee = _outcome(
            file="p.c", function="parse_hdr", status="clean",
            body="on reconsideration the function is safe",
            tools_dispatched={"smt"}, tools_inconclusive=inconclusive,
        )
        callee.verification_tier = callee.compute_tier()
        caller = ReviewOutcome(
            file="p.c", function="handle", status="suspicious",
            body="m", hypotheses=[{
                "mechanism": "if parse_hdr() returns NULL the deref of "
                             "h->len at line 11 crashes",
                "counter": "",
            }],
        )
        edges = {"p.c:handle": [
            {"callee_file": "p.c", "callee": "parse_hdr"}]}
        demotions = propagate_confidence([callee, caller], edges)
        assert bool(demotions) is demoted
        assert caller.status == ("clean" if demoted else "suspicious")


# ------------------------------------------------- [tool-refuted] observation


class TestToolRefutedNeedsProbativeRefutation:
    """The [tool-refuted] observation, stored to SAGE as a
    mechanical verdict, needs a probative channel."""

    @pytest.mark.parametrize("record", [
        {},
        {"tools_dispatched": {"semgrep"}, "tools_errored": {"semgrep"}},
        {"tools_dispatched": {"semgrep"}, "tools_inconclusive": {"semgrep"}},
    ], ids=["no_tool", "errored_only", "inconclusive_only"])
    def test_no_probative_channel_no_tool_refutation(
        self, monkeypatch, record,
    ):
        """No tool, an errored tool, or an inconclusive tool: no
        tool_refutation observation and nothing stored."""
        from core.audit.orchestrator import _accumulate_observations

        stored = []
        monkeypatch.setattr(
            orch, "_sage_store_observation",
            lambda text, kind, source: stored.append(kind))
        obs: list = []
        outcome = _outcome(
            file="a.php", function="q", status="suspicious", body="b",
            hypothesis="SQL injection via $db->query", **record,
        )
        _accumulate_observations(
            obs, outcome, {"file": "a.php", "name": "q"},
            sweep_pre_status="finding",
        )
        assert [o["kind"] for o in obs] == []
        assert stored == []

    def test_control_probative_refutation_is_recorded(self, monkeypatch):
        """Control: a probative channel still records and stores the
        tool_refutation."""
        from core.audit.orchestrator import _accumulate_observations

        stored = []
        monkeypatch.setattr(
            orch, "_sage_store_observation",
            lambda text, kind, source: stored.append(kind))
        obs: list = []
        outcome = _outcome(
            file="a.php", function="q", status="suspicious", body="b",
            hypothesis="SQL injection via $db->query",
            tools_dispatched={"semgrep", "smt"},
            tools_inconclusive={"smt"},
        )
        _accumulate_observations(
            obs, outcome, {"file": "a.php", "name": "q"},
            sweep_pre_status="finding",
        )
        assert [o["kind"] for o in obs] == ["tool_refutation"]
        assert stored == ["tool_refutation"]


# ----------------------------------------------- record writers / merges


class TestFoldInconclusiveRecordAcrossPasses:
    """``_fold_inconclusive_record``: "probative in any pass wins",
    pinned per term (each case flips under one mutation of the
    algebra)."""

    def _fold(self, prior_dispatched, prior_inconclusive, *, ran,
              inconclusive, errored=None):
        from core.audit.orchestrator import _fold_inconclusive_record

        outcome = _outcome(
            file="a.c", function="f", status="suspicious", body="b",
            tools_dispatched=set(prior_dispatched),
            tools_inconclusive=(set(prior_inconclusive)
                                if prior_inconclusive else None),
        )
        _fold_inconclusive_record(
            outcome, ran=set(ran), inconclusive=set(inconclusive),
            errored=set(errored or ()))
        return _inc(outcome), getattr(outcome, "tools_inconclusive", None)

    def test_earlier_refutation_stays_probative(self):
        """A channel probative in an earlier pass is not booked by a
        later inconclusive pass."""
        inc, _ = self._fold({"semgrep"}, None, ran={"semgrep"},
                            inconclusive={"semgrep"})
        assert inc == set()

    def test_later_refutation_clears_the_booking(self):
        """A later probative pass clears an earlier booking."""
        inc, _ = self._fold({"semgrep"}, {"semgrep"}, ran={"semgrep"},
                            inconclusive=set())
        assert inc == set()

    def test_cleared_set_is_written_back_as_none(self):
        """An emptied booking is written back as None, the field's
        absent value."""
        _, raw = self._fold({"semgrep"}, {"semgrep"}, ran={"semgrep"},
                            inconclusive=set())
        assert raw is None

    def test_type_that_did_not_run_is_not_booked(self):
        """Only types that ran in this pass can be booked."""
        inc, _ = self._fold(set(), None, ran={"smt"},
                            inconclusive={"smt", "semgrep"})
        assert inc == {"smt"}

    def test_errored_now_does_not_clear_an_earlier_booking(self):
        """An errored pass is not probative, so it does not clear an
        earlier booking."""
        inc, _ = self._fold({"smt"}, {"smt"}, ran={"smt"},
                            inconclusive=set(), errored={"smt"})
        assert inc == {"smt"}

    def test_first_pass_books(self):
        """With no prior record, an inconclusive first pass books the
        channel."""
        inc, _ = self._fold(set(), None, ran={"smt"}, inconclusive={"smt"})
        assert inc == {"smt"}


class TestChainReportsOnlyNonErroredNonSkipped:
    """A type that ALSO errored or skipped in the same call is reported
    in errored/skipped, never inconclusive."""

    @pytest.mark.parametrize("second, bucket", [
        ("error", "errored"), ("skipped", "skipped"),
    ])
    def test_exclusion(self, tmp_path, monkeypatch, second, bucket):
        """A type that also errored or skipped in the same chain call is
        reported there and not as inconclusive."""
        tgt, out = _target(tmp_path, "app.php", _PHP)
        rule = tmp_path / "r.yml"
        rule.write_text("rules: []\n")
        _arm_channel_stubs(monkeypatch, "semgrep", "inconclusive")
        seq = iter(["inconclusive", second])
        monkeypatch.setattr(
            orch, "_memoized_sweep_step",
            lambda cfg, n, k, fn: SweepResult(
                tool="semgrep", file_path="f", function_name="g",
                outcome=next(seq), details={"reason": "stub"},
                errors=["boom"] if second == "error" else []),
        )
        errored, skipped, inconclusive = set(), set(), set()
        orch._run_tool_chain(
            [{"type": "semgrep", "config": {"rule": str(rule)}}] * 2,
            config=OrchestratorConfig(target_path=tgt, out_dir=out),
            file_path="app.php", function_name="getUser", source=_PHP,
            hypothesis="h", line_start=2, errored_types=errored,
            skipped_types=skipped, inconclusive_types=inconclusive,
        )
        assert "semgrep" in {"errored": errored, "skipped": skipped}[bucket]
        assert inconclusive == set()


class TestResweepWriterBooksInconclusive:
    """The zero-dispatch resweep is the third record writer: its
    inconclusive-only channel must not become class coverage, and its
    audit-log record names the channel."""

    def test_inconclusive_resweep_resolves_dark(self, tmp_path, monkeypatch):
        """An inconclusive-only resweep resolves dark and its audit-log
        record names the channel."""
        tgt, out = _target(tmp_path, "app.php", _PHP)
        (tmp_path / "r.yml").write_text("rules: []\n")
        _arm_channel_stubs(monkeypatch, "semgrep", "inconclusive")
        monkeypatch.setattr(
            orch, "_hypothesis_to_tool_chain",
            lambda *a, **k: [{"type": "semgrep",
                              "config": {"rule": str(tmp_path / "r.yml")}}])
        config = OrchestratorConfig(target_path=tgt, out_dir=out)
        config.zero_dispatch_resweep_seconds = 60.0
        outcome = ReviewOutcome(
            file="app.php", function="getUser", status="suspicious",
            body="model suspects SQL injection",
            hypothesis="user id concatenated into $db->query",
            evidence_tool="",
            review_result={"cwe": "CWE-89", "mechanism": "SQL injection"},
            line=2,
        )
        result = OrchestratorResult()
        result.outcomes = [outcome]
        result.suspicious = 1
        orch._resweep_zero_dispatch_suspicious(
            result, config, sarif_cache=SarifCache(), checklist=_PHP_CK)
        swept = result.outcomes[0]
        assert "semgrep" in (swept.tools_dispatched or set())
        assert _inc(swept) == {"semgrep"}
        final, exported = _resolve(
            swept, config, SarifCache(), _PHP_CK,
            {"joern": True, "semgrep": True})
        assert final.status == "dark" and exported == 1
        records = [
            json.loads(line)
            for line in (out / ".audit-log.jsonl").read_text().splitlines()
            if "zero_dispatch_resweep" in line
        ]
        assert records and records[-1].get("tools_inconclusive") == [
            "semgrep"]


class TestDeepenPriorMergeProbativeWins:
    """The deepen prior-merge unions the prior's dispatch record into
    the re-review: it must carry the prior's inconclusive channels
    (else they read probative) and drop those probative in either."""

    def _deepen(self, tmp_path, monkeypatch, new_record):
        import time

        prior = _outcome(
            file="a.c", function="foo", status="suspicious",
            body="review prose", hypothesis="alpha",
            evidence_tool="semgrep:rule-x", review_result={"body": "b"},
            tools_dispatched={"semgrep", "smt"},
            tools_inconclusive={"smt"},
        )
        result = OrchestratorResult(outcomes=[prior], suspicious=1)
        monkeypatch.setattr(
            orch, "_build_context",
            lambda cfg, gap, *a, **kw: {"file": gap["file"],
                                        "function": gap["name"]})
        monkeypatch.setattr(orch, "_check_budget", lambda *a, **kw: False)

        def review(ctx, cfg):
            return _outcome(
                file=ctx["file"], function=ctx["function"],
                status="suspicious", body="deepened prose",
                hypothesis="beta", evidence_tool="",
                review_result={"body": "d"}, **new_record)

        config = OrchestratorConfig(
            target_path=tmp_path, out_dir=tmp_path,
            sweep_validate_findings=False, deepen_suspicious=True,
            enable_session_context=False, blind_first_pass=False,
        )
        orch._deepen_suspicious(
            result, config, review,
            {"files": [{"path": "a.c", "functions": [
                {"name": "foo", "line_start": 1, "line_end": 100}]}]},
            None, None, [], None, set(), time.time(), None, max_workers=1,
        )
        (merged,) = [o for o in result.outcomes if o.function == "foo"]
        assert merged.evidence_tool == "semgrep:rule-x", (
            "precondition: the prior receipt branch ran")
        return merged

    def test_prior_inconclusive_channel_carried(self, tmp_path,
                                                monkeypatch):
        """The prior's inconclusive channel survives the merge, so it
        does not read as probative."""
        merged = self._deepen(tmp_path, monkeypatch, {})
        assert merged.tools_dispatched == {"semgrep", "smt"}
        assert _inc(merged) == {"smt"}

    def test_channel_probative_in_the_re_review_wins(self, tmp_path,
                                                     monkeypatch):
        """A channel probative in the re-review clears the prior's
        booking."""
        merged = self._deepen(
            tmp_path, monkeypatch, {"tools_dispatched": {"smt"}})
        assert _inc(merged) == set()


class TestProactiveErrorIsNotInconclusive:
    """_proactive_validate keeps errored and inconclusive apart."""

    def test_smt_error_books_errored(self, tmp_path, monkeypatch):
        """An smt error is booked errored, never inconclusive."""
        tgt, out = _target(tmp_path, "a.c", _C)
        monkeypatch.setattr(
            orch, "run_smt_verb_direct", _stub_result("smt", "error"))
        monkeypatch.setattr(
            orch, "run_coccinelle_sweep", _stub_result("c", "skipped"))
        outcome = ReviewOutcome(
            file="a.c", function="cp", status="suspicious", body="x",
            hypothesis="integer overflow in n * 4", evidence_tool="",
            review_result={"cwe": "CWE-190",
                           "mechanism": "integer overflow in n * 4"},
            line=2,
        )
        res = orch._proactive_validate(
            outcome, OrchestratorConfig(target_path=tgt, out_dir=out), None)
        assert "smt" in (res.tools_errored or set())
        assert "smt" not in _inc(res)


class TestRefinementMergeErroredIsNotProbative:
    """An errored round in refinement.merge_outcomes is not probative."""

    def test_errored_round_does_not_clear_inconclusive(self):
        """An errored original round does not clear the refined round's
        inconclusive booking."""
        from core.audit.refinement import merge_outcomes

        original = _outcome(
            file="a.c", function="f", status="suspicious", body="b",
            tools_dispatched={"smt"}, tools_errored={"smt"})
        refined = _outcome(
            file="a.c", function="f", status="suspicious", body="b",
            tools_dispatched={"smt"}, tools_inconclusive={"smt"})
        assert _inc(merge_outcomes(original, refined)) == {"smt"}


class TestChainBookedThenErrored:
    """A leg that books its inconclusive and THEN fails (exception after
    the booking) is errored: errored wins over inconclusive in the
    report."""

    def test_errored_after_booking_is_not_reported_inconclusive(
        self, tmp_path, monkeypatch,
    ):
        """If the leg fails after booking, the chain reports it errored
        and not inconclusive."""
        tgt, out = _target(tmp_path, "app.php", _PHP)
        rule = tmp_path / "r.yml"
        rule.write_text("rules: []\n")
        _arm_channel_stubs(monkeypatch, "semgrep", "inconclusive")
        real_inc = orch._increment_tier_dict

        def _boom(counters, tier, field, *a, **kw):
            if field == "inconclusive":
                raise RuntimeError("counter backend down")
            return real_inc(counters, tier, field, *a, **kw)

        monkeypatch.setattr(orch, "_increment_tier_dict", _boom)
        errored, inconclusive = set(), set()
        orch._run_tool_chain(
            [{"type": "semgrep", "config": {"rule": str(rule)}}],
            config=OrchestratorConfig(target_path=tgt, out_dir=out),
            file_path="app.php", function_name="getUser", source=_PHP,
            hypothesis="h", line_start=2,
            tier_counters=OrchestratorResult().tier_counters,
            errored_types=errored, inconclusive_types=inconclusive,
        )
        assert errored == {"semgrep"}
        assert inconclusive == set()

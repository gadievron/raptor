"""Differential pass — orchestrator fold and evidence admission.

The load-bearing invariants pinned here:

- the two differential stamps are admitted evidence at every consumer
  (the evidence firewall, the receipt map, the promotion alarm, the
  verification tier, the record CLI's G2 gate) and the pass mints NO
  refuting stamp — family agreement is only a failure to promote;
- the fold's only outcome write is a promotion: agreement,
  nondirectional divergence and inconclusive leave every outcome and
  every counter untouched;
- promotion needs directional confirmation AND the census family
  floor over the EXECUTED conforming set — never majority statistics;
- a metamorphic violation promotes only family-validated: the
  deciding pair re-executes over the conforming peers, and a relation
  the family also violates poisons the witness (false relation, not a
  deviant property);
- a deviant error poisons its vector before any peer is spent;
- the execution budget stops the pass mid-lead without minting a
  directional verdict;
- a containment-floor refusal records one structured row then
  re-raises (record-then-raise, same contract as the dark pass).
"""

from __future__ import annotations

import importlib.util
import json
from importlib.machinery import SourceFileLoader
from pathlib import Path
from types import SimpleNamespace

import pytest

import core.audit.differential as diff_pkg
from core.audit.dark_verify import DarkVerifyResult
from core.audit.differential import (
    VERDICT_CONFIRMED,
    VERDICT_FAMILY_AGREES,
    VERDICT_INCONCLUSIVE,
    VERDICT_RELATION_VIOLATED,
    DifferentialBudget,
)
from core.audit.evidence_grade import (
    _RECEIPT_MAP,
    _SOURCE_CONFIDENCE,
    VALID_EVIDENCE_TOOLS,
    Confidence,
    EvidenceSource,
    is_tool_evidence,
)
from core.audit.orchestrator import (
    OrchestratorConfig,
    OrchestratorResult,
    ReviewOutcome,
    _run_differential_verification,
)
from core.audit.promotion_alarm import build_alarm_record
from core.sandbox.errors import SandboxFloorError
from core.sandbox.tiers import ContainmentTier

_STAMPS = ("differential:confirmed", "differential:relation-violation")

# -- fixtures -----------------------------------------------------------------


def _family(n: int = 3) -> list[dict[str, object]]:
    return [
        {"file": f"pkg/peer_{i}.py", "function": f"peer_{i}",
         "line": 10 + i}
        for i in range(n)
    ]


def _lead(**over) -> dict[str, object]:
    lead: dict[str, object] = {
        "dimension": "guard-predicate",
        "file": "pkg/dev.py",
        "function": "deviant",
        "line": 42,
        "description": (
            "deviant guard admits the boundary value its siblings reject"
        ),
        "family_functions": _family(),
    }
    lead.update(over)
    return lead


def _outcome(
    status: str = "dark", evidence_tool: str = "",
) -> ReviewOutcome:
    o = ReviewOutcome(
        file="pkg/dev.py", function="deviant", status=status,
        body="suspected bug", hypothesis="missing boundary guard",
    )
    if evidence_tool:
        o.evidence_tool = evidence_tool
    return o


def _result(outcomes: list[ReviewOutcome]) -> OrchestratorResult:
    r = OrchestratorResult()
    r.outcomes = list(outcomes)
    for o in outcomes:
        if o.status in ("dark", "dormant"):
            r.dormant += 1
        elif o.status == "finding":
            r.findings += 1
        elif o.status == "suspicious":
            r.suspicious += 1
        elif o.status == "clean":
            r.clean += 1
    return r


def _config(tmp_path: Path) -> OrchestratorConfig:
    return OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path)


_VECTOR_JSON = json.dumps({
    "contract": "accept-reject-equivalence",
    "vectors": [
        {"args": [0], "kwargs": {}, "rationale": "boundary zero"},
    ],
})

_RELATION_JSON = json.dumps({
    "relation": "argument order must not matter",
    "pairs": [
        {"left": {"args": [[1, 2]], "kwargs": {}},
         "right": {"args": [[2, 1]], "kwargs": {}}},
    ],
    "differ": {
        "left": {"args": [[1]], "kwargs": {}},
        "right": {"args": [[3]], "kwargs": {}},
    },
})


def _install_fake(monkeypatch, behave) -> list:
    """Stub the witness executor; ``behave(spec)`` returns
    ``(observed_status, value)``."""
    calls: list = []

    def fake(spec, target_path, audit_run_dir=None):
        calls.append(spec)
        status, value = behave(spec)
        return DarkVerifyResult(
            finding_key=spec.finding_key,
            verdict="inconclusive",
            observed_status=status,
            actual_return=value if status == "returned" else "",
            actual_exception=value if status == "exception" else "",
        )

    monkeypatch.setattr("core.audit.dark_verify.execute_witness", fake)
    return calls


def _divergent(spec) -> tuple[str, str]:
    # The single confirming pattern: the deviant accepts what every
    # conforming peer rejects.
    if spec.function == "deviant":
        return ("returned", "ok")
    return ("exception", "ValueError: rejected")


def _agreeing(spec) -> tuple[str, str]:
    # Deterministic, argument-sensitive acceptance: the family agrees
    # on any shared vector, while the metamorphic controls can still
    # distinguish inputs. Every member is order-sensitive the same
    # way, so an order-insensitivity relation is FALSE for the whole
    # family.
    return ("returned", repr(spec.args))


def _order_sensitive_deviant(spec) -> tuple[str, str]:
    # Conforming peers canonicalise (sort) their list argument before
    # observing; the deviant does not — a true order-insensitivity
    # relation that the deviant ALONE violates.
    args = spec.args
    if spec.function != "deviant" and args and isinstance(args[0], list):
        return ("returned", repr([sorted(args[0])]))
    return ("returned", repr(args))


def _seq_client(*responses: str):
    """LLM stub returning canned responses in order, recording calls."""
    calls: list[str] = []

    def client(prompt: str, system: str) -> str:
        calls.append(prompt)
        return responses[min(len(calls) - 1, len(responses) - 1)]

    return client, calls


def _records(tmp_path: Path) -> list[dict]:
    return json.loads(
        (tmp_path / "differential-results.json").read_text(),
    )


# -- evidence admission -------------------------------------------------------


class TestEvidenceAdmission:
    def test_stamps_are_valid_evidence(self):
        for stamp in _STAMPS:
            assert stamp in VALID_EVIDENCE_TOOLS
            assert is_tool_evidence(stamp)

    def test_no_refuting_stamp_exists(self):
        # The pass mints no refuting stamp — family agreement on a
        # handful of vectors is only a failure to promote, so a
        # ``differential:refuted``-style receipt would be dead
        # vocabulary that a demote path could later grow around.
        assert "differential:refuted" not in VALID_EVIDENCE_TOOLS
        assert {
            t for t in VALID_EVIDENCE_TOOLS
            if t == "differential" or t.startswith("differential:")
        } == set(_STAMPS)

    def test_composite_chain_qualifies(self):
        assert is_tool_evidence("semgrep+differential:confirmed")

    def test_llm_claimed_prefix_poisons(self):
        assert not is_tool_evidence("llm-claimed:differential:confirmed")
        assert not is_tool_evidence(
            "semgrep+llm-claimed:differential:confirmed",
        )

    def test_receipt_rows_and_confidence(self):
        for stamp in (*_STAMPS, "differential"):
            source, receipt = _RECEIPT_MAP[stamp]
            assert source is EvidenceSource.DIFFERENTIAL
            assert receipt
        assert (
            _SOURCE_CONFIDENCE[EvidenceSource.DIFFERENTIAL]
            is Confidence.HIGH
        )

    def test_grading_yields_one_high_confidence_receipt(self):
        from core.audit.evidence_grade import grade_review_result

        for stamp in _STAMPS:
            items = grade_review_result({}, evidence_tool=stamp)
            rows = [
                e for e in items
                if e.source is EvidenceSource.DIFFERENTIAL
            ]
            assert len(rows) == 1
            assert rows[0].confidence is Confidence.HIGH

    def test_namespace_registered_for_composite_parts(self):
        # Pipeline sub-stamps riding in "+"-composites must read as a
        # recognized producer namespace (aggregation-eligible), never
        # as an unknown one — same registration the other execution
        # namespaces carry.
        from core.audit.evidence_grade import _TOOL_NAMESPACES

        assert "differential" in _TOOL_NAMESPACES

    def test_compute_tier_is_confirmed(self):
        for et in (*_STAMPS, "semgrep+differential:confirmed"):
            o = _outcome(status="finding", evidence_tool=et)
            assert o.compute_tier() == "confirmed"

    def test_promotion_alarm_silent_on_differential_evidence(self):
        for et in (*_STAMPS, "semgrep+differential:confirmed"):
            rec = build_alarm_record(
                stage="journal-write", file="pkg/dev.py",
                function="deviant", verdict="finding",
                evidence_tool=et,
            )
            assert rec is None, f"alarm fired on tool evidence {et!r}"

    def test_promotion_alarm_still_fires_without_evidence(self):
        # Discrimination control: the silence above must come from the
        # stamps, not from a broken alarm.
        rec = build_alarm_record(
            stage="journal-write", file="pkg/dev.py",
            function="deviant", verdict="finding", evidence_tool="",
        )
        assert rec is not None


# -- record CLI (G2 gate) -----------------------------------------------------

_REPO_ROOT = Path(__file__).resolve().parents[3]
_SCRIPT = _REPO_ROOT / "libexec" / "raptor-audit"


def _load_cli():
    loader = SourceFileLoader(
        "raptor_audit_cli_differential", str(_SCRIPT),
    )
    spec = importlib.util.spec_from_loader(
        "raptor_audit_cli_differential", loader,
    )
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def _seed_run(tmp_path: Path, *, sweep_tool: str):
    from core.audit.record import append_audit_log

    out_dir = tmp_path / "out"
    out_dir.mkdir()
    target = tmp_path / "target"
    (target / "src").mkdir(parents=True)
    (target / "src" / "a.py").write_text("def foo(p):\n    return p\n")
    append_audit_log(out_dir, {
        "action": "context", "key": "src/a.py:foo",
        "file": "src/a.py", "function": "foo",
    })
    append_audit_log(out_dir, {
        "action": "sweep", "key": "src/a.py:foo",
        "file": "src/a.py", "function": "foo",
        "tool": sweep_tool, "outcome": "confirmed",
    })
    return out_dir, target


class TestRecordCliAcceptsStamps:
    @pytest.mark.parametrize("stamp", _STAMPS)
    def test_differential_stamp_records_finding(
        self, tmp_path, capsys, stamp,
    ):
        mod = _load_cli()
        out_dir, target = _seed_run(tmp_path, sweep_tool=stamp)
        rc = mod.cmd_record(SimpleNamespace(
            out=str(out_dir),
            target=str(target),
            file="src/a.py",
            function="foo",
            status="finding",
            body="deviant accepted the vector every sibling rejected",
            line_start=None,
            line_end=None,
            cwe=None,
            strategies=None,
            evidence_tool=stamp,
            hypothesis=(
                "if the guard admits the boundary value its siblings "
                "reject, CWE-20"
            ),
            vuln_type="improper_input_validation",
            related_to=None,
            reach_via="exported API",
        ))
        captured = capsys.readouterr()
        assert rc == 0, captured.err
        assert "not a recognised tool" not in captured.err


# -- the fold -----------------------------------------------------------------


class TestDifferentialFold:
    def _run(self, result, config, leads, client, start_time=None):
        return _run_differential_verification(
            result, config, {"leads": leads},
            llm_client=client, start_time=start_time,
        )

    def test_no_llm_client_is_noop(self, tmp_path):
        result = _result([_outcome()])
        out = _run_differential_verification(
            result, _config(tmp_path), {"leads": [_lead()]},
            llm_client=None,
        )
        assert out == []
        assert result.outcomes[0].status == "dark"
        assert not (tmp_path / "differential-results.json").exists()

    def test_no_leads_is_noop(self, tmp_path):
        result = _result([_outcome()])
        out = self._run(
            result, _config(tmp_path), [],
            lambda p, s: _VECTOR_JSON,
        )
        assert out == []
        assert not (tmp_path / ".audit-log.jsonl").exists()

    def test_confirmed_divergence_promotes(self, tmp_path, monkeypatch):
        _install_fake(monkeypatch, _divergent)
        outcome = _outcome(status="dark")
        result = _result([outcome])
        client, calls = _seq_client(_VECTOR_JSON)
        out = self._run(result, _config(tmp_path), [_lead()], client)
        assert outcome.status == "finding"
        assert outcome.evidence_tool == "differential:confirmed"
        assert result.findings == 1
        assert result.dormant == 0
        assert out == []  # existing outcome: nothing synthesized
        recs = _records(tmp_path)
        fam = [r for r in recs if r["kind"] == "family-differential"]
        assert fam[0]["verdict"] == VERDICT_CONFIRMED
        assert fam[0]["promoted"] is True
        assert fam[0]["fold"] == {
            "applied": "chain-extend", "prior_status": "dark",
        }
        assert len(calls) == 1  # promoted: no metamorphic attempt

    def test_chain_extend_preserves_engine_receipt(
        self, tmp_path, monkeypatch,
    ):
        _install_fake(monkeypatch, _divergent)
        outcome = _outcome(status="suspicious", evidence_tool="semgrep")
        result = _result([outcome])
        client, _ = _seq_client(_VECTOR_JSON)
        self._run(result, _config(tmp_path), [_lead()], client)
        assert outcome.status == "finding"
        assert outcome.evidence_tool == "semgrep+differential:confirmed"
        assert result.findings == 1
        assert result.suspicious == 0

    def test_promotion_synthesizes_when_no_outcome_exists(
        self, tmp_path, monkeypatch,
    ):
        _install_fake(monkeypatch, _divergent)
        result = _result([])
        client, _ = _seq_client(_VECTOR_JSON)
        out = self._run(result, _config(tmp_path), [_lead()], client)
        assert len(out) == 1
        co = out[0]
        assert (co.file, co.function) == ("pkg/dev.py", "deviant")
        assert co.status == "finding"
        assert co.evidence_tool == "differential:confirmed"
        assert co.discovered_by == "differential_execution"
        assert co.hypothesis  # G1: the lead's hypothesis rides along
        assert result.post_loop_mechanical == 1
        recs = _records(tmp_path)
        assert recs[0]["fold"]["applied"] == "synthesized"

    def test_family_agreement_never_demotes(self, tmp_path, monkeypatch):
        _install_fake(monkeypatch, _agreeing)
        suspicious = _outcome(status="suspicious")
        finding = ReviewOutcome(
            file="pkg/peer_0.py", function="peer_0", status="finding",
            body="separate finding", hypothesis="unrelated",
        )
        finding.evidence_tool = "semgrep"
        result = _result([suspicious, finding])
        # Second LLM call is the metamorphic proposal — unusable, so
        # the relation lane records inconclusive and writes nothing.
        client, calls = _seq_client(_VECTOR_JSON, "not json")
        out = self._run(
            result, _config(tmp_path),
            [_lead()], client,
        )
        assert out == []
        assert suspicious.status == "suspicious"
        assert finding.status == "finding"
        assert finding.evidence_tool == "semgrep"
        assert (result.findings, result.suspicious) == (1, 1)
        recs = _records(tmp_path)
        fam = [r for r in recs if r["kind"] == "family-differential"]
        assert fam[0]["verdict"] == VERDICT_FAMILY_AGREES
        assert fam[0]["promoted"] is False
        meta = [r for r in recs if r["kind"] == "metamorphic"]
        assert meta[0]["verdict"] == VERDICT_INCONCLUSIVE
        assert len(calls) == 2

    def test_family_floor_gates_promotion(self, tmp_path, monkeypatch):
        # Directional confirmation with 3 executed conforming peers,
        # but the run config raises the census family floor to 4:
        # recorded, never promoted (and never demoted).
        (tmp_path / "audit-run-config.json").write_text(json.dumps({
            "version": 1,
            "consistency_floors": {"guard-predicate.min_sites": 4},
        }))
        _install_fake(monkeypatch, _divergent)
        outcome = _outcome(status="dark")
        result = _result([outcome])
        client, calls = _seq_client(_VECTOR_JSON)
        self._run(result, _config(tmp_path), [_lead()], client)
        assert outcome.status == "dark"
        assert result.findings == 0
        recs = _records(tmp_path)
        rec = recs[0]
        assert rec["verdict"] == VERDICT_CONFIRMED
        assert rec["promoted"] is False
        assert "floor" in rec["fold"]["reason"]
        # Confirmed-but-unpromoted is not a no-direction outcome: the
        # metamorphic lane must not spend budget on it.
        assert len(calls) == 1

    def test_deviant_error_spends_no_peers(self, tmp_path, monkeypatch):
        calls = _install_fake(
            monkeypatch,
            lambda spec: (
                ("", "") if spec.function == "deviant"
                else ("exception", "x")
            ),
        )
        outcome = _outcome(status="dark")
        result = _result([outcome])
        client, llm_calls = _seq_client(_VECTOR_JSON)
        self._run(result, _config(tmp_path), [_lead()], client)
        # Only the deviant executed: its error poisoned the vector
        # before any conforming peer was charged or run.
        assert len(calls) == 1
        assert calls[0].function == "deviant"
        assert outcome.status == "dark"
        recs = _records(tmp_path)
        assert recs[0]["verdict"] == VERDICT_INCONCLUSIVE
        assert recs[0]["promoted"] is False
        # Inconclusive family: no metamorphic attempt either.
        assert len(llm_calls) == 1

    def test_budget_rail_stops_without_verdict(
        self, tmp_path, monkeypatch,
    ):
        calls = _install_fake(monkeypatch, _divergent)
        monkeypatch.setattr(
            diff_pkg, "DifferentialBudget",
            lambda: DifferentialBudget(
                max_executions=3, max_wall_s=999.0,
            ),
        )
        outcome = _outcome(status="dark")
        result = _result([outcome])
        client, _ = _seq_client(_VECTOR_JSON)
        self._run(result, _config(tmp_path), [_lead()], client)
        # Deviant charged (1), the 3 peers refused all-or-nothing:
        # only the deviant ever ran, and no directional verdict was
        # minted from the partial execution.
        assert len(calls) == 1
        assert outcome.status == "dark"
        assert result.findings == 0
        recs = _records(tmp_path)
        assert recs[0]["verdict"] == VERDICT_INCONCLUSIVE
        assert recs[0]["promoted"] is False

    def test_metamorphic_violation_promotes(self, tmp_path, monkeypatch):
        # Peers canonicalise, the deviant is order-sensitive: the
        # relation is a TRUE invariant of the family that the deviant
        # alone violates — every control passes, the peers vouch for
        # the relation on the deciding pair, and the violation
        # promotes family-validated.
        calls_exec = _install_fake(monkeypatch, _order_sensitive_deviant)
        outcome = _outcome(status="dark")
        result = _result([outcome])
        client, calls = _seq_client(_VECTOR_JSON, _RELATION_JSON)
        self._run(result, _config(tmp_path), [_lead()], client)
        assert outcome.status == "finding"
        assert outcome.evidence_tool == "differential:relation-violation"
        assert result.findings == 1
        assert result.dormant == 0
        assert len(calls) == 2
        # 4 family executions + 6 target relation executions + the
        # deciding pair on each of the 3 conforming peers.
        assert len(calls_exec) == 16
        recs = _records(tmp_path)
        meta = [r for r in recs if r["kind"] == "metamorphic"]
        assert meta[0]["verdict"] == VERDICT_RELATION_VIOLATED
        assert meta[0]["controls_passed"] is True
        assert meta[0]["family_validated"] is True
        assert meta[0]["promoted"] is True

    def test_unvalidated_relation_never_promotes(
        self, tmp_path, monkeypatch,
    ):
        # Last-line defense on the promote gate itself: hand it a
        # relation violation that never earned family validation. The
        # family-validation step is made a pass-through here — the
        # provisional verdict (family_validated=False) reaches the
        # gate unchanged, standing in for any future path that skips
        # validation. The gate must refuse on the missing
        # family_validated conjunct alone, even though the verdict is
        # VIOLATED and both channel controls passed.
        calls_exec = _install_fake(monkeypatch, _order_sensitive_deviant)
        monkeypatch.setattr(
            "core.audit.differential.validate_relation_on_family",
            lambda verdict, peer_pairs, *, quorum: verdict,
        )
        outcome = _outcome(status="dark")
        result = _result([outcome])
        client, calls = _seq_client(_VECTOR_JSON, _RELATION_JSON)
        self._run(result, _config(tmp_path), [_lead()], client)
        assert outcome.status == "dark"
        assert result.findings == 0
        assert len(calls) == 2
        assert len(calls_exec) == 16
        recs = _records(tmp_path)
        meta = [r for r in recs if r["kind"] == "metamorphic"]
        assert meta[0]["verdict"] == VERDICT_RELATION_VIOLATED
        assert meta[0]["controls_passed"] is True
        assert meta[0]["family_validated"] is False
        assert meta[0]["promoted"] is False

    def test_false_relation_poisoned_by_peers(
        self, tmp_path, monkeypatch,
    ):
        # Every member is order-sensitive the same way: the target's
        # "violation" passes both channel controls (the comparison CAN
        # see differences), but the conforming peers violate the
        # relation identically — the proposer's "equivalence" is a
        # false relation, not a deviant property. Poisoned, never
        # promoted.
        _install_fake(monkeypatch, _agreeing)
        outcome = _outcome(status="dark")
        result = _result([outcome])
        client, calls = _seq_client(_VECTOR_JSON, _RELATION_JSON)
        out = self._run(result, _config(tmp_path), [_lead()], client)
        assert out == []
        assert outcome.status == "dark"
        assert result.findings == 0
        assert len(calls) == 2
        recs = _records(tmp_path)
        meta = [r for r in recs if r["kind"] == "metamorphic"]
        assert meta[0]["verdict"] == VERDICT_INCONCLUSIVE
        assert meta[0]["family_validated"] is False
        assert "false relation" in meta[0]["reason"]
        assert meta[0]["promoted"] is False

    def test_spec_build_failure_named_in_excluded(
        self, tmp_path, monkeypatch,
    ):
        # A conforming member whose witness spec cannot build (here a
        # top-level __init__.py, which derives no import path) must be
        # NAMED in the excluded rows — silence would read as
        # "executed and conformed". The remaining peers still carry
        # the verdict.
        _install_fake(monkeypatch, _divergent)
        outcome = _outcome(status="dark")
        result = _result([outcome])
        family = _family() + [
            {"file": "__init__.py", "function": "peer_init", "line": 3},
        ]
        client, _ = _seq_client(_VECTOR_JSON)
        self._run(
            result, _config(tmp_path),
            [_lead(family_functions=family)], client,
        )
        assert outcome.status == "finding"
        recs = _records(tmp_path)
        rec = recs[0]
        assert rec["verdict"] == VERDICT_CONFIRMED
        assert rec["executed_conforming"] == 3
        assert {
            "member": "peer_init", "reason": "spec-build-failed",
        } in rec["excluded"]

    def test_ineligible_dimension_never_dispatches(self, tmp_path):
        result = _result([_outcome()])

        def client(prompt: str, system: str) -> str:
            raise AssertionError("LLM dispatched for ineligible lead")

        out = self._run(
            result, _config(tmp_path),
            [_lead(dimension="ordering")], client,
        )
        assert out == []
        assert result.outcomes[0].status == "dark"
        rows = [
            json.loads(line)
            for line in (tmp_path / ".audit-log.jsonl")
            .read_text().splitlines() if line.strip()
        ]
        telemetry = [
            r for r in rows
            if r.get("action") == "differential_verification"
        ]
        assert telemetry[0]["leads_eligible"] == 0
        assert telemetry[0]["skipped_ineligible"][0]["dimension"] == (
            "ordering"
        )

    def test_floor_refusal_records_then_raises(
        self, tmp_path, monkeypatch,
    ):
        def raising(spec, target_path, audit_run_dir=None):
            raise SandboxFloorError(
                "sandbox containment floor violated",
                "install uidmap; re-run",
                achievable=ContainmentTier.LANDLOCK_ONLY,
                floor=ContainmentTier.MOUNT_NS,
                setup_category="U",
            )

        monkeypatch.setattr(
            "core.audit.dark_verify.execute_witness", raising,
        )
        outcome = _outcome(status="dark")
        result = _result([outcome])
        client, _ = _seq_client(_VECTOR_JSON)
        with pytest.raises(SandboxFloorError):
            self._run(result, _config(tmp_path), [_lead()], client)
        assert outcome.status == "dark"
        recs = _records(tmp_path)
        refusals = [r for r in recs if r["kind"] == "floor-refusal"]
        assert len(refusals) == 1
        assert refusals[0]["function"] == "deviant"

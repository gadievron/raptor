"""Tests for ``AutonomousSecurityAgentV2._record_exploit_witness``.

The wiring is "after compile_verify + intent_match, before
return". These tests pin:

  * Witness store is lazy (no filesystem touch when the gate
    fires zero times)
  * ``record_witnesses=False`` disables the call site cleanly
  * Recorded witness has the expected verdicts threaded through
    from the finding's fields
  * Failures (store I/O, missing fields) are non-fatal
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Optional


# packages/llm_analysis/tests/test_agent_record_witness.py
#   parents[3] = repo root
REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO))

from core.witness import WitnessOutcome, WitnessSource  # noqa: E402
from packages.llm_analysis.agent import (  # noqa: E402
    AutonomousSecurityAgentV2,
    VulnerabilityContext,
)


@dataclass
class _StubVerdict:
    verdict: str = "matches"
    confidence: float = 0.85


def _stub_agent(out_dir: Path, record_witnesses: bool = True):
    """Minimal stub agent with just enough state for
    ``_record_exploit_witness`` to run."""
    agent = SimpleNamespace(
        out_dir=out_dir,
        record_witnesses=record_witnesses,
        _witness_store=None,
    )
    agent._record_exploit_witness = (
        AutonomousSecurityAgentV2._record_exploit_witness.__get__(
            agent, type(agent)
        )
    )
    return agent


def _make_vuln(
    finding_id: str = "FIND-0001",
    cwe_id: Optional[str] = "CWE-120",
    intent_match=None,
    repo_path: Optional[Path] = None,
    file_path: str = "src/auth.c",
):
    vuln = VulnerabilityContext.__new__(VulnerabilityContext)
    vuln.finding_id = finding_id
    vuln.rule_id = "cpp/buffer-overflow"
    vuln.file_path = file_path
    vuln.start_line = 1
    vuln.end_line = 1
    vuln.level = "error"
    vuln.message = "test"
    vuln.cwe_id = cwe_id
    vuln.tool = "test"
    vuln.full_code = None
    vuln.surrounding_context = None
    vuln.exploitable = True
    vuln.exploitability_score = 0.8
    vuln.exploit_code = "// poc\n"
    vuln.exploit_compiled = True
    vuln.exploit_compile_errors = []
    vuln.intent_match = intent_match
    vuln.patch_code = None
    vuln.feasibility = {"status": "pending"}
    vuln.has_dataflow = False
    vuln.metadata = None
    vuln.analysis = None
    vuln.repo_path = repo_path or Path("/nonexistent")
    return vuln


# ----------------------------------------------------------------------
# Happy path
# ----------------------------------------------------------------------


def test_records_one_witness_per_call(tmp_path):
    agent = _stub_agent(tmp_path)
    vuln = _make_vuln(intent_match=_StubVerdict())
    agent._record_exploit_witness(vuln, "// exploit\n")

    assert agent._witness_store is not None
    # WitnessStore at tmp_path/witnesses; one manifest written
    manifests = list((tmp_path / "witnesses" / "manifests").glob("*.json"))
    blobs = list((tmp_path / "witnesses" / "blobs").glob("*"))
    assert len(manifests) == 1
    assert len(blobs) == 1


def test_recorded_witness_has_llm_emit_run_source(tmp_path):
    agent = _stub_agent(tmp_path)
    vuln = _make_vuln(intent_match=_StubVerdict())
    agent._record_exploit_witness(vuln, "// exploit\n")

    # Read back the manifest via the store
    from core.witness import WitnessStore
    store = WitnessStore(tmp_path / "witnesses")
    manifests = list(
        (tmp_path / "witnesses" / "manifests").glob("*.json")
    )
    bytes_hash = manifests[0].stem
    witness = store.get_witness(bytes_hash)
    assert witness.source is WitnessSource.LLM_EMIT_RUN
    assert witness.observed_outcome is WitnessOutcome.NOT_RUN


def test_recorded_witness_carries_intent_match_verdict(tmp_path):
    """The verdict + confidence on ``vuln.intent_match`` flows
    into ``outcome_detail`` so consumers don't need to re-judge."""
    agent = _stub_agent(tmp_path)
    vuln = _make_vuln(
        intent_match=_StubVerdict(verdict="off_target", confidence=0.7),
    )
    agent._record_exploit_witness(vuln, "// exploit\n")

    from core.witness import WitnessStore
    store = WitnessStore(tmp_path / "witnesses")
    manifests = list(
        (tmp_path / "witnesses" / "manifests").glob("*.json")
    )
    witness = store.get_witness(manifests[0].stem)
    assert witness.outcome_detail["intent_verdict"] == "off_target"
    assert witness.outcome_detail["intent_confidence"] == 0.7


def test_compile_failure_threads_through(tmp_path):
    agent = _stub_agent(tmp_path)
    vuln = _make_vuln()
    vuln.exploit_compiled = False
    vuln.exploit_compile_errors = ["err1", "err2", "err3"]
    agent._record_exploit_witness(vuln, "// poc\n")

    from core.witness import WitnessStore
    store = WitnessStore(tmp_path / "witnesses")
    manifests = list(
        (tmp_path / "witnesses" / "manifests").glob("*.json")
    )
    witness = store.get_witness(manifests[0].stem)
    assert witness.outcome_detail["compiled"] is False
    assert witness.outcome_detail["compile_error_count"] == 3


def test_no_intent_match_no_verdict_key(tmp_path):
    """``vuln.intent_match=None`` → ``intent_verdict`` omitted
    from outcome_detail (absence-is-encoding)."""
    agent = _stub_agent(tmp_path)
    vuln = _make_vuln(intent_match=None)
    agent._record_exploit_witness(vuln, "// poc\n")

    from core.witness import WitnessStore
    store = WitnessStore(tmp_path / "witnesses")
    manifests = list(
        (tmp_path / "witnesses" / "manifests").glob("*.json")
    )
    witness = store.get_witness(manifests[0].stem)
    assert "intent_verdict" not in witness.outcome_detail
    assert "intent_confidence" not in witness.outcome_detail


# ----------------------------------------------------------------------
# Store lazy-open
# ----------------------------------------------------------------------


def test_witness_store_lazy_opens_on_first_call(tmp_path):
    agent = _stub_agent(tmp_path)
    # Pre-call: no store, no files
    assert agent._witness_store is None
    assert not (tmp_path / "witnesses").exists()

    vuln = _make_vuln()
    agent._record_exploit_witness(vuln, "// poc\n")
    assert agent._witness_store is not None
    assert (tmp_path / "witnesses").exists()


def test_witness_store_reused_across_calls(tmp_path):
    """The second call uses the same WitnessStore instance — not
    a perf bug if it re-opens, but lazy means lazy-once."""
    agent = _stub_agent(tmp_path)
    vuln1 = _make_vuln(finding_id="FIND-0001")
    vuln2 = _make_vuln(finding_id="FIND-0002")
    agent._record_exploit_witness(vuln1, "// poc 1\n")
    store_instance = agent._witness_store
    agent._record_exploit_witness(vuln2, "// poc 2\n")
    assert agent._witness_store is store_instance


# ----------------------------------------------------------------------
# Failure modes (non-fatal)
# ----------------------------------------------------------------------


def test_store_io_failure_does_not_raise(tmp_path, monkeypatch):
    """A WitnessStore.put() exception is logged + swallowed —
    the exploit artefact on disk is the primary record."""
    agent = _stub_agent(tmp_path)
    vuln = _make_vuln()

    # Force the put() to raise after the store is opened
    import core.witness.store as store_mod

    real_put = store_mod.WitnessStore.put

    def _boom(self, witness, data):
        raise IOError("disk gone")

    monkeypatch.setattr(store_mod.WitnessStore, "put", _boom)
    try:
        agent._record_exploit_witness(vuln, "// poc\n")
    finally:
        monkeypatch.setattr(store_mod.WitnessStore, "put", real_put)


def test_adapter_failure_does_not_raise(tmp_path, monkeypatch):
    """Adapter exception (e.g. non-encodable string) is logged
    + swallowed — the exploit artefact on disk is the primary
    record."""
    agent = _stub_agent(tmp_path)
    vuln = _make_vuln()

    import packages.llm_analysis.witness_adapter as adapter_mod

    def _boom(*args, **kwargs):
        raise RuntimeError("adapter exploded")

    monkeypatch.setattr(
        adapter_mod, "witness_from_exploit", _boom,
    )
    # Force store to open first by pre-running once
    agent._record_exploit_witness(vuln, "// poc\n")


# ----------------------------------------------------------------------
# Dedup via hash
# ----------------------------------------------------------------------


def test_identical_exploits_dedup_in_store(tmp_path):
    """Two findings, same exploit text → one blob in the store
    (manifests may differ in outcome_detail — that's WitnessStore's
    concern; the blob is shared)."""
    agent = _stub_agent(tmp_path)
    v1 = _make_vuln(finding_id="FIND-0001")
    v2 = _make_vuln(finding_id="FIND-0002")
    agent._record_exploit_witness(v1, "// identical poc\n")
    agent._record_exploit_witness(v2, "// identical poc\n")
    blobs = list((tmp_path / "witnesses" / "blobs").glob("*"))
    assert len(blobs) == 1


# ----------------------------------------------------------------------
# Constructor flag wiring
# ----------------------------------------------------------------------


def test_constructor_default_record_witnesses_true(tmp_path):
    """The agent constructor defaults ``record_witnesses=True``
    so operators get the substrate without opting in."""
    # We can't easily build the full agent without an LLM, so
    # just inspect the dataclass-style attribute by calling
    # ``__init__`` with prep_only=True (which uses ClaudeCodeProvider
    # and is the cheapest constructor path).
    agent = AutonomousSecurityAgentV2(
        repo_path=tmp_path,
        out_dir=tmp_path / "out",
        prep_only=True,
    )
    assert agent.record_witnesses is True


def test_constructor_record_witnesses_false_opt_out(tmp_path):
    agent = AutonomousSecurityAgentV2(
        repo_path=tmp_path,
        out_dir=tmp_path / "out",
        prep_only=True,
        record_witnesses=False,
    )
    assert agent.record_witnesses is False

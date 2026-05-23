"""Tests for ``CrashAnalysisAgent._record_exploit_witness``.

Mirrors ``test_agent_record_witness.py`` but for the fuzzing
side: ``crash_context.intent_match`` is a ``dict`` (asdict
flavour) rather than the ``IntentMatchVerdict`` dataclass that
``/agentic`` holds, so the recorder reads via ``.get(...)``
rather than attribute access.
"""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Optional


# packages/llm_analysis/tests/test_crash_agent_record_witness.py
#   parents[3] = repo root
REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO))

from core.witness import WitnessOutcome, WitnessSource  # noqa: E402
from packages.binary_analysis.crash_analyser import CrashContext  # noqa: E402
from packages.llm_analysis.crash_agent import CrashAnalysisAgent  # noqa: E402


def _stub_agent(
    out_dir: Path,
    binary: Path,
    record_witnesses: bool = True,
):
    agent = SimpleNamespace(
        out_dir=out_dir,
        binary=binary,
        record_witnesses=record_witnesses,
        _witness_store=None,
    )
    agent._record_exploit_witness = (
        CrashAnalysisAgent._record_exploit_witness.__get__(
            agent, type(agent)
        )
    )
    return agent


def _make_crash_context(
    crash_id: str = "000001",
    crash_type: str = "stack_overflow",
    source_location: str = "src/parser.c:42",
    intent_match: Optional[dict] = None,
    binary_path: Optional[Path] = None,
):
    return CrashContext(
        crash_id=crash_id,
        binary_path=binary_path or Path("/nonexistent"),
        input_file=Path("/nonexistent_input"),
        signal="11",
        crash_type=crash_type,
        source_location=source_location,
        exploit_code="// PoC\n",
        exploit_compiled=True,
        exploit_compile_errors=[],
        intent_match=intent_match,
    )


# ----------------------------------------------------------------------
# Happy path
# ----------------------------------------------------------------------


def test_records_witness_with_llm_emit_run_source(tmp_path):
    binary = tmp_path / "target"
    binary.write_bytes(b"ELF mock")
    agent = _stub_agent(tmp_path, binary=binary)
    crash = _make_crash_context(binary_path=binary)
    agent._record_exploit_witness(crash, "// exploit\n")

    from core.witness import WitnessStore
    store = WitnessStore(tmp_path / "witnesses")
    manifests = list(
        (tmp_path / "witnesses" / "manifests").glob("*.json")
    )
    assert len(manifests) == 1
    witness = store.get_witness(manifests[0].stem)
    assert witness.source is WitnessSource.LLM_EMIT_RUN
    assert witness.observed_outcome is WitnessOutcome.NOT_RUN
    assert witness.produced_by == "crash-agent"


def test_target_binary_hashed(tmp_path):
    """Binary hash is the relevant target slot for fuzzing
    (vs source for /agentic) — must be set."""
    binary = tmp_path / "target"
    binary.write_bytes(b"\x7fELF...binary contents")
    agent = _stub_agent(tmp_path, binary=binary)
    crash = _make_crash_context()
    agent._record_exploit_witness(crash, "// exploit\n")

    from core.witness import WitnessStore
    store = WitnessStore(tmp_path / "witnesses")
    manifests = list(
        (tmp_path / "witnesses" / "manifests").glob("*.json")
    )
    witness = store.get_witness(manifests[0].stem)
    assert witness.target_binary_hash is not None
    assert len(witness.target_binary_hash) == 64


def test_crash_type_mapped_to_cwe(tmp_path):
    """The same crash_type → CWE lookup the judge uses flows
    into outcome_detail."""
    binary = tmp_path / "target"
    binary.write_bytes(b"x")
    agent = _stub_agent(tmp_path, binary=binary)
    crash = _make_crash_context(crash_type="heap_overflow")
    agent._record_exploit_witness(crash, "// exploit\n")

    from core.witness import WitnessStore
    store = WitnessStore(tmp_path / "witnesses")
    manifests = list(
        (tmp_path / "witnesses" / "manifests").glob("*.json")
    )
    witness = store.get_witness(manifests[0].stem)
    assert witness.outcome_detail["cwe_id"] == "CWE-122"


def test_unmapped_crash_type_no_cwe(tmp_path):
    """``use_after_free`` is in the judge's table but has
    ``None`` — adapter should omit the field (absence is
    encoding)."""
    binary = tmp_path / "target"
    binary.write_bytes(b"x")
    agent = _stub_agent(tmp_path, binary=binary)
    crash = _make_crash_context(crash_type="use_after_free")
    agent._record_exploit_witness(crash, "// exploit\n")

    from core.witness import WitnessStore
    store = WitnessStore(tmp_path / "witnesses")
    manifests = list(
        (tmp_path / "witnesses" / "manifests").glob("*.json")
    )
    witness = store.get_witness(manifests[0].stem)
    assert "cwe_id" not in witness.outcome_detail


def test_intent_match_dict_threaded_through(tmp_path):
    """``crash_context.intent_match`` is a ``dict`` here, not
    the dataclass — the recorder must read via ``.get(...)``."""
    binary = tmp_path / "target"
    binary.write_bytes(b"x")
    agent = _stub_agent(tmp_path, binary=binary)
    crash = _make_crash_context(
        intent_match={
            "verdict": "matches",
            "confidence": 0.92,
            "reasoning": "should not leak",
        }
    )
    agent._record_exploit_witness(crash, "// exploit\n")

    from core.witness import WitnessStore
    store = WitnessStore(tmp_path / "witnesses")
    manifests = list(
        (tmp_path / "witnesses" / "manifests").glob("*.json")
    )
    witness = store.get_witness(manifests[0].stem)
    assert witness.outcome_detail["intent_verdict"] == "matches"
    assert witness.outcome_detail["intent_confidence"] == 0.92
    # reasoning should NOT leak (avoid bloating outcome_detail)
    assert "reasoning" not in witness.outcome_detail


def test_intent_match_non_dict_does_not_crash(tmp_path):
    """Defensive: same shape-tolerance lesson as the agent.py
    side learned post-merge of #577."""
    binary = tmp_path / "target"
    binary.write_bytes(b"x")
    agent = _stub_agent(tmp_path, binary=binary)
    crash = _make_crash_context(intent_match="raw string")
    agent._record_exploit_witness(crash, "// exploit\n")

    from core.witness import WitnessStore
    store = WitnessStore(tmp_path / "witnesses")
    manifests = list(
        (tmp_path / "witnesses" / "manifests").glob("*.json")
    )
    witness = store.get_witness(manifests[0].stem)
    assert "intent_verdict" not in witness.outcome_detail


def test_source_location_threads_into_file_path(tmp_path):
    """``source_location`` is ``"file:line"`` — only the path
    half should land in outcome_detail."""
    binary = tmp_path / "target"
    binary.write_bytes(b"x")
    agent = _stub_agent(tmp_path, binary=binary)
    crash = _make_crash_context(source_location="src/parser.c:42")
    agent._record_exploit_witness(crash, "// exploit\n")

    from core.witness import WitnessStore
    store = WitnessStore(tmp_path / "witnesses")
    manifests = list(
        (tmp_path / "witnesses" / "manifests").glob("*.json")
    )
    witness = store.get_witness(manifests[0].stem)
    assert witness.outcome_detail["file_path"] == "src/parser.c"


# ----------------------------------------------------------------------
# Failure modes (non-fatal)
# ----------------------------------------------------------------------


def test_store_io_failure_does_not_raise(tmp_path, monkeypatch):
    binary = tmp_path / "target"
    binary.write_bytes(b"x")
    agent = _stub_agent(tmp_path, binary=binary)
    crash = _make_crash_context()

    import core.witness.store as store_mod
    real_put = store_mod.WitnessStore.put

    def _boom(self, witness, data):
        raise IOError("disk gone")

    monkeypatch.setattr(store_mod.WitnessStore, "put", _boom)
    try:
        agent._record_exploit_witness(crash, "// exploit\n")
    finally:
        monkeypatch.setattr(store_mod.WitnessStore, "put", real_put)

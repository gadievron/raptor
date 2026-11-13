"""LLM compilation totals must use the same population as their denominator."""
import pytest

from core.reporting.witnesses import build_witness_summary, render_witness_summary
from core.witness import Witness, WitnessOutcome, WitnessSource, WitnessStore, compute_bytes_hash


@pytest.mark.parametrize("other_source", [WitnessSource.FUZZ, WitnessSource.VALIDATE_SKILL_POC])
def test_saved_non_llm_compile_detail_does_not_inflate_llm_population(tmp_path, monkeypatch, other_source):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "trust"))
    directory = tmp_path / "witnesses"
    store = WitnessStore(directory)
    for index, (source, compiled) in enumerate([
        (other_source, True), (WitnessSource.LLM_EMIT_RUN, True),
        (WitnessSource.LLM_EMIT_RUN, False),
    ]):
        data = f"inert saved record {index}".encode()
        store.put(Witness(bytes_hash=compute_bytes_hash(data), bytes_len=len(data), source=source,
                          observed_outcome=WitnessOutcome.NOT_RUN,
                          outcome_detail={"compiled": compiled}), data)
    before = {path.relative_to(directory): path.read_bytes()
              for path in directory.rglob("*") if path.is_file()}

    summary = build_witness_summary(directory)
    assert summary["total"] == 3
    assert summary["by_source"] == {other_source.value: 1, "llm_emit_run": 2}
    assert summary["by_outcome"] == {"not_run": 3}
    assert summary["executed"] == 0
    assert summary["compiled"] == 1
    rendered = render_witness_summary(directory)
    assert "Compiled: 1/2 LLM exploits" in rendered
    assert "Executed: 0/3" in rendered
    assert "partial enumeration" not in rendered
    assert {path.relative_to(directory): path.read_bytes()
            for path in directory.rglob("*") if path.is_file()} == before

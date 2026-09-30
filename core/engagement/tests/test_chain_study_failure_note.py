"""The chain's study stage surfaces the study side's failure record.

When binary-study ends without a domain model it exits nonzero and
drops ``study-failure.json`` in the study dir; the stage folds that
record's reason into the failure text, so the ledger row carries the
root cause (e.g. the LLM budget exhausting with zero completed
batches) instead of a bare rc / no-model symptom.

Failing-first taxonomy (this file copied verbatim onto the BASE tree):

- ``test_nonzero_exit_failure_carries_record_cause``: RED
  (mechanism) — BASE records the bare ``binary-study rc=1``.
- ``test_zero_exit_no_model_failure_carries_record_cause``: RED
  (mechanism) — BASE records only the generic no-model text.
- ``test_garbled_record_falls_back_to_plain_reason`` and
  ``test_no_record_keeps_plain_reason``: green-by-design pins — BASE
  never appends a note, so the fallback direction passes trivially;
  they exist to pin the record as diagnosis-never-dependency once
  the note exists.
- ``test_record_detail_rendered_inert``: RED (mechanism) — BASE
  carries no note at all, so the escaped form is absent.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from core.engagement.chain_elf import RC_FAILED, run_chain
from core.engagement.tests.test_chain_elf import (
    ART,
    FakeRunner,
    _setup,
    _status,
    _wire,
)
from core.json import save_json


class StudyFails(FakeRunner):
    """binary-study exits nonzero after writing a failure record —
    exactly what the exit contract produces on a no-model run."""

    def __init__(self, *, record: "dict[str, Any] | str | None",
                 rc: int = 1, write_model: bool = False) -> None:
        super().__init__()
        self.record = record
        self.rc = rc
        self.write_model = write_model

    def __call__(self, cmd: list[str], *, llm: bool = False,
                 timeout_s: int = 0) -> int:
        tool = self._tool(cmd)
        if tool != "raptor-binary-study":
            return super().__call__(cmd, llm=llm, timeout_s=timeout_s)
        self.calls.append([str(c) for c in cmd])
        out = Path(cmd[3])
        out.mkdir(parents=True, exist_ok=True)
        if isinstance(self.record, str):
            (out / "study-failure.json").write_text(
                self.record, encoding="utf-8")
        elif self.record is not None:
            save_json(out / "study-failure.json", self.record)
        if self.write_model:
            save_json(out / "domain-model.json", {"concepts": []})
        return self.rc


def test_nonzero_exit_failure_carries_record_cause(
        tmp_path: Path, monkeypatch: Any) -> None:
    out, _ = _setup(tmp_path)
    _wire(monkeypatch, StudyFails(record={
        "schema": "study-failure/1",
        "reason": "llm_budget_exhausted",
        "detail": ("LLM budget exhausted with 0 completed Phase 2 "
                   "batch(es)"),
    }))
    assert run_chain(out, ART) == RC_FAILED
    st = _status(out)
    assert st["state"] == "failed"
    assert "stage=study" in st["detail"]
    assert "binary-study rc=1" in st["detail"]
    assert "llm_budget_exhausted" in st["detail"]
    assert "0 completed Phase 2 batch(es)" in st["detail"]


def test_zero_exit_no_model_failure_carries_record_cause(
        tmp_path: Path, monkeypatch: Any) -> None:
    # Belt-and-braces path: a driver predating the exit contract
    # (rc 0, no model) whose record still names the cause.
    out, _ = _setup(tmp_path)
    _wire(monkeypatch, StudyFails(rc=0, record={
        "schema": "study-failure/1",
        "reason": "no_domain_model",
        "detail": "study pass(es) exited 0 without producing "
                  "domain-model.json",
    }))
    assert run_chain(out, ART) == RC_FAILED
    st = _status(out)
    assert st["state"] == "failed"
    assert "wrote no domain-model.json" in st["detail"]
    assert "no_domain_model" in st["detail"]


def test_no_record_keeps_plain_reason(
        tmp_path: Path, monkeypatch: Any) -> None:
    out, _ = _setup(tmp_path)
    _wire(monkeypatch, StudyFails(record=None, rc=3))
    assert run_chain(out, ART) == RC_FAILED
    st = _status(out)
    assert "(binary-study rc=3)" in st["detail"]


def test_garbled_record_falls_back_to_plain_reason(
        tmp_path: Path, monkeypatch: Any) -> None:
    # The record is diagnosis, never a dependency: unusable bytes in
    # the study dir must not break (or decorate) the stage failure.
    out, _ = _setup(tmp_path)
    _wire(monkeypatch, StudyFails(record="{not json", rc=1))
    assert run_chain(out, ART) == RC_FAILED
    st = _status(out)
    # The stage reason is the parenthesised part of the ledger
    # detail — bare rc, no note appended from the unusable record.
    assert "(binary-study rc=1)" in st["detail"]


def test_record_detail_rendered_inert(
        tmp_path: Path, monkeypatch: Any) -> None:
    # The record's detail may quote target bytes — the note must land
    # on the ledger escaped (\\xHH), never raw.
    out, _ = _setup(tmp_path)
    _wire(monkeypatch, StudyFails(record={
        "schema": "study-failure/1",
        "reason": "study_error",
        "detail": "bad byte \x1b[31m here",
    }))
    assert run_chain(out, ART) == RC_FAILED
    st = _status(out)
    assert "\x1b" not in st["detail"]
    assert "\\x1b" in st["detail"]

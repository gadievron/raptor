"""The post-loop smt-clean pass gates out binary outcomes.

Binary review outcomes (``binary:``-prefixed file slots) carry no
source path or line geometry: ``_read_raw_source`` can never resolve
them, so the source-SMT checks are unreachable for them. Without the
gate, every binary function with ``line=0`` fired the line-geometry
warning and had its line rewritten from the checklist gap on the way
to that dead end (observed live: 18 warnings on an 18-function .so).
"""

from __future__ import annotations

import logging

import core.audit.orchestrator as orch
from core.audit.orchestrator import (
    OrchestratorConfig,
    OrchestratorResult,
    ReviewOutcome,
)


def _clean_binary_outcome() -> ReviewOutcome:
    return ReviewOutcome(
        file="binary:libfoo", function="g", status="clean",
        body="clean", hypothesis="", line=0,
    )


def _run(outcome, tmp_path):
    target = tmp_path / "t"
    target.mkdir()
    out = tmp_path / "o"
    out.mkdir()
    config = OrchestratorConfig(target_path=target, out_dir=out)
    result = OrchestratorResult()
    result.outcomes = [outcome]
    result.clean = 1
    checklist = {"files": [{"path": "binary:libfoo", "items": [
        {"name": "g", "line_start": 7, "line_end": 9}]}]}
    orch._promote_smt_clean(result, config, checklist=checklist)
    return result


class TestSmtCleanBinaryGate:
    def test_binary_outcome_skipped_without_line_warning(
        self, tmp_path, caplog,
    ):
        outcome = _clean_binary_outcome()
        with caplog.at_level(logging.DEBUG,
                             logger="core.audit.orchestrator"):
            result = _run(outcome, tmp_path)
        # Geometry untouched: the checklist gap must not be written
        # into a binary outcome that has none.
        assert outcome.line == 0
        assert outcome.status == "clean"
        assert result.sweep_promoted == 0
        warned = [r for r in caplog.records
                  if "outcome.line=0" in r.getMessage()]
        assert warned == []
        skipped = [r for r in caplog.records
                   if "binary outcome(s) skipped" in r.getMessage()]
        assert len(skipped) == 1
        assert skipped[0].levelno == logging.DEBUG

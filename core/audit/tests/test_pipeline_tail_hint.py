"""Deferred pipeline-tail hint for resumed --gap-audit runs.

The /agentic post-pass runs its audit with --no-validate and stages
pipeline-tail.json; a later `raptor-audit resume` must tell the
operator which tail steps (validate, feedback) nobody will run.
"""

import json

from core.audit.resume import PIPELINE_TAIL_FILENAME, pipeline_tail_hint


def _stage(tmp_path, deferred=("validate", "feedback")):
    (tmp_path / PIPELINE_TAIL_FILENAME).write_text(json.dumps({
        "parent_run": "/x/agentic_run",
        "deferred": list(deferred),
        "reason": "validation unified in the parent /agentic run",
    }), encoding="utf-8")


def test_hint_names_both_tail_steps(tmp_path):
    _stage(tmp_path)
    hint = pipeline_tail_hint(tmp_path, findings_count=3)
    assert hint is not None
    assert "/validate" in hint
    assert str(tmp_path / "findings.json") in hint
    assert "raptor-audit feedback" in hint
    assert f"--audit-out {tmp_path}" in hint


def test_no_marker_is_silent(tmp_path):
    assert pipeline_tail_hint(tmp_path, findings_count=3) is None


def test_no_findings_is_silent(tmp_path):
    _stage(tmp_path)
    assert pipeline_tail_hint(tmp_path, findings_count=0) is None


def test_corrupt_marker_is_silent(tmp_path):
    (tmp_path / PIPELINE_TAIL_FILENAME).write_text("{not json",
                                                   encoding="utf-8")
    assert pipeline_tail_hint(tmp_path, findings_count=3) is None


def test_validate_only_deferred(tmp_path):
    _stage(tmp_path, deferred=("validate",))
    hint = pipeline_tail_hint(tmp_path, findings_count=1)
    assert "/validate" in hint
    assert "feedback" not in hint

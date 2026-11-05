"""Real prep must retain call-graph hints without asserting security impact."""

import json
import logging
from unittest.mock import patch

import pytest

from core.audit import orchestrator as orch
from core.audit.context import format_context_for_prompt
from core.audit.mechanical_gates import format_security_decision_for_context


SOURCE = """def check_access(value):
    return bool(value)


def prepare_value(value):
    return check_access(value)


def plain(value):
    return str(value)
"""


@pytest.fixture
def prepared(checklist_builds, tmp_path, monkeypatch, caplog):
    build = checklist_builds.build({"policy.py": SOURCE})
    out = build.make_run_dir(tmp_path / "private" / "run")
    context = {
        "entry_points": [], "sinks": [], "trust_boundaries": [], "unchecked_flows": [],
        "call_edges": [
            {"caller_file": "policy.py", "caller": "prepare_value",
             "callee_file": "policy.py", "callee": "check_access"},
            {"caller_file": "policy.py", "caller": "plain",
             "callee_file": "policy.py", "callee": "str"},
        ],
    }
    (out / "context-map.json").write_text(json.dumps(context))
    monkeypatch.setattr(orch, "_run_mechanical_detectors", lambda *a, **kw: ({}, set()))
    monkeypatch.setattr("core.audit.capabilities._angr_available", lambda: False)
    def no_provider(*args, **kwargs):
        raise AssertionError("provider construction forbidden in prep-context test")
    monkeypatch.setattr("core.llm.client.LLMClient.__init__", no_provider)
    config = orch.OrchestratorConfig(
        target_path=build.target, out_dir=out, resume=False, force=True,
        include_stale=False, enable_session_context=False, propagate_constraints=False,
    )
    with caplog.at_level(logging.DEBUG, logger=orch.__name__):
        with patch.object(orch, "_resolve_joern_evidence_raw", return_value=({}, None)):
            prep = orch._compute_audit_prep(config)
    assert prep is not None
    return prep, caplog


def test_prep_accepts_the_real_frozenset_producer_contract(prepared):
    prep, caplog = prepared
    assert prep["security_decision_keys"] == frozenset({"policy.py:check_access"})
    assert prep["feeds_security_keys"] == frozenset({"policy.py:prepare_value"})
    assert not any("mechanical gate" in record.message and "failed" in record.message
                   for record in caplog.records)


def test_restored_caller_hint_renders_as_a_lead(prepared):
    prep, _ = prepared
    assert "policy.py:prepare_value" in prep["feeds_security_keys"]
    text = format_security_decision_for_context(True)
    assert "SECURITY CALL-GRAPH HINT" in text
    assert "Inspect whether" in text
    assert "do not establish data flow or security impact" in text
    assert "has SECURITY impact" not in text


@pytest.mark.parametrize("key", ["is_security_decision", "feeds_security_decision"])
def test_both_naming_hints_require_semantic_review(key):
    text = format_context_for_prompt({
        "file": "policy.py", "function": "prepare_value", "source": SOURCE,
        "line_start": 1, "line_end": 2, key: True,
    })
    assert "security" in text.lower()
    assert "Inspect" in text
    assert "security impact" in text
    assert "has SECURITY impact" not in text
    assert "This function IS a" not in text

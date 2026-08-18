"""Security-event emission at the sandbox denial chokepoint.

``record_denial`` is the seam every observed sandbox denial (network /
write / seccomp / udp) flows through. The restored security-event
stream mirrors each recorded denial into the framework audit trail:

  * one ``sandbox_denial`` event per recorded denial, carrying the
    denial type, the redacted/escaped cmd display, and the caller's
    context identifiers;
  * no emission outside an active run and none past the per-run cap
    (flood control mirrors the JSONL evidence posture);
  * emission is independent of evidence-file health, and a broken
    security sink never breaks record_denial (observability, not a
    control).
"""

from __future__ import annotations

import json

import pytest

from core.sandbox import summary as summary_mod


@pytest.fixture
def active_run(tmp_path):
    """Activate a run dir for the module and clean up after."""
    summary_mod.set_active_run_dir(tmp_path)
    yield tmp_path
    summary_mod.set_active_run_dir(None)


@pytest.fixture
def events(monkeypatch):
    """Capture security events emitted through the module seam."""
    captured = []

    def _capture(event_type, message, **kwargs):
        captured.append((event_type, message, kwargs))

    monkeypatch.setattr(summary_mod, "_log_security_event", _capture)
    return captured


def _denials_jsonl(run_dir):
    path = run_dir / ".audit" / summary_mod.DENIALS_FILE
    if not path.exists():
        return []
    return [json.loads(line) for line in
            path.read_text().splitlines() if line]


def test_recorded_denial_emits_security_event(active_run, events):
    summary_mod.record_denial(
        "curl https://blocked.example", 1, "network",
        host="blocked.example",
    )
    assert len(events) == 1
    event_type, message, kwargs = events[0]
    assert event_type == "sandbox_denial"
    assert "network" in message
    assert kwargs["denial_type"] == "network"
    assert kwargs["returncode"] == 1
    assert kwargs["host"] == "blocked.example"


def test_reserved_detail_keys_do_not_crash_emission(active_run, events):
    # A caller smuggling "type"/"cmd" through **details (the same
    # masking vector the `record` construction defends against) must
    # not clobber the event's explicit fields or crash the emission.
    summary_mod.record_denial(
        "touch /etc/x", 1, "write",
        type="evil", cmd="evil", path="/etc/x",
    )
    assert len(events) == 1
    _, _, kwargs = events[0]
    assert kwargs["denial_type"] == "write"
    assert kwargs["returncode"] == 1
    assert kwargs["path"] == "/etc/x"
    assert "type" not in kwargs
    assert "cmd" not in kwargs


def test_no_emission_without_active_run(events):
    summary_mod.set_active_run_dir(None)
    summary_mod.record_denial("curl https://x", 1, "network")
    assert events == []


def test_no_emission_past_per_run_cap(active_run, events, monkeypatch):
    monkeypatch.setattr(summary_mod, "MAX_DENIALS_PER_RUN", 2)
    for _ in range(5):
        summary_mod.record_denial("curl https://x", 1, "network")
    assert len(events) == 2


def test_emission_survives_evidence_append_failure(
    active_run, events, monkeypatch,
):
    # Evidence-file failure loses the JSONL record (logged at WARNING,
    # see F071) but must not also lose the audit-trail event.
    monkeypatch.setattr(
        summary_mod, "_get_evidence_handle_locked",
        lambda run_dir: None,
    )
    summary_mod.record_denial("curl https://x", 1, "network")
    assert len(events) == 1


def test_broken_security_sink_never_breaks_record_denial(
    active_run, monkeypatch,
):
    # End-to-end no-raise with the REAL emitter: break the logging
    # sink underneath core.logging and assert the denial still lands
    # in the evidence JSONL.
    from core.logging import RaptorLogger

    def _flaky_warning(message, *args, **kwargs):
        if str(message).startswith("SECURITY:"):
            raise OSError("sink down")

    monkeypatch.setattr(RaptorLogger, "warning", _flaky_warning)
    summary_mod.record_denial("curl https://x", 7, "network")
    records = _denials_jsonl(active_run)
    assert len(records) == 1
    assert records[0]["type"] == "network"
    assert records[0]["returncode"] == 7

"""Strict CI admission is distinct from ordinary telemetry inspection."""
import json

import pytest

from core.sandbox import summary, triage, triage_deep
from core.testing.state_isolation import pin_user_state_dirs


@pytest.fixture(autouse=True)
def owned_state(tmp_path, monkeypatch):
    pin_user_state_dirs(monkeypatch, tmp_path / "state")
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))


@pytest.fixture
def authenticated_run(tmp_path):
    run = tmp_path / "run"
    run.mkdir()
    summary.record_run_posture(run, mount_ns_active=True, restrict_reads=False)

    def write(records):
        summary._assemble_and_write_summary(
            run, records=records, refusals=[], corrupt_lines=0,
            inode_mismatch=False, planted_object="",
        )
        return run
    return run, write


@pytest.mark.parametrize("strict", [False, True], ids=["inspect", "required"])
@pytest.mark.parametrize("json_output", [False, True], ids=["human", "json"])
@pytest.mark.parametrize("deep", [False, True], ids=["rules", "deep"])
def test_empty_evidence_cannot_pass_strict_gate(tmp_path, capsys, monkeypatch,
                                               strict, json_output, deep):
    def unexpected_deep(*args, **kwargs):
        pytest.fail("missing evidence must not reach advisory reasoning")
    monkeypatch.setattr(triage_deep, "deep_analyse", unexpected_deep)
    args = [str(tmp_path)]
    args += ["--require-evidence"] if strict else []
    args += ["--json"] if json_output else []
    args += ["--deep"] if deep else []
    assert triage._cli_main(args) == (1 if strict else 0)
    captured = capsys.readouterr()
    if json_output:
        assert json.loads(captured.out) is None
    assert ("required sandbox evidence is missing" in captured.err) is strict
    assert not (tmp_path / triage.TRIAGE_FILE).exists()
    assert not (tmp_path / triage_deep.DEEP_FILE).exists()


@pytest.mark.parametrize("records,expected", [
    ([{"type": "write", "path": "/tmp/owned", "verdict": "allow"}], 0),
    ([{"type": "seccomp", "syscall": "ptrace", "cmd": "owned operation"}], 4),
], ids=["verified-clean", "verified-suspicious"])
def test_verified_evidence_retains_rules_status(authenticated_run, capsys, records, expected):
    run, write = authenticated_run
    write(records)
    assert triage._cli_main([str(run), "--require-evidence", "--json"]) == expected
    captured = capsys.readouterr()
    report = json.loads(captured.out)
    assert report == json.loads((run / triage.TRIAGE_FILE).read_text())
    assert triage.verify_triage_report(report, run) == "verified"
    assert not captured.err


def test_required_mode_rejects_legacy_before_reading_evidence(tmp_path, capsys):
    assert triage._cli_main([str(tmp_path), "--require-evidence", "--legacy"]) == 2
    assert "cannot be combined" in capsys.readouterr().err
    assert not (tmp_path / triage.TRIAGE_FILE).exists()


@pytest.mark.parametrize("unavailable", ["disabled", "refused"])
def test_authenticated_nonexecution_cannot_pass_required_gate(
    authenticated_run, capsys, unavailable,
):
    run, write = authenticated_run
    if unavailable == "disabled":
        summary.record_cli_disable(run, "explicit-cli")
        write([{"type": "write", "path": "/tmp/owned", "verdict": "allow"}])
    else:
        summary.record_floor_refusal(
            run, floor="namespace", achievable="landlock",
            reason="owned refusal before execution",
        )
        assert summary.summarize_and_write(run) is not None
    assert triage._cli_main([str(run), "--require-evidence", "--json"]) == 1
    captured = capsys.readouterr()
    report = json.loads(captured.out)
    assert triage.verify_triage_report(report, run) == "verified"
    assert "sandbox execution was disabled or refused" in captured.err


@pytest.mark.parametrize("damage", ["missing-summary", "bad-mac", "exposed-key"])
def test_damaged_evidence_never_becomes_clean_success(authenticated_run, capsys, damage):
    run, write = authenticated_run
    write([{"type": "write", "path": "/tmp/owned", "verdict": "allow"}])
    path = run / summary.SUMMARY_FILE
    if damage == "missing-summary":
        path.unlink()
    elif damage == "bad-mac":
        data = json.loads(path.read_text())
        data["mac"] = "owned invalid token"
        path.write_text(json.dumps(data))
    else:
        summary.record_run_posture(run, mount_ns_active=False, restrict_reads=False)
    assert triage._cli_main([str(run), "--require-evidence", "--json"]) == 1
    captured = capsys.readouterr()
    json.loads(captured.out)
    assert "required sandbox evidence" in captured.err


@pytest.mark.parametrize("control,expected", [
    ({"type": "audit_summary", "reader_drained": True}, 0),
    ({"type": "audit_summary", "reader_drained": False}, 1),
    ({"type": "audit_summary", "reader_drained": True,
      "dropped_by_category": {"read": 2}}, 1),
], ids=["healthy", "incomplete", "dropped"])
def test_authenticated_capture_loss_cannot_pass_required_gate(
    authenticated_run, capsys, monkeypatch, control, expected,
):
    from core.sandbox import evidence
    run, _ = authenticated_run
    path = evidence.evidence_write_path(run, summary.DENIALS_FILE)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(control) + "\n")
    written = summary.summarize_and_write(run, raise_on_io_error=True)
    assert written is not None and written["total_denials"] == 0
    prior = triage.triage_run(run, allow_legacy=False)
    assert prior is not None
    assert (prior["verdict"] == "clean") is (expected == 0)

    def unexpected_deep(*args, **kwargs):
        pytest.fail("advisory reasoning cannot fill missing capture")
    monkeypatch.setattr(triage_deep, "deep_analyse", unexpected_deep)
    assert triage._cli_main([str(run), "--require-evidence", "--json", "--deep"]) == expected
    captured = capsys.readouterr()
    report = json.loads(captured.out)
    assert report["verdict"] == prior["verdict"]
    assert triage.verify_triage_report(report, run) == "verified"
    assert ("evidence capture is incomplete" in captured.err) is bool(expected)


def test_historical_retriage_does_not_require_ephemeral_parent_memory(
    authenticated_run, monkeypatch, capsys,
):
    run, write = authenticated_run
    write([{"type": "write", "path": "/tmp/owned", "verdict": "allow"}])
    # A fresh CLI process has no in-memory posture from the original run.
    # Keep the existing one-way provenance policy: disk claims cannot
    # promote posture, while authenticated evidence still verifies.
    monkeypatch.setattr(triage, "get_run_posture", lambda directory: None)
    assert triage._cli_main([str(run), "--require-evidence", "--json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["inputs"]["mac_key_posture"] == "unknown"
    assert triage.verify_triage_report(report, run) == "verified"


@pytest.mark.parametrize("capture", ["clean", "loss", "reserve", "edited-counters"])
def test_proxy_buffer_limit_cannot_attest_complete_capture(
    authenticated_run, monkeypatch, capsys, capture,
):
    import itertools

    from core.sandbox import context, proxy

    run, write = authenticated_run
    write([{"type": "write", "path": "/tmp/owned", "verdict": "allow"}])
    events = [{"host": "kept.example", "result": "allowed"}]
    if capture != "clean":
        # The actual marker producer needs only owned Python state;
        # no proxy construction, thread, socket or target execution.
        monkeypatch.setattr(proxy, '_SANDBOX_BUFFER_MAX_EVENTS', 1)
        producer = object.__new__(proxy.EgressProxy)
        producer._sandbox_buffer_overflow = {}
        producer._event_seq = itertools.count()
        producer._stats_events = {'buffer_overflow': 0}
        producer._append_bounded_locked(1, events, {
            'host': 'later.example',
            'result': 'denied_host' if capture == 'reserve' else 'allowed',
        })
        marker = next(e for e in events if e['result'] == 'buffer_overflow')
        assert marker['dropped'] == (0 if capture == 'reserve' else 1)
    # Persistence sequence state is owned by this case, not the caller.
    monkeypatch.setattr(context, '_PROXY_STREAM_STATE', {})
    context._persist_proxy_events(events, output=run)
    if capture == 'edited-counters':
        # These counters are outside the event MAC. They cannot promote
        # a capped stream to complete, even if edited to look loss-free.
        path = run / proxy.PROXY_EVENTS_FILENAME
        rows = [json.loads(line) for line in path.read_text().splitlines()]
        for row in rows:
            if row['result'] == 'buffer_overflow':
                row['dropped'] = row['dropped_denials'] = 0
        path.write_text(''.join(json.dumps(row) + '\n' for row in rows))
    expected = 0 if capture == 'clean' else 1
    assert triage._cli_main([str(run), '--json']) == 0
    inspection = json.loads(capsys.readouterr().out)
    assert inspection['verdict'] == 'clean'
    assert any('Proxy capture' in note for note in inspection['caveats']) is bool(expected)
    assert triage._cli_main([str(run), '--require-evidence', '--json']) == expected
    captured = capsys.readouterr()
    report = json.loads(captured.out)
    assert report['inputs']['integrity']['proxy_events'] == 'verified'
    assert report['verdict'] == 'clean'  # Capture limits do not establish intent.
    assert triage.verify_triage_report(report, run) == 'verified'
    assert report['inputs'].get('proxy_capture_unconfirmed', False) is bool(expected)
    assert any('Proxy capture' in note for note in report['caveats']) is bool(expected)
    assert ('proxy event capture is unconfirmed' in captured.err) is bool(expected)

"""Adversarial tests with real run-bound summary MACs and real classifiers."""

import json

import pytest

from core.project.correlate import correlate_sandbox_triage
from core.sandbox import summary, telemetry_mac
from core.sandbox.triage import _verify_summary, triage_run


@pytest.fixture(autouse=True)
def isolated_key(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))


def _run(base, i, records=None, *, target="/target", **writer_flags):
    directory = base / f"r{i:02d}"
    directory.mkdir()
    (directory / ".raptor-run.json").write_text(json.dumps({
        "target_path": target, "started_at": f"2026-10-{i + 1:02d}T00:00:00Z",
        "sandbox_triage": "clean" if records == [] else "suspicious",
    }))
    if records is not None:
        summary.record_run_posture(directory, mount_ns_active=True, restrict_reads=False)
        # Real writer supports an authenticated zero-denial summary for
        # allowed audit reports, without fabricating a clean MAC by hand.
        summary._assemble_and_write_summary(
            directory, records=records or [{"type": "write", "path": "/tmp/x", "verdict": "allow"}],
            refusals=[], corrupt_lines=writer_flags.get("corrupt_lines", 0),
            inode_mismatch=writer_flags.get("inode_mismatch", False),
            planted_object=writer_flags.get("planted_object", ""))
        triage_run(directory, allow_legacy=False)
    return directory


def _escape(name):
    return {"type": "seccomp", "cmd": name}


def _target(dirs):
    return correlate_sandbox_triage(dirs)["targets"]["/target"]


def _signatures(target):
    return {s["example"]: s for s in target["signatures"].values()}


@pytest.mark.parametrize("forged", [None, {}, {"severity": "routine"},
                                    {"severity": "critical", "escape_primitives": {"count": 999}}])
def test_derived_bucket_edits_cannot_change_authenticated_classification(tmp_path, forged):
    run = _run(tmp_path, 0, [_escape("ptrace")])
    path = run / summary.SUMMARY_FILE
    data = json.loads(path.read_text())
    if forged is None:
        data.pop("triage", None)
    else:
        data["triage"] = forged
    path.write_text(json.dumps(data))
    assert _verify_summary(data, telemetry_mac.run_binding(run), allow_legacy=False)[1] == "verified"
    result = _target([run])
    assert result["campaign_severity"] == "critical"
    assert result["integrity"] == "verified"
    assert _signatures(result)["ptrace"]["total_occurrences"] == 1


def test_forged_derived_attack_cannot_upgrade_routine_authenticated_records(tmp_path):
    run = _run(tmp_path, 0, [{"type": "write", "path": "/tmp/output"}])
    path = run / summary.SUMMARY_FILE
    data = json.loads(path.read_text())
    data["triage"] = {"severity": "critical", "escape_primitives": {"count": 100}}
    path.write_text(json.dumps(data))
    assert _target([run])["campaign_severity"] == "routine"


@pytest.mark.parametrize("mutation", ["delete_records", "remove_mac", "bad_mac", "replay", "garbage"])
def test_forged_or_destroyed_source_never_becomes_routine_history(tmp_path, mutation):
    first = _run(tmp_path, 0, [_escape("ptrace")])
    second = _run(tmp_path, 1, [_escape("bpf")])
    path = second / summary.SUMMARY_FILE
    data = json.loads(path.read_text())
    if mutation == "delete_records":
        data["denials"] = []
        data["total_denials"] = 0
    elif mutation == "remove_mac":
        data.pop("mac")
    elif mutation == "bad_mac":
        data["mac"] = "forged"
    elif mutation == "replay":
        data = json.loads((first / summary.SUMMARY_FILE).read_text())
    path.write_text("not json" if mutation == "garbage" else json.dumps(data))
    result = _target([first, second])
    assert result["integrity"] == "degraded"
    assert result["runs_unknown"] == 1
    assert result["severity_history"][-1]["severity"] is None
    assert _signatures(result)["ptrace"]["trend"] == "unknown"


def test_deleted_summary_with_surviving_run_metadata_stays_visible(tmp_path):
    run = _run(tmp_path, 0, [_escape("ptrace")])
    (run / summary.SUMMARY_FILE).unlink()
    result = _target([run])
    assert result["runs_unknown"] == 1
    assert result["campaign_severity"] == "elevated"
    assert result["severity_history"][0]["integrity"] == "missing"


@pytest.mark.parametrize("flag", ["corrupt_lines", "inode_mismatch", "planted_object"])
def test_authenticated_writer_tamper_flags_are_not_accepted_as_verified(tmp_path, flag):
    value = "symlink" if flag == "planted_object" else 1
    run = _run(tmp_path, 0, [_escape("ptrace")], **{flag: value})
    result = _target([run])
    assert result["integrity"] == "degraded"
    assert result["runs_with_triage"] == 0
    assert result["signatures"] == {}


def test_foreign_or_exposed_key_cannot_produce_trusted_clean_history(tmp_path, monkeypatch):
    run = _run(tmp_path, 0, [])
    summary.record_run_posture(run, mount_ns_active=False, restrict_reads=False)
    result = _target([run])
    assert result["campaign_severity"] == "elevated"
    assert result["severity_history"][0]["integrity"] == "key_exposed"
    monkeypatch.setattr(telemetry_mac, "key_usable", lambda: False)
    assert _target([run])["severity_history"][0]["integrity"] == "unavailable"


def test_distinct_primitives_are_not_one_recurring_signature(tmp_path):
    dirs = [_run(tmp_path, i, [_escape(name)]) for i, name in enumerate(
        ("ptrace", "bpf", "mount", "keyctl"))]
    target = _target(dirs)
    signatures = _signatures(target)
    assert len(signatures) == 4
    assert all(s["runs_seen"] == 1 and s["persistence"] == .25 for s in signatures.values())
    assert target["categories"]["escape_primitives"]["persistence"] == 1


def test_alternating_signatures_have_independent_counts_and_trends(tmp_path):
    dirs = [_run(tmp_path, i, [_escape(name)]) for i, name in enumerate(
        ("ptrace", "bpf", "ptrace", "bpf"))]
    signatures = _signatures(_target(dirs))
    assert signatures["ptrace"]["runs_seen"] == signatures["bpf"]["runs_seen"] == 2
    assert signatures["ptrace"]["persistence"] == .5
    assert signatures["ptrace"]["trend"] == "stable"
    assert signatures["bpf"]["trend"] == "new"


def test_new_and_disappearing_signature_are_not_hidden_by_category(tmp_path):
    dirs = [_run(tmp_path, i, [_escape("ptrace" if i == 0 else "bpf")]) for i in range(4)]
    signatures = _signatures(_target(dirs))
    assert signatures["ptrace"]["trend"] == "resolved"
    assert signatures["bpf"]["trend"] == "new"


def test_missing_runs_widen_persistence_and_never_establish_resolution(tmp_path):
    dirs = [_run(tmp_path, 0, [_escape("ptrace")]), _run(tmp_path, 1),
            _run(tmp_path, 2), _run(tmp_path, 3)]
    result = _target(dirs)
    signature = _signatures(result)["ptrace"]
    assert signature["persistence"] == .25
    assert signature["persistence_upper"] == 1
    assert signature["trend"] == "unknown"
    assert result["runs_total"] == 4 and result["runs_with_triage"] == 1


def test_unknown_earlier_history_does_not_prove_a_signature_is_new(tmp_path):
    dirs = [_run(tmp_path, 0), _run(tmp_path, 1, [_escape("ptrace")])]
    assert _signatures(_target(dirs))["ptrace"]["trend"] == "unknown"


def test_duplicate_directory_cannot_manufacture_persistence(tmp_path):
    run = _run(tmp_path, 0, [_escape("ptrace")])
    target = _target([run] * 5)
    assert target["runs_total"] == 1
    assert _signatures(target)["ptrace"]["runs_seen"] == 1


def test_signatures_beyond_display_example_cap_are_all_correlated(tmp_path):
    records = [{"type": "network", "cmd": f"curl host{i}"} for i in range(8)]
    target = _target([_run(tmp_path, 0, records)])
    assert len(target["signatures"]) == 8
    assert len(target["categories"]["network_probing"]["examples"]) == 8


def test_display_truncation_does_not_collapse_signature_identity(tmp_path):
    prefix = "curl " + "x" * 600
    run = _run(tmp_path, 0, [{"type": "network", "cmd": prefix + tail} for tail in ("a", "b")])
    signatures = _target([run])["signatures"]
    assert len(signatures) == 2
    assert all(s["total_occurrences"] == 1 for s in signatures.values())


def test_path_case_and_internal_whitespace_are_identity_bearing(tmp_path):
    paths = ["/etc/a  b", "/etc/a b", "/etc/A b"]
    run = _run(tmp_path, 0, [{"type": "write", "path": p} for p in paths])
    assert len(_target([run])["signatures"]) == 3


def test_missing_visibility_does_not_add_a_second_severity_upgrade(tmp_path):
    dirs = [_run(tmp_path, i, [{"type": "network", "cmd": "curl host"}]) for i in range(4)]
    dirs.append(_run(tmp_path, 4))
    assert _target(dirs)["campaign_severity"] == "elevated"


def test_campaign_reads_do_not_rewrite_run_artifacts(tmp_path):
    run = _run(tmp_path, 0, [_escape("ptrace")])
    before = {p.name: p.read_bytes() for p in run.iterdir() if p.is_file()}
    _target([run])
    after = {p.name: p.read_bytes() for p in run.iterdir() if p.is_file()}
    assert before == after


def test_unrelated_network_signatures_do_not_trigger_persistence_upgrade(tmp_path):
    dirs = [_run(tmp_path, i, [{"type": "network", "cmd": f"curl host{i}"}]) for i in range(4)]
    target = _target(dirs)
    assert target["categories"]["network_probing"]["persistence"] == 1
    assert all(s["persistence"] == .25 for s in target["signatures"].values())
    assert target["campaign_severity"] == "routine"


def test_signature_counts_retain_duplicate_events_but_count_each_run_once(tmp_path):
    run = _run(tmp_path, 0, [_escape("ptrace")] * 3)
    signature = _signatures(_target([run]))["ptrace"]
    assert signature["total_occurrences"] == 3
    assert signature["runs_seen"] == 1


def test_never_observed_category_is_not_reported_resolved(tmp_path):
    dirs = [_run(tmp_path, i, []) for i in range(4)]
    assert _target(dirs)["categories"]["escape_primitives"]["trend"] == "stable"


def test_malformed_run_metadata_cannot_abort_other_campaign_evidence(tmp_path):
    run = _run(tmp_path, 0, [_escape("ptrace")])
    (run / ".raptor-run.json").write_text('["malformed"]')
    result = correlate_sandbox_triage([run])
    assert result["targets"]["unknown"]["campaign_severity"] == "critical"


def test_denial_cap_prevents_negative_evidence_of_resolution(tmp_path, monkeypatch):
    first = _run(tmp_path, 0, [_escape("ptrace")])
    second = _run(tmp_path, 1, [{"type": "network", "cmd": "curl host"}])
    # Simulate reaching the producer's real cap without constructing 10k rows.
    monkeypatch.setattr('core.project.sandbox_campaign.MAX_DENIALS_PER_RUN', 1)
    result = _target([first, second])
    assert result["integrity"] == "degraded"
    assert _signatures(result)["ptrace"]["trend"] == "unknown"


def test_degraded_audit_marker_blocks_resolution(tmp_path):
    first = _run(tmp_path, 0, [_escape("ptrace")])
    second = _run(tmp_path, 1, [])
    (second / summary.AUDIT_DEGRADED_FILE).write_text('{}')
    result = _target([first, second])
    assert result["runs_unknown"] == 1
    assert _signatures(result)["ptrace"]["trend"] == "unknown"


@pytest.mark.parametrize("content", ['{}', '{"denials": [7], "total_denials": 1}',
                                     '{"denials": [], "total_denials": true}'])
def test_bad_summary_shapes_fail_toward_degraded(tmp_path, content):
    run = _run(tmp_path, 0, [_escape("ptrace")])
    (run / summary.SUMMARY_FILE).write_text(content)
    assert _target([run])["integrity"] == "degraded"


def test_planted_fifo_does_not_hang_or_look_clean(tmp_path):
    import os
    run = _run(tmp_path, 0, [_escape("ptrace")])
    path = run / summary.SUMMARY_FILE
    path.unlink()
    os.mkfifo(path)
    assert _target([run])["severity_history"][0]["integrity"] == "tampered"


def test_same_timestamp_order_is_deterministic(tmp_path):
    first = _run(tmp_path, 0, [_escape("ptrace")])
    second = _run(tmp_path, 1, [])
    meta = json.loads((second / '.raptor-run.json').read_text())
    meta['started_at'] = '2026-10-01T00:00:00Z'
    (second / '.raptor-run.json').write_text(json.dumps(meta))
    assert _target([first, second]) == _target([second, first])


@pytest.mark.parametrize('record,label', [
    ({'type': 'seccomp', 'cmd': 'python target.py', 'syscall': 'bpf'}, 'bpf'),
    ({'type': 'seccomp', 'cmd': 'python target.py', 'syscall': 'io_uring_setup'}, 'io_uring_setup'),
    ({'type': 'seccomp', 'syscall': 'socket', 'args': [2, 3, 0]}, 'socket(SOCK_RAW)'),
    ({'type': 'seccomp', 'syscall': 'ioctl', 'args': [0, 0x5412, 0]}, 'ioctl(TIOCSTI)'),
])
def test_real_tracer_shapes_preserve_primitive_identity(tmp_path, record, label):
    run = _run(tmp_path, 0, [record])
    result = _target([run])
    assert result['campaign_severity'] == 'critical'
    assert _signatures(result)[label]['category'] == 'escape_primitives'


def test_deeply_nested_summary_does_not_abort_campaign(tmp_path):
    run = _run(tmp_path, 0, [_escape('ptrace')])
    (run / summary.SUMMARY_FILE).write_text('[' * 1500 + '0' + ']' * 1500)
    assert _target([run])['integrity'] == 'degraded'


@pytest.mark.parametrize('marker', [
    {'type': 'category_budget_exceeded_sampling'},
    {'type': 'pid_budget_exceeded'},
    {'type': 'audit_summary', 'sampled_keeps': 1},
    {'type': 'audit_summary', 'dropped_by_category': {'file': 7}},
])
def test_sampling_and_budget_markers_are_unknown_absence_not_signatures(tmp_path, marker):
    first = _run(tmp_path, 0, [_escape('ptrace')])
    second = _run(tmp_path, 1, [marker])
    result = _target([first, second])
    assert result['integrity'] == 'degraded'
    assert _signatures(result)['ptrace']['trend'] == 'unknown'
    assert len(result['signatures']) == 1


def test_missing_degraded_marker_is_still_visible_in_authenticated_report(tmp_path):
    from core.sandbox.triage import triage_run
    first = _run(tmp_path, 0, [_escape('ptrace')])
    second = _run(tmp_path, 1, [])
    summary.record_audit_degraded(second, reason='test audit gap')
    triage_run(second, allow_legacy=False)
    (second / summary.AUDIT_DEGRADED_FILE).unlink()
    assert _signatures(_target([first, second]))['ptrace']['trend'] == 'unknown'


def test_removed_expected_triage_report_is_degraded(tmp_path):
    run = _run(tmp_path, 0, [])
    (run / 'sandbox-triage.json').unlink()
    assert _target([run])['integrity'] == 'degraded'


def test_disabled_sandbox_is_not_negative_evidence(tmp_path):
    from core.sandbox.triage import triage_run
    first = _run(tmp_path, 0, [_escape('ptrace')])
    second = _run(tmp_path, 1, [])
    summary.record_cli_disable(second, 'explicit-cli')
    summary._assemble_and_write_summary(
        second, records=[{'type': 'write', 'path': '/tmp/x', 'verdict': 'allow'}],
        refusals=[], corrupt_lines=0, inode_mismatch=False, planted_object='')
    triage_run(second, allow_legacy=False)
    assert _signatures(_target([first, second]))['ptrace']['trend'] == 'unknown'


def test_floor_refusal_is_not_negative_execution_evidence(tmp_path):
    from core.sandbox.triage import triage_run
    first = _run(tmp_path, 0, [_escape('ptrace')])
    second = _run(tmp_path, 1, [])
    summary.record_floor_refusal(second, floor='namespace', achievable='landlock',
                                reason='fixture refuses before execution')
    data = summary.summarize_and_write(second)
    assert data['floor_refusals']
    triage_run(second, allow_legacy=False)
    assert _signatures(_target([first, second]))['ptrace']['trend'] == 'unknown'


def test_authenticated_proxy_erasure_warning_prevents_clean_campaign_history(tmp_path):
    from core.sandbox.triage import triage_run
    first = _run(tmp_path, 0, [_escape('ptrace')])
    second = _run(tmp_path, 1, [])
    event = {'type': 'denied', 'host': 'evil.test', 'port': 443, 'seq': 0}
    event['mac'] = telemetry_mac.mint(telemetry_mac.proxy_event_fields(
        event, telemetry_mac.run_binding(second)))
    # A stamped stream without its expected count sidecar is tampered.
    (second / 'proxy-events.jsonl').write_text(json.dumps(event) + '\n')
    report = triage_run(second, allow_legacy=False)
    assert report['inputs']['integrity']['proxy_events'] == 'tampered'
    assert _signatures(_target([first, second]))['ptrace']['trend'] == 'unknown'

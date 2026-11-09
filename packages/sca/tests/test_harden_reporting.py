"""Hardening report capture retains mode, policy and failure provenance."""
import pytest

from core.json import JsonCache
from core.reporting.writer import load_committed_report
from packages.sca import harden
from packages.sca.harden import HardenCandidate
from packages.sca.osv import OsvClient
from packages.sca.review import _synthesise_dep


def _subject(tmp_path, monkeypatch, *, degraded=False):
    target = tmp_path / "target"
    target.mkdir()
    manifest = target / "requirements.txt"
    manifest.write_text("owned==1.0.0\n")
    osv = OsvClient(harden.default_client(offline=True), JsonCache(root=tmp_path / "cache"), offline=True)
    if degraded:
        osv.query_batch([_synthesise_dep("PyPI", "uncached", "1.0.0")])
        assert osv.degraded
    candidate = HardenCandidate("PyPI", "owned", str(manifest), "exact", "1.0.0", "1.1.0", False,
                                 status="promoted", resolved_in=str(manifest))
    calls = []

    def recorded_plan(**kwargs):
        calls.append(kwargs)
        return [candidate]

    monkeypatch.setattr(harden, "plan", recorded_plan)
    monkeypatch.setattr(harden, "_build_lookup_clients", lambda *a, **k: (osv, None, None))
    return target, manifest, calls


@pytest.mark.parametrize("degraded,expected", [(False, 1), (True, 2)])
def test_check_export_retains_recorded_gate_and_unknown_actionability(tmp_path, monkeypatch, capsys, degraded, expected):
    target, manifest, calls = _subject(tmp_path, monkeypatch, degraded=degraded)
    output = tmp_path / "receipt.json"
    assert harden.main([str(target), "--check", "--offline", "--out", str(tmp_path / "out"),
                        "--report-format", "json", "--report-output", str(output)]) == expected
    assert len(calls) == 1 and manifest.read_text() == "owned==1.0.0\n"
    context, _, _ = load_committed_report(tmp_path / ".receipt-report")
    payload = context.extensions["raptor.result"]
    assert payload["mode"] == "check only" and payload["exit_code"] == expected
    assert payload["status counts"] == {"promoted": 1}
    assert payload["policy-filtered actionable"] == (None if degraded else 1)
    assert payload["candidates"][0]["resolved_in"] == str(manifest)
    assert payload["candidates"][0]["selection"] == "highest_safe"
    assert payload["advisory coverage"]["degraded"] is degraded
    assert "Summary" in capsys.readouterr().err


def test_self_test_failure_is_captured_once_without_apply(tmp_path, monkeypatch, capsys):
    target, manifest, calls = _subject(tmp_path, monkeypatch)
    phases = []

    def failed_self_test(**kwargs):
        phases.append(kwargs["target"])
        return 9

    monkeypatch.setattr(harden, "_run_self_test", failed_self_test)
    output = tmp_path / "receipt.json"
    assert harden.main([str(target), "--self-test", "--offline", "--out", str(tmp_path / "out"),
                        "--report-format", "json", "--report-output", str(output)]) == 9
    assert phases == [target] and len(calls) == 1
    assert manifest.read_text() == "owned==1.0.0\n"
    context, _, _ = load_committed_report(tmp_path / ".receipt-report")
    assert context.state == "failed"
    assert context.extensions["raptor.result"]["mode"] == "self-test failed"
    assert next(stage for stage in context.stages if stage.stage_id == "self-test").state == "failed"


def test_apply_refusal_keeps_native_gate_and_records_failed_phase(tmp_path, monkeypatch, capsys):
    target, manifest, calls = _subject(tmp_path, monkeypatch)
    emitted = []

    def owned_patch(changes, out_dir):
        assert len(changes) == 1
        patch = out_dir / "upgrade.patch"
        patch.write_text("owned test patch")
        emitted.append(patch)
        return patch, target

    monkeypatch.setattr(harden, "_emit_git_patch", owned_patch)
    output = tmp_path / "receipt.json"
    # The actual apply helper refuses this non-Git target before any subprocess.
    assert harden.main([str(target), "--apply", "--offline", "--out", str(tmp_path / "out"),
                        "--report-format", "json", "--report-output", str(output)]) == 4
    assert len(emitted) == 1 and len(calls) == 1
    assert manifest.read_text() == "owned==1.0.0\n"
    context, _, _ = load_committed_report(tmp_path / ".receipt-report")
    payload = context.extensions["raptor.result"]
    assert payload["mode"] == "apply failed" and payload["phases"]["apply exit"] == 4
    assert context.state == "failed"

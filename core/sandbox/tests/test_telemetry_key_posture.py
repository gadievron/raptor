"""Telemetry-MAC key exposure posture.

The HMAC key lives outside the run directory, but only a mount
namespace or a restrict_reads read allowlist hides it from the
sandboxed child — on a read-unrestricted run the target can read the
key and mint valid telemetry tokens. Triage must therefore be able to
distinguish "token verified AND the key was plausibly hidden from the
child" from "token verified but the run posture exposed the key", and
demote the latter to legacy confidence.
"""

import json
import subprocess
import types

import pytest

from core.sandbox import summary as summary_mod
from core.sandbox import telemetry_mac
from core.sandbox import triage as triage_mod


@pytest.fixture(autouse=True)
def _isolated_state(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    monkeypatch.setattr(summary_mod, "_run_postures", {})
    monkeypatch.setattr(summary_mod, "_degraded_markers", {})
    summary_mod.set_active_run_dir(None)
    yield
    summary_mod.set_active_run_dir(None)


def _write_real_summary(run_dir):
    """Produce a genuinely-stamped summary via the real writer API."""
    summary_mod.set_active_run_dir(run_dir)
    try:
        summary_mod.record_denial(
            "cat /root/.ssh/id_rsa", 1, "write", path="/root/.ssh/id_rsa")
        return summary_mod.summarize_and_write(run_dir)
    finally:
        summary_mod.set_active_run_dir(None)


def _mint_summary(run_dir, denials, posture=None):
    """Simulate a key-holder minting a summary directly (what a target
    that read the key could do)."""
    payload = {
        "run_dir": str(run_dir),
        "generated_at": "2026-07-23T00:00:00Z",
        "total_denials": len(denials),
        "by_type": {},
        "denials": denials,
    }
    if posture is not None:
        payload["posture"] = posture
    payload["mac"] = telemetry_mac.mint(telemetry_mac.summary_fields(
        len(denials), triage_mod._denials_sha256(denials),
        run=telemetry_mac.run_binding(run_dir), posture=posture))
    (run_dir / summary_mod.SUMMARY_FILE).write_text(json.dumps(payload))
    return payload


class TestPostureRecording:
    def test_roundtrip(self, tmp_path):
        summary_mod.record_run_posture(
            tmp_path, mount_ns_active=True, restrict_reads=False)
        assert summary_mod.get_run_posture(tmp_path) == {
            "mount_ns_active": True, "restrict_reads": False,
            "mac_key_hidden": True,
        }

    def test_unknown_run_is_none(self, tmp_path):
        assert summary_mod.get_run_posture(tmp_path) is None

    def test_key_hidden_needs_mount_ns_or_restrict_reads(self, tmp_path):
        summary_mod.record_run_posture(
            tmp_path, mount_ns_active=False, restrict_reads=False)
        assert summary_mod.get_run_posture(
            tmp_path)["mac_key_hidden"] is False

    def test_restrict_reads_alone_hides_key(self, tmp_path):
        summary_mod.record_run_posture(
            tmp_path, mount_ns_active=False, restrict_reads=True)
        assert summary_mod.get_run_posture(
            tmp_path)["mac_key_hidden"] is True

    def test_weakest_posture_wins_across_calls(self, tmp_path):
        summary_mod.record_run_posture(
            tmp_path, mount_ns_active=True, restrict_reads=True)
        summary_mod.record_run_posture(
            tmp_path, mount_ns_active=False, restrict_reads=False)
        posture = summary_mod.get_run_posture(tmp_path)
        assert posture["mac_key_hidden"] is False
        # ... and a later strong call cannot repair it.
        summary_mod.record_run_posture(
            tmp_path, mount_ns_active=True, restrict_reads=True)
        assert summary_mod.get_run_posture(
            tmp_path)["mac_key_hidden"] is False


class TestSummaryCarriesPosture:
    def test_summary_embeds_recorded_posture(self, tmp_path):
        summary_mod.record_run_posture(
            tmp_path, mount_ns_active=False, restrict_reads=False)
        written = _write_real_summary(tmp_path)
        assert written["posture"]["mac_key_hidden"] is False
        on_disk = json.loads(
            (tmp_path / summary_mod.SUMMARY_FILE).read_text())
        assert on_disk["posture"]["mac_key_hidden"] is False

    def test_no_posture_recorded_no_field(self, tmp_path):
        written = _write_real_summary(tmp_path)
        assert "posture" not in written

    def test_stripping_posture_breaks_the_token(self, tmp_path):
        summary_mod.record_run_posture(
            tmp_path, mount_ns_active=False, restrict_reads=False)
        _write_real_summary(tmp_path)
        path = tmp_path / summary_mod.SUMMARY_FILE
        payload = json.loads(path.read_text())
        del payload["posture"]
        path.write_text(json.dumps(payload))
        # Fresh-process view: registry cleared, only the disk copy.
        summary_mod._run_postures.clear()
        result = triage_mod.triage_run(tmp_path)
        assert result["inputs"]["integrity"]["sandbox_summary"] == "tampered"

    def test_flipping_posture_breaks_the_token(self, tmp_path):
        summary_mod.record_run_posture(
            tmp_path, mount_ns_active=False, restrict_reads=False)
        _write_real_summary(tmp_path)
        path = tmp_path / summary_mod.SUMMARY_FILE
        payload = json.loads(path.read_text())
        payload["posture"]["mac_key_hidden"] = True
        path.write_text(json.dumps(payload))
        summary_mod._run_postures.clear()
        result = triage_mod.triage_run(tmp_path)
        assert result["inputs"]["integrity"]["sandbox_summary"] == "tampered"


class TestTriageDemotion:
    def test_exposed_key_demotes_verified_summary_to_legacy(self, tmp_path):
        summary_mod.record_run_posture(
            tmp_path, mount_ns_active=False, restrict_reads=False)
        _write_real_summary(tmp_path)
        result = triage_mod.triage_run(tmp_path, allow_legacy=False)
        assert result["inputs"]["integrity"]["sandbox_summary"] == "legacy"
        assert result["inputs"]["mac_key_posture"]["mac_key_hidden"] is False
        assert result["inputs"]["mac_key_posture"]["source"] == "parent-memory"
        assert any("could not hide the telemetry-mac key" in c
                   for c in result["caveats"])
        # Content is still assessed — demotion lowers confidence, it
        # does not silence signals.
        assert any(s["type"] == "credential_path_touch"
                   for s in result["signals"])
        # Demotion is not tampering: no HIGH tampering signal from it.
        assert not any(s["type"] == "telemetry_tampering"
                       for s in result["signals"])

    def test_hidden_key_keeps_verified_tier(self, tmp_path):
        summary_mod.record_run_posture(
            tmp_path, mount_ns_active=True, restrict_reads=False)
        _write_real_summary(tmp_path)
        result = triage_mod.triage_run(tmp_path, allow_legacy=False)
        assert result["inputs"]["integrity"]["sandbox_summary"] == "verified"
        assert result["inputs"]["mac_key_posture"]["mac_key_hidden"] is True
        assert not any("could not hide" in c for c in result["caveats"])

    def test_unknown_posture_keeps_current_behaviour(self, tmp_path):
        _write_real_summary(tmp_path)
        result = triage_mod.triage_run(tmp_path, allow_legacy=False)
        assert result["inputs"]["integrity"]["sandbox_summary"] == "verified"
        assert result["inputs"]["mac_key_posture"] == "unknown"

    def test_exposed_key_demotes_stamped_proxy_events(self, tmp_path):
        summary_mod.record_run_posture(
            tmp_path, mount_ns_active=False, restrict_reads=False)
        run = telemetry_mac.run_binding(tmp_path)
        events = []
        for i in range(3):
            event = {"t": 1.0, "host": f"h{i}.example", "port": 443,
                     "result": "denied_host", "reason": "not allowed",
                     "resolved_ip": None, "seq": i}
            event["mac"] = telemetry_mac.mint(
                telemetry_mac.proxy_event_fields(event, run))
            events.append(event)
        (tmp_path / triage_mod.PROXY_EVENTS_FILENAME).write_text(
            "\n".join(json.dumps(e) for e in events) + "\n")
        # Under lifecycle semantics a stamped stream needs its count
        # sidecar or it reads as tampered before the key-exposure
        # demotion applies — mint a consistent one, as the writer
        # would have.
        (tmp_path / triage_mod.PROXY_EVENTS_COUNT_FILENAME).write_text(
            json.dumps({
                "count": 3, "flags": [],
                "mac": telemetry_mac.mint(
                    telemetry_mac.proxy_events_count_fields(
                        3, [], run)),
            }))
        result = triage_mod.triage_run(tmp_path, allow_legacy=False)
        assert result["inputs"]["integrity"]["proxy_events"] == "legacy"
        assert any("could not hide the telemetry-mac key" in c
                   for c in result["caveats"])

    def test_parent_memory_beats_forged_disk_claim(self, tmp_path):
        # An attacker who read the key mints a summary CLAIMING the
        # key was hidden. The parent's own record says it was not.
        summary_mod.record_run_posture(
            tmp_path, mount_ns_active=False, restrict_reads=False)
        _mint_summary(
            tmp_path,
            [{"type": "write", "cmd": "x", "returncode": 1,
              "path": "/tmp/a"}],
            posture={"mount_ns_active": True, "restrict_reads": True,
                     "mac_key_hidden": True})
        result = triage_mod.triage_run(tmp_path, allow_legacy=False)
        assert result["inputs"]["integrity"]["sandbox_summary"] == "legacy"
        assert result["inputs"]["mac_key_posture"]["source"] == "parent-memory"
        assert result["inputs"]["mac_key_posture"]["mac_key_hidden"] is False

    def test_disk_exposed_claim_demotes_without_registry(self, tmp_path):
        # Fresh-process re-triage: no parent memory. An on-disk
        # "exposed" record is trusted one-way (nobody gains from
        # forging a demotion) — the run still reads as legacy tier.
        _mint_summary(
            tmp_path,
            [{"type": "write", "cmd": "x", "returncode": 1,
              "path": "/tmp/a"}],
            posture={"mount_ns_active": False, "restrict_reads": False,
                     "mac_key_hidden": False})
        result = triage_mod.triage_run(tmp_path)
        assert result["inputs"]["integrity"]["sandbox_summary"] == "legacy"
        assert result["inputs"]["mac_key_posture"]["source"] == "summary"

    def test_disk_hidden_claim_alone_does_not_upgrade(self, tmp_path):
        # One-way trust, other direction: with no parent memory, an
        # on-disk "hidden" claim proves nothing (a key-holder target
        # would forge exactly that) — but absent any exposure record
        # the tier stays as computed today. Documented residual: a
        # fresh-process re-triage cannot distinguish this forgery.
        _mint_summary(
            tmp_path,
            [{"type": "write", "cmd": "x", "returncode": 1,
              "path": "/tmp/a"}],
            posture={"mount_ns_active": True, "restrict_reads": True,
                     "mac_key_hidden": True})
        result = triage_mod.triage_run(tmp_path)
        assert result["inputs"]["integrity"]["sandbox_summary"] == "verified"
        assert result["inputs"]["mac_key_posture"] == "unknown"


class _FakePopen:
    """Stand-in for the seatbelt shim process — never spawns."""

    def __init__(self, cmd, **kwargs):
        self.cmd = cmd
        self.pid = 4190001  # never signalled on the normal path

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def communicate(self, input=None, timeout=None):
        return ("", "")

    def poll(self):
        return 0

    def wait(self, timeout=None):
        return 0

    def kill(self):
        pass


class TestMacosSpawnWiring:
    """The macOS backend records the invocation posture: no mount
    namespace ever exists there, so restrict_reads alone decides
    whether the key was hidden."""

    def _run(self, tmp_path, monkeypatch, **kwargs):
        from core.sandbox import _macos_spawn
        fake_subprocess = types.SimpleNamespace(
            Popen=_FakePopen,
            TimeoutExpired=subprocess.TimeoutExpired,
            CompletedProcess=subprocess.CompletedProcess,
            PIPE=subprocess.PIPE,
        )
        monkeypatch.setattr(_macos_spawn, "subprocess", fake_subprocess)
        # Keep the post-wait descendant sweep hermetic: no real ps, no
        # signals from this test (the sweep has its own dedicated tests).
        monkeypatch.setattr(_macos_spawn, "_ps_snapshot", lambda: [])
        return _macos_spawn.run_sandboxed(
            ["/usr/bin/true"], env={}, audit_run_dir=str(tmp_path),
            **kwargs)

    def test_read_unrestricted_run_records_exposed_key(
            self, tmp_path, monkeypatch):
        self._run(tmp_path, monkeypatch, restrict_reads=False)
        posture = summary_mod.get_run_posture(tmp_path)
        assert posture == {"mount_ns_active": False,
                           "restrict_reads": False,
                           "mac_key_hidden": False}

    def test_restrict_reads_run_records_hidden_key(
            self, tmp_path, monkeypatch):
        self._run(tmp_path, monkeypatch, restrict_reads=True)
        posture = summary_mod.get_run_posture(tmp_path)
        assert posture["mac_key_hidden"] is True


class TestLinuxContextWiring:
    """The Linux dispatch layer records the per-call posture too —
    a real sandboxed call with an output dir must land a posture
    record keyed to that dir."""

    def _mount_usable(self):
        import shutil as _sh
        from pathlib import Path as _P
        if not _sh.which("newuidmap") or not _sh.which("newgidmap"):
            return False
        p = _P("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
        return not (p.exists() and p.read_text().strip() == "1")

    def test_run_records_posture_for_output_dir(self, tmp_path,
                                                monkeypatch):
        if not self._mount_usable():
            pytest.skip("mount-ns unusable here")
        from core.sandbox import run as sandbox_run
        from core.sandbox import summary as summary_mod
        out = tmp_path / "out"
        out.mkdir()
        r = sandbox_run(["/usr/bin/true"], target=str(out),
                        output=str(out), block_network=True,
                        capture_output=True, text=True, timeout=30)
        posture = summary_mod.get_run_posture(out)
        assert posture is not None, (
            "Linux run() must record the telemetry-key posture")
        if (getattr(r, "sandbox_info", None) or {}).get(
                "mount_ns_active"):
            assert posture["mac_key_hidden"] is True

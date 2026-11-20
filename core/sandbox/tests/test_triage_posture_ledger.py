"""Fresh-process posture grading via the session run ledger.

The live triage path reads the telemetry-key posture from parent
memory; a fresh process (CI ``--require-evidence`` gates, post-hoc
re-triage) has none, and on a key-exposed run the target could have
minted fully-verifying records. These tests pin the persisted-posture
contract: run end writes the final posture into the parent-owned
session ledger keyed by the FULL resolved run-dir path; fresh-process
triage consults it; a key-exposed record demotes exactly like the
live path; a same-basename record for a different directory is the
cross-run replay signature and never a usable posture; and parent
memory stays authoritative when present.
"""

import json
import os

import pytest

from core.json import save_json
from core.project import sessions
from core.run import RUN_METADATA_FILE, fail_run
from core.sandbox import summary as summary_mod
from core.sandbox import telemetry_mac
from core.sandbox import triage as triage_mod
from core.testing.sandbox_state_scope import isolated_summary_state
from core.testing.state_isolation import pin_user_state_dirs

HIDDEN = {"mount_ns_active": True, "restrict_reads": False,
          "mac_key_hidden": True}
EXPOSED = {"mount_ns_active": False, "restrict_reads": False,
           "mac_key_hidden": False}


@pytest.fixture(autouse=True)
def _owned_state(tmp_path, monkeypatch):
    with isolated_summary_state():
        try:
            pin_user_state_dirs(monkeypatch, tmp_path / "state")
            monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
            # The ledger writers' identity gate wants a claude-shaped
            # session owner; the pytest process is python-shaped.
            monkeypatch.setattr(
                sessions, "_comm",
                lambda pid: "claude" if pid == os.getpid() else None)
            monkeypatch.setattr(summary_mod, "_run_postures", {})
            monkeypatch.setattr(summary_mod, "_degraded_markers", {})
            summary_mod.set_active_run_dir(None)
            yield
            summary_mod.set_active_run_dir(None)
        finally:
            monkeypatch.undo()


def _sessioned() -> int:
    pid = os.getpid()
    assert sessions.record_session("posturelane", pid=pid) == pid
    return pid


def _write_real_summary(run_dir):
    """Produce a genuinely-stamped summary via the real writer API."""
    summary_mod.set_active_run_dir(run_dir)
    try:
        summary_mod.record_denial(
            "touch /tmp/owned", 1, "write", path="/tmp/owned")
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


_DENIAL = {"type": "write", "cmd": "x", "returncode": 1, "path": "/tmp/a"}


class TestRunEndPersistence:
    def test_terminal_transition_writes_full_path_keyed_record(
            self, tmp_path):
        pid = _sessioned()
        run = tmp_path / "out" / "scan_1"
        run.mkdir(parents=True)
        save_json(run / RUN_METADATA_FILE,
                  {"status": "running", "session_pid": pid})
        summary_mod.record_run_posture(
            run, mount_ns_active=True, restrict_reads=False)
        fail_run(run, "owned failure")
        posture, collision = sessions.ledger_run_posture(run)
        assert posture is not None and posture["mac_key_hidden"] is True
        assert collision is False
        # Keyed by the FULL resolved path, not the basename.
        ledger = sessions._sessions_dir() / f"{pid}.run"
        assert f" {run.resolve()}\n" in ledger.read_text(encoding="utf-8")

    def test_no_parent_posture_writes_nothing(self, tmp_path):
        # Heuristic finalisers / sweeps terminate runs from processes
        # that never sandboxed anything: no posture to persist, and a
        # later fresh-process triage must read unknown (fail closed),
        # never a fabricated record.
        pid = _sessioned()
        run = tmp_path / "out" / "scan_2"
        run.mkdir(parents=True)
        save_json(run / RUN_METADATA_FILE,
                  {"status": "running", "session_pid": pid})
        fail_run(run, "owned failure")
        assert sessions.ledger_run_posture(run) == (None, False)


class TestFreshProcessGrading:
    def test_ledger_exposed_record_demotes_forged_hidden_claim(
            self, tmp_path):
        # The run exposed the key; the (possibly target-minted) summary
        # claims it was hidden. Parent memory is gone — only the
        # parent-owned ledger record remains, and it demotes exactly
        # like the live path: never "verified".
        pid = _sessioned()
        run = tmp_path / "run"
        run.mkdir()
        _mint_summary(run, [_DENIAL], posture=dict(HIDDEN))
        assert sessions.ledger_record_posture(run, EXPOSED, pid=pid)
        summary_mod._run_postures.clear()
        result = triage_mod.triage_run(run, allow_legacy=False)
        assert result["inputs"]["integrity"]["sandbox_summary"] == "legacy"
        posture = result["inputs"]["mac_key_posture"]
        assert posture["source"] == "session-ledger"
        assert posture["mac_key_hidden"] is False
        assert any("could not hide the telemetry-mac key" in c
                   for c in result["caveats"])

    def test_ledger_hidden_record_restores_strict_admission(
            self, tmp_path, capsys):
        pid = _sessioned()
        run = tmp_path / "run"
        run.mkdir()
        summary_mod.record_run_posture(
            run, mount_ns_active=True, restrict_reads=False)
        _write_real_summary(run)
        assert sessions.ledger_record_posture(
            run, summary_mod.get_run_posture(run), pid=pid)
        summary_mod._run_postures.clear()
        assert triage_mod._cli_main(
            [str(run), "--require-evidence", "--json"]) == 0
        report = json.loads(capsys.readouterr().out)
        assert report["inputs"]["integrity"]["sandbox_summary"] == "verified"
        posture = report["inputs"]["mac_key_posture"]
        assert posture["source"] == "session-ledger"
        assert posture["mac_key_hidden"] is True

    def test_no_record_fails_strict_gate_closed(self, tmp_path, capsys):
        # No parent memory, no ledger record — a disk "hidden" claim
        # alone (exactly what a key-holder would forge) cannot satisfy
        # the strict gate.
        run = tmp_path / "run"
        run.mkdir()
        _mint_summary(run, [_DENIAL], posture=dict(HIDDEN))
        summary_mod._run_postures.clear()
        assert triage_mod._cli_main(
            [str(run), "--require-evidence", "--json"]) == 1
        captured = capsys.readouterr()
        report = json.loads(captured.out)
        assert report["inputs"]["mac_key_posture"] == "unknown"
        assert "posture is unavailable" in captured.err


class TestBasenameReplay:
    def test_same_basename_record_is_conflict_not_match(
            self, tmp_path, capsys):
        # Validly-stamped artefacts replayed into a same-named run dir
        # verify (the MAC run-binding is the basename alone), but the
        # posture record is full-path keyed: the mismatch is reported
        # as a conflict and the strict gate refuses.
        pid = _sessioned()
        genuine = tmp_path / "a" / "scan_9"
        replayed = tmp_path / "b" / "scan_9"
        genuine.mkdir(parents=True)
        replayed.mkdir(parents=True)
        assert sessions.ledger_record_posture(genuine, HIDDEN, pid=pid)
        _mint_summary(genuine, [_DENIAL])
        _mint_summary(replayed, [_DENIAL])
        summary_mod._run_postures.clear()
        result = triage_mod.triage_run(replayed, allow_legacy=False)
        assert result["inputs"]["posture_conflict"] is True
        assert result["inputs"]["mac_key_posture"] == "unknown"
        assert any("different run directory" in c
                   for c in result["caveats"])
        assert triage_mod._cli_main(
            [str(replayed), "--require-evidence", "--json"]) == 1
        captured = capsys.readouterr()
        assert "different run directory with the same name" in captured.err
        # The genuine dir itself is unaffected by the sibling: its own
        # full-path record matches, so no conflict is raised.
        result = triage_mod.triage_run(genuine, allow_legacy=False)
        assert result["inputs"].get("posture_conflict") is None
        assert result["inputs"]["mac_key_posture"]["source"] == \
            "session-ledger"


class TestLivePathAuthority:
    def test_parent_memory_beats_ledger_hidden_claim(self, tmp_path):
        # The live in-process posture stays authoritative: a ledger
        # record (stale resume, hand-edited) never upgrades what the
        # parent itself observed.
        pid = _sessioned()
        run = tmp_path / "run"
        run.mkdir()
        summary_mod.record_run_posture(
            run, mount_ns_active=False, restrict_reads=False)
        _write_real_summary(run)
        assert sessions.ledger_record_posture(run, HIDDEN, pid=pid)
        result = triage_mod.triage_run(run, allow_legacy=False)
        assert result["inputs"]["integrity"]["sandbox_summary"] == "legacy"
        posture = result["inputs"]["mac_key_posture"]
        assert posture["source"] == "parent-memory"
        assert posture["mac_key_hidden"] is False

    def test_parent_memory_source_wins_when_both_agree(self, tmp_path):
        pid = _sessioned()
        run = tmp_path / "run"
        run.mkdir()
        summary_mod.record_run_posture(
            run, mount_ns_active=True, restrict_reads=False)
        _write_real_summary(run)
        assert sessions.ledger_record_posture(run, EXPOSED, pid=pid)
        result = triage_mod.triage_run(run, allow_legacy=False)
        assert result["inputs"]["integrity"]["sandbox_summary"] == "verified"
        assert result["inputs"]["mac_key_posture"]["source"] == \
            "parent-memory"

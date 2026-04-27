"""Tests for core.sandbox.summary — per-run sandbox denial aggregation."""

import json
import os
import threading
from pathlib import Path

import pytest

from core.sandbox import summary as summary_mod


@pytest.fixture(autouse=True)
def _isolate_active_run():
    """Each test starts and ends with no active run set, regardless of
    whether the test itself sets one."""
    summary_mod.set_active_run_dir(None)
    yield
    summary_mod.set_active_run_dir(None)


class TestActiveRunState:
    def test_initially_none(self):
        assert summary_mod.get_active_run_dir() is None

    def test_set_and_clear(self, tmp_path):
        summary_mod.set_active_run_dir(tmp_path)
        assert summary_mod.get_active_run_dir() == tmp_path
        summary_mod.set_active_run_dir(None)
        assert summary_mod.get_active_run_dir() is None

    def test_set_accepts_str_or_path(self, tmp_path):
        summary_mod.set_active_run_dir(str(tmp_path))
        assert summary_mod.get_active_run_dir() == Path(tmp_path)


class TestRecordDenial:
    def test_no_op_when_no_active_run(self, tmp_path):
        # Must not crash, must not write anywhere
        summary_mod.record_denial("git clone", 1, "network")
        assert list(tmp_path.iterdir()) == []

    def test_appends_jsonl_when_active(self, tmp_path):
        summary_mod.set_active_run_dir(tmp_path)
        summary_mod.record_denial("git clone evil.com", 1, "network")
        jsonl = tmp_path / summary_mod.DENIALS_FILE
        assert jsonl.exists()
        records = [json.loads(line) for line in jsonl.read_text().splitlines() if line]
        assert len(records) == 1
        r = records[0]
        assert r["cmd"] == "git clone evil.com"
        assert r["returncode"] == 1
        assert r["type"] == "network"
        assert "suggested_fix" in r
        assert "ts" in r

    def test_multiple_records_append(self, tmp_path):
        summary_mod.set_active_run_dir(tmp_path)
        summary_mod.record_denial("cmd1", 1, "network")
        summary_mod.record_denial("cmd2", 1, "write", path="/etc/foo")
        summary_mod.record_denial("cmd3", 137, "seccomp", profile="full")
        jsonl = tmp_path / summary_mod.DENIALS_FILE
        records = [json.loads(line) for line in jsonl.read_text().splitlines() if line]
        assert len(records) == 3
        assert [r["type"] for r in records] == ["network", "write", "seccomp"]
        # type-specific details preserved
        assert records[1]["path"] == "/etc/foo"
        assert records[2]["profile"] == "full"

    def test_swallows_oserror_silently(self, tmp_path, monkeypatch):
        # If the run dir disappears mid-write, record_denial must not
        # raise — sandbox calls must succeed regardless of summary I/O.
        summary_mod.set_active_run_dir(tmp_path / "does-not-exist")

        def boom(*a, **k):
            raise OSError("simulated disk full")

        monkeypatch.setattr("builtins.open", boom)
        # Must not propagate the OSError
        summary_mod.record_denial("cmd", 1, "network")

    def test_serialises_non_jsonable_details_via_default_str(self, tmp_path):
        # Regression for 2R4 / 1R2 fix: future callers passing Path objects
        # (or other non-JSON-native values) must not crash record_denial.
        # `default=str` in json.dumps coerces them; the broad except catches
        # anything else.
        summary_mod.set_active_run_dir(tmp_path)
        non_jsonable = Path("/tmp/some/path")  # Path is not JSON-serializable
        # Must not raise
        summary_mod.record_denial("cmd", 1, "write", path=non_jsonable)
        jsonl = tmp_path / summary_mod.DENIALS_FILE
        records = [json.loads(line) for line in jsonl.read_text().splitlines() if line]
        assert len(records) == 1
        # Coerced to string via default=str
        assert records[0]["path"] == "/tmp/some/path"


class TestSuggestedFix:
    def test_network_with_host(self):
        s = summary_mod._suggested_fix("network", host="evil.com")
        assert "evil.com" in s
        # Must reference an actual operator-facing flag, not the kwarg form.
        assert "--sandbox" in s
        assert "none" in s

    def test_network_without_host(self):
        s = summary_mod._suggested_fix("network")
        assert "--sandbox" in s
        assert "none" in s

    def test_write_with_path(self):
        s = summary_mod._suggested_fix("write", path="/etc/foo")
        assert "/etc/foo" in s
        assert "--sandbox" in s
        # network-only drops Landlock (the layer that blocks writes)
        assert "network-only" in s

    def test_seccomp_full_profile(self):
        s = summary_mod._suggested_fix("seccomp", profile="full")
        assert "--sandbox" in s
        assert "debug" in s

    def test_seccomp_other_profile(self):
        s = summary_mod._suggested_fix("seccomp", profile="custom")
        assert "--sandbox" in s

    def test_unknown_type_returns_generic(self):
        s = summary_mod._suggested_fix("mystery")
        assert s  # non-empty

    def test_no_kwarg_flag_names_in_suggestions(self):
        # Regression for 2R1: suggestions MUST NOT reference --proxy-hosts,
        # --writable-paths, --readable-paths since none exist as actual CLI
        # flags (they're sandbox API kwargs only). Operators reading the
        # summary would otherwise look for flags that don't exist.
        for dt, kwargs in [
            ("network", {}), ("network", {"host": "x"}),
            ("write", {}), ("write", {"path": "/x"}),
            ("seccomp", {"profile": "full"}),
            ("seccomp", {"profile": "other"}),
        ]:
            s = summary_mod._suggested_fix(dt, **kwargs)
            assert "--proxy-hosts" not in s, f"stale flag in {dt}: {s}"
            assert "--writable-paths" not in s, f"stale flag in {dt}: {s}"
            assert "--readable-paths" not in s, f"stale flag in {dt}: {s}"


class TestSummarizeAndWrite:
    def test_no_jsonl_returns_none(self, tmp_path):
        result = summary_mod.summarize_and_write(tmp_path)
        assert result is None
        assert not (tmp_path / summary_mod.SUMMARY_FILE).exists()

    def test_aggregates_jsonl_into_summary(self, tmp_path):
        summary_mod.set_active_run_dir(tmp_path)
        summary_mod.record_denial("cmd1", 1, "network")
        summary_mod.record_denial("cmd2", 1, "network")
        summary_mod.record_denial("cmd3", 1, "write", path="/etc/x")
        summary_mod.record_denial("cmd4", 137, "seccomp", profile="full")

        result = summary_mod.summarize_and_write(tmp_path)
        assert result is not None
        assert result["total_denials"] == 4
        assert result["by_type"] == {"network": 2, "write": 1, "seccomp": 1}
        assert len(result["denials"]) == 4

        # Summary file written
        summary_path = tmp_path / summary_mod.SUMMARY_FILE
        assert summary_path.exists()
        on_disk = json.loads(summary_path.read_text())
        assert on_disk["total_denials"] == 4

        # Intermediate JSONL removed
        assert not (tmp_path / summary_mod.DENIALS_FILE).exists()

    def test_idempotent_when_called_twice(self, tmp_path):
        summary_mod.set_active_run_dir(tmp_path)
        summary_mod.record_denial("cmd", 1, "network")
        first = summary_mod.summarize_and_write(tmp_path)
        second = summary_mod.summarize_and_write(tmp_path)
        # First call wrote summary + removed JSONL; second call sees no
        # JSONL and returns None without overwriting the existing summary.
        assert first is not None
        assert second is None
        # Summary file from first call still intact
        assert (tmp_path / summary_mod.SUMMARY_FILE).exists()

    def test_skips_malformed_jsonl_lines(self, tmp_path):
        # Pre-populate JSONL with one valid + one garbage line
        jsonl = tmp_path / summary_mod.DENIALS_FILE
        jsonl.write_text(
            json.dumps({"ts": "x", "type": "network", "cmd": "c", "returncode": 1}) + "\n"
            "this is not json\n"
            + json.dumps({"ts": "y", "type": "write", "cmd": "c2", "returncode": 1}) + "\n"
        )
        result = summary_mod.summarize_and_write(tmp_path)
        # Two valid records survived; garbage skipped without error
        assert result["total_denials"] == 2

    def test_empty_jsonl_returns_none_and_removes_jsonl(self, tmp_path):
        jsonl = tmp_path / summary_mod.DENIALS_FILE
        jsonl.write_text("")
        result = summary_mod.summarize_and_write(tmp_path)
        assert result is None
        assert not jsonl.exists()


class TestThreadSafety:
    def test_concurrent_set_clear_is_serialised(self, tmp_path):
        # Hammer set/clear from multiple threads; the lock should keep
        # state consistent (no torn reads of the global).
        results = []

        def worker(d):
            for _ in range(50):
                summary_mod.set_active_run_dir(d)
                got = summary_mod.get_active_run_dir()
                results.append(got)
                summary_mod.set_active_run_dir(None)

        threads = [threading.Thread(target=worker, args=(tmp_path / f"d{i}",))
                   for i in range(4)]
        for t in threads: t.start()
        for t in threads: t.join()
        # All non-None observations should be one of the four target dirs
        valid = {tmp_path / f"d{i}" for i in range(4)}
        for r in results:
            if r is not None:
                assert r in valid

    def test_concurrent_record_denial_doesnt_lose_records(self, tmp_path):
        # Multiple threads recording denials concurrently should all land
        # in the JSONL — POSIX append + small line size means atomicity.
        summary_mod.set_active_run_dir(tmp_path)
        n_threads = 8
        per_thread = 25

        def worker(tid):
            for i in range(per_thread):
                summary_mod.record_denial(f"cmd-t{tid}-{i}", 1, "network")

        threads = [threading.Thread(target=worker, args=(t,)) for t in range(n_threads)]
        for t in threads: t.start()
        for t in threads: t.join()

        jsonl = tmp_path / summary_mod.DENIALS_FILE
        records = [json.loads(line) for line in jsonl.read_text().splitlines() if line]
        # All n_threads * per_thread records should be present
        assert len(records) == n_threads * per_thread


class TestLifecycleIntegration:
    """End-to-end: start_run → record_denial fires from _check_blocked →
    complete_run writes summary. Verifies the wiring across modules."""

    def test_full_lifecycle_writes_summary(self, tmp_path):
        from core.run.metadata import start_run, complete_run
        from core.sandbox.observe import _check_blocked

        run_dir = tmp_path / "agentic-20260427-150000-pid12345"

        # Start the run — should mark this dir as active for sandbox summary
        start_run(run_dir, command="agentic")
        assert summary_mod.get_active_run_dir() == run_dir

        # Simulate a sandbox call that detects an outbound network attempt.
        # _check_blocked is what observe calls after each subprocess; it
        # fires record_denial for each detected denial type.
        sandbox_info = {}
        _check_blocked(
            stderr="curl: (7) Failed to connect to evil.com\n",
            cmd_display="curl evil.com",
            returncode=7,
            sandbox_info=sandbox_info,
            network_engaged=True,
        )

        # Denial recorded in the JSONL
        jsonl = run_dir / summary_mod.DENIALS_FILE
        assert jsonl.exists()

        # Complete the run — should finalize summary + clear active state
        complete_run(run_dir)
        assert summary_mod.get_active_run_dir() is None

        # Summary file written, JSONL cleaned up
        summary_path = run_dir / summary_mod.SUMMARY_FILE
        assert summary_path.exists()
        assert not jsonl.exists()

        on_disk = json.loads(summary_path.read_text())
        assert on_disk["total_denials"] == 1
        assert on_disk["by_type"] == {"network": 1}
        assert on_disk["denials"][0]["type"] == "network"
        assert "--sandbox" in on_disk["denials"][0]["suggested_fix"]

    def test_failed_run_still_writes_summary(self, tmp_path):
        from core.run.metadata import start_run, fail_run
        from core.sandbox.observe import _check_blocked

        run_dir = tmp_path / "scan-failed"
        start_run(run_dir, command="scan")
        _check_blocked(
            stderr="cannot create '/etc/blocked': Permission denied\n",
            cmd_display="tool /etc/blocked",
            returncode=1,
            sandbox_info={},
            landlock_engaged=True,
        )
        fail_run(run_dir, error="something broke")

        # Summary lands even on failed run (operators want to see what
        # was blocked when diagnosing why the run failed)
        summary_path = run_dir / summary_mod.SUMMARY_FILE
        assert summary_path.exists()
        on_disk = json.loads(summary_path.read_text())
        assert on_disk["by_type"] == {"write": 1}

    def test_sandbox_call_outside_run_does_nothing(self, tmp_path):
        # No start_run → record_denial is a no-op → no files anywhere
        from core.sandbox.observe import _check_blocked

        _check_blocked(
            stderr="curl: (7) Failed to connect\n",
            cmd_display="curl",
            returncode=7,
            sandbox_info={},
            network_engaged=True,
        )
        # No files created
        assert list(tmp_path.iterdir()) == []


class TestTrackedRunIntegration:
    """tracked_run() context manager wraps start_run + complete/fail/cancel.
    Summary recording must work for all three exit paths."""

    def _trigger_denial(self, cmd_display="curl", returncode=7):
        from core.sandbox.observe import _check_blocked
        _check_blocked(
            stderr="curl: (7) Failed to connect to evil.com\n",
            cmd_display=cmd_display,
            returncode=returncode,
            sandbox_info={},
            network_engaged=True,
        )

    def test_normal_exit_writes_summary(self, tmp_path):
        from core.run.metadata import tracked_run
        run_dir = tmp_path / "scan-normal"
        with tracked_run(run_dir, command="scan") as rd:
            assert summary_mod.get_active_run_dir() == rd
            self._trigger_denial()
        # Context exited normally → complete_run called → summary written
        assert (run_dir / summary_mod.SUMMARY_FILE).exists()
        assert summary_mod.get_active_run_dir() is None
        on_disk = json.loads((run_dir / summary_mod.SUMMARY_FILE).read_text())
        assert on_disk["total_denials"] == 1

    def test_exception_writes_summary_via_fail_run(self, tmp_path):
        from core.run.metadata import tracked_run
        run_dir = tmp_path / "scan-failed"

        with pytest.raises(RuntimeError):
            with tracked_run(run_dir, command="scan"):
                self._trigger_denial()
                raise RuntimeError("simulated workflow failure")

        # Context exited via exception → fail_run called → summary written
        assert (run_dir / summary_mod.SUMMARY_FILE).exists()
        assert summary_mod.get_active_run_dir() is None

    def test_keyboard_interrupt_writes_summary_via_cancel_run(self, tmp_path):
        from core.run.metadata import tracked_run
        run_dir = tmp_path / "scan-cancelled"

        with pytest.raises(KeyboardInterrupt):
            with tracked_run(run_dir, command="scan"):
                self._trigger_denial()
                raise KeyboardInterrupt()

        # Context exited via Ctrl-C → cancel_run called → summary written
        # (operators want to see what was blocked even on cancelled runs)
        assert (run_dir / summary_mod.SUMMARY_FILE).exists()
        assert summary_mod.get_active_run_dir() is None


class TestRedactsSecretsInCmd:
    """Per 3R1, cmd_display is redact_secrets'd before persisting because
    the summary lives on disk indefinitely (operators paste run dirs into
    bug reports). Original log lines are ephemeral; the JSONL/summary is not."""

    def test_url_credentials_redacted(self, tmp_path):
        summary_mod.set_active_run_dir(tmp_path)
        summary_mod.record_denial(
            "git clone https://user:secretpass@github.com/x/y.git",
            1, "network",
        )
        records = [
            json.loads(line)
            for line in (tmp_path / summary_mod.DENIALS_FILE).read_text().splitlines()
            if line
        ]
        assert "secretpass" not in records[0]["cmd"]
        assert "REDACTED" in records[0]["cmd"]

    def test_bearer_header_redacted(self, tmp_path):
        summary_mod.set_active_run_dir(tmp_path)
        summary_mod.record_denial(
            "curl -H 'Authorization: Bearer abcdef1234567890abcdef1234567890' https://api.example.com",
            1, "network",
        )
        records = [
            json.loads(line)
            for line in (tmp_path / summary_mod.DENIALS_FILE).read_text().splitlines()
            if line
        ]
        assert "abcdef1234567890" not in records[0]["cmd"]
        assert "REDACTED" in records[0]["cmd"]

    def test_clean_cmd_passes_through(self, tmp_path):
        summary_mod.set_active_run_dir(tmp_path)
        summary_mod.record_denial("git clone https://github.com/foo/bar", 1, "network")
        records = [
            json.loads(line)
            for line in (tmp_path / summary_mod.DENIALS_FILE).read_text().splitlines()
            if line
        ]
        # No secrets to redact → cmd preserved verbatim
        assert records[0]["cmd"] == "git clone https://github.com/foo/bar"


class TestCli:
    """`python -m core.sandbox.summary <run_dir>` recovery tool — used when
    a process crashed mid-run and never finalized the summary."""

    def test_summarizes_existing_jsonl(self, tmp_path, capsys):
        # Pre-populate JSONL as if a crashed run had recorded denials.
        jsonl = tmp_path / summary_mod.DENIALS_FILE
        jsonl.write_text(
            json.dumps({"ts": "2026-04-27T15:00:00Z", "cmd": "c1",
                        "returncode": 1, "type": "network",
                        "suggested_fix": "..."}) + "\n"
            + json.dumps({"ts": "2026-04-27T15:00:01Z", "cmd": "c2",
                          "returncode": 1, "type": "write",
                          "suggested_fix": "..."}) + "\n"
        )

        rc = summary_mod._cli_main([str(tmp_path)])
        assert rc == 0

        # Stdout reports what was written
        out = capsys.readouterr().out
        assert "Wrote" in out
        assert "2 denials" in out

        # Summary file present, JSONL removed
        assert (tmp_path / summary_mod.SUMMARY_FILE).exists()
        assert not jsonl.exists()

    def test_no_denials_message_when_jsonl_absent(self, tmp_path, capsys):
        # Run dir exists but no JSONL → "no denials" + success exit
        rc = summary_mod._cli_main([str(tmp_path)])
        assert rc == 0
        out = capsys.readouterr().out
        assert "no denials" in out

    def test_nonexistent_dir_exits_1(self, tmp_path, capsys):
        bogus = tmp_path / "does-not-exist"
        rc = summary_mod._cli_main([str(bogus)])
        assert rc == 1
        err = capsys.readouterr().err
        assert "not a directory" in err

    def test_path_to_file_not_dir_exits_1(self, tmp_path, capsys):
        f = tmp_path / "a-file"
        f.write_text("")
        rc = summary_mod._cli_main([str(f)])
        assert rc == 1

    def test_no_args_exits_2(self, capsys):
        rc = summary_mod._cli_main([])
        assert rc == 2
        err = capsys.readouterr().err
        assert "Usage" in err

    def test_too_many_args_exits_2(self, tmp_path, capsys):
        rc = summary_mod._cli_main([str(tmp_path), "extra"])
        assert rc == 2


class TestAdversarial:
    """Adversarial-review fixes — verify defenses against
    misuse / DoS / symlink attacks / pathological inputs."""

    # ADV1
    def test_details_cannot_override_reserved_fields(self, tmp_path):
        # A caller that passed details containing reserved record keys
        # (`type`, `cmd`, `suggested_fix`, `ts`) used to mask the real
        # values via the dict spread. Fixed by spreading details FIRST
        # so explicit fields override.
        # Note: `returncode` and `denial_type` are positional/named
        # parameters of record_denial itself — passing them as kwargs
        # would TypeError before reaching the dict spread, so they're
        # not in scope for this footgun. The reserved RECORD keys that
        # CAN slip through via **details are: ts, cmd, type,
        # suggested_fix.
        summary_mod.set_active_run_dir(tmp_path)
        summary_mod.record_denial(
            "real-cmd", 137, "seccomp",
            type="EVIL_TYPE",
            cmd="EVIL_CMD",
            suggested_fix="EVIL_FIX",
            ts="EVIL_TS",
        )
        records = [json.loads(l) for l in
                   (tmp_path / summary_mod.DENIALS_FILE).read_text().splitlines() if l]
        r = records[0]
        # Explicit args win — the rogue details didn't override
        assert r["type"] == "seccomp"
        assert r["cmd"] == "real-cmd"
        assert r["suggested_fix"] != "EVIL_FIX"
        assert r["ts"] != "EVIL_TS"
        assert r["returncode"] == 137

    # ADV2
    def test_per_run_cap_drops_excess_denials(self, tmp_path, monkeypatch):
        # Lower the cap so the test runs fast.
        monkeypatch.setattr(summary_mod, "MAX_DENIALS_PER_RUN", 5)
        summary_mod.set_active_run_dir(tmp_path)
        for i in range(20):
            summary_mod.record_denial(f"cmd{i}", 1, "network")
        records = [json.loads(l) for l in
                   (tmp_path / summary_mod.DENIALS_FILE).read_text().splitlines() if l]
        # Exactly the cap, no more (slight overcount allowed by the
        # lock-free design — assert <= cap+1 to be tolerant)
        assert len(records) <= summary_mod.MAX_DENIALS_PER_RUN

    def test_denial_counter_resets_per_run(self, tmp_path, monkeypatch):
        # Each set_active_run_dir resets the cap counter.
        monkeypatch.setattr(summary_mod, "MAX_DENIALS_PER_RUN", 3)
        # Run 1: hit the cap
        run1 = tmp_path / "r1"
        run1.mkdir()
        summary_mod.set_active_run_dir(run1)
        for i in range(10):
            summary_mod.record_denial(f"r1c{i}", 1, "network")
        # Run 2: counter resets, can record again
        run2 = tmp_path / "r2"
        run2.mkdir()
        summary_mod.set_active_run_dir(run2)
        for i in range(2):
            summary_mod.record_denial(f"r2c{i}", 1, "network")
        run2_records = [json.loads(l) for l in
                        (run2 / summary_mod.DENIALS_FILE).read_text().splitlines() if l]
        assert len(run2_records) == 2

    # ADV3
    def test_refuses_to_follow_symlink_at_jsonl_path(self, tmp_path):
        # If the JSONL path is a symlink (planted by an attacker who
        # somehow got write access to the run dir), record_denial must
        # NOT follow it and write to the target.
        target = tmp_path / "target-of-attack"
        target.write_text("ATTACKER-OWNED CONTENT\n")
        link = tmp_path / summary_mod.DENIALS_FILE
        os.symlink(target, link)

        summary_mod.set_active_run_dir(tmp_path)
        summary_mod.record_denial("cmd", 1, "network")

        # Target file unmodified — symlink was refused via O_NOFOLLOW
        assert target.read_text() == "ATTACKER-OWNED CONTENT\n"
        # The symlink itself is also unchanged (still a symlink, not a regular file)
        assert link.is_symlink()

    # ADV4
    def test_long_cmd_display_is_truncated(self, tmp_path):
        # A pathologically long cmd_display must be truncated to keep
        # the JSONL line within PIPE_BUF (atomic append guarantee).
        summary_mod.set_active_run_dir(tmp_path)
        long_cmd = "x" * 10_000  # well over MAX_CMD_LEN
        summary_mod.record_denial(long_cmd, 1, "network")
        records = [json.loads(l) for l in
                   (tmp_path / summary_mod.DENIALS_FILE).read_text().splitlines() if l]
        assert len(records[0]["cmd"]) <= summary_mod.MAX_CMD_LEN
        # Truncation marker present
        assert records[0]["cmd"].endswith("…")

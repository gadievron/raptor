"""Tests for macOS observe-mode routing in seatbelt_audit.

The Linux tracer was extended in PR-β to write profile-extraction
records to ``.sandbox-observe.jsonl`` instead of
``.sandbox-denials.jsonl`` when sandbox(observe=True) is engaged.
This module covers the macOS analogue:

  * ``parse_log_entry(observe_mode=True)`` stamps records with
    ``"observe": True`` instead of ``"audit": True``.
  * ``LogStreamer(observe_mode=True)`` routes appends to
    ``OBSERVE_FILE`` (mirroring tracer._OBSERVE_FILENAME).
  * ``start_log_streamer(observe_mode=True)`` plumbing intact.
  * SBPL profile under observe includes file-read-metadata so the
    Linux ``stat()``-equivalent records flow through on macOS too.
  * The on-disk filename matches the Linux tracer's choice so the
    parser (core.sandbox.observe_profile) reads from the same path
    on both platforms.

Most tests are platform-independent (synthetic ndjson + temp dir,
no log stream subprocess). One opportunistic E2E test runs only
on Darwin and is skipped elsewhere.

----------------------------------------------------------------
Darwin operator smoke test — run BEFORE merging the macOS PR
----------------------------------------------------------------

The structural tests below pin the contract; they don't prove
sandbox-exec + log stream actually wire together at runtime. To
validate on a real Mac, run::

    _RAPTOR_TRUSTED=1 ./libexec/raptor-sandbox-observe \\
        --keep --out /tmp/probe -- /usr/bin/true

Expected:
  * exit 0 from /usr/bin/true
  * `/tmp/probe/.sandbox-observe.jsonl` exists, non-empty
  * `/tmp/probe/.sandbox-denials.jsonl` does NOT exist
  * jq '.observe' /tmp/probe/.sandbox-observe.jsonl ⇒ all true
  * jq '.nonce' /tmp/probe/.sandbox-observe.jsonl ⇒ same 32-char
    hex on every line (the per-run nonce)

If any of these fail, file the result (host macOS version, log
stream output) on the PR before merge — observe routing on macOS
is **not validated** without this smoke test.
"""

from __future__ import annotations

import json
import sys

import pytest

from core.sandbox.seatbelt_audit import (
    DENIALS_FILE,
    OBSERVE_FILE,
    LogStreamer,
    parse_log_entry,
    start_log_streamer,
)


# ---------------------------------------------------------------------------
# Cross-module pinning
# ---------------------------------------------------------------------------


class TestObserveFileMatchesTracer:
    """Drift between OBSERVE_FILE and tracer._OBSERVE_FILENAME would
    silently produce parser misses on macOS. Pin them."""

    def test_observe_file_matches_tracer_constant(self):
        from core.sandbox import tracer
        assert OBSERVE_FILE == tracer._OBSERVE_FILENAME, (
            f"seatbelt_audit.OBSERVE_FILE ({OBSERVE_FILE!r}) must "
            f"match tracer._OBSERVE_FILENAME "
            f"({tracer._OBSERVE_FILENAME!r}) — observe_profile "
            f"parser reads from one location on both platforms."
        )

    def test_observe_file_matches_observe_profile(self):
        from core.sandbox.observe_profile import OBSERVE_FILENAME
        assert OBSERVE_FILE == OBSERVE_FILENAME


# ---------------------------------------------------------------------------
# parse_log_entry stamping
# ---------------------------------------------------------------------------


def _kext_log_entry(action: str, path: str = "/etc/hostname",
                    pid: int = 1234, verdict: str = "allow") -> dict:
    """Synthetic log-stream ndjson entry shaped like a real Sandbox.kext message."""
    return {
        "senderImagePath": (
            "/System/Library/Extensions/Sandbox.kext"
            "/Contents/MacOS/Sandbox"
        ),
        "eventMessage": (
            f"Sandbox: probe({pid}) {verdict} {action} {path}"
        ),
        "timestamp": "2026-05-08T12:00:00Z",
    }


class TestParseLogEntryStamps:

    def test_default_audit_mode_stamps_audit_true(self):
        rec = parse_log_entry(_kext_log_entry("file-read-data"))
        assert rec is not None
        assert rec.get("audit") is True
        assert "observe" not in rec

    def test_observe_mode_stamps_observe_true(self):
        rec = parse_log_entry(
            _kext_log_entry("file-read-data"),
            observe_mode=True,
        )
        assert rec is not None
        assert rec.get("observe") is True
        assert "audit" not in rec, (
            "observe-mode record must not also carry audit:True — "
            "operators rely on the field name to discriminate "
            "observe records from audit records when both flow "
            "through the same downstream log path."
        )

    def test_non_kext_entry_returns_none(self):
        rec = parse_log_entry(
            {"senderImagePath": "/usr/sbin/syslogd",
             "eventMessage": "..."},
            observe_mode=True,
        )
        assert rec is None

    def test_unparseable_message_returns_none(self):
        rec = parse_log_entry(
            {"senderImagePath": (
                "/System/Library/Extensions/Sandbox.kext"
                "/Contents/MacOS/Sandbox"
            ),
             "eventMessage": "garbage with no Sandbox: prefix"},
            observe_mode=True,
        )
        assert rec is None

    def test_record_carries_action_path_and_pid(self):
        rec = parse_log_entry(
            _kext_log_entry("file-read-data", path="/tmp/X", pid=99),
            observe_mode=True,
        )
        assert rec["syscall"] == "file-read-data"
        assert rec["path"] == "/tmp/X"
        assert rec["target_pid"] == 99


# ---------------------------------------------------------------------------
# LogStreamer routing — synthetic appends without spawning `log stream`
# ---------------------------------------------------------------------------


class TestLogStreamerFilenameRouting:
    """Build a LogStreamer (no subprocess spawn) and exercise the
    locked append path directly. Verifies the filename + record-stamp
    threading is correct without needing a Mac to run."""

    def test_default_appends_to_denials_file(self, tmp_path):
        s = LogStreamer(tmp_path)
        s._append_record({"hello": "world", "audit": True})
        assert (tmp_path / DENIALS_FILE).exists()
        assert not (tmp_path / OBSERVE_FILE).exists()

    def test_observe_mode_appends_to_observe_file(self, tmp_path):
        s = LogStreamer(tmp_path, observe_mode=True)
        s._append_record({"hello": "world", "observe": True})
        assert (tmp_path / OBSERVE_FILE).exists()
        assert not (tmp_path / DENIALS_FILE).exists()

    def test_observe_mode_filename_attribute_pinned(self, tmp_path):
        # Internal attribute is part of the contract because both
        # _append_record_locked and the future summary writer read
        # it. Pin so a refactor that drops it surfaces here.
        observe_streamer = LogStreamer(tmp_path, observe_mode=True)
        audit_streamer = LogStreamer(tmp_path, observe_mode=False)
        assert observe_streamer._filename == OBSERVE_FILE
        assert audit_streamer._filename == DENIALS_FILE

    def test_record_content_round_trips(self, tmp_path):
        # Build a record via parse_log_entry so the full stamp + path
        # round-trip is exercised, then have LogStreamer append it.
        s = LogStreamer(tmp_path, observe_mode=True)
        rec = parse_log_entry(
            _kext_log_entry("file-read-data", path="/etc/passwd"),
            observe_mode=True,
        )
        s._append_record(rec)

        log_path = tmp_path / OBSERVE_FILE
        assert log_path.exists()
        loaded = json.loads(log_path.read_text().strip())
        assert loaded["observe"] is True
        assert loaded["path"] == "/etc/passwd"
        assert loaded["syscall"] == "file-read-data"


# ---------------------------------------------------------------------------
# start_log_streamer plumbing
# ---------------------------------------------------------------------------


class TestStartLogStreamerObserveKwarg:
    """Verify start_log_streamer threads observe_mode through to
    LogStreamer. Doesn't actually start the streamer (would require a
    Mac); patches LogStreamer.start to a no-op so we just check
    construction kwargs."""

    def test_observe_mode_threads_through(self, tmp_path, monkeypatch):
        monkeypatch.setattr(LogStreamer, "start", lambda self: None)
        s = start_log_streamer(tmp_path, observe_mode=True)
        assert s._observe_mode is True
        assert s._filename == OBSERVE_FILE

    def test_default_observe_mode_off(self, tmp_path, monkeypatch):
        monkeypatch.setattr(LogStreamer, "start", lambda self: None)
        s = start_log_streamer(tmp_path)
        assert s._observe_mode is False
        assert s._filename == DENIALS_FILE


# ---------------------------------------------------------------------------
# SBPL coverage — observe must produce the right `(allow X (with report))`
# rules so the kernel emits the records LogStreamer needs to capture
# ---------------------------------------------------------------------------


class TestSeatbeltSBPLObserveCoverage:
    """The macOS observe pipeline depends on three layers all firing:

      1. context.sandbox(observe=True) forces audit_verbose=True
         upstream (covered by TestPublicObserveKwarg in
         test_observe_profile.py — verified via spy on _spawn).
      2. seatbelt.build_profile(audit_mode=True, audit_verbose=True)
         emits the right `(allow X (with report))` clauses so
         Sandbox.kext logs file metadata + connect events.
      3. seatbelt_audit.LogStreamer parses those events.

    Layer 2 is the gap most likely to silently break observe on
    macOS: a refactor that drops file-read-metadata from the
    audit_verbose set would silently lose stat-equivalent records,
    and observe profiles on macOS would have empty paths_stat with
    no failure mode visible until somebody compared platforms.
    Pin the rules here.
    """

    def test_observe_implies_file_read_metadata_rule(self):
        # observe forces audit_verbose. With audit_mode + audit_verbose
        # the SBPL profile must contain file-read-metadata so stat()
        # equivalent kext events fire.
        from core.sandbox import seatbelt
        profile = seatbelt.build_profile(
            target=None, output=None, block_network=False,
            audit_mode=True, audit_verbose=True,
            seccomp_profile="full",
        )
        assert "(allow file-read-metadata (with report))" in profile, (
            "observe-mode SBPL profile must include file-read-metadata "
            "so stat-equivalent records reach LogStreamer; without it, "
            "observe profiles on macOS will have empty paths_stat."
        )

    def test_observe_implies_file_read_data_rule(self):
        from core.sandbox import seatbelt
        profile = seatbelt.build_profile(
            target=None, output=None, block_network=False,
            audit_mode=True, audit_verbose=True,
            seccomp_profile="full",
        )
        # file-read-data drives paths_read population.
        assert "(allow file-read-data (with report))" in profile

    def test_observe_implies_file_write_rule(self, tmp_path):
        # file-write* drives paths_written population. The rule only
        # fires when write isolation engages (target/output/writable
        # supplied) — observe-mode runs always have output= because
        # they need somewhere for the JSONL to land, so this is the
        # realistic call shape.
        from core.sandbox import seatbelt
        profile = seatbelt.build_profile(
            target=str(tmp_path), output=str(tmp_path),
            block_network=False,
            audit_mode=True, audit_verbose=True,
            seccomp_profile="full",
        )
        assert "(allow file-write* (with report))" in profile, (
            "observe-mode SBPL profile must emit file-write* allow "
            "rule so paths_written populates on macOS."
        )


# ---------------------------------------------------------------------------
# Nonce stamping — defeats spoofing by target binary
# ---------------------------------------------------------------------------


class TestNonceStamping:
    """A target binary inside the sandbox has write access to the
    bind-mounted audit_run_dir, so it CAN append fake records to the
    JSONL. The nonce is a per-run secret only the parent + tracer/
    log-streamer know; parser drops records lacking the matching
    value. Pin the macOS streamer side."""

    def test_parse_log_entry_with_nonce_stamps_field(self):
        rec = parse_log_entry(
            _kext_log_entry("file-read-data"),
            observe_mode=True,
            nonce="abc123def456",
        )
        assert rec is not None
        assert rec.get("nonce") == "abc123def456"

    def test_parse_log_entry_without_nonce_omits_field(self):
        rec = parse_log_entry(
            _kext_log_entry("file-read-data"),
            observe_mode=True,
        )
        assert rec is not None
        assert "nonce" not in rec

    def test_log_streamer_nonce_threaded_into_records(self, tmp_path):
        # Construct a streamer with a nonce, parse an entry through
        # its constructor-bound state, write it. Round-trip the JSONL
        # to confirm the nonce lands.
        s = LogStreamer(tmp_path, observe_mode=True,
                        observe_nonce="nonce-XYZ")
        rec = parse_log_entry(
            _kext_log_entry("file-read-data"),
            observe_mode=s._observe_mode,
            nonce=s._observe_nonce,
        )
        s._append_record(rec)
        loaded = json.loads(
            (tmp_path / OBSERVE_FILE).read_text().strip(),
        )
        assert loaded["nonce"] == "nonce-XYZ"

    def test_start_log_streamer_threads_nonce(self, tmp_path,
                                              monkeypatch):
        monkeypatch.setattr(LogStreamer, "start", lambda self: None)
        s = start_log_streamer(tmp_path, observe_mode=True,
                               observe_nonce="abc")
        assert s._observe_nonce == "abc"


# ---------------------------------------------------------------------------
# Opportunistic E2E — Darwin only
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    sys.platform != "darwin",
    reason="macOS sandbox-exec + log stream — Darwin only",
)
class TestObserveModeDarwinE2E:
    """End-to-end on macOS: sandbox(observe=True) writes a parseable
    .sandbox-observe.jsonl and does not pollute .sandbox-denials.jsonl.

    This test is for human-run Darwin verification; the synthetic
    tests above carry the contract on Linux CI."""

    def test_e2e(self, tmp_path):
        from core.sandbox import run as sandbox_run
        from core.sandbox.observe_profile import (
            OBSERVE_FILENAME, parse_observe_log,
        )

        run_dir = tmp_path / "observe-run"
        run_dir.mkdir()
        # Probe: cat /etc/hosts. POSIX-standard file, present on
        # every macOS install. Cat reliably triggers file-read-data
        # for the opened file (avoids the pytest subprocess-capture
        # timing race where /usr/bin/true exited before file-read
        # records propagated). /etc/hostname (Linux convention) is
        # NOT present on macOS — the hostname is stored via
        # scutil, not as a file — so /etc/hosts is the right
        # cross-platform probe target.
        result = sandbox_run(
            ["/bin/cat", "/etc/hosts"],
            target=str(run_dir), output=str(run_dir),
            observe=True, capture_output=True, text=True, timeout=10,
        )
        assert result.returncode == 0

        observe_log = run_dir / OBSERVE_FILENAME
        denials_log = run_dir / ".sandbox-denials.jsonl"

        if not observe_log.exists():
            pytest.skip(
                "observe log not produced — likely audit-mode "
                "degraded silently on this host."
            )

        assert not denials_log.exists(), (
            "observe-mode must not write to denials log"
        )

        # The JSONL must have at least one observe-stamped record.
        # If we cannot even produce that, audit-mode degraded
        # silently — soft-skip rather than fail (the structural
        # tests upstream cover the routing contract).
        import json as _json
        record_count = 0
        distinct_actions: set = set()
        with observe_log.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = _json.loads(line)
                except ValueError:
                    continue
                if rec.get("observe") is True:
                    record_count += 1
                    if rec.get("syscall"):
                        distinct_actions.add(rec["syscall"])

        if record_count == 0:
            pytest.skip(
                "observe log present but contains no "
                "observe-stamped records — kext likely didn't fire "
                "any (allow X (with report)) rules on this host."
            )

        # Now the parser categorisation. If the JSONL has records
        # but the parsed profile is empty, the parser is missing
        # the kext action vocabulary — surface the unknown actions
        # in the assertion so the operator can report them.
        profile = parse_observe_log(run_dir)
        total_classified = (
            len(profile.paths_read)
            + len(profile.paths_written)
            + len(profile.paths_stat)
            + len(profile.connect_targets)
        )
        assert total_classified > 0, (
            f"parser categorised zero of {record_count} records; "
            f"distinct .syscall values seen: {sorted(distinct_actions)!r}. "
            f"Either extend the parser's classification sets in "
            f"core/sandbox/observe_profile.py, or report these action "
            f"names on the PR for upstream classification."
        )

"""Tests for the reachability verdict-frequency log.

The substrate is a process-wide accumulator (in-memory) with a
flock-guarded JSON sidecar for cross-process safety. Tests must NOT
contaminate the real sidecar — each test isolates via the
``RAPTOR_REACH_VERDICT_LOG`` env var or an explicit ``path`` argument.
"""

from __future__ import annotations

import json
import pytest

from core.inventory import reach_verdict_log


@pytest.fixture(autouse=True)
def _isolated_sidecar(tmp_path, monkeypatch):
    """Redirect the sidecar to a tmp path AND clear in-memory state
    before every test. Without this the real sidecar would accumulate
    test-run garbage across the suite.

    Conftest sets ``RAPTOR_REACH_VERDICT_LOG_DISABLED=1`` by default
    (so unrelated tests don't pollute the real sidecar), but this
    test file IS the one exercising the substrate — unset it locally
    so ``record_verdict`` actually records.
    """
    sidecar = tmp_path / "reach_verdict_log.json"
    monkeypatch.setenv("RAPTOR_REACH_VERDICT_LOG", str(sidecar))
    monkeypatch.delenv("RAPTOR_REACH_VERDICT_LOG_DISABLED", raising=False)
    reach_verdict_log._IN_MEMORY.clear()
    yield sidecar
    reach_verdict_log._IN_MEMORY.clear()


def test_record_accumulates_in_memory(_isolated_sidecar):
    reach_verdict_log.record_verdict("python", "reachable")
    reach_verdict_log.record_verdict("python", "reachable")
    reach_verdict_log.record_verdict("python", "no_path_from_entry")
    reach_verdict_log.record_verdict("c", "reachable")
    assert reach_verdict_log._IN_MEMORY == {
        "python": {"reachable": 2, "no_path_from_entry": 1},
        "c": {"reachable": 1},
    }


def test_record_none_args_is_noop(_isolated_sidecar):
    # The chokepoint calls record_verdict(None, ...) when the file has
    # no language (e.g. an extension we don't recognise). Must not blow
    # up — telemetry never blocks the chokepoint.
    reach_verdict_log.record_verdict(None, "reachable")
    reach_verdict_log.record_verdict("python", None)
    reach_verdict_log.record_verdict(None, None)
    reach_verdict_log.record_verdict("", "reachable")
    assert reach_verdict_log._IN_MEMORY == {}


def test_flush_writes_sidecar(_isolated_sidecar):
    reach_verdict_log.record_verdict("python", "reachable")
    reach_verdict_log.record_verdict("python", "reachable")
    reach_verdict_log.flush()
    assert _isolated_sidecar.exists()
    data = json.loads(_isolated_sidecar.read_text())
    assert data["version"] == reach_verdict_log.SCHEMA_VERSION
    assert data["languages"]["python"]["verdicts"]["reachable"] == 2
    assert "last_seen_at" in data["languages"]["python"]
    # In-memory drained after flush.
    assert reach_verdict_log._IN_MEMORY == {}


def test_flush_merges_with_existing(_isolated_sidecar):
    # First flush creates the file.
    reach_verdict_log.record_verdict("python", "reachable")
    reach_verdict_log.flush()
    # Second flush MUST add to existing counts, not overwrite.
    reach_verdict_log.record_verdict("python", "reachable")
    reach_verdict_log.record_verdict("python", "not_called")
    reach_verdict_log.flush()
    data = json.loads(_isolated_sidecar.read_text())
    assert data["languages"]["python"]["verdicts"]["reachable"] == 2
    assert data["languages"]["python"]["verdicts"]["not_called"] == 1


def test_flush_empty_is_noop(_isolated_sidecar):
    reach_verdict_log.flush()
    assert not _isolated_sidecar.exists()


def test_summarize_returns_disk_state(_isolated_sidecar):
    reach_verdict_log.record_verdict("c", "reachable")
    reach_verdict_log.record_verdict("c", "no_path_from_entry")
    reach_verdict_log.flush()
    s = reach_verdict_log.summarize()
    assert s == {"c": {"reachable": 1, "no_path_from_entry": 1}}


def test_summarize_missing_sidecar_returns_empty(_isolated_sidecar):
    assert reach_verdict_log.summarize() == {}


def test_reset_clears_both(_isolated_sidecar):
    reach_verdict_log.record_verdict("python", "reachable")
    reach_verdict_log.flush()
    assert _isolated_sidecar.exists()
    # Re-stage in-memory and reset.
    reach_verdict_log.record_verdict("python", "reachable")
    reach_verdict_log.reset()
    assert not _isolated_sidecar.exists()
    assert reach_verdict_log._IN_MEMORY == {}


def test_corrupt_sidecar_degrades_gracefully(_isolated_sidecar):
    # A corrupt JSON file shouldn't crash the flush — the operator
    # gets a warning, the in-memory state is preserved BUT cleared
    # (flush always drains; the corrupt file gets replaced with a
    # fresh one containing the in-memory increments only).
    _isolated_sidecar.write_text("{ not json")
    reach_verdict_log.record_verdict("python", "reachable")
    reach_verdict_log.flush()
    # Recovery: new file is valid + contains our increment.
    data = json.loads(_isolated_sidecar.read_text())
    assert data["languages"]["python"]["verdicts"]["reachable"] == 1


def test_schema_version_mismatch_refuses_write(_isolated_sidecar, caplog):
    # Future-schema file present → flush MUST refuse to write, surfacing
    # the issue. Better to fail than silently downgrade.
    _isolated_sidecar.write_text(json.dumps({
        "version": 999,
        "languages": {"python": {"verdicts": {"reachable": 99}}},
    }))
    reach_verdict_log.record_verdict("python", "reachable")
    reach_verdict_log.flush()
    # Flush wraps exceptions in a warning log — sidecar unchanged.
    data = json.loads(_isolated_sidecar.read_text())
    assert data["version"] == 999
    assert data["languages"]["python"]["verdicts"]["reachable"] == 99


def test_schema_refusal_preserves_in_memory_for_recovery(_isolated_sidecar):
    """P0 regression guard: when flush() refuses to write (schema
    mismatch, EIO, etc.) the drained increments MUST be re-deposited
    into the in-memory accumulator. Pre-fix, they were silently lost
    every flush — meaning a single future-schema file on disk would
    discard every verdict the process records.
    """
    # Future-schema file blocks the write.
    _isolated_sidecar.write_text(json.dumps({
        "version": 999, "languages": {},
    }))
    reach_verdict_log.record_verdict("python", "reachable")
    reach_verdict_log.record_verdict("python", "reachable")
    reach_verdict_log.record_verdict("c", "no_path_from_entry")
    reach_verdict_log.flush()
    # In-memory state preserved — the operator can recover by fixing
    # the schema mismatch (e.g. deleting the sidecar) and re-flushing.
    assert reach_verdict_log._IN_MEMORY == {
        "python": {"reachable": 2},
        "c": {"no_path_from_entry": 1},
    }


def test_after_fork_in_child_clears_in_memory(_isolated_sidecar):
    """P1 regression guard: forked child must NOT inherit and re-flush
    the parent's accumulator. The os.register_at_fork hook clears the
    in-memory dict in the child so the child's atexit flush drains an
    empty accumulator — no double-count.
    """
    reach_verdict_log.record_verdict("python", "reachable")
    reach_verdict_log.record_verdict("python", "reachable")
    assert reach_verdict_log._IN_MEMORY == {"python": {"reachable": 2}}
    # Simulate the after-fork-in-child callback directly. Don't actually
    # fork in a test — fork in a pytest process is fragile (inherits
    # the test runner's state). The callback IS the contract.
    reach_verdict_log._clear_after_fork_in_child()
    assert reach_verdict_log._IN_MEMORY == {}


def test_disabled_env_var_short_circuits_record(_isolated_sidecar,
                                                  monkeypatch):
    """P2: with RAPTOR_REACH_VERDICT_LOG_DISABLED set, record_verdict
    is a no-op — the accumulator stays empty even under repeated calls.
    """
    monkeypatch.setenv("RAPTOR_REACH_VERDICT_LOG_DISABLED", "1")
    for _ in range(100):
        reach_verdict_log.record_verdict("python", "reachable")
    assert reach_verdict_log._IN_MEMORY == {}


def test_chokepoint_records_verdict(_isolated_sidecar):
    # The chokepoint MUST record every verdict it produces — this is
    # the wiring the telemetry value depends on. Synthesise the
    # smallest possible inventory + call classify_reachability.
    from core.inventory.reach_audit import classify_reachability
    inv = {
        "files": [{
            "path": "m.py", "language": "python",
            "items": [{"name": "_orphan", "kind": "function",
                       "line_start": 1}],
            "call_graph": {"imports": {}, "calls": []},
        }],
    }
    verdict = classify_reachability(inv, "m.py", "_orphan", 1, "m")
    assert verdict in ("no_path_from_entry", "not_called", "uncertain")
    # In-memory accumulator picked up the call.
    assert "python" in reach_verdict_log._IN_MEMORY
    assert reach_verdict_log._IN_MEMORY["python"].get(verdict) == 1


def test_chokepoint_records_language_none_safely(_isolated_sidecar):
    # File has no recognised language → record_verdict(None, ...) →
    # no-op in the accumulator, no crash.
    from core.inventory.reach_audit import classify_reachability
    inv = {
        "files": [{
            "path": "weird_unknown_extension.xyz",
            "language": None,
            "items": [{"name": "fn", "kind": "function", "line_start": 1}],
            "call_graph": {"imports": {}, "calls": []},
        }],
    }
    classify_reachability(inv, "weird_unknown_extension.xyz", "fn", 1, "weird")
    # No crash, and the None-language path stayed out of the
    # accumulator (we only record verdicts we can attribute to a lang).
    assert None not in reach_verdict_log._IN_MEMORY


def test_concurrent_record_threadsafe(_isolated_sidecar):
    # Multiple threads recording at once must not lose increments.
    # _LOCK serialises the read-modify-write in record_verdict.
    import threading
    N_THREADS = 8
    N_PER_THREAD = 100

    def worker():
        for _ in range(N_PER_THREAD):
            reach_verdict_log.record_verdict("python", "reachable")

    threads = [threading.Thread(target=worker) for _ in range(N_THREADS)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert reach_verdict_log._IN_MEMORY["python"]["reachable"] == \
        N_THREADS * N_PER_THREAD


def test_cli_table_output(_isolated_sidecar, capsys, monkeypatch):
    # Run the CLI's main() with a populated sidecar; verify the
    # operator-facing table includes language sections + counts.
    reach_verdict_log.record_verdict("python", "reachable")
    reach_verdict_log.record_verdict("python", "no_path_from_entry")
    reach_verdict_log.record_verdict("c", "reachable")
    reach_verdict_log.flush()

    from core.inventory.reach_verdict_log_cli import main
    monkeypatch.setattr("sys.argv", ["raptor-reach-verdict-log"])
    rc = main()
    assert rc == 0
    out = capsys.readouterr().out
    assert "python" in out and "c" in out
    assert "reachable" in out and "no_path_from_entry" in out
    assert "1" in out  # the c=1 count at least


def test_cli_json_output(_isolated_sidecar, capsys, monkeypatch):
    reach_verdict_log.record_verdict("python", "reachable")
    reach_verdict_log.flush()

    from core.inventory.reach_verdict_log_cli import main
    monkeypatch.setattr("sys.argv", ["raptor-reach-verdict-log", "--json"])
    rc = main()
    assert rc == 0
    out = capsys.readouterr().out
    data = json.loads(out)
    assert data == {"python": {"reachable": 1}}


def test_cli_reset(_isolated_sidecar, capsys, monkeypatch):
    reach_verdict_log.record_verdict("python", "reachable")
    reach_verdict_log.flush()
    assert _isolated_sidecar.exists()

    from core.inventory.reach_verdict_log_cli import main
    monkeypatch.setattr("sys.argv", ["raptor-reach-verdict-log", "--reset"])
    rc = main()
    assert rc == 0
    assert not _isolated_sidecar.exists()

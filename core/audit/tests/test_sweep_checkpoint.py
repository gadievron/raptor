"""Durable sweep checkpoint: cross-segment replay, content-keyed
invalidation, the corrupt-trail fail-open direction (recompute, never
skip), record/trail byte bounds in both directions, concurrent
writers, and the dispatch-seam integration in
``orchestrator._memoized_sweep_step``. Hermetic — no spatch, no LLM."""

from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
import textwrap
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

import core.audit.sweep_checkpoint as sc
from core.audit.orchestrator import _memoized_sweep_step
from core.audit.sweep import SweepResult
from core.audit.sweep_checkpoint import (
    CHECKPOINT_FILENAME,
    CHECKPOINT_VERSION,
    SweepCheckpoint,
    checkpoint_for_run,
    reset_checkpoint_registry,
    tool_checkpointable,
)
from core.audit.sweep_memo import SweepMemo


@pytest.fixture(autouse=True)
def _fresh_registry():
    reset_checkpoint_registry()
    yield
    reset_checkpoint_registry()


def _key(rule: str = "aaa", file: str = "bbb",
         path: str = "src/x.c") -> tuple:
    key = SweepMemo.make_key(
        "coccinelle",
        {"rule": rule, "file": file, "path": path, "defines": ""},
    )
    assert key is not None
    return key


def _result(outcome: str = "refuted", **kw) -> SweepResult:
    defaults: dict = dict(
        tool="coccinelle", file_path="src/x.c", function_name="",
        outcome=outcome, matches=[], errors=[],
        rule_id="rules/check.cocci",
    )
    defaults.update(kw)
    return SweepResult(**defaults)


def test_roundtrip_replays_on_fresh_instance(tmp_path: Path) -> None:
    cp = SweepCheckpoint(tmp_path)
    result = _result(
        "confirmed", matches=[{"line": 3, "text": "memcpy"}],
        details={"note": "x"},
    )
    cp.record(_key(), result)
    assert cp.recorded == 1

    resumed = SweepCheckpoint(tmp_path)
    replayed = resumed.lookup(_key())
    assert replayed is not None
    assert replayed.outcome == "confirmed"
    assert replayed.matches == [{"line": 3, "text": "memcpy"}]
    assert replayed.rule_id == "rules/check.cocci"
    assert replayed.details == {"note": "x"}
    assert resumed.replayed == 1


def test_lookup_returns_independent_copies(tmp_path: Path) -> None:
    cp = SweepCheckpoint(tmp_path)
    cp.record(_key(), _result("confirmed", matches=[{"line": 1}]))
    resumed = SweepCheckpoint(tmp_path)
    first = resumed.lookup(_key())
    assert first is not None
    first.matches.append({"line": 99})
    second = resumed.lookup(_key())
    assert second is not None
    assert second.matches == [{"line": 1}]


def test_changed_rule_or_file_digest_misses(tmp_path: Path) -> None:
    cp = SweepCheckpoint(tmp_path)
    cp.record(_key(rule="r1", file="f1"), _result())
    resumed = SweepCheckpoint(tmp_path)
    assert resumed.lookup(_key(rule="r2", file="f1")) is None
    assert resumed.lookup(_key(rule="r1", file="f2")) is None
    assert resumed.lookup(_key(rule="r1", file="f1")) is not None


def test_error_and_negative_control_results_never_persist(
    tmp_path: Path,
) -> None:
    cp = SweepCheckpoint(tmp_path)
    cp.record(_key(rule="e"), _result("error", errors=["spatch died"]))
    cp.record(
        _key(rule="nc"),
        _result("confirmed", details={"negative_control_error": True}),
    )
    assert cp.recorded == 0
    assert not (tmp_path / CHECKPOINT_FILENAME).exists()


def test_non_checkpointable_tool_never_persists(tmp_path: Path) -> None:
    assert not tool_checkpointable("semgrep")
    cp = SweepCheckpoint(tmp_path)
    key = SweepMemo.make_key("semgrep", {"rule": "a", "file": "b"})
    assert key is not None
    cp.record(key, _result(tool="semgrep"))
    assert cp.recorded == 0
    assert not (tmp_path / CHECKPOINT_FILENAME).exists()


def test_duplicate_keys_append_once(tmp_path: Path) -> None:
    cp = SweepCheckpoint(tmp_path)
    cp.record(_key(), _result())
    cp.record(_key(), _result())
    lines = (tmp_path / CHECKPOINT_FILENAME).read_text().splitlines()
    assert len(lines) == 1
    # ... and a resumed segment does not re-append what it replayed.
    resumed = SweepCheckpoint(tmp_path)
    resumed.record(_key(), _result())
    lines = (tmp_path / CHECKPOINT_FILENAME).read_text().splitlines()
    assert len(lines) == 1


# ── corruption: fail-open to recompute, never to skip ────────────────


def _assert_invalidated(
    tmp_path: Path, caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.WARNING, logger=sc.__name__):
        resumed = SweepCheckpoint(tmp_path)
    assert resumed.lookup(_key()) is None
    warnings = [
        r for r in caplog.records
        if "fail-open to recompute" in r.getMessage()
    ]
    assert len(warnings) == 1  # WARN once
    # The bad trail is rotated aside so the fresh segment starts clean.
    assert not (tmp_path / CHECKPOINT_FILENAME).exists()
    assert (tmp_path / (CHECKPOINT_FILENAME + ".corrupt")).exists()


def test_corrupt_line_invalidates_whole_trail(
    tmp_path: Path, caplog: pytest.LogCaptureFixture,
) -> None:
    SweepCheckpoint(tmp_path).record(_key(), _result())
    with (tmp_path / CHECKPOINT_FILENAME).open("a") as fh:
        fh.write("{not json\n")
    _assert_invalidated(tmp_path, caplog)


def test_version_mismatch_invalidates_whole_trail(
    tmp_path: Path, caplog: pytest.LogCaptureFixture,
) -> None:
    cp = SweepCheckpoint(tmp_path)
    cp.record(_key(), _result())
    trail = tmp_path / CHECKPOINT_FILENAME
    rec = json.loads(trail.read_text())
    rec["v"] = CHECKPOINT_VERSION + 1
    trail.write_text(json.dumps(rec) + "\n")
    _assert_invalidated(tmp_path, caplog)


def test_schema_invalid_outcome_invalidates(
    tmp_path: Path, caplog: pytest.LogCaptureFixture,
) -> None:
    cp = SweepCheckpoint(tmp_path)
    cp.record(_key(), _result())
    trail = tmp_path / CHECKPOINT_FILENAME
    rec = json.loads(trail.read_text())
    rec["result"]["outcome"] = "error"  # never a valid persisted state
    trail.write_text(json.dumps(rec) + "\n")
    _assert_invalidated(tmp_path, caplog)


@pytest.mark.skipif(
    not hasattr(os, "mkfifo"), reason="platform lacks mkfifo",
)
def test_planted_fifo_neither_hangs_nor_loads(tmp_path: Path) -> None:
    """A FIFO planted at the trail path must fail into the corrupt-
    trail rotation, not block the constructor (which runs under the
    registry lock — a hang there wedges every sweep worker).

    Subprocess-based with a wall-clock timeout: an in-process
    ``signal.alarm`` guard cannot prove this, because ``TimeoutError``
    is an ``OSError`` subclass that ``_load``'s own handler would
    swallow into a clean-looking invalidation.
    """
    os.mkfifo(tmp_path / CHECKPOINT_FILENAME)
    repo = Path(sc.__file__).resolve().parents[2]
    child = textwrap.dedent(
        f"""
        import os
        import sys
        sys.path.insert(0, {str(repo)!r})
        os.environ["RAPTOR_DIR"] = {str(repo)!r}
        os.environ["XDG_DATA_HOME"] = {str(tmp_path / "xdg")!r}
        from pathlib import Path
        from core.audit.sweep_checkpoint import (
            CHECKPOINT_FILENAME, SweepCheckpoint,
        )
        run_dir = Path({str(tmp_path)!r})
        cp = SweepCheckpoint(run_dir)
        assert not cp._loaded
        assert not (run_dir / CHECKPOINT_FILENAME).exists()
        assert (run_dir / (CHECKPOINT_FILENAME + ".corrupt")).exists()
        print("LOAD-COMPLETED")
        """
    )
    proc = subprocess.run(  # noqa: S603 — own interpreter, literal argv
        [sys.executable, "-c", child],
        capture_output=True, text=True,
        timeout=60,  # generous vs the failure mode being pinned: forever
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert "LOAD-COMPLETED" in proc.stdout
    # The other direction — a regular trail file loads and replays —
    # is pinned by test_roundtrip_replays_on_fresh_instance.


def test_rotation_makes_next_resume_clean(
    tmp_path: Path, caplog: pytest.LogCaptureFixture,
) -> None:
    (tmp_path / CHECKPOINT_FILENAME).write_text("garbage\n")
    with caplog.at_level(logging.WARNING, logger=sc.__name__):
        SweepCheckpoint(tmp_path).record(_key(), _result())
        caplog.clear()
        resumed = SweepCheckpoint(tmp_path)
    assert resumed.lookup(_key()) is not None
    assert not [
        r for r in caplog.records if r.levelno >= logging.WARNING
    ]


# ── byte bounds, both directions ─────────────────────────────────────


def test_record_size_bound_two_directions(tmp_path: Path) -> None:
    cp = SweepCheckpoint(tmp_path, max_record_bytes=4096)
    fits = _result("confirmed", matches=[{"pad": "x" * 100}])
    too_big = _result("confirmed", matches=[{"pad": "x" * 8192}])
    cp.record(_key(rule="fits"), fits)
    cp.record(_key(rule="big"), too_big)
    assert cp.recorded == 1
    resumed = SweepCheckpoint(tmp_path, max_record_bytes=4096)
    assert resumed.lookup(_key(rule="fits")) is not None
    assert resumed.lookup(_key(rule="big")) is None  # recompute, not skip


def test_total_size_bound_two_directions(
    tmp_path: Path, caplog: pytest.LogCaptureFixture,
) -> None:
    cp = SweepCheckpoint(tmp_path)
    for i in range(4):
        cp.record(_key(rule=f"r{i}"), _result())
    size = (tmp_path / CHECKPOINT_FILENAME).stat().st_size
    under = SweepCheckpoint(tmp_path, max_total_bytes=size)
    assert under.lookup(_key(rule="r0")) is not None
    _assert_invalidated_total = SweepCheckpoint(
        tmp_path, max_total_bytes=size - 1,
    )
    assert _assert_invalidated_total.lookup(_key(rule="r0")) is None


def test_write_failure_warns_once_and_disables(
    tmp_path: Path, caplog: pytest.LogCaptureFixture,
) -> None:
    cp = SweepCheckpoint(tmp_path)
    # Plant a symlink at the trail path: append_jsonl refuses it
    # (O_NOFOLLOW) with OSError.
    (tmp_path / "elsewhere").write_text("")
    (tmp_path / CHECKPOINT_FILENAME).symlink_to(tmp_path / "elsewhere")
    with caplog.at_level(logging.WARNING, logger=sc.__name__):
        cp.record(_key(rule="a"), _result())
        cp.record(_key(rule="b"), _result())
    warnings = [
        r for r in caplog.records if "append" in r.getMessage()
    ]
    assert len(warnings) == 1
    assert cp.recorded == 0


def test_concurrent_writers_all_records_line_atomic(
    tmp_path: Path,
) -> None:
    """Parallel workers appending distinct units: every record lands
    as one well-formed line (O_APPEND single-write), none torn, none
    lost — the property a future cross-file worker pool relies on."""
    cp = SweepCheckpoint(tmp_path)
    n = 32
    barrier = threading.Barrier(n)

    def _write(i: int) -> None:
        barrier.wait()
        cp.record(_key(rule=f"rule-{i}"), _result())

    threads = [
        threading.Thread(target=_write, args=(i,)) for i in range(n)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    lines = (
        (tmp_path / CHECKPOINT_FILENAME).read_text().strip().splitlines()
    )
    assert len(lines) == n
    for line in lines:
        json.loads(line)  # every line parses whole
    resumed = SweepCheckpoint(tmp_path)
    for i in range(n):
        assert resumed.lookup(_key(rule=f"rule-{i}")) is not None


# ── registry + dispatch seam ─────────────────────────────────────────


def test_registry_shares_one_instance_and_resets(tmp_path: Path) -> None:
    assert checkpoint_for_run(None) is None
    assert checkpoint_for_run("") is None
    a = checkpoint_for_run(tmp_path)
    b = checkpoint_for_run(str(tmp_path))
    assert a is not None and a is b
    reset_checkpoint_registry()
    assert checkpoint_for_run(tmp_path) is not a


def _seam_config(out_dir: Path) -> SimpleNamespace:
    return SimpleNamespace(sweep_memo=SweepMemo(), out_dir=out_dir)


def test_memoized_step_replays_across_segments(tmp_path: Path) -> None:
    parts = {"rule": "rh", "file": "fh", "path": "src/x.c", "defines": ""}
    calls: list[int] = []

    def _runner() -> SweepResult:
        calls.append(1)
        return _result("confirmed", matches=[{"line": 7}])

    first = _memoized_sweep_step(
        _seam_config(tmp_path), "coccinelle", parts, _runner,
    )
    assert first.outcome == "confirmed"
    assert len(calls) == 1

    # New segment: fresh process state (registry + memo), same run dir.
    reset_checkpoint_registry()
    second = _memoized_sweep_step(
        _seam_config(tmp_path), "coccinelle", parts, _runner,
    )
    assert len(calls) == 1  # replayed from the durable trail
    assert second.outcome == "confirmed"
    assert second.matches == [{"line": 7}]


def test_memoized_step_reruns_on_changed_digests(tmp_path: Path) -> None:
    calls: list[int] = []

    def _runner() -> SweepResult:
        calls.append(1)
        return _result()

    base = {"rule": "r1", "file": "f1", "path": "src/x.c", "defines": ""}
    _memoized_sweep_step(_seam_config(tmp_path), "coccinelle", base, _runner)
    reset_checkpoint_registry()
    changed = dict(base, file="f2")
    _memoized_sweep_step(
        _seam_config(tmp_path), "coccinelle", changed, _runner,
    )
    assert len(calls) == 2  # changed file content digest ⇒ re-sweep


def test_memoized_step_non_checkpointable_tool_stays_memo_only(
    tmp_path: Path,
) -> None:
    calls: list[int] = []

    def _runner() -> SweepResult:
        calls.append(1)
        return _result(tool="semgrep")

    parts = {"rule": "r", "file": "f"}
    _memoized_sweep_step(_seam_config(tmp_path), "semgrep", parts, _runner)
    reset_checkpoint_registry()
    _memoized_sweep_step(_seam_config(tmp_path), "semgrep", parts, _runner)
    assert len(calls) == 2
    assert not (tmp_path / CHECKPOINT_FILENAME).exists()


def test_memoized_step_no_out_dir_degrades_to_memo(tmp_path: Path) -> None:
    calls: list[int] = []

    def _runner() -> SweepResult:
        calls.append(1)
        return _result()

    config = SimpleNamespace(sweep_memo=SweepMemo(), out_dir=None)
    parts = {"rule": "r", "file": "f", "path": "p", "defines": ""}
    _memoized_sweep_step(config, "coccinelle", parts, _runner)
    _memoized_sweep_step(config, "coccinelle", parts, _runner)
    assert len(calls) == 1  # memo still serves in-process

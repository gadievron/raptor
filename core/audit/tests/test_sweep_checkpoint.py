"""Durable sweep checkpoint: cross-segment replay, content-keyed
invalidation, the corrupt-trail fail-open direction (recompute, never
skip), record/trail byte bounds in both directions, concurrent
writers, and the dispatch-seam integration in
``orchestrator._memoized_sweep_step``. Hermetic — no spatch, no LLM."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
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


def _restamp(rec: dict, run_dir: Path) -> dict:
    """Re-mint a VALID token over an edited record, so the test
    reaches the post-verification schema/version checks (an edit
    without a re-mint lands in the tampered-skip tier instead)."""
    key = sc._usable_mac_key()
    assert key is not None
    rec[sc.TOKEN_KEY] = sc._mint_token(key, rec, sc._run_binding(run_dir))
    return rec


def test_version_mismatch_invalidates_whole_trail(
    tmp_path: Path, caplog: pytest.LogCaptureFixture,
) -> None:
    cp = SweepCheckpoint(tmp_path)
    cp.record(_key(), _result())
    trail = tmp_path / CHECKPOINT_FILENAME
    rec = json.loads(trail.read_text())
    rec["v"] = CHECKPOINT_VERSION + 1
    trail.write_text(json.dumps(_restamp(rec, tmp_path)) + "\n")
    _assert_invalidated(tmp_path, caplog)


def test_schema_invalid_outcome_invalidates(
    tmp_path: Path, caplog: pytest.LogCaptureFixture,
) -> None:
    cp = SweepCheckpoint(tmp_path)
    cp.record(_key(), _result())
    trail = tmp_path / CHECKPOINT_FILENAME
    rec = json.loads(trail.read_text())
    rec["result"]["outcome"] = "error"  # never a valid persisted state
    trail.write_text(json.dumps(_restamp(rec, tmp_path)) + "\n")
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


# ── record authentication: adopt only what THIS install stamped ─────


def _forged_record(parts: dict, outcome: str, matches: list) -> dict:
    """A hand-crafted record with VALID content digests but no token —
    exactly what an attacker with run-dir write access and read access
    to the rule/file bytes can produce."""
    return {
        "v": CHECKPOINT_VERSION, "tool": "coccinelle", "parts": parts,
        "result": {
            "tool": "coccinelle", "file_path": parts["path"],
            "function_name": "victim", "outcome": outcome,
            "matches": matches, "errors": [], "rule_id": "planted",
            "raw_output": "", "details": None,
        },
    }


def _auth_warnings(
    caplog: pytest.LogCaptureFixture,
) -> list[logging.LogRecord]:
    return [
        r for r in caplog.records
        if "unauthenticated record" in r.getMessage()
    ]


def test_forged_trail_with_valid_digests_never_adopted(
    tmp_path: Path, caplog: pytest.LogCaptureFixture,
) -> None:
    """The full forgery drive: a planted trail whose digests are all
    VALID (sha256 of readable rule/file bytes — computable by anyone
    who can read them) carrying fabricated results, served through
    the real dispatch seam. Both forgery directions must lose: the
    runner runs for EVERY candidate and its result wins — a forged
    ``refuted`` cannot suppress a real confirmation, and a forged
    ``confirmed`` cannot mint a tool receipt."""
    rule_hex = hashlib.sha256(b"@r@ expression E; @@\n- memcpy(E);\n").hexdigest()
    file_hex = hashlib.sha256(b"int main(void){ memcpy(b, big, 400); }\n").hexdigest()
    parts_a = {
        "rule": rule_hex, "file": file_hex, "path": "src/a.c",
        "defines": "",
    }
    parts_b = dict(parts_a, path="src/b.c")
    trail = tmp_path / CHECKPOINT_FILENAME
    with trail.open("w") as fh:
        fh.write(json.dumps(_forged_record(parts_a, "refuted", [])) + "\n")
        fh.write(json.dumps(_forged_record(
            parts_b, "confirmed",
            [{"file": "src/b.c", "line": 13, "content": "FABRICATED"}],
        )) + "\n")

    calls = {"a": 0, "b": 0}

    def runner_a() -> SweepResult:
        calls["a"] += 1
        return _result(
            "confirmed", file_path="src/a.c", matches=[{"line": 1}],
        )

    def runner_b() -> SweepResult:
        calls["b"] += 1
        return _result("refuted", file_path="src/b.c")

    with caplog.at_level(logging.WARNING, logger=sc.__name__):
        config = _seam_config(tmp_path)
        res_a = _memoized_sweep_step(config, "coccinelle", parts_a, runner_a)
        res_b = _memoized_sweep_step(config, "coccinelle", parts_b, runner_b)
    assert calls == {"a": 1, "b": 1}  # spatch ran for every candidate
    assert res_a.outcome == "confirmed"  # suppression forgery rejected
    assert res_b.outcome == "refuted"  # receipt forgery rejected
    assert res_b.matches == []
    warnings = _auth_warnings(caplog)
    assert len(warnings) == 1  # ONE loud warning, with counts
    assert "unstamped=2" in warnings[0].getMessage()
    assert "tampered=0" in warnings[0].getMessage()


def test_bit_flipped_token_rejected(
    tmp_path: Path, caplog: pytest.LogCaptureFixture,
) -> None:
    SweepCheckpoint(tmp_path).record(_key(), _result())
    trail = tmp_path / CHECKPOINT_FILENAME
    rec = json.loads(trail.read_text())
    tok = rec[sc.TOKEN_KEY]
    rec[sc.TOKEN_KEY] = ("0" if tok[0] != "0" else "1") + tok[1:]
    trail.write_text(json.dumps(rec) + "\n")
    with caplog.at_level(logging.WARNING, logger=sc.__name__):
        resumed = SweepCheckpoint(tmp_path)
    assert resumed.lookup(_key()) is None  # recompute, not adopt
    warnings = _auth_warnings(caplog)
    assert len(warnings) == 1
    assert "tampered=1" in warnings[0].getMessage()


def test_edited_content_under_kept_token_rejected(
    tmp_path: Path, caplog: pytest.LogCaptureFixture,
) -> None:
    cp = SweepCheckpoint(tmp_path)
    cp.record(_key(), _result("confirmed", matches=[{"line": 2}]))
    trail = tmp_path / CHECKPOINT_FILENAME
    rec = json.loads(trail.read_text())
    rec["result"]["outcome"] = "refuted"  # flip the verdict, keep token
    rec["result"]["matches"] = []
    trail.write_text(json.dumps(rec) + "\n")
    with caplog.at_level(logging.WARNING, logger=sc.__name__):
        resumed = SweepCheckpoint(tmp_path)
    assert resumed.lookup(_key()) is None
    assert "tampered=1" in _auth_warnings(caplog)[0].getMessage()


def test_replanted_trail_from_another_run_rejected(
    tmp_path: Path, caplog: pytest.LogCaptureFixture,
) -> None:
    """Run binding: a genuinely-stamped trail copied verbatim from a
    sibling run's directory must not verify there — its records are
    not THIS run's history."""
    run_a = tmp_path / "run-a"
    run_b = tmp_path / "run-b"
    run_a.mkdir()
    run_b.mkdir()
    SweepCheckpoint(run_a).record(_key(), _result())
    shutil.copy(
        run_a / CHECKPOINT_FILENAME, run_b / CHECKPOINT_FILENAME,
    )
    assert SweepCheckpoint(run_a).lookup(_key()) is not None  # genuine
    with caplog.at_level(logging.WARNING, logger=sc.__name__):
        moved = SweepCheckpoint(run_b)
    assert moved.lookup(_key()) is None
    assert "tampered=1" in _auth_warnings(caplog)[0].getMessage()


def test_unstamped_record_rejected_then_repersisted(
    tmp_path: Path, caplog: pytest.LogCaptureFixture,
) -> None:
    """No unstamped legacy tier (the format never shipped without
    tokens): a token-stripped record is skipped — and the recompute
    path re-records the unit, so the NEXT resume replays it."""
    SweepCheckpoint(tmp_path).record(_key(), _result())
    trail = tmp_path / CHECKPOINT_FILENAME
    rec = json.loads(trail.read_text())
    del rec[sc.TOKEN_KEY]
    trail.write_text(json.dumps(rec) + "\n")
    with caplog.at_level(logging.WARNING, logger=sc.__name__):
        resumed = SweepCheckpoint(tmp_path)
    assert resumed.lookup(_key()) is None
    assert "unstamped=1" in _auth_warnings(caplog)[0].getMessage()
    # The skipped digest is NOT dedup-blocked: recompute re-persists...
    resumed.record(_key(), _result())
    assert resumed.recorded == 1
    # ...and the fresh stamped record is adopted next segment (the
    # stripped one still sits on line 1, skipped again).
    third = SweepCheckpoint(tmp_path)
    assert third.lookup(_key()) is not None


def test_mixed_trail_adopts_only_verified_records(
    tmp_path: Path, caplog: pytest.LogCaptureFixture,
) -> None:
    cp = SweepCheckpoint(tmp_path)
    cp.record(_key(rule="genuine"), _result())
    forged = _forged_record(
        {"rule": "aaa", "file": "bbb", "path": "src/x.c", "defines": ""},
        "confirmed", [{"line": 3}],
    )
    with (tmp_path / CHECKPOINT_FILENAME).open("a") as fh:
        fh.write(json.dumps(forged) + "\n")
    with caplog.at_level(logging.WARNING, logger=sc.__name__):
        resumed = SweepCheckpoint(tmp_path)
    assert resumed.lookup(_key(rule="genuine")) is not None  # kept
    assert resumed.lookup(_key()) is None  # forged sibling skipped
    message = _auth_warnings(caplog)[0].getMessage()
    assert "verified=1" in message
    assert "unstamped=1" in message


def test_unusable_key_disables_checkpoint(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Key unavailability (here: an unwritable/undirectory XDG data
    path) degrades to checkpoint-disabled — warn, recompute
    everything, adopt nothing, write nothing, never crash."""
    blocked = tmp_path / "blocked-xdg"
    blocked.write_text("")  # a FILE where the data dir should be
    monkeypatch.setenv("XDG_DATA_HOME", str(blocked))
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    # A planted trail is already present — it must NOT be adopted.
    (run_dir / CHECKPOINT_FILENAME).write_text(
        json.dumps(_forged_record(
            {"rule": "aaa", "file": "bbb", "path": "src/x.c",
             "defines": ""},
            "refuted", [],
        )) + "\n",
    )
    with caplog.at_level(logging.WARNING, logger=sc.__name__):
        cp = SweepCheckpoint(run_dir)
    assert cp.lookup(_key()) is None
    cp.record(_key(rule="new"), _result())
    assert cp.recorded == 0  # writes disabled too — nothing unstamped
    disabled = [
        r for r in caplog.records
        if "durable sweep state disabled" in r.getMessage()
    ]
    assert len(disabled) == 1


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

"""E2E: kill a stubbed audit mid-loop (SIGKILL), resume as the same run.

Segment 1 runs the REAL orchestrator loop in a child process with a
slow stub review_fn (no LLM); the parent SIGKILLs it after the journal
shows progress — the exact external-supervisor failure shape (harness
background-shell cap). The resume then:

* re-imports the prior segment's verdicts at $0 (hash-verified),
* reviews ONLY the remaining gaps (no double review),
* books the prior spend so the rewritten ledger has no double-booking,
* produces ONE report covering both segments.

CLI-level refusal gates (`raptor-audit resume`) are exercised via
subprocess — they exit before any LLM plumbing. ~10s wall time.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import pytest

pytestmark = pytest.mark.slow

_RAPTOR_DIR = Path(__file__).resolve().parents[3]
_CHECKLIST_CLI = str(_RAPTOR_DIR / "libexec" / "raptor-build-checklist")
_AUDIT_CLI = str(_RAPTOR_DIR / "libexec" / "raptor-audit")

_ORIGINAL_CAP_USD = 10.0
_COST_PER_REVIEW = 0.25

# Synthetic C target: enough substantial functions that a mid-loop
# kill leaves BOTH completed reviews and remaining gaps. Every
# function copies attacker-shaped input so triage never rules the
# whole queue trivial.
_FUNC_TEMPLATE = """\
int handle_{name}(const char *input, unsigned len) {{
    char buf[{size}];
    unsigned i;
    if (!input)
        return -1;
    if (len > sizeof(buf))
        len = sizeof(buf);
    for (i = 0; i < len; i++) {{
        buf[i] = input[i];
        if (buf[i] == '\\n')
            break;
    }}
    if (i > 4 && buf[0] == 'H') {{
        memcpy(buf, input + 1, len - 1);
        return (int)i + {size};
    }}
    return (int)i;
}}
"""


def _make_target(root: Path) -> Path:
    target = root / "target"
    target.mkdir()
    names = ["alpha", "bravo", "charlie", "delta", "echo", "foxtrot"]
    for file_idx in range(2):
        body = ["#include <string.h>", ""]
        for name in names[file_idx * 3:(file_idx + 1) * 3]:
            body.append(_FUNC_TEMPLATE.format(
                name=name, size=64 + 16 * file_idx,
            ))
        (target / f"proto{file_idx}.c").write_text("\n".join(body))
    return target

_DRIVER = textwrap.dedent("""\
    import sys, time
    sys.path.insert(0, sys.argv[3])
    from pathlib import Path
    from core.audit.orchestrator import (
        OrchestratorConfig, ReviewOutcome, run_orchestrator,
    )

    def review_fn(ctx, config):
        time.sleep(0.6)   # window for the parent's SIGKILL
        return ReviewOutcome(
            file=ctx["file"], function=ctx["function"],
            status="clean", body="stub segment-1 review",
            cost_usd=%(cost)s,
        )

    config = OrchestratorConfig(
        target_path=Path(sys.argv[1]),
        out_dir=Path(sys.argv[2]),
        max_cost_usd=%(cap)s,
        max_workers=1,
        prefilter=False,
        batch_sloc_threshold=0,
        sweep_validate_findings=False,
        validate=False,
        deepen_suspicious=False,
        clean_check=False,
        adversarial=False,
        enable_session_context=False,
        propagate_constraints=False,
        include_stale=False,
        on_demand_synthesis=False,
    )
    run_orchestrator(config, review_fn)
""") % {"cost": _COST_PER_REVIEW, "cap": _ORIGINAL_CAP_USD}


def _env():
    return dict(
        os.environ, CLAUDECODE="1", _RAPTOR_TRUSTED="1",
        PYTHONPATH=str(_RAPTOR_DIR),
    )


def _journal_entries(out_dir: Path) -> list[dict]:
    path = out_dir / "review-journal.jsonl"
    if not path.is_file():
        return []
    entries = []
    for line in path.read_text().splitlines():
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            continue  # truncated tail from the kill — expected
    return entries


@pytest.fixture(scope="module")
def killed_run(tmp_path_factory):
    """Segment 1: real orchestrator, stub reviews, SIGKILL mid-loop.

    Yields ``(out_dir, target_dir, killed_state)`` where
    ``killed_state`` snapshots the run metadata and resume
    eligibility AT KILL TIME: later fixtures/tests mutate the run
    (resume, completion), and under randomised test order
    (RAPTOR_RANDOMISE_TESTS) the killed-state assertions can run
    after those mutations — they must assert on the snapshot, not on
    the current on-disk state.
    """
    root = tmp_path_factory.mktemp("resume_e2e")
    target = _make_target(root)
    out = root / "audit-run"

    r = subprocess.run(
        [sys.executable, _CHECKLIST_CLI, str(target), str(out)],
        env=_env(), capture_output=True, text=True, check=False,
    )
    assert r.returncode == 0, f"build-checklist failed: {r.stderr}"

    # What `raptor-audit run` persists at start: lifecycle metadata +
    # the resolved run config (the resume contract's two inputs).
    from core.audit.resume import save_run_config
    from core.run import start_run
    start_run(out, "audit", target=str(target))
    save_run_config(out, {
        "version": 1,
        "target_path": str(target),
        "max_cost_usd": _ORIGINAL_CAP_USD,
        "models": [],
        "validate": False,
        "verdict_reuse": True,
        "no_binary_oracle": True,
    })

    driver = out.parent / "driver.py"
    driver.write_text(_DRIVER)
    child = subprocess.Popen(
        [sys.executable, str(driver), str(target), str(out),
         str(_RAPTOR_DIR)],
        env=_env(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )

    # Record the child as the run's worker — in production the
    # lifecycle-start subprocess records its parent (the raptor-audit
    # process), which is exactly what the supervisor kills. The
    # eligibility check keys "still in flight" off this pid.
    from core.json import load_json, save_json
    from core.run import RUN_METADATA_FILE
    meta_path = out / RUN_METADATA_FILE
    meta = load_json(meta_path)
    meta["tool_pid"] = child.pid
    save_json(meta_path, meta)

    # SIGKILL once at least two reviews are journaled — mid-loop, some
    # work done, more remaining.
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        if child.poll() is not None:
            pytest.fail(
                "segment-1 child finished before the kill — "
                "no mid-loop window",
            )
        if len(_journal_entries(out)) >= 2:
            break
        time.sleep(0.1)
    else:
        child.kill()
        pytest.fail("segment-1 child produced no journal entries in time")

    os.kill(child.pid, signal.SIGKILL)
    child.wait(timeout=30)

    from core.audit.resume import resume_ineligibility
    from core.run import load_run_metadata
    killed_state = {
        "status": load_run_metadata(out)["status"],
        "ineligibility": resume_ineligibility(out),
        "journal_entries": _journal_entries(out),
    }
    return out, target, killed_state


class TestKilledRunState:

    def test_status_stuck_running_and_resumable(self, killed_run):
        _out, _target, killed_state = killed_run
        assert killed_state["status"] == "running", (
            "SIGKILL must leave the run without a terminal transition"
        )
        assert killed_state["ineligibility"] is None

    def test_journal_survived_the_kill(self, killed_run):
        entries = killed_run[2]["journal_entries"]
        assert len(entries) >= 2
        assert all(e.get("verdict") == "clean" for e in entries)


@pytest.fixture(scope="module")
def resumed_run(killed_run):
    """Segment 2: resume in-process with a counting stub review_fn.

    Mirrors what `raptor-audit resume` wires up (same_run_reuse,
    remaining budget, prior ledger, segment number) with the pipeline's
    LLM-client construction replaced by a stub — the CLI's refusal
    gates are tested separately below.
    """
    from core.audit.orchestrator import (
        OrchestratorConfig,
        ReviewOutcome,
        run_orchestrator,
    )
    from core.audit.resume import (
        append_resume_markers,
        compute_drift,
        journal_spend_usd,
        load_run_config,
        remaining_budget_usd,
    )
    from core.run.metadata import resume_run

    out, target, killed_state = killed_run
    seg1_keys = {
        f"{e['file']}:{e['function']}"
        for e in killed_state["journal_entries"]
    }
    seg1_count = len(seg1_keys)

    drifted, checked = compute_drift(out, target)
    assert drifted == [], "target unchanged — staleness gate must pass"
    assert checked >= seg1_count

    # The run died pre-reconciliation: journal floor is the booked
    # figure the resume math uses.
    booked = journal_spend_usd(out)
    run_cfg = load_run_config(out)
    remaining = remaining_budget_usd(run_cfg["max_cost_usd"], booked)

    segment = resume_run(out, note="e2e resume")
    append_resume_markers(out, segment)

    seg2_calls: list[str] = []

    def review_fn(ctx, config):
        seg2_calls.append(f"{ctx['file']}:{ctx['function']}")
        return ReviewOutcome(
            file=ctx["file"], function=ctx["function"],
            status="clean", body="stub segment-2 review",
            cost_usd=_COST_PER_REVIEW,
        )

    config = OrchestratorConfig(
        target_path=target,
        out_dir=out,
        max_cost_usd=remaining,
        max_workers=1,
        prefilter=False,
        batch_sloc_threshold=0,
        sweep_validate_findings=False,
        validate=False,
        deepen_suspicious=False,
        clean_check=False,
        adversarial=False,
        enable_session_context=False,
        propagate_constraints=False,
        include_stale=False,
        on_demand_synthesis=False,
        same_run_reuse=True,
        prior_cost_breakdown={"totals": {"total_spend_usd": booked}},
        resume_segment=segment,
    )
    result = run_orchestrator(config, review_fn)
    return {
        "out": out,
        "result": result,
        "seg1_keys": seg1_keys,
        "seg1_count": seg1_count,
        "seg2_calls": seg2_calls,
        "booked": booked,
        "remaining": remaining,
        "segment": segment,
    }


class TestResumedSegment:

    def test_remaining_budget_math(self, resumed_run):
        booked = resumed_run["booked"]
        assert booked == pytest.approx(
            _COST_PER_REVIEW * resumed_run["seg1_count"],
        )
        assert resumed_run["remaining"] == pytest.approx(
            _ORIGINAL_CAP_USD - booked,
        )

    def test_prior_verdicts_reimported_at_zero_dollars(self, resumed_run):
        result = resumed_run["result"]
        assert result.reused_from_prior == resumed_run["seg1_count"]
        reused = [o for o in result.outcomes if o.reused]
        assert len(reused) == resumed_run["seg1_count"]
        assert all(o.cost_usd == 0.0 for o in reused)

    def test_no_double_review(self, resumed_run):
        overlap = set(resumed_run["seg2_calls"]) & resumed_run["seg1_keys"]
        assert overlap == set(), (
            f"segment 2 re-reviewed segment-1 functions: {overlap}"
        )
        assert resumed_run["seg2_calls"], (
            "segment 2 reviewed nothing — the kill left no remaining "
            "gaps, so the fixture proves nothing"
        )

    def test_no_double_booking_in_ledger(self, resumed_run):
        ledger = json.loads(
            (resumed_run["out"] / "cost-breakdown.json").read_text(),
        )
        seg2_cost = _COST_PER_REVIEW * len(set(resumed_run["seg2_calls"]))
        assert ledger["totals"]["total_spend_usd"] == pytest.approx(
            resumed_run["booked"] + seg2_cost, abs=0.01,
        )
        assert ledger["segments"] == [{
            "segment": resumed_run["segment"],
            "prior_spend_usd": pytest.approx(resumed_run["booked"]),
        }]
        assert ledger["phases"]["prior_segments"]["cost_usd"] == (
            pytest.approx(resumed_run["booked"])
        )

    def test_resume_markers_in_both_ledgers(self, resumed_run):
        out = resumed_run["out"]
        from core.audit.record import load_audit_log
        markers = [
            e for e in load_audit_log(out) if e.get("action") == "resume"
        ]
        assert len(markers) == 1
        assert markers[0]["segment"] == resumed_run["segment"]
        telemetry_markers = [
            json.loads(line)
            for line in (out / "llm-telemetry.jsonl").read_text().splitlines()
            if '"resume_marker"' in line
        ]
        assert len(telemetry_markers) == 1

    def test_single_coherent_report_covers_both_segments(self, resumed_run):
        from core.audit.report import generate_report, write_report
        out = resumed_run["out"]
        report = generate_report(out)
        write_report(report, out)

        total_functions = (
            resumed_run["seg1_count"]
            + len(set(resumed_run["seg2_calls"]))
        )
        assert report["stats"]["reviewed"] == total_functions, (
            "one report must cover both segments' verdicts"
        )
        assert report["stats"]["clean"] == total_functions
        assert (out / "audit-report.json").is_file()

        # Segment provenance: every re-imported verdict names this
        # run as its producing origin.
        entries = _journal_entries(out)
        reused_rows = [e for e in entries if e.get("reused")]
        assert len(reused_rows) == resumed_run["seg1_count"]
        assert all(
            e.get("reused_from_run") == out.name for e in reused_rows
        )

    def test_lifecycle_completes_with_segment_history(self, resumed_run):
        from core.run import complete_run, load_run_metadata
        out = resumed_run["out"]
        complete_run(out)
        meta = load_run_metadata(out)
        assert meta["status"] == "completed"
        assert [r["segment"] for r in meta["extra"]["resumes"]] == [
            resumed_run["segment"],
        ]


class TestResumeCliGates:
    """`raptor-audit resume` refusal gates (no LLM plumbing reached)."""

    def test_refuses_completed_run(self, resumed_run):
        # Complete the run HERE rather than relying on
        # test_lifecycle_completes_with_segment_history having run
        # first — under randomised test order (the nightly sets
        # RAPTOR_RANDOMISE_TESTS) this test can come earlier, and a
        # still-running run with a dead worker pid is legitimately
        # resumable, so the CLI proceeded instead of refusing.
        # complete_run is idempotent on a completed run (the terminal-
        # status guard only refuses CHANGES of terminal state).
        from core.run import complete_run
        complete_run(resumed_run["out"])

        r = subprocess.run(
            [sys.executable, _AUDIT_CLI, "resume",
             str(resumed_run["out"])],
            env=_env(), capture_output=True, text=True, timeout=120,
            check=False,
        )
        assert r.returncode == 1
        assert "completed" in r.stderr
        assert "verdict reuse" in r.stderr

    def test_refuses_non_run_directory(self, tmp_path):
        r = subprocess.run(
            [sys.executable, _AUDIT_CLI, "resume", str(tmp_path)],
            env=_env(), capture_output=True, text=True, timeout=120,
            check=False,
        )
        assert r.returncode == 1
        assert "not a run directory" in r.stderr

    def test_refuses_run_without_persisted_config(self, tmp_path):
        from core.run import interrupt_run, start_run
        out = tmp_path / "run"
        start_run(out, "audit", target=str(tmp_path))
        interrupt_run(out, "test")
        r = subprocess.run(
            [sys.executable, _AUDIT_CLI, "resume", str(out)],
            env=_env(), capture_output=True, text=True, timeout=120,
            check=False,
        )
        assert r.returncode == 1
        assert "audit-run-config.json" in r.stderr

    def test_refuses_drift_without_allow_drift(self, tmp_path):
        """A drifted tree is named function-by-function and refused."""
        from core.audit.resume import save_run_config
        from core.coverage.journal import (
            ReviewJournalEntry,
            append_entry,
            now_iso,
        )
        from core.run import interrupt_run, start_run
        from core.staleness import hash_spans

        target = tmp_path / "target"
        target.mkdir()
        src = target / "a.c"
        src.write_text("int f() {\n  return 1;\n}\n")
        out = tmp_path / "run"
        start_run(out, "audit", target=str(target))
        save_run_config(out, {
            "version": 1, "target_path": str(target),
            "max_cost_usd": 1.0, "models": [],
        })
        (out / "checklist.json").write_text(json.dumps({
            "target_path": str(target),
            "files": [{"path": "a.c", "language": "c", "items": [
                {"name": "f", "kind": "function",
                 "line_start": 1, "line_end": 3},
            ]}],
        }))
        h = hash_spans(src, [(1, 3)])[0]
        append_entry(out, ReviewJournalEntry(
            ts=now_iso(), run_id=out.name, file="a.c", function="f",
            verdict="clean", source_hash=h, line_start=1, line_end=3,
        ))
        interrupt_run(out, "test")
        src.write_text("int f() {\n  return 2;\n}\n")

        r = subprocess.run(
            [sys.executable, _AUDIT_CLI, "resume", str(out)],
            env=_env(), capture_output=True, text=True, timeout=120,
            check=False,
        )
        assert r.returncode == 1
        assert "drifted" in r.stderr
        assert "a.c:f" in r.stderr
        assert "--allow-drift" in r.stderr
        # The refusal must leave the run resumable (no state change).
        from core.run import load_run_metadata
        assert load_run_metadata(out)["status"] == "interrupted"

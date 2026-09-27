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
import contextlib
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


def _home(base: Path) -> Path:
    """Isolated HOME for a spawned segment: a fresh interpreter derives
    both the projects registry (~/.raptor/projects) and the sessions
    registry (~/.local/share/raptor/sessions.d) from Path.home() at
    import, so the redirect keeps a child from adopting whatever
    project the box's live claude session has active."""
    home = Path(base) / "home"
    home.mkdir(parents=True, exist_ok=True)
    return home


#: Live-LLM opt-in for this file's subprocesses. The CLI gates under
#: test are REFUSAL paths, but their failure mode is the opposite: a
#: gate that unexpectedly proceeds runs a real audit, and on an
#: operator host the ambient env (a configured models.json, provider
#: API keys, the live claude CLI on PATH) would make that audit spend
#: real model budget. Default = hermetic children; export
#: RAPTOR_TEST_LIVE_LLM=1 to deliberately exercise the live shapes.
_LIVE_LLM_OPT_IN = "RAPTOR_TEST_LIVE_LLM"


def _env(home: Path):
    if os.environ.get(_LIVE_LLM_OPT_IN) == "1":
        env = dict(
            os.environ, CLAUDECODE="1", _RAPTOR_TRUSTED="1",
            PYTHONPATH=str(_RAPTOR_DIR), HOME=str(home),
            XDG_DATA_HOME=str(home / ".local" / "share"),
        )
        # The launcher's session env would let the child token-verify
        # into the operator's live session registry even under the
        # HOME redirect.
        env.pop("RAPTOR_SESSION_PID", None)
        env.pop("RAPTOR_SESSION_TOKEN", None)
        return env
    # Hermetic default — built UP from an allowlist, never filtered
    # down from os.environ (same doctrine as the web live-tool tests):
    # subtractive scrubbing misses the next credential variable by
    # construction, so the operator's API keys, models.json pointer
    # and session identity are absent rather than removed.
    env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": str(home),
        # Explicit, not HOME-derived: an exported XDG_DATA_HOME in the
        # ambient env would otherwise still point the child at the
        # real install's row-provenance key — segment 2 must verify
        # the child's journal tokens against the SAME key.
        "XDG_DATA_HOME": str(home / ".local" / "share"),
        "PYTHONPATH": str(_RAPTOR_DIR),
        "CLAUDECODE": "1",
        "_RAPTOR_TRUSTED": "1",
        # Spawn-time kill switch: even with the live CLI on PATH and
        # CLAUDECODE set, a billed claude spawn in the child refuses
        # with a named error instead of executing (cc_adapter).
        "RAPTOR_CC_TRANSPORT_DISABLED": "1",
        # Nonexistent by construction — a configured operator
        # models.json can never steer the child's model selection.
        "RAPTOR_CONFIG": str(home / "no-operator-models.json"),
        "RAPTOR_REACH_VERDICT_LOG_DISABLED": "1",
    }
    # Inherit only behaviour-neutral plumbing.
    for var in ("TMPDIR", "LANG", "LC_ALL", "COLUMNS"):
        if var in os.environ:
            env[var] = os.environ[var]
    return env


@contextlib.contextmanager
def _isolated_registries(home: Path):
    """In-process twin of _env()'s HOME redirect for the module-scoped
    fixtures: they call start_run and the resume orchestration in THIS
    process, outside the per-test conftest isolation, and the layered
    active-project resolution would otherwise walk to the box's live
    claude session and adopt the operator's binding / .active project
    — the sealed run pin then folds a foreign project's journal index
    into the test run."""
    from core.project import project as _project
    from core.project import sessions as _sessions
    from core.run import pin as _pin
    mp = pytest.MonkeyPatch()
    try:
        # The pid walk stays LIVE: the child segment records its run
        # ledger under the walked session pid in the redirected
        # registry, and the in-process resume discovers the prior
        # segment through that same ledger — disabling the walk here
        # severs the linkage and re-import finds nothing. The
        # redirect alone is the isolation: the operator's binding
        # lives in the real registry this never reads.
        mp.setattr(_sessions, "SESSIONS_DIR",
                   home / ".local" / "share" / "raptor" / "sessions.d")
        mp.setattr(_project, "PROJECTS_DIR", home / ".raptor" / "projects")
        # Same key as the child segments: journal row-provenance
        # tokens verify against the XDG-resolved per-install key, and
        # a key mismatch demotes every prior row to the no-reuse tier.
        mp.setenv("XDG_DATA_HOME", str(home / ".local" / "share"))
        mp.delenv(_sessions.ENV_SESSION_PID, raising=False)
        mp.delenv(_sessions.ENV_SESSION_TOKEN, raising=False)
        _pin._frozen_pins.clear()
        yield
    finally:
        mp.undo()
        _pin._frozen_pins.clear()


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
    home = _home(root)

    r = subprocess.run(
        [sys.executable, _CHECKLIST_CLI, str(target), str(out)],
        env=_env(home), capture_output=True, text=True, check=False,
    )
    assert r.returncode == 0, f"build-checklist failed: {r.stderr}"

    # What `raptor-audit run` persists at start: lifecycle metadata +
    # the resolved run config (the resume contract's two inputs).
    from core.audit.resume import save_run_config
    from core.run import start_run
    with _isolated_registries(home):
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
        env=_env(home), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
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

    with _isolated_registries(_home(out.parent)):
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
    with _isolated_registries(_home(out.parent)):
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


class TestHermeticByDefault:
    """Live-LLM invocation is explicit opt-in (RAPTOR_TEST_LIVE_LLM=1),
    never a side effect of running this file: the subprocess env is
    allowlist-built, and the spawn-time transport kill switch makes a
    fall-through loud and free instead of silent and billed."""

    def test_env_is_allowlist_built_without_opt_in(
        self, tmp_path, monkeypatch,
    ):
        monkeypatch.delenv(_LIVE_LLM_OPT_IN, raising=False)
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test-not-a-real-key")
        fake_models = tmp_path / "models.json"
        fake_models.write_text('{"models": []}')
        monkeypatch.setenv("RAPTOR_CONFIG", str(fake_models))
        monkeypatch.setenv("RAPTOR_SESSION_PID", "12345")

        env = _env(_home(tmp_path))

        assert "ANTHROPIC_API_KEY" not in env
        assert "RAPTOR_SESSION_PID" not in env
        assert env["RAPTOR_CC_TRANSPORT_DISABLED"] == "1"
        # The child's config pointer is OURS and nonexistent — the
        # ambient (operator-shaped) models.json cannot steer it.
        assert env["RAPTOR_CONFIG"] != str(fake_models)
        assert not Path(env["RAPTOR_CONFIG"]).exists()

    def test_opt_in_restores_the_live_shape(self, tmp_path, monkeypatch):
        monkeypatch.setenv(_LIVE_LLM_OPT_IN, "1")
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test-not-a-real-key")
        env = _env(_home(tmp_path))
        assert env["ANTHROPIC_API_KEY"] == "sk-test-not-a-real-key"

    def test_child_cannot_reach_a_live_llm_without_opt_in(
        self, tmp_path, monkeypatch,
    ):
        """Instrumented proof, not absence-of-errors: with a fully
        operator-shaped ambient env — a configured models.json, a
        provider key, and a canary ``claude`` FIRST on PATH that
        records any execution — a child under ``_env()``:

        * resolves no external LLM (the key/config are invisible),
        * refuses the billed claude spawn at the exec chokepoint with
          the named kill-switch error (loud, free), and
        * never executes the canary binary (log stays absent),

        end-to-end through a real ``raptor-audit resume`` invocation
        as well as a direct probe of the decision chain.
        """
        canary_dir = tmp_path / "bin"
        canary_dir.mkdir()
        canary_log = tmp_path / "canary-invocations.log"
        canary = canary_dir / "claude"
        canary.write_text(
            f"#!/bin/sh\necho \"$@\" >> {canary_log}\nexit 1\n",
        )
        canary.chmod(0o755)
        monkeypatch.setenv(
            "PATH", f"{canary_dir}:{os.environ.get('PATH', '')}",
        )
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test-not-a-real-key")
        fake_models = tmp_path / "models.json"
        fake_models.write_text(json.dumps({"models": [{
            "name": "fake", "provider": "anthropic",
            "model": "fake-model", "api_key": "sk-test-not-a-real-key",
        }]}))
        # Key-bearing fixture must be private: the loader fail-closes
        # on a group/other-readable models.json with inline keys.
        fake_models.chmod(0o600)
        monkeypatch.setenv("RAPTOR_CONFIG", str(fake_models))
        monkeypatch.delenv(_LIVE_LLM_OPT_IN, raising=False)

        env = _env(_home(tmp_path))

        probe = subprocess.run(
            [sys.executable, "-c", textwrap.dedent("""\
                import json, shutil
                from core.llm.detection import detect_llm_availability
                from core.llm.cc_adapter import (
                    cc_transport_disabled, run_cc_streaming,
                )
                av = detect_llm_availability()
                out = {
                    "external_llm": av.external_llm,
                    "kill_switch": cc_transport_disabled(),
                    "which": shutil.which("claude"),
                }
                try:
                    run_cc_streaming(
                        [shutil.which("claude"), "-p"], "x", {}, 5,
                    )
                    out["spawn"] = "EXECUTED"
                except RuntimeError as exc:
                    out["spawn"] = (
                        "refused" if "transport disabled" in str(exc)
                        else f"other: {exc}"
                    )
                print(json.dumps(out))
            """)],
            env=env, capture_output=True, text=True, timeout=120,
            check=False,
        )
        assert probe.returncode == 0, probe.stderr
        data = json.loads(probe.stdout.strip().splitlines()[-1])
        assert data["external_llm"] is False, (
            "ambient key/models.json leaked into the child"
        )
        assert data["kill_switch"] is True
        assert data["which"] == str(canary), (
            "the canary must be the resolvable CLI — otherwise this "
            "test proves nothing about spawn refusal"
        )
        assert data["spawn"] == "refused"

        # End-to-end: a real CLI-gate invocation stays hermetic.
        r = subprocess.run(
            [sys.executable, _AUDIT_CLI, "resume", str(tmp_path)],
            env=env, capture_output=True, text=True, timeout=120,
            check=False,
        )
        assert r.returncode == 1
        assert "not a run directory" in r.stderr
        assert not canary_log.exists(), (
            f"a child executed the live CLI: {canary_log.read_text()!r}"
        )


class TestResumeCliGates:
    """`raptor-audit resume` refusal gates (no LLM plumbing reached)."""

    def test_refuses_completed_run(self, resumed_run, tmp_path):
        # Complete the run HERE rather than relying on
        # test_lifecycle_completes_with_segment_history having run
        # first — under randomised test order (the nightly sets
        # RAPTOR_RANDOMISE_TESTS) this test can come earlier, and a
        # still-running run with a dead worker pid is legitimately
        # resumable, so the CLI proceeded instead of refusing.
        # complete_run is idempotent on a completed run (the terminal-
        # status guard only refuses CHANGES of terminal state).
        # A LEGITIMATELY completed run has its report on disk — write
        # it via the production path first, or (under randomised
        # order, before the report test has run) the CLI's
        # contradicted-completion detector fires its --reopen message
        # instead of the generic completed refusal under test.
        from core.audit.report import generate_report, write_report
        from core.run import complete_run
        out = resumed_run["out"]
        if not (out / "audit-report.json").is_file():
            write_report(generate_report(out), out)
        complete_run(out)

        r = subprocess.run(
            [sys.executable, _AUDIT_CLI, "resume",
             str(resumed_run["out"])],
            env=_env(_home(tmp_path)), capture_output=True, text=True, timeout=120,
            check=False,
        )
        assert r.returncode == 1
        assert "completed" in r.stderr
        assert "verdict reuse" in r.stderr

    def test_refuses_non_run_directory(self, tmp_path):
        r = subprocess.run(
            [sys.executable, _AUDIT_CLI, "resume", str(tmp_path)],
            env=_env(_home(tmp_path)), capture_output=True, text=True, timeout=120,
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
            env=_env(_home(tmp_path)), capture_output=True, text=True, timeout=120,
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
            env=_env(_home(tmp_path)), capture_output=True, text=True, timeout=120,
            check=False,
        )
        assert r.returncode == 1
        assert "drifted" in r.stderr
        assert "a.c:f" in r.stderr
        assert "--allow-drift" in r.stderr
        # The refusal must leave the run resumable (no state change).
        from core.run import load_run_metadata
        assert load_run_metadata(out)["status"] == "interrupted"

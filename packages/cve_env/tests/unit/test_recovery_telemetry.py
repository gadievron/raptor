"""Phase 26 — Recovery audit telemetry (#30) RED→GREEN TDD tests.

Detector signature:

    _process_tool_result_for_recovery(
        state,
        *,
        tool_name: str,
        turn: int,
        tool_status: str,         # "tool_ok" | "tool_error"
        tool_result: Any,         # dict (with ``ok`` or ``passed``) or string
    ) -> AuditEntry | None

Emits ``AuditEntry(status="recovery", ...)`` when a previously-failing tool
succeeds within ``RECOVERY_GAP_TURNS`` (default 20) AND the tool's stage is
in ``RECOVERY_ELIGIBLE_STAGES`` (ACQUIRE / RESOLVE / LAUNCH / VERIFY).

Failure signal = ``status == "tool_error"`` OR
``isinstance(tool_result, dict) and (tool_result.get("ok") is False or
tool_result.get("passed") is False)``. The ``ok`` / ``passed`` split is
empirical: build-path tools use ``ok``; ``verify`` uses ``passed``.

These tests use ``xfail(strict=True)`` per the established TDD pattern
(Phase 21.1, 21.3.1) — the markers are removed atomically when 26.3
wires the detector and the tests turn GREEN.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
pytest.importorskip("claude_agent_sdk")

from cve_env.agent.audit import AuditEntry
from cve_env.agent.loop import _StreamState


def _make_state() -> _StreamState:
    """Minimal _StreamState — all defaults; tests pre-populate fields they care about."""
    return _StreamState()


def _try_import_detector():
    """Return the detector callable or None if not yet implemented (RED phase)."""
    try:
        from cve_env.agent.loop import _process_tool_result_for_recovery

        return _process_tool_result_for_recovery
    except ImportError:
        return None


# ---------------------------------------------------------------------------
# RED tests via xfail(strict=True). Removed atomically by Phase 26.3.
# ---------------------------------------------------------------------------


def test_recovery_emits_on_same_tool_within_k():
    """docker_build ok=False at T16 → ok=True at T32 emits recovery (gap=16, K=20)."""
    detect = _try_import_detector()
    assert detect is not None, "detector not implemented yet"
    state = _make_state()
    # Simulate failure at T16
    e1 = detect(
        state,
        tool_name="docker_build",
        turn=16,
        tool_status="tool_ok",
        tool_result={"ok": False, "reason": "build_failed"},
    )
    assert e1 is None, "failure should not emit recovery"
    # Recovery at T32 (gap=16, within K=20)
    entry = detect(
        state,
        tool_name="docker_build",
        turn=32,
        tool_status="tool_ok",
        tool_result={"ok": True, "image_id": "sha256:abc"},
    )
    assert entry is not None
    assert isinstance(entry, AuditEntry)
    assert entry.status == "recovery"
    assert entry.tool_name == "docker_build"
    assert entry.turn == 32
    assert isinstance(entry.tool_result, dict)
    assert entry.tool_result["error_turn"] == 16
    assert entry.tool_result["recovery_turn"] == 32
    assert entry.tool_result["gap"] == 16
    assert entry.tool_result["stage"] == "ACQUIRE"


def test_no_recovery_when_gap_exceeds_k():
    """ok=False at T5 → ok=True at T30 (gap=25 > K=20) does NOT emit."""
    detect = _try_import_detector()
    assert detect is not None
    state = _make_state()
    detect(
        state,
        tool_name="image_resolve",
        turn=5,
        tool_status="tool_ok",
        tool_result={"ok": False},
    )
    entry = detect(
        state,
        tool_name="image_resolve",
        turn=30,
        tool_status="tool_ok",
        tool_result={"ok": True},
    )
    assert entry is None


def test_no_recovery_on_diagnostic_tools():
    """Bash is DIAGNOSTIC stage; recoveries on it are noisy → filtered out."""
    detect = _try_import_detector()
    assert detect is not None
    state = _make_state()
    detect(
        state,
        tool_name="Bash",
        turn=11,
        tool_status="tool_error",
        tool_result={"is_error": True},
    )
    entry = detect(
        state,
        tool_name="Bash",
        turn=15,
        tool_status="tool_ok",
        tool_result={"ok": True},
    )
    assert entry is None, "DIAGNOSTIC tools must be filtered out"


def test_idempotent_only_first_ok_emits():
    """Sequence: fail, fail, ok (emit), ok (no emit), fail, ok (emit again)."""
    detect = _try_import_detector()
    assert detect is not None
    state = _make_state()
    # 2 failures
    assert (
        detect(
            state,
            tool_name="docker_build",
            turn=16,
            tool_status="tool_ok",
            tool_result={"ok": False},
        )
        is None
    )
    assert (
        detect(
            state,
            tool_name="docker_build",
            turn=23,
            tool_status="tool_ok",
            tool_result={"ok": False},
        )
        is None
    )
    # First success → emits recovery; errors_in_window=2; gap measured to MOST RECENT failure
    e3 = detect(
        state,
        tool_name="docker_build",
        turn=32,
        tool_status="tool_ok",
        tool_result={"ok": True},
    )
    assert e3 is not None
    assert e3.tool_result["errors_in_window"] == 2
    assert e3.tool_result["error_turn"] == 23  # most recent failure
    assert e3.tool_result["gap"] == 9  # 32 - 23
    # Second success (state was cleared by the emit) → no emit
    e4 = detect(
        state,
        tool_name="docker_build",
        turn=35,
        tool_status="tool_ok",
        tool_result={"ok": True},
    )
    assert e4 is None
    # New failure → re-armed
    assert (
        detect(
            state,
            tool_name="docker_build",
            turn=40,
            tool_status="tool_ok",
            tool_result={"ok": False},
        )
        is None
    )
    # Recovery again
    e6 = detect(
        state,
        tool_name="docker_build",
        turn=42,
        tool_status="tool_ok",
        tool_result={"ok": True},
    )
    assert e6 is not None
    assert e6.tool_result["errors_in_window"] == 1
    assert e6.tool_result["gap"] == 2


def test_recovery_row_full_shape():
    """The recovery AuditEntry has the documented tool_result shape."""
    detect = _try_import_detector()
    assert detect is not None
    state = _make_state()
    detect(
        state,
        tool_name="verify",
        turn=24,
        tool_status="tool_ok",
        tool_result={"passed": False, "reason": "missing-marker"},
    )
    detect(
        state,
        tool_name="verify",
        turn=37,
        tool_status="tool_ok",
        tool_result={"passed": False, "reason": "missing-marker"},
    )
    entry = detect(
        state,
        tool_name="verify",
        turn=43,
        tool_status="tool_ok",
        tool_result={"passed": True},
    )
    assert entry is not None
    # Required fields
    expected_keys = {"error_turn", "recovery_turn", "gap", "stage", "errors_in_window"}
    assert set(entry.tool_result.keys()) >= expected_keys
    assert entry.tool_result["stage"] == "VERIFY"
    assert entry.status == "recovery"
    assert entry.tool_name == "verify"


def test_per_tool_isolation():
    """A failure of tool A doesn't trigger a recovery for tool B's success."""
    detect = _try_import_detector()
    assert detect is not None
    state = _make_state()
    # docker_build fails
    detect(
        state,
        tool_name="docker_build",
        turn=16,
        tool_status="tool_ok",
        tool_result={"ok": False},
    )
    # image_resolve succeeds — DIFFERENT tool. No recovery for it.
    entry = detect(
        state,
        tool_name="image_resolve",
        turn=20,
        tool_status="tool_ok",
        tool_result={"ok": True},
    )
    assert entry is None


# ---------------------------------------------------------------------------
# Replay-corpus test (Stage 26.5): replays 3 canonical Phase-23 audit JSONLs
# through the detector. xfail until Phase 26.3 lands.
# ---------------------------------------------------------------------------


_PHASE_23_AUDIT_ROOT = Path(__file__).parent.parent.parent / "output" / "agentic"


def _replay_audit_jsonl(detect, path: Path) -> list[AuditEntry]:
    """Replay one CVE's audit JSONL through the recovery detector; return emits."""
    state = _make_state()
    emits: list[AuditEntry] = []
    with path.open() as fh:
        for line in fh:
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if row.get("status") not in ("tool_ok", "tool_error"):
                continue
            entry = detect(
                state,
                tool_name=row["tool_name"],
                turn=row["turn"],
                tool_status=row["status"],
                tool_result=row.get("tool_result"),
            )
            if entry is not None:
                emits.append(entry)
    return emits


def test_replay_phase23_canonical_cves():
    """Replay 3 canonical Phase-23 audit JSONLs.

    Empirical recoveries (re-derived 2026-05-13 from bench50-20260513-053526):
      - CVE-2024-0229: 2 recoveries — docker_build T32 (gap=9, errors=2)
        + verify T40 (gap=3, errors=1)
      - CVE-2024-0668: 1 recovery — verify T60 (gap=5, errors=6)
        (the canonical verify-iteration win)
      - CVE-2024-1061: 1 recovery — verify T89 (gap=18, errors=5)
        (also a verify-iteration win at the edge of K=20)
    """
    detect = _try_import_detector()
    assert detect is not None
    bench = _PHASE_23_AUDIT_ROOT / "bench50-20260513-053526"
    if not bench.exists():
        pytest.skip(f"Phase 23 audit corpus not present at {bench}")
    candidates: dict[str, list[Path]] = {
        "CVE-2024-0229": list(bench.glob("manual-*/CVE-2024-0229.jsonl")),
        "CVE-2024-0668": list(bench.glob("manual-*/CVE-2024-0668.jsonl")),
        "CVE-2024-1061": list(bench.glob("manual-*/CVE-2024-1061.jsonl")),
    }
    found: dict[str, list[AuditEntry]] = {}
    for cve, paths in candidates.items():
        if not paths:
            pytest.skip(f"audit JSONL for {cve} not found in {bench}")
        found[cve] = _replay_audit_jsonl(detect, paths[0])

    # CVE-2024-0229: docker_build (T32) + verify (T40)
    assert len(found["CVE-2024-0229"]) == 2, found["CVE-2024-0229"]
    tools_0229 = {e.tool_name for e in found["CVE-2024-0229"]}
    assert tools_0229 == {"docker_build", "verify"}
    dbuild = next(e for e in found["CVE-2024-0229"] if e.tool_name == "docker_build")
    assert dbuild.tool_result["stage"] == "ACQUIRE"
    assert dbuild.tool_result["errors_in_window"] == 2

    # CVE-2024-0668: 1 verify-iteration recovery (passed=False×6 → passed=True)
    assert len(found["CVE-2024-0668"]) == 1, found["CVE-2024-0668"]
    e = found["CVE-2024-0668"][0]
    assert e.tool_name == "verify"
    assert e.tool_result["stage"] == "VERIFY"
    assert e.tool_result["errors_in_window"] >= 5

    # CVE-2024-1061: 1 verify recovery (passed=False×5 → passed=True at T89)
    assert len(found["CVE-2024-1061"]) == 1, found["CVE-2024-1061"]
    e = found["CVE-2024-1061"][0]
    assert e.tool_name == "verify"
    assert e.tool_result["stage"] == "VERIFY"
    assert e.tool_result["errors_in_window"] >= 4


def test_replay_phase33_canonical_distribution():
    """Phase 33.T.4 — Replay all 8 in-scope benches (2026-05-14+) and
    assert canonical recovery distribution.

    Per Phase 33.1 reconciled artifact `artifact.md:112`:
    - 54 recovery events / 35 episodes

    Per Phase 33.2a-RECONCILE Anomaly 8 + Phase 33.3 Cat 3 R2:
    - verify=27 (50.0%), docker_build=14 (25.9%),
      image_resolve=5 (9.3%), dockerfile_gen=5 (9.3%),
      run_in_container=3 (5.6%)

    Per Phase 33.2a-RECONCILE Anomaly 8 stage distribution:
    - VERIFY=27, ACQUIRE=19, RESOLVE=5, LAUNCH=3 (total 54)

    Per gap distribution: 36 of 54 events (66.7%) at gap=3 (detector floor).
    """
    detect = _try_import_detector()
    assert detect is not None

    BENCHES_IN_SCOPE = [
        "bench50-20260514-051249",
        "bench50-20260514-054533",
        "bench50-20260514-055517",
        "bench50-20260514-065709",
        "bench50-20260514-124834",
        "bench50-20260514-234443",
        "bench50-20260514-235030",
        "bench50-20260515-014156",
    ]

    from collections import Counter

    all_emits: list[AuditEntry] = []
    audit_root = Path(__file__).resolve().parents[2] / "output" / "agentic"
    for bench_id in BENCHES_IN_SCOPE:
        bench_dir = audit_root / bench_id
        if not bench_dir.exists():
            pytest.skip(f"audit corpus missing: {bench_dir}")
        for jsonl in bench_dir.glob("manual-*/CVE-*.jsonl"):
            all_emits.extend(_replay_audit_jsonl(detect, jsonl))

    # Canonical totals
    assert len(all_emits) == 54, (
        f"Expected 54 recovery events; got {len(all_emits)}. "
        f"Per 33.1 reconciled artifact line 112."
    )

    # Tool distribution
    by_tool = Counter(e.tool_name for e in all_emits)
    expected_by_tool = {
        "verify": 27,
        "docker_build": 14,
        "image_resolve": 5,
        "dockerfile_gen": 5,
        "run_in_container": 3,
    }
    assert dict(by_tool) == expected_by_tool, (
        f"Tool distribution drift: expected {expected_by_tool}, got {dict(by_tool)}"
    )

    # Stage distribution
    by_stage = Counter(e.tool_result.get("stage", "?") for e in all_emits)
    expected_by_stage = {
        "VERIFY": 27,
        "ACQUIRE": 19,
        "RESOLVE": 5,
        "LAUNCH": 3,
    }
    assert dict(by_stage) == expected_by_stage, (
        f"Stage distribution drift: expected {expected_by_stage}, got {dict(by_stage)}"
    )

    # Gap distribution: 36 of 54 at gap=3
    gap_counts = Counter(e.tool_result.get("gap") for e in all_emits)
    assert gap_counts[3] == 36, (
        f"Expected 36 events at gap=3; got {gap_counts[3]}. "
        f"Per 33.2a-RECONCILE Anomaly 8."
    )

    # Episode count: 35 distinct (cve_id, bench_id) pairs
    # (per-CVE-per-bench episodes that emit ≥1 recovery)
    # The AuditEntry doesn't carry cve_id/bench_id directly; episode count
    # is structural via the upstream walker. We assert via event count only;
    # episode_count is upstream-canonical (35) per artifact.md:112.


def test_replay_phase36_38_canonical_distribution() -> None:
    """Phase 41 (2026-05-16) — extend canonical replay to post-Phase-33 era.

    Adds 2 benches not in Phase 33.T.4's original 8-bench scope:
    - bench50-20260516-053221 (Phase 36 partial — 1 finished CVE)
    - bench50-20260516-103837 (Phase 38 full 50-CVE bench)

    This test is the regression-lock for Phase 38's recovery telemetry
    distribution. If the detector's algorithm changes, the canonical counts
    below will drift and this test surfaces it before downstream analysis
    builds on stale numbers.

    Canonical distribution (derived via _replay_audit_jsonl on the 2 benches,
    2026-05-16):
    - 52 total events / 25 distinct CVEs
    - By tool: docker_build=25, docker_run=9, verify=6, image_resolve=6,
      dockerfile_gen=3, docker_compose_up=3
    - By stage: ACQUIRE=28, LAUNCH=12, VERIFY=6, RESOLVE=6 (total 52)
    - Most-common gap: gap=3 (21 events = 40%)

    Note: distribution shape differs from Phase 33 era (which had verify=27
    dominant, ACQUIRE=19). Phase 38's data shows docker_build=25 dominant
    (most build-retry recoveries) and ACQUIRE=28 — different bench corpus,
    different failure-mode mix. Both are valid distributions; this test
    locks Phase 36+38 era as the new canonical.
    """
    detect = _try_import_detector()
    assert detect is not None

    BENCHES_IN_SCOPE = [
        "bench50-20260516-053221",  # Phase 36 partial
        "bench50-20260516-103837",  # Phase 38 full 50-CVE
    ]

    from collections import Counter

    all_emits: list[AuditEntry] = []
    audit_root = Path(__file__).resolve().parents[2] / "output" / "agentic"
    for bench_id in BENCHES_IN_SCOPE:
        bench_dir = audit_root / bench_id
        if not bench_dir.exists():
            pytest.skip(f"audit corpus missing: {bench_dir}")
        for jsonl in bench_dir.glob("manual-*/CVE-*.jsonl"):
            all_emits.extend(_replay_audit_jsonl(detect, jsonl))

    # Canonical total
    assert len(all_emits) == 52, (
        f"Expected 52 recovery events; got {len(all_emits)}. "
        f"If intentional, update this test's canonical numbers."
    )

    # Tool distribution
    by_tool = Counter(e.tool_name for e in all_emits)
    expected_by_tool = {
        "docker_build": 25,
        "docker_run": 9,
        "verify": 6,
        "image_resolve": 6,
        "dockerfile_gen": 3,
        "docker_compose_up": 3,
    }
    assert dict(by_tool) == expected_by_tool, (
        f"Tool distribution drift: expected {expected_by_tool}, got {dict(by_tool)}"
    )

    # Stage distribution
    by_stage = Counter(e.tool_result.get("stage", "?") for e in all_emits)
    expected_by_stage = {
        "ACQUIRE": 28,
        "LAUNCH": 12,
        "VERIFY": 6,
        "RESOLVE": 6,
    }
    assert dict(by_stage) == expected_by_stage, (
        f"Stage distribution drift: expected {expected_by_stage}, got {dict(by_stage)}"
    )

    # Most-common gap
    gap_counts = Counter(e.tool_result.get("gap") for e in all_emits)
    assert gap_counts[3] == 21, (
        f"Expected 21 events at gap=3 (detector floor); got {gap_counts[3]}. "
        f"This is the modal gap — ~40% of recoveries fire at the minimum window."
    )

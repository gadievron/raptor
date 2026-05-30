"""Tests for ``core.llm.scorecard.cli`` — the user-facing CLI for
inspecting and maintaining the scorecard.

These exercise the rendering + filter logic over a seeded scorecard.
They don't shell out — we drive the parsed argparse Namespace
directly via ``cmd_*`` for fast feedback. End-to-end shim
invocation is covered by a small smoke test below.
"""

from __future__ import annotations

import datetime as _dt
import io
import os
import subprocess
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace

import pytest

from core.llm.scorecard import EventType, ModelScorecard
from core.llm.scorecard import cli as cli_mod


# ---------------------------------------------------------------------------
# Fixture: a richly-populated scorecard
# ---------------------------------------------------------------------------


@pytest.fixture
def seeded_scorecard(tmp_path):
    """Three cells across two models so the renderers have
    something representative to work with: trustworthy, learning,
    and fall-through."""
    path = tmp_path / "sc.json"
    sc = ModelScorecard(path)

    # trustworthy
    for _ in range(100):
        sc.record_event(
            "codeql:py/sql-injection", "claude-haiku-4-5",
            EventType.CHEAP_SHORT_CIRCUIT, "correct",
        )
    # learning (n<10)
    for _ in range(5):
        sc.record_event(
            "codeql:cpp/uncontrolled-format", "claude-haiku-4-5",
            EventType.CHEAP_SHORT_CIRCUIT, "correct",
        )
    # fall-through (high miss rate) + samples
    for _ in range(20):
        sc.record_event(
            "codeql:js/path-injection", "claude-haiku-4-5",
            EventType.CHEAP_SHORT_CIRCUIT, "correct",
        )
    for i in range(5):
        sc.record_event(
            "codeql:js/path-injection", "claude-haiku-4-5",
            EventType.CHEAP_SHORT_CIRCUIT, "incorrect",
            sample={
                "this_reasoning": f"cheap thought FP {i}",
                "other_reasoning": f"full found real bug {i}",
            },
        )
    # second model
    for _ in range(50):
        sc.record_event(
            "codeql:py/sql-injection", "gemini-2.5-flash-lite",
            EventType.CHEAP_SHORT_CIRCUIT, "correct",
        )
    return path


def _make_args(**kwargs):
    """Build a Namespace with the union of all defaults the CLI
    handlers expect; tests override specific fields."""
    base = dict(
        path=None, by_savings=False, by_miss_rate=False, by_cost=False,
        untrusted=False, learning=False, consumer=None, since=None,
        model_a=None, model_b=None,
        decision_class=None, model=None, as_=None,
        older_than_days=None, all=False,
        outcome=None, note=None,
        event_type=EventType.CHEAP_SHORT_CIRCUIT,
        freshness_half_life_days=None, half_life_days=None,
        json=False,
    )
    base.update(kwargs)
    return SimpleNamespace(**base)


def _capture(handler, args):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        rc = handler(args)
    return rc, out.getvalue(), err.getvalue()


# ---------------------------------------------------------------------------
# list
# ---------------------------------------------------------------------------


def test_list_default_shows_all_cells(seeded_scorecard):
    rc, out, _ = _capture(
        cli_mod.cmd_list, _make_args(path=seeded_scorecard),
    )
    assert rc == 0
    # All three decision_classes appear.
    assert "codeql:py/sql-injection" in out
    assert "codeql:cpp/uncontrolled-format" in out
    assert "codeql:js/path-injection" in out


def test_list_default_event_type_renders_calls_saved_column(seeded_scorecard):
    """Default behaviour is unchanged: column header is
    ``calls_saved`` because the event slot is the cheap-tier."""
    rc, out, _ = _capture(
        cli_mod.cmd_list, _make_args(path=seeded_scorecard),
    )
    assert rc == 0
    assert "calls_saved" in out
    # Generic name only appears under non-cheap event types.
    assert "| correct " not in out


def test_list_event_type_renames_correct_column(seeded_scorecard):
    """Selecting a non-cheap event slot relabels the column to
    ``correct`` (panel-counter semantics, not call-savings)."""
    rc, out, _ = _capture(
        cli_mod.cmd_list,
        _make_args(
            path=seeded_scorecard,
            event_type=EventType.REASONING_DIVERGENCE,
        ),
    )
    assert rc == 0
    assert "correct" in out
    assert "calls_saved" not in out


def test_list_event_type_reflects_chosen_slot_counts(seeded_scorecard, tmp_path):
    """``n`` and ``correct`` columns track the chosen event slot.

    Seed the scorecard with REASONING_DIVERGENCE events on a fresh
    cell, then assert those numbers surface only when
    ``--event-type reasoning_divergence`` is selected — and the
    cheap-tier view stays at zero on this cell.
    """
    sc = ModelScorecard(seeded_scorecard)
    dc = "agentic:py/test-rule"
    for _ in range(7):
        sc.record_event(
            dc, "gemini-2.5-pro",
            EventType.REASONING_DIVERGENCE, "correct",
        )
    for _ in range(3):
        sc.record_event(
            dc, "gemini-2.5-pro",
            EventType.REASONING_DIVERGENCE, "incorrect",
        )
    # Default cheap-tier view: cell is brand new on the cheap slot,
    # so n should be 0 for it.
    rc, out_cheap, _ = _capture(
        cli_mod.cmd_list,
        _make_args(path=seeded_scorecard, consumer="agentic"),
    )
    assert rc == 0
    cheap_row = next(
        (line for line in out_cheap.splitlines()
         if dc in line and "gemini-2.5-pro" in line),
        None,
    )
    assert cheap_row is not None, out_cheap
    # Non-cheap view: 10 total events, 7 correct.
    rc, out_div, _ = _capture(
        cli_mod.cmd_list,
        _make_args(
            path=seeded_scorecard, consumer="agentic",
            event_type=EventType.REASONING_DIVERGENCE,
        ),
    )
    assert rc == 0
    div_row = next(
        (line for line in out_div.splitlines()
         if dc in line and "gemini-2.5-pro" in line),
        None,
    )
    assert div_row is not None, out_div
    # n column = 10 ; correct column = 7 should appear in the row.
    cells = [c.strip() for c in div_row.split("|")]
    assert "10" in cells
    assert "7" in cells


def test_list_invalid_event_type_rejected_at_argparse(seeded_scorecard):
    """argparse choices=ALL_EVENT_TYPES rejects unknown values
    before they reach the handler."""
    parser = cli_mod._build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["list", "--event-type", "bogus_slot"])


def test_list_by_savings_sorts_descending(seeded_scorecard):
    rc, out, _ = _capture(
        cli_mod.cmd_list,
        _make_args(path=seeded_scorecard, by_savings=True),
    )
    lines = [line for line in out.splitlines() if "codeql:" in line]
    # Highest calls_saved (py/sql-injection on haiku, 100) should
    # appear before js/path-injection (20).
    py_idx = next(i for i, line in enumerate(lines) if "py/sql-injection" in line and "claude" in line)
    js_idx = next(i for i, line in enumerate(lines) if "js/path-injection" in line)
    assert py_idx < js_idx


def test_list_untrusted_filters_to_fall_through_only(seeded_scorecard):
    rc, out, _ = _capture(
        cli_mod.cmd_list,
        _make_args(path=seeded_scorecard, untrusted=True),
    )
    # Only the js/path-injection cell on Haiku is fall-through.
    assert "js/path-injection" in out
    # py/sql-injection (haiku) is short-circuit, must not appear.
    haiku_py_lines = [
        line for line in out.splitlines()
        if "py/sql-injection" in line and "claude-haiku-4-5" in line
    ]
    assert haiku_py_lines == []


def test_list_learning_filters_to_below_floor_only(seeded_scorecard):
    rc, out, _ = _capture(
        cli_mod.cmd_list,
        _make_args(path=seeded_scorecard, learning=True),
    )
    assert "cpp/uncontrolled-format" in out
    assert "py/sql-injection" not in out


def test_list_consumer_filter_prefix_matches(seeded_scorecard):
    """Cells starting with ``codeql:`` match ``--consumer codeql``.
    Defends the operator's expectation that prefix-filtering works
    without trailing colons."""
    rc, out, _ = _capture(
        cli_mod.cmd_list,
        _make_args(path=seeded_scorecard, consumer="codeql"),
    )
    assert "codeql:py/sql-injection" in out


def test_list_consumer_filter_excludes_other_prefixes(seeded_scorecard):
    """A scorecard with both codeql and (synthetic) sca cells →
    --consumer codeql shows only codeql."""
    sc = ModelScorecard(seeded_scorecard)
    sc.record_event(
        "sca:major_bump:PyPI", "claude-haiku-4-5",
        EventType.CHEAP_SHORT_CIRCUIT, "correct",
    )
    rc, out, _ = _capture(
        cli_mod.cmd_list,
        _make_args(path=seeded_scorecard, consumer="codeql"),
    )
    assert "sca:major_bump" not in out
    assert "codeql:py/sql-injection" in out


# ---------------------------------------------------------------------------
# compare
# ---------------------------------------------------------------------------


def test_compare_shows_overlap_only(seeded_scorecard):
    """``compare`` only shows decision_classes BOTH models have
    seen — comparing where there's no shared evidence is
    misleading."""
    rc, out, _ = _capture(
        cli_mod.cmd_compare,
        _make_args(
            path=seeded_scorecard,
            model_a="claude-haiku-4-5",
            model_b="gemini-2.5-flash-lite",
        ),
    )
    assert "codeql:py/sql-injection" in out
    # cpp/uncontrolled-format and js/path-injection were only seen
    # by haiku — must not appear in the comparison output.
    assert "cpp/uncontrolled-format" not in out
    assert "js/path-injection" not in out


def test_compare_no_overlap_returns_helpful_message(seeded_scorecard):
    rc, out, _ = _capture(
        cli_mod.cmd_compare,
        _make_args(
            path=seeded_scorecard,
            model_a="claude-haiku-4-5",
            model_b="some-model-no-data",
        ),
    )
    assert "no decision_classes" in out


# ---------------------------------------------------------------------------
# samples
# ---------------------------------------------------------------------------


def test_samples_renders_disagreements(seeded_scorecard):
    rc, out, _ = _capture(
        cli_mod.cmd_samples,
        _make_args(
            path=seeded_scorecard,
            decision_class="codeql:js/path-injection",
        ),
    )
    assert rc == 0
    assert "Sample 1" in out
    assert "cheap thought FP" in out
    assert "full found real bug" in out


def test_samples_unknown_class_returns_nonzero(seeded_scorecard):
    rc, out, err = _capture(
        cli_mod.cmd_samples,
        _make_args(path=seeded_scorecard, decision_class="nope:nope"),
    )
    assert rc == 1


# ---------------------------------------------------------------------------
# pin / unpin
# ---------------------------------------------------------------------------


def test_pin_sets_policy_override(seeded_scorecard):
    args = _make_args(
        path=seeded_scorecard,
        decision_class="codeql:py/sql-injection",
        model="claude-haiku-4-5",
        as_="force_fall_through",
    )
    _capture(cli_mod.cmd_pin, args)
    sc = ModelScorecard(seeded_scorecard)
    stat = sc.get_stat("codeql:py/sql-injection", "claude-haiku-4-5")
    assert stat.policy_override == "force_fall_through"


def test_pin_friendly_value_maps_to_storage(seeded_scorecard):
    """The ergonomic `--as short-circuit` (matching the `list` policy vocab)
    maps to the internal `force_short_circuit` storage value — on-disk format
    and verdict comparisons are unchanged."""
    args = _make_args(
        path=seeded_scorecard,
        decision_class="codeql:py/sql-injection",
        model="claude-haiku-4-5",
        as_="short-circuit",
    )
    _capture(cli_mod.cmd_pin, args)
    sc = ModelScorecard(seeded_scorecard)
    stat = sc.get_stat("codeql:py/sql-injection", "claude-haiku-4-5")
    assert stat.policy_override == "force_short_circuit"


def test_prefix_filters_by_decision_class():
    """`--prefix` is the decision_class prefix filter (renamed from the jargon
    `--consumer`)."""
    parser = cli_mod._build_parser()
    assert parser.parse_args(["list", "--prefix", "codeql"]).consumer == "codeql"


def test_unpin_releases_to_auto(seeded_scorecard):
    sc = ModelScorecard(seeded_scorecard)
    sc.set_policy_override(
        "codeql:py/sql-injection", "claude-haiku-4-5",
        "force_short_circuit",
    )
    args = _make_args(
        path=seeded_scorecard,
        decision_class="codeql:py/sql-injection",
        model="claude-haiku-4-5",
    )
    _capture(cli_mod.cmd_unpin, args)
    stat = sc.get_stat("codeql:py/sql-injection", "claude-haiku-4-5")
    assert stat.policy_override == "auto"


# ---------------------------------------------------------------------------
# reset
# ---------------------------------------------------------------------------


def test_reset_single_decision_class(seeded_scorecard):
    args = _make_args(
        path=seeded_scorecard,
        decision_class="codeql:py/sql-injection",
    )
    rc, _, err = _capture(cli_mod.cmd_reset, args)
    assert rc == 0
    sc = ModelScorecard(seeded_scorecard)
    remaining = {s.decision_class for s in sc.get_stats()}
    assert "codeql:py/sql-injection" not in remaining


def test_reset_by_model(seeded_scorecard):
    args = _make_args(path=seeded_scorecard, model="claude-haiku-4-5")
    rc, _, _ = _capture(cli_mod.cmd_reset, args)
    sc = ModelScorecard(seeded_scorecard)
    remaining = {(s.model, s.decision_class) for s in sc.get_stats()}
    assert all(m != "claude-haiku-4-5" for (m, _) in remaining)


def test_reset_all(seeded_scorecard):
    args = _make_args(path=seeded_scorecard, all=True)
    _capture(cli_mod.cmd_reset, args)
    sc = ModelScorecard(seeded_scorecard)
    assert sc.get_stats() == []


# ---------------------------------------------------------------------------
# mark — operator_feedback producer
# ---------------------------------------------------------------------------


def test_mark_correct_records_operator_feedback(seeded_scorecard):
    args = _make_args(
        path=seeded_scorecard,
        decision_class="codeql:py/sql-injection",
        model="claude-haiku-4-5",
        outcome="correct",
    )
    rc, _, err = _capture(cli_mod.cmd_mark, args)
    assert rc == 0
    assert "operator_feedback 'correct'" in err
    sc = ModelScorecard(seeded_scorecard)
    stat = sc.get_stat("codeql:py/sql-injection", "claude-haiku-4-5")
    from core.llm.scorecard.scorecard import EventType
    assert stat.events[EventType.OPERATOR_FEEDBACK].correct == 1
    assert stat.events[EventType.OPERATOR_FEEDBACK].incorrect == 0


def test_mark_incorrect_records_and_attaches_note(seeded_scorecard):
    args = _make_args(
        path=seeded_scorecard,
        decision_class="codeql:py/sql-injection",
        model="claude-haiku-4-5",
        outcome="incorrect",
        note="Verified false positive — sanitiser was applied upstream.",
    )
    rc, _, _ = _capture(cli_mod.cmd_mark, args)
    assert rc == 0
    sc = ModelScorecard(seeded_scorecard)
    stat = sc.get_stat("codeql:py/sql-injection", "claude-haiku-4-5")
    from core.llm.scorecard.scorecard import EventType
    assert stat.events[EventType.OPERATOR_FEEDBACK].incorrect == 1
    # Note attached to the disagreement-samples log on incorrect.
    notes = [s.get("note") for s in stat.disagreement_samples
             if s.get("event_type") == EventType.OPERATOR_FEEDBACK]
    assert "sanitiser was applied upstream" in (notes[0] or "")


def test_mark_correct_with_note_does_not_attach_note(seeded_scorecard):
    """retain_samples policy: notes only kept on incorrect outcomes
    (mirrors the cheap/full producer's behaviour). Correct + note is
    accepted but the note doesn't accumulate — keeps the cell from
    becoming an operator notebook."""
    args = _make_args(
        path=seeded_scorecard,
        decision_class="codeql:py/sql-injection",
        model="claude-haiku-4-5",
        outcome="correct",
        note="great catch",
    )
    _capture(cli_mod.cmd_mark, args)
    sc = ModelScorecard(seeded_scorecard)
    stat = sc.get_stat("codeql:py/sql-injection", "claude-haiku-4-5")
    correct_notes = [s for s in stat.disagreement_samples
                     if s.get("note") == "great catch"]
    assert correct_notes == []


def test_mark_creates_cell_when_absent(seeded_scorecard):
    """The cell may not yet exist (operator marking a finding before
    the model has any cheap-tier history). ``record_event`` creates
    it on demand."""
    args = _make_args(
        path=seeded_scorecard,
        decision_class="codeql:py/never-seen",
        model="brand-new-model",
        outcome="correct",
    )
    _capture(cli_mod.cmd_mark, args)
    sc = ModelScorecard(seeded_scorecard)
    stat = sc.get_stat("codeql:py/never-seen", "brand-new-model")
    from core.llm.scorecard.scorecard import EventType
    assert stat.events[EventType.OPERATOR_FEEDBACK].correct == 1


def test_mark_does_not_pollute_cheap_short_circuit_counters(seeded_scorecard):
    """Operator feedback is its own counter; the prefilter gate's
    Wilson math runs over CHEAP_SHORT_CIRCUIT only. Marking does
    NOT shift the auto-policy decision."""
    sc = ModelScorecard(seeded_scorecard)
    from core.llm.scorecard.scorecard import EventType
    before = sc.get_stat("codeql:py/sql-injection", "claude-haiku-4-5")
    before_cheap = (
        before.events[EventType.CHEAP_SHORT_CIRCUIT].correct,
        before.events[EventType.CHEAP_SHORT_CIRCUIT].incorrect,
    )
    args = _make_args(
        path=seeded_scorecard,
        decision_class="codeql:py/sql-injection",
        model="claude-haiku-4-5",
        outcome="incorrect",
    )
    _capture(cli_mod.cmd_mark, args)
    after = sc.get_stat("codeql:py/sql-injection", "claude-haiku-4-5")
    after_cheap = (
        after.events[EventType.CHEAP_SHORT_CIRCUIT].correct,
        after.events[EventType.CHEAP_SHORT_CIRCUIT].incorrect,
    )
    assert before_cheap == after_cheap


def test_mark_emits_typo_notice_on_new_cell(seeded_scorecard):
    """Adversarial: catch decision_class / --model typos that would
    silently create a fresh cell no producer touches. Soft notice
    rather than refusal — operator may legitimately be marking a
    brand-new finding."""
    args = _make_args(
        path=seeded_scorecard,
        decision_class="codeql:py/typo-class",  # no prior events
        model="brand-new-model",
        outcome="correct",
    )
    rc, _, err = _capture(cli_mod.cmd_mark, args)
    assert rc == 0
    assert "no prior events" in err
    assert "typo" in err


def test_mark_no_notice_on_existing_cell(seeded_scorecard):
    """Marking a cell with prior history → no typo notice (it's
    clearly the right cell). Reduces operator-friction on the
    expected case."""
    # seeded_scorecard already has codeql:py/sql-injection on
    # claude-haiku-4-5 with cheap-tier history.
    args = _make_args(
        path=seeded_scorecard,
        decision_class="codeql:py/sql-injection",
        model="claude-haiku-4-5",
        outcome="correct",
    )
    rc, _, err = _capture(cli_mod.cmd_mark, args)
    assert rc == 0
    assert "no prior events" not in err


def test_mark_invalid_outcome_rejected(seeded_scorecard):
    """``outcome`` must be ``correct`` or ``incorrect`` —
    ``record_event`` raises on anything else. The argparse ``choices=``
    layer is the first defence; this test pins the substrate-side
    validation that catches direct API misuse."""
    import pytest
    args = _make_args(
        path=seeded_scorecard,
        decision_class="codeql:py/sql-injection",
        model="claude-haiku-4-5",
        outcome="maybe",
    )
    with pytest.raises(ValueError, match="outcome must be"):
        _capture(cli_mod.cmd_mark, args)


# ---------------------------------------------------------------------------
# Smoke test: the shim actually executes
# ---------------------------------------------------------------------------


def test_libexec_shim_runs(tmp_path):
    """End-to-end: the shim is executable and dispatches to the CLI.
    Empty scorecard → "(no scorecard data)" message.

    Sets ``_RAPTOR_TRUSTED=1`` to bypass the inline trust-marker
    check the shim shares with every libexec script — that gate is
    designed to refuse bare-shell invocation but allow tests."""
    repo_root = Path(__file__).resolve().parents[4]
    shim = repo_root / "libexec" / "raptor-llm-scorecard"
    if not shim.exists():
        pytest.skip("shim not present (running outside the repo)")
    sc_path = tmp_path / "empty.json"
    env = {**os.environ, "_RAPTOR_TRUSTED": "1"}
    out = subprocess.run(
        [str(shim), "--path", str(sc_path), "list"],
        capture_output=True, text=True, timeout=10, env=env,
    )
    assert out.returncode == 0, out.stderr
    assert "no scorecard data" in out.stdout


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def test_parse_since_durations():
    assert cli_mod._parse_since("7d") == _dt.timedelta(days=7)
    assert cli_mod._parse_since("12h") == _dt.timedelta(hours=12)
    assert cli_mod._parse_since("30m") == _dt.timedelta(minutes=30)
    assert cli_mod._parse_since("90s") == _dt.timedelta(seconds=90)


def test_parse_since_rejects_garbage():
    import argparse
    with pytest.raises(argparse.ArgumentTypeError):
        cli_mod._parse_since("abc")


def test_humanise_age_recent():
    now = _dt.datetime(2026, 5, 6, 12, 0, 0, tzinfo=_dt.timezone.utc)
    ten_min_ago = (now - _dt.timedelta(minutes=10)).isoformat()
    assert cli_mod._humanise_age(ten_min_ago, now=now) == "10m ago"


def test_humanise_age_days():
    now = _dt.datetime(2026, 5, 6, 12, 0, 0, tzinfo=_dt.timezone.utc)
    three_days_ago = (now - _dt.timedelta(days=3, hours=2)).isoformat()
    assert cli_mod._humanise_age(three_days_ago, now=now) == "3d ago"


# ---------------------------------------------------------------------------
# freshness
# ---------------------------------------------------------------------------


def _write_freshness_fixture(path):
    """A cell trusted unweighted (stale correct dominates) but untrusted under
    freshness (recent failures dominate)."""
    import json

    from core.llm.scorecard.freshness import bucket_key

    now = _dt.datetime.now(_dt.timezone.utc)
    cur = bucket_key(now)
    stale = f"{now.year - 2:04d}-{now.month:02d}"
    fixture = {"version": 2, "models": {"haiku": {"codeql:py/sqli": {
        "first_seen_at": f"{stale}-01T00:00:00+00:00",
        "last_seen_at": f"{cur}-01T00:00:00+00:00",
        "model_version": "", "policy_override": "auto",
        "events": {
            "cheap_short_circuit": {cur: {"correct": 0, "incorrect": 18},
                                    stale: {"correct": 4000, "incorrect": 0}},
            "multi_model_consensus": {}, "judge_review": {},
            "tool_evidence": {}, "operator_feedback": {},
        },
        "disagreement_samples": [],
    }}}}
    path.write_text(json.dumps(fixture), encoding="utf-8")
    return path


def test_list_freshness_flag_reweights_policy(tmp_path):
    """`list --freshness-half-life-days` reflects recent behaviour: the cell is
    trusted unweighted but falls through once the stale data decays away."""
    path = _write_freshness_fixture(tmp_path / "sc.json")
    _, out_off, _ = _capture(cli_mod.cmd_list, _make_args(path=path))
    assert "short-circuit" in out_off
    _, out_on, _ = _capture(
        cli_mod.cmd_list, _make_args(path=path, freshness_half_life_days=30))
    assert "fall-through" in out_on
    # the freshness view appends an inline impact footer (folded-in what-if)
    assert "fall out of short-circuit" in out_on


def test_list_shows_calls_column(tmp_path):
    """`list` surfaces the per-model usage count, so a used-but-unscored model
    is visible with its call volume."""
    sc = ModelScorecard(tmp_path / "sc.json")
    sc.register_uses([{"model": "haiku", "decision_class": "_usage", "calls": 7}])
    rc, out, _ = _capture(cli_mod.cmd_list, _make_args(path=tmp_path / "sc.json"))
    assert rc == 0
    assert "calls" in out                          # the new column header
    assert "_usage" in out and "haiku" in out and "7" in out


def test_list_freshness_shows_drift_marker_on_regression(tmp_path):
    """When --freshness flips a cell from short-circuit -> fall-through, the
    policy column gets a ↓ drift marker — the silent-regression signal."""
    path = _write_freshness_fixture(tmp_path / "sc.json")
    _, out, _ = _capture(
        cli_mod.cmd_list, _make_args(path=path, freshness_half_life_days=30))
    assert "↓ fall-through" in out


def test_list_no_drift_marker_without_freshness(tmp_path):
    """No drift markers in the default unweighted view (markers only make
    sense when comparing weighted vs baseline)."""
    path = _write_freshness_fixture(tmp_path / "sc.json")
    _, out, _ = _capture(cli_mod.cmd_list, _make_args(path=path))
    assert "↓" not in out and "↑" not in out


def test_recommend_picks_cheapest_trusted(tmp_path):
    """`recommend` ranks trusted models for a decision_class by cost-per-call
    and surfaces the cheapest — the actionable payoff of the scorecard."""
    sc = ModelScorecard(tmp_path / "sc.json", shadow_rate=0.0)
    # both models earn trust on codeql:py/sqli (n >= 73 clean keeps Wilson UB <= 5%)
    for _ in range(80):
        sc.record_event("codeql:py/sqli", "haiku",
                        EventType.CHEAP_SHORT_CIRCUIT, "correct")
        sc.record_event("codeql:py/sqli", "sonnet",
                        EventType.CHEAP_SHORT_CIRCUIT, "correct")
    # _usage cells set per-model spend (haiku cheap, sonnet 12x more)
    sc.register_uses([
        {"model": "haiku", "decision_class": "_usage",
         "calls": 100, "cost_usd": 0.10},
        {"model": "sonnet", "decision_class": "_usage",
         "calls": 100, "cost_usd": 1.20},
    ])
    rc, out, _ = _capture(
        cli_mod.cmd_recommend,
        _make_args(path=tmp_path / "sc.json",
                   decision_class="codeql:py/sqli"))
    assert rc == 0
    assert "use: haiku" in out                      # cheapest trusted wins
    assert "also trusted: sonnet" in out


def test_recommend_no_data_reports_clearly(tmp_path):
    """Unknown decision_class -> clear message, exit 0 (informational, not
    an error to operator scripts)."""
    sc = ModelScorecard(tmp_path / "sc.json")
    sc.register_uses([{"model": "haiku", "decision_class": "_usage",
                       "calls": 1, "cost_usd": 0.001}])
    rc, _, err = _capture(
        cli_mod.cmd_recommend,
        _make_args(path=tmp_path / "sc.json",
                   decision_class="codeql:py/unknown"))
    assert rc == 0
    assert "no scorecard data" in err


def test_recommend_handles_pinned_trusted_with_no_events(tmp_path):
    """A `force_short_circuit` pin with NO cheap_short_circuit events makes
    max_miss% None for a SHORT_CIRCUIT cell; recommend must format it
    gracefully (`max_miss=n/a`), not crash on `None.__format__`."""
    sc = ModelScorecard(tmp_path / "sc.json", shadow_rate=0.0)
    sc.set_policy_override("codeql:py/sqli", "haiku", "force_short_circuit")
    rc, out, _ = _capture(
        cli_mod.cmd_recommend,
        _make_args(path=tmp_path / "sc.json",
                   decision_class="codeql:py/sqli"))
    assert rc == 0
    assert "use: haiku" in out
    assert "max_miss=n/a" in out


def test_recommend_freshness_shows_banner(tmp_path):
    """When --freshness is set, the output header carries the half-life so a
    different recommendation than unweighted has a visible breadcrumb."""
    sc = ModelScorecard(tmp_path / "sc.json", shadow_rate=0.0)
    for _ in range(80):
        sc.record_event("codeql:py/sqli", "haiku",
                        EventType.CHEAP_SHORT_CIRCUIT, "correct")
    rc, out, _ = _capture(
        cli_mod.cmd_recommend,
        _make_args(path=tmp_path / "sc.json",
                   decision_class="codeql:py/sqli",
                   freshness_half_life_days=30))
    assert rc == 0
    assert "freshness half-life 30d" in out


def test_list_shows_cost_column_and_by_cost_sorts(tmp_path):
    """`list` surfaces per-cell spend in the $$ column, and `--by-cost` ranks
    by it. The cost data is the universal 'did I get value for money' axis."""
    sc = ModelScorecard(tmp_path / "sc.json")
    sc.register_uses([
        {"model": "haiku", "decision_class": "_usage",
         "calls": 10, "cost_usd": 0.05},
        {"model": "sonnet", "decision_class": "_usage",
         "calls": 4, "cost_usd": 0.40},
    ])
    rc, out, _ = _capture(cli_mod.cmd_list, _make_args(path=tmp_path / "sc.json"))
    assert rc == 0
    assert "$$" in out                              # the cost column header
    assert "$0.40" in out and "$0.05" in out        # both cells render their spend
    # --by-cost ranks sonnet ($0.40) above haiku ($0.05)
    rc2, out2, _ = _capture(
        cli_mod.cmd_list, _make_args(path=tmp_path / "sc.json", by_cost=True))
    assert rc2 == 0
    assert out2.index("sonnet") < out2.index("haiku")


def test_bare_invocation_defaults_to_list(seeded_scorecard):
    """A bare `raptor-llm-scorecard` (no subcommand) runs `list` instead of
    erroring — so `/scorecard` is fast and useful by default."""
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        rc = cli_mod.main(["--path", str(seeded_scorecard)])
    assert rc == 0
    text = out.getvalue()
    assert "decision_class" in text                 # the list-table header rendered
    assert "-h" in text                             # discoverability footer -> -h


# ---------------------------------------------------------------------------
# enhancements (--json, summary, compare extension)
# ---------------------------------------------------------------------------


def _seed_minimal(path):
    """A small scorecard fixture: trusted haiku on codeql:py/sqli + usage cell
    + an untrusted sonnet cell — enough to exercise summary/recommend/list."""
    sc = ModelScorecard(path, shadow_rate=0.0)
    for _ in range(80):
        sc.record_event("codeql:py/sqli", "haiku",
                        EventType.CHEAP_SHORT_CIRCUIT, "correct")
    sc.register_uses([
        {"model": "haiku", "decision_class": "_usage",
         "calls": 100, "cost_usd": 0.10},
        {"model": "sonnet", "decision_class": "_usage",
         "calls": 5, "cost_usd": 0.50},
    ])
    return path


def test_list_json_emits_parseable_array(tmp_path):
    """`list --json` emits JSON that downstream scripts can parse — and the
    cells carry every field we render in the table (n / max_miss / cost / etc.)."""
    import json as _json
    _seed_minimal(tmp_path / "sc.json")
    rc, out, _ = _capture(
        cli_mod.cmd_list, _make_args(path=tmp_path / "sc.json", json=True))
    assert rc == 0
    parsed = _json.loads(out)
    assert isinstance(parsed.get("cells"), list) and parsed["cells"]
    sample = parsed["cells"][0]
    for required in (
        "decision_class", "model", "policy", "n",
        "calls", "cost_usd", "max_miss_pct", "last_seen_at",
    ):
        assert required in sample, f"missing {required} in {sample}"


def test_recommend_json_emits_recommendation(tmp_path):
    """`recommend --json` emits the structured recommendation + trusted list."""
    import json as _json
    _seed_minimal(tmp_path / "sc.json")
    rc, out, _ = _capture(
        cli_mod.cmd_recommend,
        _make_args(path=tmp_path / "sc.json",
                   decision_class="codeql:py/sqli", json=True))
    assert rc == 0
    parsed = _json.loads(out)
    assert parsed["decision_class"] == "codeql:py/sqli"
    assert parsed["recommendation"]["model"] == "haiku"
    assert any(t["model"] == "haiku" for t in parsed["short_circuit"])


def test_summary_text_dashboard(tmp_path):
    """The text summary surfaces total cells, policy breakdown, spend, and the
    cheapest-trusted line — the daily-driver view."""
    _seed_minimal(tmp_path / "sc.json")
    rc, out, _ = _capture(
        cli_mod.cmd_summary, _make_args(path=tmp_path / "sc.json"))
    assert rc == 0
    assert "cells:" in out and "trusted" in out
    assert "total spend:" in out
    assert "cheapest trusted: haiku" in out


def test_summary_json_dashboard(tmp_path):
    """`summary --json` shape: cells_total / policy_breakdown / spend_by_model /
    cheapest_trusted — parseable for dashboards."""
    import json as _json
    _seed_minimal(tmp_path / "sc.json")
    rc, out, _ = _capture(
        cli_mod.cmd_summary, _make_args(path=tmp_path / "sc.json", json=True))
    assert rc == 0
    parsed = _json.loads(out)
    assert parsed["cells_total"] > 0
    assert parsed["policy_breakdown"]["short_circuit"] >= 1
    assert parsed["cheapest_short_circuit"]["model"] == "haiku"


def test_compare_text_includes_cost_and_calls(tmp_path):
    """Extended `compare` shows $$ + calls per side, not just reliability."""
    _seed_minimal(tmp_path / "sc.json")
    # need a shared decision_class for both models — give sonnet a sql cell too
    sc = ModelScorecard(tmp_path / "sc.json", shadow_rate=0.0)
    for _ in range(80):
        sc.record_event("codeql:py/sqli", "sonnet",
                        EventType.CHEAP_SHORT_CIRCUIT, "correct")
    rc, out, _ = _capture(
        cli_mod.cmd_compare,
        _make_args(path=tmp_path / "sc.json",
                   model_a="haiku", model_b="sonnet"))
    assert rc == 0
    assert "haiku $$" in out and "sonnet $$" in out
    assert "haiku calls" in out and "sonnet calls" in out

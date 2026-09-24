"""Hypothesis seeding from context-map sink records.

A map-phase sink record can state a finding in all but name (a
redirect sink whose note names client-controllable headers reaching
the redirect base). The seeder must convert such records into
hint-tier ``injected_hypotheses`` on the matching gaps so the review
loop investigates them — and must dedup, cap, and never resurrect
dead gaps.
"""

from __future__ import annotations

from core.audit.map_seeds import (
    MAX_SEEDS_PER_GAP,
    SEED_SOURCE,
    seed_map_sink_hypotheses,
)


def _gap(file: str, name: str, lo: int = 1, hi: int = 50, **kw) -> dict:
    g = {"file": file, "name": name, "line_start": lo, "line_end": hi}
    g.update(kw)
    return g


def _redirect_map() -> dict:
    return {
        "sink_details": [{
            "id": "SINK-1",
            "type": "header_injection",
            "operation": 'header("Location: $redirect_url")',
            "file": "web/jump.src",
            "line": 61,
            "function": "top-level",
            "reaches_from": "base_url_for() (host headers) + params",
            "notes": (
                "Target host derives from client-controllable request "
                "headers — open-redirect surface."
            ),
        }],
    }


def test_reaches_from_function_gets_seeded_hypothesis():
    """The headline case: the sink record names the function whose
    review must test the reachability claim."""
    gaps = [
        _gap("lib/text.src", "base_url_for", 40, 90),
        _gap("lib/text.src", "unrelated", 1, 30),
    ]
    n = seed_map_sink_hypotheses(gaps, _redirect_map())
    assert n == 1
    hyps = gaps[0].get("injected_hypotheses")
    assert hyps and hyps[0]["source"] == SEED_SOURCE
    assert hyps[0]["confidence"] == "low"
    assert "SINK-1" in hyps[0]["mechanism"]
    assert "client-controllable" in hyps[0]["mechanism"]
    assert "injected_hypotheses" not in gaps[1]


def test_span_containing_sink_line_gets_seeded():
    gaps = [_gap("web/jump.src", "handle", 40, 80)]
    n = seed_map_sink_hypotheses(gaps, _redirect_map())
    assert n == 1
    assert gaps[0]["injected_hypotheses"][0]["source"] == SEED_SOURCE


def test_direct_file_function_match_gets_seeded():
    cmap = {"sink_details": [{
        "id": "SINK-2", "type": "sql", "operation": "query($x)",
        "file": "db.src", "line": 12, "function": "run_query",
        "notes": "unparameterised",
    }]}
    gaps = [_gap("db.src", "run_query", 5, 40)]
    assert seed_map_sink_hypotheses(gaps, cmap) == 1


def test_dedup_across_match_classes_and_reruns():
    # One gap matches by file:function AND by span AND by
    # reaches_from — still exactly one hypothesis; a second seeding
    # pass adds nothing.
    cmap = {"sink_details": [{
        "id": "SINK-3", "type": "redirect",
        "file": "a.src", "line": 10, "function": "go",
        "reaches_from": "go() builds the target",
        "notes": "n",
    }]}
    gaps = [_gap("a.src", "go", 1, 20)]
    assert seed_map_sink_hypotheses(gaps, cmap) == 1
    assert seed_map_sink_hypotheses(gaps, cmap) == 0
    assert len(gaps[0]["injected_hypotheses"]) == 1


def test_dead_gap_never_seeded():
    gaps = [_gap("web/jump.src", "handle", 150, 220, dead=True)]
    assert seed_map_sink_hypotheses(gaps, _redirect_map()) == 0
    assert "injected_hypotheses" not in gaps[0]


def test_per_gap_cap_bounds_prompt_surface():
    records = [{
        "id": f"SINK-{i}", "type": "redirect",
        "file": "a.src", "line": 10, "function": "go",
        "notes": f"variant {i}",
    } for i in range(5)]
    gaps = [_gap("a.src", "go", 1, 20)]
    n = seed_map_sink_hypotheses(gaps, {"sink_details": records})
    assert n == MAX_SEEDS_PER_GAP
    assert len(gaps[0]["injected_hypotheses"]) == MAX_SEEDS_PER_GAP


def test_legacy_sinks_shape_degrades_to_span_match():
    cmap = {"sinks": [
        {"type": "shell_exec", "location": "plugins/f.src:42"},
    ]}
    gaps = [_gap("plugins/f.src", "runner", 30, 55)]
    assert seed_map_sink_hypotheses(gaps, cmap) == 1
    mech = gaps[0]["injected_hypotheses"][0]["mechanism"]
    assert "shell_exec" in mech


def test_absent_or_empty_map_seeds_nothing():
    gaps = [_gap("a.src", "go")]
    assert seed_map_sink_hypotheses(gaps, None) == 0
    assert seed_map_sink_hypotheses(gaps, {}) == 0
    assert seed_map_sink_hypotheses([], _redirect_map()) == 0


def test_existing_other_source_hypotheses_untouched():
    gaps = [_gap("lib/text.src", "base_url_for", 40, 90,
                 injected_hypotheses=[{
                     "mechanism": "prior", "confidence": "medium",
                     "source": "fix_history_variant",
                 }])]
    assert seed_map_sink_hypotheses(gaps, _redirect_map()) == 1
    sources = [h["source"] for h in gaps[0]["injected_hypotheses"]]
    assert sources == ["fix_history_variant", SEED_SOURCE]

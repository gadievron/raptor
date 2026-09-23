"""Replay renderer scrub tests — orchestrated_report-derived strings
(model names, decision classes) are foreign input to the markdown
renderer; both control bytes and markdown STRUCTURE (in-cell pipes /
backticks that would forge table columns) must be neutralised.

Lives beside the code it pins (core/llm/multi_model/replay.py) so a
multi_model-only refactor co-selects it.
"""

from __future__ import annotations

import json

from core.llm.multi_model.replay import (
    ClassSummary,
    ReplayReport,
    render_markdown as replay_render,
)


def _report(dc: str, model: str) -> ReplayReport:
    return ReplayReport(
        sources=["r"],
        total_panels=1,
        total_findings_with_panel=1,
        distinct_models=[model],
        distinct_decision_classes=[dc],
        findings=[],
        class_summaries=[ClassSummary(
            decision_class=dc, n_findings=1,
            n_flips_to_exploitable=0, n_flips_to_not_exploitable=0,
            converged=True, iterations=1,
            model_reliabilities=[
                {"model": model, "alpha": 0.9, "beta": 0.8},
            ],
        )],
        flip_rate=0.0,
        flip_to_exploitable_rate=0.0,
        flip_to_not_exploitable_rate=0.0,
        posterior_distribution={},
    )


class TestReplayMarkdownStructureScrub:
    EVIL = "x` | 999 | 0 | `y"

    def test_class_summary_row_structure_not_injectable(self):
        md = replay_render(_report(self.EVIL, "model-a"))
        assert "` | 999 | 0 | `" not in md
        assert "&#124;" in md

    def test_reliability_model_cell_structure_not_injectable(self):
        md = replay_render(_report("dc", self.EVIL))
        assert "` | 999 | 0 | `" not in md


# Moved from core/llm/scorecard/tests/test_render_scrub.py so a
# multi_model-only refactor co-selects the tests that pin replay.py.
HOSTILE = "\x1b]0;pwned\x07\x9b2J\u202eevil"
RAW = ("\x1b", "\x07", "\x9b", "\u202e")


class TestReplayReliabilityTableScrub:
    """The per-model reliability table is fed by
    ``class_summaries[].model_reliabilities[]["model"]`` — same
    orchestrated_report provenance as the scrubbed distinct_models /
    decision_class cells. The hostile fixture must populate
    model_reliabilities (the default-empty fixture never exercised
    the cell)."""

    def test_reliability_model_cell_escaped(self):
        from core.llm.multi_model.replay import (
            ClassSummary,
            ReplayReport,
            render_markdown as replay_render,
        )
        report = ReplayReport(
            sources=["r"],
            total_panels=1,
            total_findings_with_panel=1,
            distinct_models=[f"m{HOSTILE}"],
            distinct_decision_classes=["dc"],
            findings=[],
            class_summaries=[ClassSummary(
                decision_class="dc", n_findings=1,
                n_flips_to_exploitable=0, n_flips_to_not_exploitable=0,
                converged=True, iterations=1,
                model_reliabilities=[
                    {"model": f"m{HOSTILE}", "alpha": 0.9, "beta": 0.8},
                ],
            )],
            flip_rate=0.0,
            flip_to_exploitable_rate=0.0,
            flip_to_not_exploitable_rate=0.0,
            posterior_distribution={},
        )
        md = replay_render(report)
        for raw in RAW:
            assert raw not in md
        assert "Inferred per-model reliability" in md

    def test_replay_render_json_ascii_encoded(self):
        from core.llm.multi_model.replay import (
            ClassSummary,
            ReplayReport,
            render_json as replay_render_json,
        )
        report = ReplayReport(
            sources=["r"],
            total_panels=1,
            total_findings_with_panel=1,
            distinct_models=["m-\x9b31m"],
            distinct_decision_classes=["dc-\x9d0;pwn"],
            findings=[],
            class_summaries=[ClassSummary(
                decision_class="dc-\x9d0;pwn", n_findings=1,
                n_flips_to_exploitable=0, n_flips_to_not_exploitable=0,
                converged=True, iterations=1,
                model_reliabilities=[
                    {"model": "m-\x9b31m", "alpha": 0.9, "beta": 0.8},
                ],
            )],
            flip_rate=0.0,
            flip_to_exploitable_rate=0.0,
            flip_to_not_exploitable_rate=0.0,
            posterior_distribution={},
        )
        rendered = replay_render_json(report)
        assert "\x9b" not in rendered
        assert "\x9d" not in rendered
        parsed = json.loads(rendered)
        assert parsed["distinct_models"] == ["m-\x9b31m"]  # round-trips

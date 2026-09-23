"""Replay renderer scrub tests — orchestrated_report-derived strings
(model names, decision classes) are foreign input to the markdown
renderer; both control bytes and markdown STRUCTURE (in-cell pipes /
backticks that would forge table columns) must be neutralised.

Lives beside the code it pins (core/llm/multi_model/replay.py) so a
multi_model-only refactor co-selects it.
"""

from __future__ import annotations

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

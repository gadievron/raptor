"""STUDY_QUESTION event type — recordable against the study_question
decision class."""

from __future__ import annotations

from pathlib import Path

from core.llm.scorecard.scorecard import (
    ALL_EVENT_TYPES,
    EventType,
    ModelScorecard,
)


class TestStudyQuestionEventType:
    def test_registered(self) -> None:
        assert EventType.STUDY_QUESTION in ALL_EVENT_TYPES

    def test_record_round_trip(self, tmp_path: Path) -> None:
        sc = ModelScorecard(tmp_path / "sc.json")
        sc.record_event(
            "study_question", "modelA",
            EventType.STUDY_QUESTION, "correct",
        )
        sc.record_event(
            "study_question", "modelA",
            EventType.STUDY_QUESTION, "incorrect",
            sample={"reason": "second resolution disagreed"},
        )
        stats = sc.get_stats()
        cell = next(
            c for c in stats
            if c.model == "modelA"
            and c.decision_class == "study_question"
        )
        assert cell is not None

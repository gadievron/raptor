"""study-questions.md is a RENDERING of reading-list.json — escaped,
bounded, derived and regenerable; never a second store."""

from __future__ import annotations

import json
from pathlib import Path

from core.concepts.reading_list import (
    ReadingList,
    ReadingListItem,
    write_study_questions,
)


def _write_store(output_dir: Path, questions: list[dict]) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / "reading-list.json"
    path.write_text(json.dumps({"items": questions}), encoding="utf-8")
    return path


def _q(qid: str, question: str, **kw) -> dict:
    return {"id": qid, "question": question,
            "source_command": "/audit", **kw}


class TestRenderQuestionsMarkdown:
    def test_sections_and_states(self, tmp_path: Path) -> None:
        _write_store(tmp_path, [
            _q("a", "What frees ctx?"),
            _q("b", "Resolved one", resolved=True,
               resolved_concept_id="c1"),
            _q("c", "Dynamic dispatch target?", unresolvable=True,
               unresolvable_reason="monkey-patched at runtime"),
        ])
        path = write_study_questions(tmp_path)
        assert path == tmp_path / "study-questions.md"
        text = path.read_text(encoding="utf-8")
        assert "## Pending (1)" in text
        assert "What frees ctx?" in text
        assert "## Resolved (1)" in text
        assert "## Unresolvable" in text
        assert "monkey-patched at runtime" in text
        # The derived-not-a-store header is the contract.
        assert "Derived rendering of `reading-list.json`" in text
        assert "not a store" in text

    def test_escaped_and_single_line(self, tmp_path: Path) -> None:
        _write_store(tmp_path, [
            _q("a", "evil \x1b[31mred\x1b[0m\nsecond line"),
        ])
        text = write_study_questions(tmp_path).read_text(
            encoding="utf-8")
        assert "\x1b" not in text
        # Newline folded: the whole question renders as ONE bullet
        # line — a raw newline would forge a second list entry.
        bullet_lines = [ln for ln in text.split("\n") if "evil" in ln]
        assert len(bullet_lines) == 1
        assert "second line" in bullet_lines[0]
        assert bullet_lines[0].startswith("- ")

    def test_bounded(self, tmp_path: Path) -> None:
        _write_store(tmp_path, [
            _q(f"q{i}", f"question number {i}") for i in range(250)
        ])
        rl = ReadingList.load(tmp_path / "reading-list.json")
        text = rl.render_questions_markdown(max_items=10)
        assert text.count("question number") == 10
        assert "more" in text and "reading-list.json" in text

    def test_no_store_no_file(self, tmp_path: Path) -> None:
        assert write_study_questions(tmp_path) is None
        assert not (tmp_path / "study-questions.md").exists()

    def test_regenerable_not_a_store(self, tmp_path: Path) -> None:
        _write_store(tmp_path, [_q("a", "Original question?")])
        path = write_study_questions(tmp_path)
        # Hand-edits to the rendering are lost on re-render: the
        # JSON store is the only source of truth.
        path.write_text("# my precious notes\n", encoding="utf-8")
        text = write_study_questions(tmp_path).read_text(
            encoding="utf-8")
        assert "my precious notes" not in text
        assert "Original question?" in text

    def test_render_from_instance_matches_store(
            self, tmp_path: Path) -> None:
        store = _write_store(tmp_path, [_q("a", "One?")])
        rl = ReadingList.load(store)
        rl.queue(ReadingListItem(id="b", question="Two?",
                                 source_command="/patch"))
        text = rl.render_questions_markdown()
        assert "One?" in text and "Two?" in text

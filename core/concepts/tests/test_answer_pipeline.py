"""Spot-checks, the study-answer ledger, and the agreement gate —
core/concepts/{spot_check,study_answers,answer_gate}.py.  Hermetic;
LLM stubbed.
"""

from __future__ import annotations

import json
import types
from pathlib import Path

from core.concepts.answer_gate import verify_flip_answer
from core.concepts.receipts import TIER_MECHANICAL, TIER_VERBATIM
from core.concepts.spot_check import (
    extract_constant_value,
    spot_check_question,
)
from core.concepts.study_answers import (
    StudyAnswer,
    answers_for_function,
    append_answers,
    load_answers,
)

# ------------------------------------------------------------------
# Spot checks
# ------------------------------------------------------------------

_ITEMS = [
    {"name": "MAX_FRAME", "kind": "macro", "file": "lib.rs", "line": 2,
     "definition": "pub const MAX_FRAME: usize = 4096;"},
    {"name": "RETRY_LIMIT", "kind": "macro", "file": "h.ts", "line": 1,
     "definition": "export const RETRY_LIMIT = 3;"},
    {"name": "BUF_SZ", "kind": "macro", "file": "a.h", "line": 5,
     "definition": "#define BUF_SZ 0x100"},
    {"name": "parse_config", "kind": "function", "file": "m.py", "line": 1,
     "definition": "def parse_config(path):\n    return path"},
]


class TestExtractConstantValue:
    def test_define(self) -> None:
        assert extract_constant_value("BUF_SZ", "#define BUF_SZ 0x100") == "0x100"

    def test_assignment(self) -> None:
        assert extract_constant_value(
            "MAX_FRAME", "pub const MAX_FRAME: usize = 4096;",
        ) == "4096"

    def test_no_value(self) -> None:
        assert extract_constant_value("f", "def f():\n    pass") is None


class TestSpotCheckQuestion:
    def test_value_question_matches(self) -> None:
        r = spot_check_question("Is MAX_FRAME 4096?", _ITEMS)
        assert r is not None
        assert r.value == "4096"
        assert r.matches is True
        assert r.receipt.verified
        assert r.receipt.tier == TIER_MECHANICAL

    def test_value_question_mismatch_detected(self) -> None:
        r = spot_check_question("Is MAX_FRAME equal to 8192?", _ITEMS)
        assert r is not None
        assert r.matches is False
        assert "DOES NOT match" in r.answer

    def test_hex_decimal_equivalence(self) -> None:
        r = spot_check_question("Is BUF_SZ 256?", _ITEMS)
        assert r is not None
        assert r.matches is True

    def test_open_question_reports_value(self) -> None:
        r = spot_check_question(
            "What is the value of `RETRY_LIMIT`?", _ITEMS,
        )
        assert r is not None
        assert r.value == "3"
        assert r.matches is None

    def test_non_constant_question_returns_none(self) -> None:
        assert spot_check_question(
            "Does `parse_config` validate input?", _ITEMS,
        ) is None

    def test_unknown_identifier_returns_none(self) -> None:
        assert spot_check_question("Is GHOST_LIMIT 5?", _ITEMS) is None


# ------------------------------------------------------------------
# Ledger
# ------------------------------------------------------------------

class TestStudyAnswerLedger:
    def test_append_and_load(self, tmp_path: Path) -> None:
        n = append_answers(tmp_path, [StudyAnswer(
            question="q1", source_file="a.py", source_function="f",
            answer="ans", tier=TIER_VERBATIM, status="resolved",
        )])
        assert n == 1
        recs = load_answers(tmp_path)
        assert recs[0]["question"] == "q1"
        assert recs[0]["tier"] == TIER_VERBATIM

    def test_same_question_updates_in_place(self, tmp_path: Path) -> None:
        append_answers(tmp_path, [StudyAnswer(question="q1", status="pending")])
        append_answers(tmp_path, [StudyAnswer(question="q1", status="resolved")])
        recs = load_answers(tmp_path)
        assert len(recs) == 1
        assert recs[0]["status"] == "resolved"

    def test_answers_for_function(self, tmp_path: Path) -> None:
        append_answers(tmp_path, [
            StudyAnswer(question="q1", source_file="a.py",
                        source_function="f"),
            StudyAnswer(question="q2", source_file="b.py",
                        source_function="g"),
        ])
        got = answers_for_function(tmp_path, "a.py", "f")
        assert [a["question"] for a in got] == ["q1"]

    def test_ledger_is_valid_json(self, tmp_path: Path) -> None:
        append_answers(tmp_path, [StudyAnswer(
            question="q1",
            receipt={"file": "a.py", "line": 3, "quote": "x",
                     "verified": True, "sha256": "ab", "tier": "verbatim",
                     "note": ""},
        )])
        data = json.loads((tmp_path / "study-answers.json").read_text())
        assert data["answers"][0]["receipt"]["verified"]


# ------------------------------------------------------------------
# Agreement gate
# ------------------------------------------------------------------

def _tree(tmp_path: Path) -> Path:
    (tmp_path / "m.py").write_text(
        "def parse_config(path):\n"
        "    return validate_schema(open(path).read())\n",
    )
    return tmp_path


def _snippets() -> list[dict]:
    return [{
        "name": "parse_config", "file": "m.py", "line": 1,
        "definition": "def parse_config(path):\n"
                      "    return validate_schema(open(path).read())",
    }]


def _first_receipt() -> dict:
    return {
        "file": "m.py", "line": 1,
        "quote": "def parse_config(path):",
        "verified": True, "sha256": "aa", "tier": "verbatim", "note": "",
    }


def _client(result):
    def generate_structured(prompt, schema, **kw):
        return types.SimpleNamespace(result=result)
    return types.SimpleNamespace(generate_structured=generate_structured)


class TestAgreementGate:
    def test_agreeing_second_resolution_passes(self, tmp_path: Path) -> None:
        root = _tree(tmp_path)
        client = _client({
            "answerable": True,
            "answer": "yes, it delegates to validate_schema",
            "file": "m.py", "line": 2,
            "quote": "return validate_schema(open(path).read())",
        })
        out = verify_flip_answer(
            "Does `parse_config` validate its input?",
            _snippets(), _first_receipt(), client, root,
            tier=TIER_VERBATIM,
        )
        assert out["agreed"]

    def test_disagreeing_source_quarantined(self, tmp_path: Path) -> None:
        (tmp_path / "m.py").write_text(
            "def parse_config(path):\n    return 1\n"
            + "\n" * 60
            + "def other_thing():\n    return 2\n",
        )
        client = _client({
            "answerable": True, "answer": "different claim",
            "file": "m.py", "line": 63,
            "quote": "def other_thing():",
        })
        out = verify_flip_answer(
            "q?", _snippets(), _first_receipt(), client, tmp_path,
            tier=TIER_VERBATIM,
        )
        assert not out["agreed"]
        assert "different source" in out["reason"]

    def test_abstaining_second_resolution_quarantines(
        self, tmp_path: Path,
    ) -> None:
        root = _tree(tmp_path)
        client = _client({
            "answerable": False, "answer": "", "quote": "",
        })
        out = verify_flip_answer(
            "q?", _snippets(), _first_receipt(), client, root,
            tier=TIER_VERBATIM,
        )
        assert not out["agreed"]
        assert "abstained" in out["reason"]

    def test_fabricated_second_quote_quarantines(
        self, tmp_path: Path,
    ) -> None:
        root = _tree(tmp_path)
        client = _client({
            "answerable": True, "answer": "sure",
            "file": "m.py", "line": 1,
            "quote": "def parse_config(path, strict=True):",
        })
        out = verify_flip_answer(
            "q?", _snippets(), _first_receipt(), client, root,
            tier=TIER_VERBATIM,
        )
        assert not out["agreed"]
        assert "failed verification" in out["reason"]

    def test_transport_error_fails_closed(self, tmp_path: Path) -> None:
        root = _tree(tmp_path)

        def boom(*a, **kw):
            raise RuntimeError("provider down")

        client = types.SimpleNamespace(generate_structured=boom)
        out = verify_flip_answer(
            "q?", _snippets(), _first_receipt(), client, root,
            tier=TIER_VERBATIM,
        )
        assert not out["agreed"]
        assert "call failed" in out["reason"]

    def test_mechanical_tier_skips_gate(self, tmp_path: Path) -> None:
        out = verify_flip_answer(
            "q?", [], None, None, tmp_path, tier=TIER_MECHANICAL,
        )
        assert out["agreed"]
        assert "gate skipped" in out["reason"]

    def test_unverified_first_receipt_fails(self, tmp_path: Path) -> None:
        out = verify_flip_answer(
            "q?", _snippets(), {"verified": False}, None, tmp_path,
            tier=TIER_VERBATIM,
        )
        assert not out["agreed"]

    def test_no_snippets_fails_closed(self, tmp_path: Path) -> None:
        out = verify_flip_answer(
            "q?", [], _first_receipt(), None, tmp_path,
            tier=TIER_VERBATIM,
        )
        assert not out["agreed"]
        assert "no extracted snippets" in out["reason"]

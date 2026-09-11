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

    def test_comparison_is_not_an_assignment(self) -> None:
        # Regression: [^=\n]* filler crossed '!=' so assert(NAME != 0)
        # read as NAME = 0 — a fabricated mechanical value.
        assert extract_constant_value(
            "MAX_FRAME", "assert(MAX_FRAME != 0);",
        ) is None
        assert extract_constant_value(
            "MAX_FRAME", "if (len >= MAX_FRAME) return -1;",
        ) is None
        assert extract_constant_value(
            "MAX_FRAME", "if (MAX_FRAME == 4096) {}",
        ) is None

    def test_statement_boundary_not_crossed(self) -> None:
        # Regression: an unrelated same-line assignment was picked up
        # as the constant's value.
        assert extract_constant_value(
            "MAX_FRAME", "buf[MAX_FRAME]; int other = 42;",
        ) is None

    def test_annotated_and_plain_assignments_still_extract(self) -> None:
        assert extract_constant_value(
            "MAX_FRAME", "static const size_t MAX_FRAME = 4096;",
        ) == "4096"
        assert extract_constant_value(
            "MAX_FRAME", "const MAX_FRAME: usize = 0x1000;",
        ) == "0x1000"

    def test_underscore_grouped_literal_extracted_whole(self) -> None:
        # A grammar that stopped at the first non-digit read '1' out
        # of '1_000_000' — and trusted it as the mechanical answer.
        assert extract_constant_value(
            "MAX", "MAX = 1_000_000",
        ) == "1_000_000"

    def test_scientific_notation_extracted_whole(self) -> None:
        assert extract_constant_value("E", "E = 1e6") == "1e6"
        assert extract_constant_value("F", "F = 1.5e-3") == "1.5e-3"

    def test_base_prefixed_literals_extracted_whole(self) -> None:
        assert extract_constant_value(
            "FLAGS", "#define FLAGS 0b1010",
        ) == "0b1010"
        assert extract_constant_value(
            "MODE", "MODE = 0o755",
        ) == "0o755"

    def test_c_octal_extracted(self) -> None:
        assert extract_constant_value(
            "MODE", "#define MODE 0755",
        ) == "0755"


class TestNormaliseLiteral:
    def test_underscores_canonicalised(self) -> None:
        from core.concepts.spot_check import _normalise_literal
        assert _normalise_literal("1_000_000") == "1000000"

    def test_c_octal_is_octal_not_decimal(self) -> None:
        # '0755' asserted as decimal 755 is the classic mis-read: the
        # C literal means 493.
        from core.concepts.spot_check import _normalise_literal
        assert _normalise_literal("0755") == "493"
        assert _normalise_literal("0o755") == "493"

    def test_base_prefixes(self) -> None:
        from core.concepts.spot_check import _normalise_literal
        assert _normalise_literal("0b1010") == "10"
        assert _normalise_literal("0x100") == "256"

    def test_integral_exponent_matches_plain_int(self) -> None:
        from core.concepts.spot_check import _normalise_literal
        assert _normalise_literal("1e6") == _normalise_literal("1000000")

    def test_fractional_float_kept(self) -> None:
        from core.concepts.spot_check import _normalise_literal
        assert _normalise_literal("1.5") == repr(1.5)


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

    def test_prose_word_does_not_match_corpus_global(self) -> None:
        # 'version' here is prose, not an identifier — a corpus global
        # of the same name must not yield a trusted mechanical answer
        # about the wrong thing.
        items = [{
            "name": "version", "kind": "macro", "file": "pkg.py",
            "line": 1, "definition": 'version = "1.2"',
        }]
        assert spot_check_question(
            "What version constraint governs replay?", items,
        ) is None

    def test_identifier_cased_token_still_resolves(self) -> None:
        # Identifier conventions (underscore / caps) bypass the prose
        # filter — genuine open questions keep resolving.
        r = spot_check_question(
            "What limit does MAX_FRAME impose?", _ITEMS,
        )
        assert r is not None
        assert r.identifier == "MAX_FRAME"
        assert r.value == "4096"

    def test_underscore_literal_question_matches(self) -> None:
        items = [{
            "name": "MAX_EVENTS", "kind": "macro", "file": "cfg.py",
            "line": 1, "definition": "MAX_EVENTS = 1_000_000",
        }]
        r = spot_check_question("Is MAX_EVENTS 1000000?", items)
        assert r is not None
        assert r.matches is True

    def test_c_octal_question_compared_as_octal(self) -> None:
        items = [{
            "name": "DIR_MODE", "kind": "macro", "file": "m.h",
            "line": 1, "definition": "#define DIR_MODE 0755",
        }]
        r = spot_check_question("Is DIR_MODE 755?", items)
        assert r is not None
        assert r.matches is False
        r = spot_check_question("Is DIR_MODE 493?", items)
        assert r is not None
        assert r.matches is True


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

    def test_contradicting_mechanical_answer_does_not_skip_gate(
        self, tmp_path: Path,
    ) -> None:
        """A mechanical answer that CONTRADICTS an LLM answer loses
        the deterministic exemption: the extractor repeats itself, but
        determinism does not prove it read the right statement.  With
        no verified receipt the gate fails closed."""
        out = verify_flip_answer(
            "q?", [], None, None, tmp_path,
            tier=TIER_MECHANICAL, contradicts_llm=True,
        )
        assert not out["agreed"]

    def test_contradicting_mechanical_answer_can_still_agree(
        self, tmp_path: Path,
    ) -> None:
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
            tier=TIER_MECHANICAL, contradicts_llm=True,
        )
        assert out["agreed"]

    def test_refuting_second_answer_same_quote_disagrees(
        self, tmp_path: Path,
    ) -> None:
        """Quote overlap alone is not agreement: a second resolution
        that REFUTES the first answer while citing the same code must
        be treated as a disagreement."""
        root = _tree(tmp_path)
        client = _client({
            "answerable": True,
            "answer": "no, it does not validate its input",
            "file": "m.py", "line": 2,
            "quote": "return validate_schema(open(path).read())",
        })
        out = verify_flip_answer(
            "Does `parse_config` validate its input?",
            _snippets(), _first_receipt(), client, root,
            tier=TIER_VERBATIM,
            first_answer="yes, it validates via validate_schema",
        )
        assert not out["agreed"]
        assert "opposite stance" in out["reason"]

    def test_same_stance_second_answer_still_agrees(
        self, tmp_path: Path,
    ) -> None:
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
            first_answer="yes, it validates via validate_schema",
        )
        assert out["agreed"]

    def test_both_negative_answers_agree(self, tmp_path: Path) -> None:
        # Symmetric negation is the SAME stance, not a conflict.
        root = _tree(tmp_path)
        client = _client({
            "answerable": True,
            "answer": "no, there is no validation here",
            "file": "m.py", "line": 2,
            "quote": "return validate_schema(open(path).read())",
        })
        out = verify_flip_answer(
            "Does `parse_config` sanitise its input?",
            _snippets(), _first_receipt(), client, root,
            tier=TIER_VERBATIM,
            first_answer="it does not sanitise the input",
        )
        assert out["agreed"]

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

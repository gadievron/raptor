"""Phase 2 hallucination hardening — quote-or-abstain enforcement,
provenance tiers, discards, extract-then-answer prompt pins, and
code-over-comments delivery.  All hermetic (no LLM).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.concepts.model import StudyItem
from core.concepts.receipts import (
    TIER_LLM_SUMMARIZED,
    TIER_MECHANICAL,
    TIER_VERBATIM,
)
from core.concepts.study import (
    _RESPONSE_SCHEMA,
    _SYSTEM_PROMPT,
    _format_item,
    _parse_batch_response,
    _record_discards,
)


@pytest.fixture()
def src(tmp_path: Path) -> Path:
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "mod.py").write_text(
        "def parse_config(path):\n"
        "    return validate_schema(open(path).read())\n",
    )
    return tmp_path


def _concept_raw(quote: str | None, *, file: str = "pkg/mod.py",
                 line: int = 1) -> dict:
    ev = {
        "type": "code_path", "file": file, "line": line,
        "observation": "parses config",
    }
    if quote is not None:
        ev["quote"] = quote
    return {
        "concepts": [{
            "id": "parse_config_contract",
            "description": "parse_config delegates validation",
            "evidence": [ev],
            "confidence": "traced",
        }],
    }


class TestQuoteOrAbstain:
    def test_verified_quote_earns_verbatim(self, src: Path) -> None:
        concepts, *_ = _parse_batch_response(
            _concept_raw("def parse_config(path):"), source_root=src,
        )
        assert len(concepts) == 1
        c = concepts[0]
        assert c.provenance == TIER_VERBATIM
        assert c.receipt and c.receipt["verified"]
        assert c.receipt["tier"] == TIER_VERBATIM

    def test_fabricated_quote_discards_answer(self, src: Path) -> None:
        sink: list = []
        concepts, *_ = _parse_batch_response(
            _concept_raw("def parse_config(path, strict=True):"),
            source_root=src, discard_sink=sink,
        )
        assert concepts == [], "failed receipt must never be delivered"
        assert len(sink) == 1
        assert sink[0]["reason"] == "receipt verification failed"
        assert "parse_config_contract" in sink[0]["names"]

    def test_no_quote_demotes_to_summary(self, src: Path) -> None:
        concepts, *_ = _parse_batch_response(
            _concept_raw(None), source_root=src,
        )
        assert len(concepts) == 1
        assert concepts[0].provenance == TIER_LLM_SUMMARIZED
        assert concepts[0].receipt is None

    def test_invariant_quote_verified(self, src: Path) -> None:
        raw = {
            "invariants": [{
                "id": "inv_validate", "concept": "parse_config_contract",
                "statement": "input is validated",
                "negation": "unvalidated input reaches the parser",
                "quote": "return validate_schema(open(path).read())",
                "evidence_file": "pkg/mod.py", "evidence_line": 2,
            }],
        }
        _c, invariants, *_ = _parse_batch_response(raw, source_root=src)
        assert len(invariants) == 1
        assert invariants[0].provenance == TIER_VERBATIM
        assert invariants[0].receipt["verified"]

    def test_invariant_bad_quote_discarded(self, src: Path) -> None:
        sink: list = []
        raw = {
            "invariants": [{
                "id": "inv_bogus", "concept": "c",
                "statement": "s", "negation": "n",
                "quote": "if not validated: raise ValueError(path)",
                "evidence_file": "pkg/mod.py", "evidence_line": 2,
            }],
        }
        _c, invariants, *_ = _parse_batch_response(
            raw, source_root=src, discard_sink=sink,
        )
        assert invariants == []
        assert sink and sink[0]["kind"] == "invariant"

    def test_contract_matching_focus_item_stays_llm_tier(
        self, src: Path,
    ) -> None:
        """A name match locates the function; it does NOT verify the
        contract's semantic claims (output_semantics / security_note
        are unverified LLM output). The tier must stay
        llm_summarized — mechanical means derived without an LLM —
        with the snippet receipt attached as locating context only."""
        focus = [StudyItem(
            id="i", kind="function", name="parse_config",
            file="pkg/mod.py", line=1,
            definition="def parse_config(path):\n    return 1",
        )]
        raw = {"contracts": [{
            "function": "parse_config", "file": "pkg/mod.py",
            "input_semantics": "path to config",
        }]}
        *_head, contracts, _bp, _sa = _parse_batch_response(
            raw, source_root=src, focus_items=focus,
        )
        assert contracts[0].provenance == TIER_LLM_SUMMARIZED
        assert contracts[0].provenance != TIER_MECHANICAL
        # Locating receipt still attached for prompt context.
        assert contracts[0].receipt["verified"]

    def test_contract_without_focus_item_is_summary(self, src: Path) -> None:
        raw = {"contracts": [{
            "function": "unknown_fn", "file": "pkg/mod.py",
        }]}
        *_head, contracts, _bp, _sa = _parse_batch_response(
            raw, source_root=src,
        )
        assert contracts[0].provenance == TIER_LLM_SUMMARIZED

    def test_no_source_root_leaves_legacy_behaviour(self) -> None:
        concepts, *_ = _parse_batch_response(
            _concept_raw("anything at all here"), source_root=None,
        )
        # No receipts applied without a root — provenance stays empty
        # (non-actionable by the fail-closed tier gate).
        assert len(concepts) == 1
        assert concepts[0].provenance == ""


class TestDiscardLedger:
    def test_record_and_merge(self, tmp_path: Path) -> None:
        _record_discards(tmp_path, [
            {"kind": "concept", "id": "a",
             "reason": "receipt verification failed", "names": ["a"]},
        ])
        _record_discards(tmp_path, [
            {"kind": "concept", "id": "a",
             "reason": "receipt verification failed", "names": ["a"]},
            {"kind": "invariant", "id": "b",
             "reason": "receipt verification failed", "names": ["b"]},
        ])
        data = json.loads((tmp_path / "study-discards.json").read_text())
        assert len(data["discarded"]) == 2

    def test_empty_discards_write_nothing(self, tmp_path: Path) -> None:
        _record_discards(tmp_path, [])
        assert not (tmp_path / "study-discards.json").exists()


class TestPromptPins:
    """Extract-then-answer + quote-or-abstain + code-over-comments
    are pinned in the Phase 2 system prompt: the LLM is only ever
    asked to answer FROM mechanically extracted snippets."""

    def test_extract_then_answer(self) -> None:
        assert "Answer ONLY from the provided snippets" in _SYSTEM_PROMPT
        assert "NEVER answer from training knowledge" in _SYSTEM_PROMPT
        assert "unresolved_references" in _SYSTEM_PROMPT

    def test_quote_or_abstain(self) -> None:
        assert "Quote or abstain" in _SYSTEM_PROMPT
        assert "DISCARDED" in _SYSTEM_PROMPT

    def test_code_over_comments(self) -> None:
        assert "Code over comments" in _SYSTEM_PROMPT
        assert "the CODE is the contract" in _SYSTEM_PROMPT

    def test_schema_requires_quote_semantics(self) -> None:
        ev = (_RESPONSE_SCHEMA["properties"]["concepts"]["items"]
              ["properties"]["evidence"]["items"]["properties"])
        assert "quote" in ev
        assert "VERBATIM" in ev["quote"]["description"]
        inv = (_RESPONSE_SCHEMA["properties"]["invariants"]["items"]
               ["properties"])
        assert "quote" in inv


class TestStaleDocDelivery:
    def test_format_item_carries_marker(self) -> None:
        it = StudyItem(
            id="i", kind="function", name="f", file="a.py", line=1,
            doc_comment="Returns None on failure.",
            definition="def f():\n    return 1",
            stale_doc="doc claims a None return but the code never "
                      "returns None",
        )
        text = _format_item(it)
        assert "STALE-DOC WARNING" in text
        assert "the CODE is the contract" in text

    def test_clean_item_has_no_marker(self) -> None:
        it = StudyItem(
            id="i", kind="function", name="f", file="a.py", line=1,
            doc_comment="Adds one.", definition="def f(x):\n    return x+1",
        )
        assert "STALE-DOC" not in _format_item(it)

    def test_lang_resolve_sets_marker(self, tmp_path: Path) -> None:
        from core.concepts.lang_resolve import resolve_identifiers
        (tmp_path / "m.go").write_text(
            "package m\n\n"
            "// readHeader parses one wire header.\n"
            "func ParseHeader(b []byte) error {\n"
            "\treturn nil\n"
            "}\n",
        )
        res = resolve_identifiers(tmp_path, ["ParseHeader"])
        assert res.items
        assert "readHeader" in res.items[0].stale_doc

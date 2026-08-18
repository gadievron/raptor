"""Receipts, provenance tiers, and stale-doc detection —
core/concepts/receipts.py.  All deterministic; no LLM.
"""

from __future__ import annotations

from pathlib import Path

from core.concepts.receipts import (
    ACTIONABLE_TIERS,
    TIER_LLM_PRIOR,
    TIER_LLM_SUMMARIZED,
    TIER_MECHANICAL,
    TIER_VERBATIM,
    detect_stale_doc,
    is_actionable_tier,
    mechanical_receipt,
    tier_rank,
    verify_receipt,
)


class TestTiers:
    def test_actionable_set(self) -> None:
        assert TIER_VERBATIM in ACTIONABLE_TIERS
        assert TIER_MECHANICAL in ACTIONABLE_TIERS
        assert TIER_LLM_SUMMARIZED not in ACTIONABLE_TIERS
        assert TIER_LLM_PRIOR not in ACTIONABLE_TIERS

    def test_unknown_tier_fails_closed(self) -> None:
        assert not is_actionable_tier("")
        assert not is_actionable_tier("made_up")

    def test_rank_order(self) -> None:
        assert tier_rank(TIER_VERBATIM) < tier_rank(TIER_MECHANICAL)
        assert tier_rank(TIER_MECHANICAL) < tier_rank(TIER_LLM_SUMMARIZED)
        assert tier_rank(TIER_LLM_SUMMARIZED) < tier_rank(TIER_LLM_PRIOR)
        assert tier_rank("unknown") > tier_rank(TIER_LLM_PRIOR)


class TestVerifyReceipt:
    def _tree(self, tmp_path: Path) -> Path:
        (tmp_path / "pkg").mkdir()
        (tmp_path / "pkg" / "mod.py").write_text(
            "\n".join(
                f"# line {i}" for i in range(1, 40)
            )
            + "\ndef parse_config(path):\n"
            "    return validate_schema(open(path).read())\n",
        )
        return tmp_path

    def test_verifies_quote_at_line(self, tmp_path: Path) -> None:
        root = self._tree(tmp_path)
        r = verify_receipt(
            root, "pkg/mod.py", 40,
            "def parse_config(path):",
        )
        assert r.verified
        assert r.sha256

    def test_verifies_with_whitespace_differences(self, tmp_path: Path) -> None:
        root = self._tree(tmp_path)
        r = verify_receipt(
            root, "pkg/mod.py", 41,
            "return   validate_schema(open(path).read())",
        )
        assert r.verified

    def test_wrong_line_still_verifies_with_note(self, tmp_path: Path) -> None:
        root = self._tree(tmp_path)
        r = verify_receipt(
            root, "pkg/mod.py", 2, "def parse_config(path):",
        )
        assert r.verified
        assert "not at stated line" in r.note

    def test_fabricated_quote_fails(self, tmp_path: Path) -> None:
        root = self._tree(tmp_path)
        r = verify_receipt(
            root, "pkg/mod.py", 40,
            "def parse_config(path, strict=True):",
        )
        assert not r.verified
        assert "not found" in r.note

    def test_trivial_quote_fails(self, tmp_path: Path) -> None:
        root = self._tree(tmp_path)
        r = verify_receipt(root, "pkg/mod.py", 41, "return")
        assert not r.verified
        assert "too short" in r.note

    def test_missing_file_fails(self, tmp_path: Path) -> None:
        r = verify_receipt(
            tmp_path, "no/such.py", 1, "def parse_config(path):",
        )
        assert not r.verified

    def test_path_escape_fails(self, tmp_path: Path) -> None:
        outside = tmp_path.parent / "outside.py"
        outside.write_text("def secret_definition_here(): pass\n")
        r = verify_receipt(
            tmp_path, "../outside.py", 1,
            "def secret_definition_here(): pass",
        )
        assert not r.verified
        assert "source root" in r.note

    def test_no_line_matches_anywhere(self, tmp_path: Path) -> None:
        root = self._tree(tmp_path)
        r = verify_receipt(
            root, "pkg/mod.py", None, "def parse_config(path):",
        )
        assert r.verified

    def test_mechanical_receipt_verified_by_construction(self) -> None:
        r = mechanical_receipt("pkg/mod.py", 40, "def parse_config(path):")
        assert r.verified
        assert r.tier == TIER_MECHANICAL
        assert r.sha256


class TestDetectStaleDoc:
    def test_missing_documented_param(self) -> None:
        reason = detect_stale_doc(
            "Parses input.\n:param size: max bytes",
            "def parse(data, limit):\n    return data[:limit]",
            "parse", "python",
        )
        assert "size" in reason
        assert "code is the contract" in reason

    def test_javadoc_param(self) -> None:
        reason = detect_stale_doc(
            "Sanitizes.\n@param raw the raw path",
            "public static String sanitize(String p) { return p; }",
            "sanitize", "java",
        )
        assert "raw" in reason

    def test_consistent_doc_is_clean(self) -> None:
        assert detect_stale_doc(
            "Parses input.\n:param data: bytes\n:param limit: cap",
            "def parse(data, limit):\n    return data[:limit]",
            "parse", "python",
        ) == ""

    def test_go_renamed_function_doc(self) -> None:
        reason = detect_stale_doc(
            "readHeader parses one wire header.",
            "func ParseHeader(b []byte) (*Header, error) {\n"
            "\treturn decode(b)\n}",
            "ParseHeader", "go",
        )
        assert "readHeader" in reason
        assert "stale" in reason

    def test_go_correct_leading_name_clean(self) -> None:
        assert detect_stale_doc(
            "ParseHeader parses one wire header.",
            "func ParseHeader(b []byte) (*Header, error) {}",
            "ParseHeader", "go",
        ) == ""

    def test_go_sentence_words_not_flagged(self) -> None:
        assert detect_stale_doc(
            "Deprecated: use the v2 API.",
            "func ParseHeader(b []byte) (*Header, error) {}",
            "ParseHeader", "go",
        ) == ""

    def test_null_return_claim_without_null_return(self) -> None:
        reason = detect_stale_doc(
            "Returns NULL on allocation failure.",
            "struct ctx *mk(void) {\n"
            "    return &global_ctx;\n}",
            "mk", "c",
        )
        assert "NULL" in reason

    def test_null_return_claim_with_null_return_clean(self) -> None:
        assert detect_stale_doc(
            "Returns NULL on allocation failure.",
            "struct ctx *mk(void) {\n"
            "    if (!p) return NULL;\n    return p;\n}",
            "mk", "c",
        ) == ""

    def test_empty_inputs_clean(self) -> None:
        assert detect_stale_doc("", "code", "n", "c") == ""
        assert detect_stale_doc("doc", "", "n", "c") == ""


class TestModelFields:
    def test_concept_carries_provenance_and_receipt(self) -> None:
        from core.concepts.model import Concept
        c = Concept(id="x", description="d")
        assert c.provenance == ""
        assert c.receipt is None

    def test_invariant_and_contract_fields(self) -> None:
        from core.concepts.model import Contract, Invariant
        inv = Invariant(id="i", concept="c", statement="s", negation="n")
        ct = Contract(function="f", file="a.c")
        assert inv.provenance == "" and inv.receipt is None
        assert ct.provenance == "" and ct.receipt is None

    def test_study_item_stale_doc_field(self) -> None:
        from core.concepts.model import StudyItem
        it = StudyItem(id="i", kind="function", name="f", file="a.py")
        assert it.stale_doc == ""

    def test_evidence_quote_round_trip(self) -> None:
        import json
        from dataclasses import asdict

        from core.concepts.model import Evidence
        e = Evidence(type="code_path", file="a.py", observation="o",
                     quote="def f():")
        assert json.loads(json.dumps(asdict(e)))["quote"] == "def f():"

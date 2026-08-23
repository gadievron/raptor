"""Tests for core.concepts.model — domain model dataclasses and persistence."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.concepts.model import (
    CONFIDENCE_GRADES,
    LIFECYCLE_STATES,
    Concept,
    Contract,
    DomainModel,
    Evidence,
    Invariant,
    StudyItem,
)


# ------------------------------------------------------------------
# Fixtures
# ------------------------------------------------------------------

@pytest.fixture()
def sample_evidence() -> list[Evidence]:
    return [
        Evidence(
            type="type_definition",
            file="include/linux/mm_types.h",
            line=42,
            observation="_refcount field in struct page",
            hash="a3f8c2d1",
        ),
        Evidence(
            type="api_pattern",
            file="include/linux/mm.h",
            line=123,
            observation="get_page increments _refcount",
        ),
    ]


@pytest.fixture()
def sample_model(sample_evidence: list[Evidence]) -> DomainModel:
    return DomainModel(
        target="crypto/",
        source_root="/data/linux_kernel/linux-6.18.2",
        concepts=[
            Concept(
                id="page_ownership",
                description="Pages have ownership semantics",
                evidence=sample_evidence,
                confidence="traced",
                state="validated",
                derived_version="6.18.2",
                qualified_by=["COW via copy_page"],
            ),
            Concept(
                id="scatterlist_aliasing",
                description="sg_chain creates aliases, not copies",
                evidence=[
                    Evidence(
                        type="code_path",
                        file="include/linux/scatterlist.h",
                        line=142,
                        observation="no alloc_page in sg_chain",
                    ),
                ],
                confidence="corroborated",
                state="validated",
            ),
        ],
        invariants=[
            Invariant(
                id="page_cache_readonly",
                concept="page_ownership",
                statement="Page-cache pages must not be written to",
                negation="Writing through a shared page corrupts the page cache",
                evidence=["splice path uses get_page not alloc_page"],
                confidence="traced",
            ),
        ],
        contracts=[
            Contract(
                function="extract_iter_to_sg",
                file="crypto/af_alg.c",
                when="MSG_SPLICE_PAGES set",
                input_semantics="page-cache pages via pipe buffer",
                output_semantics="scatterlist references originals",
                ownership_transfer="none — borrowed",
                implication="writes hit page cache",
            ),
        ],
    )


# ------------------------------------------------------------------
# Evidence
# ------------------------------------------------------------------

class TestEvidence:
    def test_minimal_evidence(self) -> None:
        e = Evidence(type="doc", file="README", observation="documents ownership")
        assert e.line is None
        assert e.hash is None

    def test_full_evidence(self, sample_evidence: list[Evidence]) -> None:
        e = sample_evidence[0]
        assert e.type == "type_definition"
        assert e.file == "include/linux/mm_types.h"
        assert e.line == 42
        assert e.hash == "a3f8c2d1"


# ------------------------------------------------------------------
# Concept
# ------------------------------------------------------------------

class TestConcept:
    def test_defaults(self) -> None:
        c = Concept(id="test", description="test concept")
        assert c.confidence == "inferred"
        assert c.state == "proposed"
        assert c.evidence == []
        assert c.qualified_by == []

    def test_confidence_grades_ordered(self) -> None:
        assert CONFIDENCE_GRADES.index("inferred") < CONFIDENCE_GRADES.index("tested")
        assert len(CONFIDENCE_GRADES) == 6

    def test_lifecycle_states_complete(self) -> None:
        assert "discovered" in LIFECYCLE_STATES
        assert "stale" in LIFECYCLE_STATES
        assert len(LIFECYCLE_STATES) == 7


# ------------------------------------------------------------------
# StudyItem
# ------------------------------------------------------------------

class TestStudyItem:
    def test_struct_item(self) -> None:
        item = StudyItem(
            id="struct_page",
            kind="struct",
            name="page",
            file="include/linux/mm_types.h",
            line=42,
            fields=["flags", "_refcount", "_mapcount"],
            refcount_fields=["_refcount"],
        )
        assert item.kind == "struct"
        assert "_refcount" in item.refcount_fields

    def test_paired_ops_item(self) -> None:
        item = StudyItem(
            id="paired_get_page_put_page",
            kind="paired_ops",
            name="get_page/put_page",
            file="include/linux/mm.h",
            paired_with=["put_page"],
        )
        assert item.kind == "paired_ops"
        assert "put_page" in item.paired_with

    def test_defaults(self) -> None:
        item = StudyItem(id="x", kind="struct", name="x", file="x.h")
        assert item.fields == []
        assert item.callers == []
        assert item.doc_comment == ""


# ------------------------------------------------------------------
# DomainModel persistence
# ------------------------------------------------------------------

class TestDomainModelPersistence:
    def test_save_and_load_round_trip(
        self, sample_model: DomainModel, tmp_path: Path,
    ) -> None:
        p = tmp_path / "domain-model.json"
        sample_model.save(p)

        loaded = DomainModel.load(p)
        assert len(loaded.concepts) == 2
        assert loaded.concepts[0].id == "page_ownership"
        assert len(loaded.concepts[0].evidence) == 2
        assert loaded.concepts[0].evidence[0].file == "include/linux/mm_types.h"
        assert loaded.concepts[0].confidence == "traced"
        assert loaded.concepts[0].qualified_by == ["COW via copy_page"]

    def test_invariants_round_trip(
        self, sample_model: DomainModel, tmp_path: Path,
    ) -> None:
        p = tmp_path / "domain-model.json"
        sample_model.save(p)
        loaded = DomainModel.load(p)
        assert len(loaded.invariants) == 1
        assert loaded.invariants[0].concept == "page_ownership"
        assert loaded.invariants[0].confidence == "traced"

    def test_contracts_round_trip(
        self, sample_model: DomainModel, tmp_path: Path,
    ) -> None:
        p = tmp_path / "domain-model.json"
        sample_model.save(p)
        loaded = DomainModel.load(p)
        assert len(loaded.contracts) == 1
        assert loaded.contracts[0].function == "extract_iter_to_sg"
        assert loaded.contracts[0].ownership_transfer == "none — borrowed"

    def test_creates_parent_dirs(self, sample_model: DomainModel, tmp_path: Path) -> None:
        p = tmp_path / "nested" / "deep" / "domain-model.json"
        sample_model.save(p)
        assert p.exists()

    def test_atomic_write(self, sample_model: DomainModel, tmp_path: Path) -> None:
        p = tmp_path / "domain-model.json"
        sample_model.save(p)
        assert not p.with_suffix(".tmp").exists()

    def test_load_empty_model(self, tmp_path: Path) -> None:
        p = tmp_path / "domain-model.json"
        p.write_text('{"version": "1"}', encoding="utf-8")
        loaded = DomainModel.load(p)
        assert loaded.concepts == []
        assert loaded.invariants == []
        assert loaded.contracts == []

    def test_valid_json_output(
        self, sample_model: DomainModel, tmp_path: Path,
    ) -> None:
        p = tmp_path / "domain-model.json"
        sample_model.save(p)
        raw = json.loads(p.read_text(encoding="utf-8"))
        assert raw["version"] == "1"
        assert raw["target"] == "crypto/"
        assert isinstance(raw["concepts"], list)


# ------------------------------------------------------------------
# DomainModel queries
# ------------------------------------------------------------------

class TestDomainModelQueries:
    def test_get_concept_hit(self, sample_model: DomainModel) -> None:
        c = sample_model.get_concept("page_ownership")
        assert c is not None
        assert c.description == "Pages have ownership semantics"

    def test_get_concept_miss(self, sample_model: DomainModel) -> None:
        assert sample_model.get_concept("nonexistent") is None

    def test_get_contracts_for(self, sample_model: DomainModel) -> None:
        contracts = sample_model.get_contracts_for("extract_iter_to_sg")
        assert len(contracts) == 1
        assert contracts[0].file == "crypto/af_alg.c"

    def test_get_contracts_for_miss(self, sample_model: DomainModel) -> None:
        assert sample_model.get_contracts_for("nonexistent") == []

    def test_concepts_at_confidence_traced(self, sample_model: DomainModel) -> None:
        result = sample_model.concepts_at_confidence("traced")
        assert len(result) == 2

    def test_concepts_at_confidence_corroborated(self, sample_model: DomainModel) -> None:
        result = sample_model.concepts_at_confidence("corroborated")
        assert len(result) == 1
        assert result[0].id == "scatterlist_aliasing"

    def test_concepts_at_confidence_documented(self, sample_model: DomainModel) -> None:
        result = sample_model.concepts_at_confidence("documented")
        assert len(result) == 0


# ------------------------------------------------------------------
# Forward-compatible load (extra keys ignored)
# ------------------------------------------------------------------

class TestForwardCompatibleLoad:
    def test_extra_keys_in_concept_ignored(self, tmp_path: Path) -> None:
        p = tmp_path / "model.json"
        p.write_text(json.dumps({
            "version": "2",
            "concepts": [{
                "id": "c1",
                "description": "concept with future field",
                "confidence": "traced",
                "state": "validated",
                "evidence": [],
                "future_field": "should be dropped",
            }],
        }) + "\n", encoding="utf-8")
        loaded = DomainModel.load(p)
        assert len(loaded.concepts) == 1
        assert loaded.concepts[0].id == "c1"
        assert not hasattr(loaded.concepts[0], "future_field")

    def test_extra_keys_in_evidence_ignored(self, tmp_path: Path) -> None:
        p = tmp_path / "model.json"
        p.write_text(json.dumps({
            "version": "1",
            "concepts": [{
                "id": "c1",
                "description": "test",
                "evidence": [{
                    "type": "doc",
                    "file": "x.h",
                    "observation": "something",
                    "extra_key": 42,
                }],
            }],
        }) + "\n", encoding="utf-8")
        loaded = DomainModel.load(p)
        assert len(loaded.concepts[0].evidence) == 1
        assert loaded.concepts[0].evidence[0].file == "x.h"

    def test_extra_keys_in_invariant_ignored(self, tmp_path: Path) -> None:
        p = tmp_path / "model.json"
        p.write_text(json.dumps({
            "version": "1",
            "invariants": [{
                "id": "inv1",
                "concept": "c1",
                "statement": "x must hold",
                "negation": "x violated",
                "new_field": True,
            }],
        }) + "\n", encoding="utf-8")
        loaded = DomainModel.load(p)
        assert len(loaded.invariants) == 1
        assert loaded.invariants[0].id == "inv1"

    def test_extra_keys_in_contract_ignored(self, tmp_path: Path) -> None:
        p = tmp_path / "model.json"
        p.write_text(json.dumps({
            "version": "1",
            "contracts": [{
                "function": "foo",
                "file": "bar.c",
                "v2_extension": [1, 2, 3],
            }],
        }) + "\n", encoding="utf-8")
        loaded = DomainModel.load(p)
        assert len(loaded.contracts) == 1
        assert loaded.contracts[0].function == "foo"

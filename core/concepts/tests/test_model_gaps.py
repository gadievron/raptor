"""Tests for gaps 4 (evidence grading), 8 (hierarchy), 10 (versioning)."""
from __future__ import annotations

from pathlib import Path

from core.concepts.model import (
    CONFIDENCE_GRADES,
    Concept,
    DomainModel,
    Invariant,
)


class TestInvariantsAtConfidence:
    """Gap 4: invariants_at_confidence query."""

    def test_filters_by_grade(self) -> None:
        dm = DomainModel(invariants=[
            Invariant(id="a", concept="c", statement="s", negation="n",
                      confidence="inferred"),
            Invariant(id="b", concept="c", statement="s", negation="n",
                      confidence="traced"),
            Invariant(id="c", concept="c", statement="s", negation="n",
                      confidence="documented"),
        ])
        result = dm.invariants_at_confidence("traced")
        ids = {inv.id for inv in result}
        assert ids == {"b", "c"}

    def test_unknown_grade_returns_empty(self) -> None:
        dm = DomainModel(invariants=[
            Invariant(id="a", concept="c", statement="s", negation="n",
                      confidence="traced"),
        ])
        assert dm.invariants_at_confidence("nonexistent") == []

    def test_unknown_confidence_on_invariant_excluded(self) -> None:
        dm = DomainModel(invariants=[
            Invariant(id="a", concept="c", statement="s", negation="n",
                      confidence="bogus"),
        ])
        assert dm.invariants_at_confidence("inferred") == []

    def test_all_grades_ordered(self) -> None:
        invs = [
            Invariant(id=g, concept="c", statement="s", negation="n",
                      confidence=g)
            for g in CONFIDENCE_GRADES
        ]
        dm = DomainModel(invariants=invs)
        for i, grade in enumerate(CONFIDENCE_GRADES):
            result = dm.invariants_at_confidence(grade)
            assert len(result) == len(CONFIDENCE_GRADES) - i


class TestConceptHierarchy:
    """Gap 8: parent_id and tree queries."""

    def test_parent_id_field_exists(self) -> None:
        c = Concept(id="child", description="d", parent_id="parent")
        assert c.parent_id == "parent"

    def test_concept_children(self) -> None:
        dm = DomainModel(concepts=[
            Concept(id="root", description="r"),
            Concept(id="child1", description="c1", parent_id="root"),
            Concept(id="child2", description="c2", parent_id="root"),
            Concept(id="orphan", description="o"),
        ])
        children = dm.concept_children("root")
        assert {c.id for c in children} == {"child1", "child2"}

    def test_concept_subtree(self) -> None:
        dm = DomainModel(concepts=[
            Concept(id="root", description="r"),
            Concept(id="mid", description="m", parent_id="root"),
            Concept(id="leaf", description="l", parent_id="mid"),
        ])
        subtree = dm.concept_subtree("root")
        assert {c.id for c in subtree} == {"mid", "leaf"}

    def test_subtree_handles_cycle(self) -> None:
        dm = DomainModel(concepts=[
            Concept(id="a", description="a", parent_id="b"),
            Concept(id="b", description="b", parent_id="a"),
        ])
        subtree = dm.concept_subtree("a")
        assert len(subtree) <= 2

    def test_default_parent_id_empty(self) -> None:
        c = Concept(id="x", description="d")
        assert c.parent_id == ""

    def test_serialisation_roundtrip(self) -> None:
        import json
        from dataclasses import asdict
        dm = DomainModel(concepts=[
            Concept(id="child", description="d", parent_id="parent"),
        ])
        raw = json.loads(json.dumps(asdict(dm)))
        assert raw["concepts"][0]["parent_id"] == "parent"


class TestSourceHashVersioning:
    """Gap 10: source_hash / source_hash_span on Invariant and Concept."""

    def test_invariant_hash_fields_exist(self) -> None:
        inv = Invariant(
            id="i", concept="c", statement="s", negation="n",
            source_hash="abc123", source_hash_span={"file": "f.c", "start": 1, "end": 10},
        )
        assert inv.source_hash == "abc123"
        assert inv.source_hash_span["file"] == "f.c"

    def test_concept_hash_fields_exist(self) -> None:
        c = Concept(
            id="c", description="d",
            source_hash="def456", source_hash_span={"file": "g.py", "start": 5, "end": 20},
        )
        assert c.source_hash == "def456"

    def test_stale_invariants_detects_mismatch(self, tmp_path: Path) -> None:
        import hashlib
        src = tmp_path / "f.c"
        src.write_text("line1\nline2\nline3\n")
        region = "line1\nline2\nline3\n"
        h = hashlib.sha256(region.encode()).hexdigest()[:16]

        inv = Invariant(
            id="i", concept="c", statement="s", negation="n",
            source_hash=h, source_hash_span={"file": "f.c", "start": 1, "end": 3},
        )
        dm = DomainModel(invariants=[inv])
        assert dm.stale_invariants(tmp_path) == []

        src.write_text("changed\nline2\nline3\n")
        stale = dm.stale_invariants(tmp_path)
        assert len(stale) == 1
        assert stale[0].id == "i"

    def test_mark_stale_sets_state(self, tmp_path: Path) -> None:
        inv = Invariant(
            id="i", concept="c", statement="s", negation="n",
            source_hash="wrong",
            source_hash_span={"file": "missing.c", "start": 1, "end": 5},
        )
        dm = DomainModel(invariants=[inv])
        n = dm.mark_stale(tmp_path)
        assert n == 1
        assert inv.state == "stale"

    def test_no_hash_not_stale(self, tmp_path: Path) -> None:
        inv = Invariant(id="i", concept="c", statement="s", negation="n")
        dm = DomainModel(invariants=[inv])
        assert dm.stale_invariants(tmp_path) == []

    def test_serialisation_roundtrip(self) -> None:
        import json
        from dataclasses import asdict
        inv = Invariant(
            id="i", concept="c", statement="s", negation="n",
            source_hash="h", source_hash_span={"file": "f.c", "start": 1, "end": 5},
        )
        raw = json.loads(json.dumps(asdict(inv)))
        assert raw["source_hash"] == "h"
        assert raw["source_hash_span"]["file"] == "f.c"

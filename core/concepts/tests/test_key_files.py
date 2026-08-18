"""Tests for the domain model's key_files producer.

Regression: ``DomainModel.key_files`` had a consumer (the audit
orchestrator's priority boost via ``domain_key_files``) but no
producer — Phase 3 never populated the field and the cross-pass merge
dropped it, so the boost was structurally unreachable.
"""

from __future__ import annotations

import json

from core.concepts.model import Concept, Contract, DomainModel, Evidence
from core.concepts.study import (
    _KEY_FILE_CAP,
    _derive_key_files,
    _merge_domain_models,
    run_phase3,
)

_DESCRIPTIONS = {
    "refcounting": "objects carry a reference count freed at zero",
    "locking": "the global mutex serialises writer threads",
}


def _concept(cid: str, files: list[str]) -> Concept:
    return Concept(
        id=cid,
        description=_DESCRIPTIONS.get(
            cid, f"distinct semantics token {cid} " + " ".join(
                f"word{ord(ch)}" for ch in cid
            ),
        ),
        evidence=[
            Evidence(type="code_path", file=f, observation=f"seen in {f}")
            for f in files
        ],
        confidence="observed",
    )


def _contract(fn: str, file: str) -> Contract:
    return Contract(function=fn, file=file, when="always")


class TestDeriveKeyFiles:
    def test_multiply_cited_file_becomes_key(self):
        out = _derive_key_files(
            [_concept("c1", ["src/core.c"]), _concept("c2", ["src/core.c"])],
            [],
        )
        assert out == [
            {"path": "src/core.c", "reason": "cited by 2 study entries"},
        ]

    def test_single_citation_not_key(self):
        out = _derive_key_files([_concept("c1", ["src/rare.c"])], [])
        assert out == []

    def test_contracts_count_as_citations(self):
        out = _derive_key_files(
            [_concept("c1", ["src/api.c"])],
            [_contract("api_call", "src/api.c")],
        )
        assert [kf["path"] for kf in out] == ["src/api.c"]

    def test_duplicate_evidence_in_one_concept_counts_once(self):
        c = _concept("c1", ["src/core.c", "src/core.c", "src/core.c"])
        assert _derive_key_files([c], []) == []

    def test_ranked_most_cited_first_and_capped(self):
        concepts = []
        # file_i is cited by (i + 2) concepts
        for i in range(_KEY_FILE_CAP + 3):
            for j in range(i + 2):
                concepts.append(_concept(f"c{i}_{j}", [f"src/f{i:02d}.c"]))
        out = _derive_key_files(concepts, [])
        assert len(out) == _KEY_FILE_CAP
        # Highest citation counts (largest i) first.
        assert out[0]["path"] == f"src/f{_KEY_FILE_CAP + 2:02d}.c"


class TestPhase3EmitsKeyFiles:
    def test_run_phase3_populates_key_files(self):
        concepts = [
            _concept("refcounting", ["src/obj.c"]),
            _concept("locking", ["src/obj.c"]),
        ]
        model = run_phase3(concepts, [], [], target="demo")
        assert model.key_files
        assert model.key_files[0]["path"] == "src/obj.c"

    def test_key_files_round_trip_to_consumer(self, tmp_path):
        """The emitted shape feeds domain_key_files unchanged."""
        from core.concepts.audit_bridge import domain_key_files

        concepts = [
            _concept("refcounting", ["src/obj.c"]),
            _concept("locking", ["src/obj.c"]),
        ]
        model = run_phase3(concepts, [], [], target="demo")
        path = tmp_path / "domain-model.json"
        model.save(path)
        assert domain_key_files(tmp_path) == {"src/obj.c"}
        # And the serialized form is plain JSON with both keys.
        raw = json.loads(path.read_text(encoding="utf-8"))
        assert raw["key_files"][0].keys() >= {"path", "reason"}


class TestMergePreservesKeyFiles:
    def test_merge_unions_by_path_new_wins(self):
        prior = DomainModel(key_files=[
            {"path": "src/a.c", "reason": "cited by 2 study entries"},
            {"path": "src/b.c", "reason": "cited by 3 study entries"},
        ])
        new = DomainModel(key_files=[
            {"path": "src/b.c", "reason": "cited by 5 study entries"},
            {"path": "src/c.c", "reason": "cited by 2 study entries"},
        ])
        merged = _merge_domain_models(prior, new)
        by_path = {kf["path"]: kf["reason"] for kf in merged.key_files}
        assert by_path == {
            "src/a.c": "cited by 2 study entries",
            "src/b.c": "cited by 5 study entries",
            "src/c.c": "cited by 2 study entries",
        }

    def test_merge_with_empty_new_keeps_prior(self):
        prior = DomainModel(key_files=[{"path": "src/a.c", "reason": "r"}])
        merged = _merge_domain_models(prior, DomainModel())
        assert merged.key_files == [{"path": "src/a.c", "reason": "r"}]

"""Map→study bridge: discovery precedence, extraction priority,
fid translation with miss recording, and bounded emission."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from core.orchestration import binary_study_bridge as bridge

ANCHOR = "ab12cd34ef56ab78"
OTHER_ANCHOR = "1111222233334444"


def _fid(anchor: str, rel: int) -> str:
    return f"{anchor}:0x{rel:x}"


def _write_map(directory: Path, *, anchor: str = ANCHOR,
               boundaries: list | None = None,
               anchors_list: list | None = None) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "binary-context-map.json"
    path.write_text(json.dumps({
        "content_anchor": anchor,
        "parser_boundary_candidates": boundaries or [],
        "string_anchor_functions": anchors_list or [],
    }), encoding="utf-8")
    return path


def _fake_db(names_rels: list[tuple[str, int]]) -> SimpleNamespace:
    functions = [
        SimpleNamespace(name=name, address=0x1000 + rel,
                        fid=_fid(ANCHOR, rel), is_external=False)
        for name, rel in names_rels
    ]
    return SimpleNamespace(functions=functions, binary_path=None)


# ------------------------------------------------------------------
# Discovery precedence
# ------------------------------------------------------------------

class TestDiscovery:
    def test_colocated_wins_over_sibling(self, tmp_path: Path) -> None:
        study = tmp_path / "study"
        _write_map(study)
        _write_map(tmp_path / "sibling")
        found = bridge.find_binary_artifacts(
            study, expected_anchor=ANCHOR)
        assert found is not None
        assert found.tier == "colocated"
        assert found.map_path == study / "binary-context-map.json"

    def test_colocated_accepted_without_anchor(self, tmp_path: Path) -> None:
        # Shared --out handoff: the operator aligned the dirs — a
        # missing anchor on either side does not reject tier 1.
        study = tmp_path / "study"
        _write_map(study, anchor="")
        found = bridge.find_binary_artifacts(
            study, expected_anchor=ANCHOR)
        assert found is not None and found.tier == "colocated"

    def test_colocated_anchor_mismatch_rejected(self, tmp_path: Path) -> None:
        study = tmp_path / "study"
        _write_map(study, anchor=OTHER_ANCHOR)
        found = bridge.find_binary_artifacts(
            study, expected_anchor=ANCHOR)
        assert found is None

    def test_sibling_requires_anchor_match(self, tmp_path: Path) -> None:
        study = tmp_path / "study"
        study.mkdir()
        _write_map(tmp_path / "wrong", anchor=OTHER_ANCHOR)
        _write_map(tmp_path / "right", anchor=ANCHOR)
        found = bridge.find_binary_artifacts(
            study, expected_anchor=ANCHOR)
        assert found is not None
        assert found.tier == "project_sibling"
        assert found.map_path.parent.name == "right"

    def test_no_expected_anchor_confines_to_colocated(
            self, tmp_path: Path) -> None:
        study = tmp_path / "study"
        study.mkdir()
        _write_map(tmp_path / "sibling", anchor=ANCHOR)
        assert bridge.find_binary_artifacts(
            study, expected_anchor=None) is None

    def test_anchor_gate_beats_recency_among_siblings(
            self, tmp_path: Path) -> None:
        """Mutation killer: the RIGHT-anchor sibling is written
        FIRST (older mtime) and a WRONG-anchor sibling is NEWER —
        selection must be anchor-driven, not an mtime accident."""
        import os
        study = tmp_path / "study"
        study.mkdir()
        right = _write_map(tmp_path / "right", anchor=ANCHOR)
        wrong = _write_map(tmp_path / "wrong", anchor=OTHER_ANCHOR)
        # Force the wrong-anchor candidate to sort first by recency.
        os.utime(right.parent, (1_000_000, 1_000_000))
        os.utime(wrong.parent, (2_000_000, 2_000_000))
        found = bridge.find_binary_artifacts(
            study, expected_anchor=ANCHOR)
        assert found is not None
        assert found.map_path.parent.name == "right"

    def test_project_sibling_beats_global_out(
            self, tmp_path: Path, monkeypatch) -> None:
        """Mutation killer: with matching-anchor candidates staged
        in BOTH tier 2 and tier 3, tier 2 (project sibling) wins."""
        study = tmp_path / "proj" / "study"
        study.mkdir(parents=True)
        _write_map(tmp_path / "proj" / "sibling", anchor=ANCHOR)
        out_root = tmp_path / "out"
        _write_map(out_root / "global_run", anchor=ANCHOR)
        from core.config import RaptorConfig
        monkeypatch.setattr(RaptorConfig, "get_out_dir",
                            staticmethod(lambda: out_root))
        found = bridge.find_binary_artifacts(
            study, expected_anchor=ANCHOR)
        assert found is not None
        assert found.tier == "project_sibling"
        assert found.map_path.parent.name == "sibling"

    def test_global_out_tier(self, tmp_path: Path, monkeypatch) -> None:
        study = tmp_path / "proj" / "study"
        study.mkdir(parents=True)
        out_root = tmp_path / "out"
        _write_map(out_root / "understand_1", anchor=ANCHOR)
        from core.config import RaptorConfig
        monkeypatch.setattr(RaptorConfig, "get_out_dir",
                            staticmethod(lambda: out_root))
        found = bridge.find_binary_artifacts(
            study, expected_anchor=ANCHOR)
        assert found is not None and found.tier == "global_out"

    def test_hunt_artifacts_ride_with_selected_map(
            self, tmp_path: Path) -> None:
        study = tmp_path / "study"
        _write_map(study)
        (study / "binary-hunt-magic.json").write_text("{}",
                                                      encoding="utf-8")
        found = bridge.find_binary_artifacts(
            study, expected_anchor=ANCHOR)
        assert found is not None
        assert [p.name for p in found.hunt_paths] == [
            "binary-hunt-magic.json"]


# ------------------------------------------------------------------
# Extraction priority
# ------------------------------------------------------------------

class TestExtraction:
    def test_priority_order_and_ranking(self) -> None:
        map_data = {
            "parser_boundary_candidates": [
                {"boundary_function_name": "low_pb", "score": 10},
                {"boundary_function_name": "high_pb", "score": 90},
            ],
            "string_anchor_functions": [
                {"name": "sparse", "anchor_string_count": 1},
                {"name": "dense", "anchor_string_count": 12},
            ],
        }
        hunt = {"families": [{
            "anchor": "channel file",
            "members": [{"name": "fam_a"}],
            "check_sites": [{"name": "chk_a"}],
        }]}
        cands = bridge.extract_seed_candidates(map_data, [hunt])
        names = [c["name"] for c in cands]
        assert names == ["high_pb", "low_pb", "dense", "sparse",
                         "fam_a", "chk_a"]
        origins = [c["origin"] for c in cands]
        assert origins == [
            "parser_boundary", "parser_boundary", "string_anchor",
            "string_anchor", "hunt_member", "hunt_check_site"]

    def test_candidate_bound(self) -> None:
        map_data = {"string_anchor_functions": [
            {"name": f"f{i}", "anchor_string_count": 1}
            for i in range(500)
        ]}
        cands = bridge.extract_seed_candidates(map_data, [])
        assert len(cands) == bridge._MAX_CANDIDATES

    def test_why_is_escaped_at_capture(self) -> None:
        map_data = {"parser_boundary_candidates": [{
            "boundary_function_name": "pb",
            "ingress_name": "evil\x1b[31mname",
            "score": 1,
        }]}
        cands = bridge.extract_seed_candidates(map_data, [])
        assert "\x1b" not in cands[0]["why"]
        assert "\\x1b" in cands[0]["why"]

    def test_concepts_bounded_token_shaped(self) -> None:
        map_data = {"string_anchor_functions": [{
            "name": "f", "anchor_string_count": 2,
            "sample_strings": [
                "parse channel file header",
                "channel checksum \x1b bad;rm -rf",
                "error: failed",  # stopwords — never concepts
            ],
        }]}
        hunt = {"families": [{"anchor": "channel file",
                              "members": []}]}
        concepts = bridge.extract_concepts(map_data, [hunt])
        assert concepts
        assert len(concepts) <= bridge.MAX_BRIDGE_CONCEPTS
        assert "channel" in concepts
        assert "error" not in concepts and "failed" not in concepts
        for c in concepts:
            assert bridge._CONCEPT_TOKEN_RE.fullmatch(c), c


# ------------------------------------------------------------------
# Translation
# ------------------------------------------------------------------

class TestTranslation:
    def test_exact_fid_join(self) -> None:
        db = _fake_db([("parse_hdr", 0x10)])
        cands = [{"name": "sym.other", "fid": _fid(ANCHOR, 0x10),
                  "origin": "parser_boundary", "why": "w"}]
        seeds, misses = bridge.translate_candidates(cands, db)
        assert [s.name for s in seeds] == ["parse_hdr"]
        assert seeds[0].match_method == "exact"
        assert seeds[0].seed_source == "bridge_seed"
        assert seeds[0].derived_from_target is True
        assert misses == []

    def test_name_fallback_strips_r2_prefix(self) -> None:
        db = _fake_db([("parse_hdr", 0x10)])
        cands = [{"name": "sym.parse_hdr", "fid": None,
                  "origin": "string_anchor", "why": "w"}]
        seeds, misses = bridge.translate_candidates(cands, db)
        assert [s.name for s in seeds] == ["parse_hdr"]
        assert seeds[0].match_method == "name"
        assert misses == []

    def test_no_join_recorded_as_miss(self) -> None:
        db = _fake_db([("parse_hdr", 0x10)])
        cands = [{"name": "fcn.00401000",
                  "fid": _fid(OTHER_ANCHOR, 0x99),
                  "origin": "hunt_member", "why": "w"}]
        seeds, misses = bridge.translate_candidates(cands, db)
        assert seeds == []
        assert len(misses) == 1
        assert misses[0]["reason"] == "no-join"
        assert misses[0]["origin"] == "hunt_member"

    def test_unrepresentable_resolved_name_is_a_miss(self) -> None:
        db = SimpleNamespace(functions=[SimpleNamespace(
            name="bad name; rm -rf /", address=0x1010,
            fid=_fid(ANCHOR, 0x10), is_external=False)],
            binary_path=None)
        cands = [{"name": "x", "fid": _fid(ANCHOR, 0x10),
                  "origin": "parser_boundary", "why": "w"}]
        seeds, misses = bridge.translate_candidates(cands, db)
        assert seeds == []
        assert misses[0]["reason"] == "unrepresentable-name"

    def test_dedupe_keeps_highest_priority_origin(self) -> None:
        db = _fake_db([("parse_hdr", 0x10)])
        cands = [
            {"name": "parse_hdr", "fid": _fid(ANCHOR, 0x10),
             "origin": "parser_boundary", "why": "pb"},
            {"name": "parse_hdr", "fid": _fid(ANCHOR, 0x10),
             "origin": "string_anchor", "why": "sa"},
        ]
        seeds, _ = bridge.translate_candidates(cands, db)
        assert len(seeds) == 1
        assert seeds[0].origin == "parser_boundary"

    def test_seed_bound_is_24(self) -> None:
        # Mutation killer: the bound is pinned LITERALLY — a drifted
        # MAX_BRIDGE_SEEDS constant must fail here, not re-derive
        # the assertion.
        db = _fake_db([(f"fn_{i}", 0x10 * (i + 1)) for i in range(40)])
        cands = [{"name": f"fn_{i}",
                  "fid": _fid(ANCHOR, 0x10 * (i + 1)),
                  "origin": "hunt_member", "why": "w"}
                 for i in range(40)]
        seeds, _ = bridge.translate_candidates(cands, db)
        assert len(seeds) == 24

    def test_synthetic_prefixes_not_laundered(self) -> None:
        """fcn./loc. wrap tool-synthetic placeholders, never real
        names — stripping them once laundered placeholders past the
        looks_tool_synthetic refusal in the name-fallback join."""
        db = _fake_db([("target_fn", 0x10)])
        for raw in ("loc.target_fn", "fcn.00401000"):
            seeds, misses = bridge.translate_candidates(
                [{"name": raw, "fid": None,
                  "origin": "hunt_member", "why": "w"}], db)
            assert seeds == [], raw
            assert misses and misses[0]["reason"] == "no-join", raw


# ------------------------------------------------------------------
# End-to-end emission
# ------------------------------------------------------------------

class TestBuildBridgeSeeds:
    @pytest.fixture()
    def study_dir(self, tmp_path: Path) -> Path:
        study = tmp_path / "study"
        _write_map(
            study,
            boundaries=[{
                "boundary_function_name": "sym.parse_hdr",
                "fid": _fid(ANCHOR, 0x10), "score": 90,
                "ingress_name": "recv",
            }],
            anchors_list=[{
                "name": "ghost_fn", "anchor_string_count": 3,
                "sample_strings": ["channel file header"],
            }],
        )
        return study

    def test_writes_seeds_and_misses(self, study_dir: Path) -> None:
        db = _fake_db([("parse_hdr", 0x10)])
        path = bridge.build_bridge_seeds(study_dir, db)
        assert path == study_dir / "bridge-seeds.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["schema_version"] == 1
        assert data["honesty"] == bridge.HONESTY_LINE
        assert data["discovery_tier"] == "colocated"
        names = [s["name"] for s in data["seeds"]]
        assert names == ["parse_hdr"]
        seed = data["seeds"][0]
        assert seed["seed_source"] == "bridge_seed"
        assert seed["derived_from_target"] is True
        assert seed["origin"] == "parser_boundary"
        assert seed["why"]
        # ghost_fn had no join — recorded, never silently dropped.
        assert data["miss_count"] == 1
        misses = json.loads(
            (study_dir / "fid-misses.json").read_text(encoding="utf-8"))
        ops = [op["operation"] for op in misses["operations"]]
        assert "binary-study-bridge" in ops

    def test_item_budget_tightens_seed_bound(self, tmp_path: Path) -> None:
        study = tmp_path / "study"
        _write_map(study, boundaries=[
            {"boundary_function_name": f"fn_{i}",
             "fid": _fid(ANCHOR, 0x10 * (i + 1)), "score": 100 - i}
            for i in range(20)
        ])
        db = _fake_db([(f"fn_{i}", 0x10 * (i + 1)) for i in range(20)])
        path = bridge.build_bridge_seeds(study, db, item_budget=8)
        data = json.loads(path.read_text(encoding="utf-8"))
        # ≤ fraction of the item budget: 8 * 0.5 = 4.
        assert len(data["seeds"]) == int(
            8 * bridge.DERIVED_ATTENTION_MAX_FRACTION)
        # Priority order preserved: highest-score boundaries kept.
        assert [s["name"] for s in data["seeds"]] == [
            "fn_0", "fn_1", "fn_2", "fn_3"]

    def test_no_artifacts_returns_none(self, tmp_path: Path) -> None:
        study = tmp_path / "study"
        study.mkdir()
        db = _fake_db([("parse_hdr", 0x10)])
        assert bridge.build_bridge_seeds(study, db) is None

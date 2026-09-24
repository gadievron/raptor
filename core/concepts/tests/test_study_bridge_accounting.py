"""Joint derived-attention accounting: bridge seeds + SAGE seed
blocks share one fraction of the phase-2 item budget; operator seeds
never count."""

from __future__ import annotations

import json
from pathlib import Path

from core.concepts import study
from core.concepts.model import DomainModel, StudyItem
from core.orchestration.binary_study_bridge import (
    DERIVED_ATTENTION_MAX_FRACTION,
)


def _item(name: str, *, tier: int | None = None,
          seed_source: str = "") -> StudyItem:
    return StudyItem(
        id=f"fn.{name}", kind="function", name=name, file="a.c",
        relevance_tier=tier, seed_source=seed_source,
    )


class TestDerivedAttentionCap:
    def test_defaults_arithmetic_pinned(self, monkeypatch) -> None:
        """The denominator is the EFFECTIVE batch budget. At the
        defaults (batch_target 80, output budget 16384 / ~512 tokens
        per item → 32-item phase-2 ceiling) the cap is 16 — computed
        on the raw batch_target it would be 40, more than one whole
        PAID batch of derived attention."""
        monkeypatch.delenv("RAPTOR_STUDY_MAX_OUTPUT_TOKENS",
                           raising=False)
        assert study._phase2_batch_ceiling() == 32
        assert study._derived_attention_cap(80) == 16

    def test_smaller_batch_target_wins(self, monkeypatch) -> None:
        monkeypatch.delenv("RAPTOR_STUDY_MAX_OUTPUT_TOKENS",
                           raising=False)
        assert study._derived_attention_cap(8) == int(
            8 * DERIVED_ATTENTION_MAX_FRACTION)

    def test_floor_of_one(self) -> None:
        # A tiny (or typo'd) batch target degrades to "one derived
        # entry", never all-or-nothing.
        assert study._derived_attention_cap(1) == 1
        assert study._derived_attention_cap(0) == 1


class TestBridgeSeedCap:
    def test_overflow_reverts_to_baseline(self) -> None:
        """Overflow loses the bridge's GRANT (tier back to None —
        still focus by default classification) and never sinks to
        context: an attacker must not be able to make a function
        studied LESS by naming it in the map's tail."""
        items = [_item(f"b{i}", tier=1, seed_source="bridge_seed")
                 for i in range(6)]
        kept = study._enforce_bridge_seed_cap(items, 4)
        assert kept == 4
        assert [it.relevance_tier for it in items] == [
            1, 1, 1, 1, None, None]
        assert [it.seed_source for it in items] == [
            "bridge_seed"] * 4 + ["bridge_seed_overflow"] * 2
        # Baseline check: tier None still classifies as focus.
        in_scope, deps = study._classify_scope(items, "", "")
        assert {it.name for it in deps} == set()
        assert len(in_scope) == 6

    def test_reversion_takes_the_tail(self) -> None:
        # Prep emits bridge items in bridge-priority order: the tail
        # (lowest priority) is what a tight cap drops.
        items = [_item("hi", tier=1, seed_source="bridge_seed"),
                 _item("lo", tier=1, seed_source="bridge_seed")]
        study._enforce_bridge_seed_cap(items, 1)
        assert items[0].relevance_tier == 1
        assert items[1].relevance_tier is None
        assert items[1].seed_source == "bridge_seed_overflow"

    def test_concept_seed_inflation_route(self, monkeypatch) -> None:
        """Bridge concepts can seed 20-80 identifiers into the
        bridge tier — at the DEFAULT batch_target the joint cap must
        still bind (16 kept), with the rest at baseline, not below."""
        monkeypatch.delenv("RAPTOR_STUDY_MAX_OUTPUT_TOKENS",
                           raising=False)
        items = [_item(f"seeded{i}", tier=1, seed_source="bridge_seed")
                 for i in range(20)]
        cap = study._derived_attention_cap(80)
        kept = study._enforce_bridge_seed_cap(items, cap)
        assert kept == 16
        assert sum(1 for it in items
                   if it.seed_source == "bridge_seed") == 16
        overflow = [it for it in items
                    if it.seed_source == "bridge_seed_overflow"]
        assert len(overflow) == 4
        assert all(it.relevance_tier is None for it in overflow)

    def test_operator_and_corroborated_never_touched(self) -> None:
        items = [
            _item("op", tier=0, seed_source="operator"),
            _item("corr", tier=0, seed_source="bridge_corroborated"),
            _item("plain", tier=1),
        ]
        kept = study._enforce_bridge_seed_cap(items, 0)
        assert kept == 0
        assert [it.relevance_tier for it in items] == [0, 0, 1]

    def test_under_cap_untouched(self) -> None:
        items = [_item("b0", tier=1, seed_source="bridge_seed")]
        assert study._enforce_bridge_seed_cap(items, 4) == 1
        assert items[0].relevance_tier == 1


class TestSagePriorSeedBlockCap:
    def _prior(self, names: list[str]) -> dict[str, list]:
        # Content without evidence hashes → the seed path (no
        # mechanical skip), which is the capped surface.
        return {n: [{"content": f"prior for {n}", "confidence": 0.9}]
                for n in names}

    def test_blocks_trimmed_beyond_cap(self, tmp_path: Path) -> None:
        items = [_item(f"f{i}") for i in range(4)]
        remaining, _c, _i, _ct, seed_ctx = study._apply_sage_prior(
            items, self._prior([f"f{i}" for i in range(4)]),
            tmp_path, seed_block_cap=2,
        )
        # Trimmed items are still studied — only their prior block
        # is withheld.
        assert len(remaining) == 4
        assert seed_ctx.count("## Prior study knowledge") == 2

    def test_cap_none_is_uncapped(self, tmp_path: Path) -> None:
        items = [_item(f"f{i}") for i in range(3)]
        _r, _c, _i, _ct, seed_ctx = study._apply_sage_prior(
            items, self._prior([f"f{i}" for i in range(3)]), tmp_path,
        )
        assert seed_ctx.count("## Prior study knowledge") == 3

    def test_zero_cap_emits_no_blocks(self, tmp_path: Path) -> None:
        items = [_item("f0")]
        _r, _c, _i, _ct, seed_ctx = study._apply_sage_prior(
            items, self._prior(["f0"]), tmp_path, seed_block_cap=0,
        )
        assert seed_ctx == ""


class TestRunStudyJointAccounting:
    def test_bridge_and_sage_share_the_budget(
            self, tmp_path: Path, monkeypatch) -> None:
        """batch_target=4 → cap=2. Two bridge focus items fill it:
        the third demotes to context AND the SAGE seed blocks get a
        zero allowance (joint, not parallel, budgets)."""
        items = [
            _item("b0", tier=1, seed_source="bridge_seed"),
            _item("b1", tier=1, seed_source="bridge_seed"),
            _item("b2", tier=1, seed_source="bridge_seed"),
            _item("auto0"),
        ]
        sl_path = tmp_path / "study-list.json"
        sl_path.write_text(json.dumps({
            "target": "t", "source_root": "",
            "items": [
                {"id": it.id, "kind": it.kind, "name": it.name,
                 "file": it.file, "relevance_tier": it.relevance_tier,
                 "seed_source": it.seed_source}
                for it in items
            ],
        }), encoding="utf-8")

        import core.sage.hooks as sage_hooks
        monkeypatch.setattr(
            sage_hooks, "recall_concepts_for_study",
            lambda **_kw: {
                "auto0": [{"content": "prior auto0",
                           "confidence": 0.9}],
            },
        )
        monkeypatch.setattr(
            sage_hooks, "store_study_concepts", lambda **_kw: 0,
        )

        captured: dict = {}

        def fake_phase2(items_in, _target, _client, **kwargs):
            captured["items"] = list(items_in)
            captured["doc_context"] = kwargs.get("doc_context", "")
            return [], [], [], [], []

        monkeypatch.setattr(study, "run_phase2", fake_phase2)
        monkeypatch.setattr(
            study, "run_phase3",
            lambda *_a, **_kw: DomainModel(target="t"),
        )
        monkeypatch.setattr(
            study, "_promote_to_project", lambda *_a, **_kw: None,
        )

        progress: list[tuple[str, str]] = []
        study.run_study(
            sl_path, tmp_path, llm_client=object(),
            on_progress=lambda phase, msg: progress.append((phase, msg)),
            batch_target=4,
        )

        by_name = {it.name: it for it in captured["items"]}
        assert by_name["b0"].relevance_tier == 1
        assert by_name["b1"].relevance_tier == 1
        # Third bridge seed reverted to BASELINE by the joint cap
        # (4 * 0.5 = 2) — never below it.
        assert by_name["b2"].relevance_tier is None
        assert by_name["b2"].seed_source == "bridge_seed_overflow"
        # SAGE's allowance was cap - bridge_kept = 0: prior block
        # trimmed, item still studied.
        assert "auto0" in by_name
        assert "## Prior study knowledge" not in captured["doc_context"]
        assert any(p == "bridge" for p, _m in progress)

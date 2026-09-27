"""Tests for the engagement depth-policy + budget governor
(``core.engagement.governor``) and the ledger's policy-slot schema
(``core.engagement.ledger`` extensions the governor rides on).

Fixture discipline mirrors the ledger tests: ELF install trees are
crafted in-test (never a host compiler), the sandboxed build-id probe
is stubbed autouse, and where a test needs exposure signals it plants
them directly on synthetic documents — the extraction itself is the
ledger battery's subject.
"""

from __future__ import annotations

import json
import struct
from pathlib import Path
from typing import Any

import pytest

from core.audit.triage import TriageBucket
from core.binary import elf as elf_mod
from core.engagement import governor as gov
from core.engagement import ledger as ledger_mod
from core.engagement.governor import (
    BASIS_NEEDED_BY_T3,
    BASIS_SAMPLE,
    BASIS_SIGNAL,
    PARK_AFTER_DEATHS,
    TIER_BUCKET,
    TIER_T0,
    TIER_T1,
    TIER_T2,
    TIER_T3,
    VERDICT_CONFLICT,
    VERDICT_FITS,
    VERDICT_TIGHT,
    assign_depth,
    depth_label,
)


@pytest.fixture(autouse=True)
def _stub_build_id(monkeypatch):
    monkeypatch.setattr(elf_mod, "_read_build_id",
                        lambda p: (None, None))


# ── fixture builders ─────────────────────────────────────────────────

_ELF_FACTS_EXTRACTOR = "core.binary.elf.extract_elf_facts"


def _write_elf(path: Path) -> None:
    path.write_bytes(
        b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8
        + struct.pack("<HHIQQQIHHHHHH",
                      3, 0x3E, 1, 0, 0, 0, 0, 64, 0, 0, 64, 0, 0)
        + path.name.encode())


def _build(tmp_path: Path, names: tuple[str, ...] = ("alpha", "beta",
                                                     "gamma"),
           out: str = "out") -> tuple[Path, dict[str, Any]]:
    target = tmp_path / "install"
    target.mkdir(exist_ok=True)
    for n in names:
        _write_elf(target / n)
    out_dir = tmp_path / out
    doc = ledger_mod.build_ledger(target, out_dir)
    return out_dir, doc


def _row(aid: str, *, cls: str = "elf-linux", size: int = 1000,
         exposure: list[dict[str, Any]] | None = None,
         needed: list[str] | None = None,
         **extra: Any) -> dict[str, Any]:
    row: dict[str, Any] = {
        "artifact_id": aid, "class": cls, "size_bytes": size,
        "exposure": exposure or [],
        "links": {"needed": needed or []},
    }
    row.update(extra)
    return row


def _signal(feature: str = "input_channels") -> dict[str, Any]:
    return {"feature": feature, "value": ["network"],
            "extractor": "packages.binary_analysis.input_channels"
                         ".recover_static_channels"}


def _facts_feature() -> dict[str, Any]:
    return {"feature": "interpreter", "value": True,
            "extractor": _ELF_FACTS_EXTRACTOR}


def _doc(rows: list[dict[str, Any]],
         reverse_needed: list[dict[str, Any]] | None = None,
         ) -> dict[str, Any]:
    return {"rows": rows, "reverse_needed": reverse_needed or []}


# ── ledger policy-slot schema ────────────────────────────────────────

class TestPolicySlotSchema:
    def test_valid_policy_and_reservation_land(self, tmp_path):
        out, doc = _build(tmp_path)
        aid = doc["rows"][0]["artifact_id"]
        assert ledger_mod.set_artifact_policy(
            out, aid,
            policy={"tier": "T3", "bucket": "deep_dive",
                    "basis": "exposure_signal", "floor": "T1",
                    "signals": [{"feature": "input_channels",
                                 "extractor": "pkg.mod.fn"}]},
            reservation={"segment": 1, "reserved_usd": 12.5,
                         "state": "reserved", "deaths": 0},
        )
        row = next(r for r in ledger_mod.load_ledger(out)["rows"]
                   if r["artifact_id"] == aid)
        assert row["policy"]["tier"] == "T3"
        assert row["reservation"]["reserved_usd"] == 12.5

    @pytest.mark.parametrize("policy", [
        {"tier": "T3", "surprise": 1},              # unknown key
        {"tier": "T3\x1b[31m"},                     # escape bytes
        {"signals": [{"feature": "a b", "extractor": "x"}]},  # space
        {"promoted_by": ["../evil"]},               # non-id
    ])
    def test_bad_policy_refused_document_untouched(self, tmp_path,
                                                   policy):
        out, doc = _build(tmp_path)
        aid = doc["rows"][0]["artifact_id"]
        before = ledger_mod.ledger_path(out).read_bytes()
        with pytest.raises(ValueError):
            ledger_mod.set_artifact_policy(out, aid, policy=policy)
        assert ledger_mod.ledger_path(out).read_bytes() == before

    @pytest.mark.parametrize("reservation", [
        {"reserved_usd": float("inf")},
        {"reserved_usd": float("nan")},
        {"reserved_usd": -1.0},
        {"state": "spent"},
        {"deaths": -1},
        {"segment": True},
    ])
    def test_bad_reservation_refused(self, tmp_path, reservation):
        out, doc = _build(tmp_path)
        aid = doc["rows"][0]["artifact_id"]
        with pytest.raises(ValueError):
            ledger_mod.set_artifact_policy(out, aid,
                                           reservation=reservation)

    def test_nothing_to_write_refused(self, tmp_path):
        out, doc = _build(tmp_path)
        with pytest.raises(ValueError):
            ledger_mod.set_artifact_policy(
                out, doc["rows"][0]["artifact_id"])

    def test_bulk_validates_all_before_writing_any(self, tmp_path):
        out, doc = _build(tmp_path)
        ids = [r["artifact_id"] for r in doc["rows"]][:2]
        with pytest.raises(ValueError):
            ledger_mod.set_artifact_policies(out, {
                ids[0]: {"tier": "T1"},
                ids[1]: {"tier": "T1", "nope": 1},
            })
        fresh = ledger_mod.load_ledger(out)
        assert all("policy" not in r for r in fresh["rows"])
        assert ledger_mod.set_artifact_policies(out, {
            ids[0]: {"tier": "T1"}, ids[1]: {"tier": "T2"},
        }) == 2

    def test_amendment_stamps_seq_and_at(self, tmp_path):
        out, _doc_ = _build(tmp_path)
        assert ledger_mod.append_policy_amendment(
            out, {"kind": "degradation"}) == 1
        assert ledger_mod.append_policy_amendment(
            out, {"kind": "degradation"}) == 2
        trail = ledger_mod.load_policy_amendments(out)
        assert [a["seq"] for a in trail] == [1, 2]
        assert all(a["at"] for a in trail)

    def test_amendment_cap_refuses_with_one_time_residual(
            self, tmp_path, monkeypatch):
        out, _doc_ = _build(tmp_path)
        monkeypatch.setattr(ledger_mod, "_MAX_POLICY_AMENDMENTS", 2)
        assert ledger_mod.append_policy_amendment(
            out, {"kind": "a"}) == 1
        assert ledger_mod.append_policy_amendment(
            out, {"kind": "a"}) == 2
        assert ledger_mod.append_policy_amendment(
            out, {"kind": "a"}) == -1
        assert ledger_mod.append_policy_amendment(
            out, {"kind": "a"}) == -1
        doc = ledger_mod.load_ledger(out)
        truncs = [r for r in doc["residuals"]
                  if r["kind"] == "policy_amendments_truncated"]
        assert len(truncs) == 1
        assert len(doc["policy_amendments"]) == 2

    def test_amendment_kind_token_gated_and_byte_bounded(self,
                                                         tmp_path):
        out, _doc_ = _build(tmp_path)
        with pytest.raises(ValueError):
            ledger_mod.append_policy_amendment(out, {"kind": "a b"})
        with pytest.raises(ValueError):
            ledger_mod.append_policy_amendment(
                out, {"kind": "big", "blob": "x" * 5000})

    def test_engagement_policy_merge_token_keys_byte_bound(
            self, tmp_path, monkeypatch):
        out, _doc_ = _build(tmp_path)
        assert ledger_mod.update_engagement_policy(
            out, {"envelope_usd": 50.0})
        assert ledger_mod.update_engagement_policy(
            out, {"policy_version": 1})
        block = ledger_mod.load_engagement_policy(out)
        assert block == {"envelope_usd": 50.0, "policy_version": 1}
        with pytest.raises(ValueError):
            ledger_mod.update_engagement_policy(out, {"bad key": 1})
        monkeypatch.setattr(ledger_mod,
                            "_MAX_ENGAGEMENT_POLICY_BYTES", 64)
        with pytest.raises(ValueError):
            ledger_mod.update_engagement_policy(
                out, {"flood": "x" * 100})
        assert ledger_mod.load_engagement_policy(out) == block

    def test_append_residual_bounded(self, tmp_path, monkeypatch):
        out, doc = _build(tmp_path)
        aid = doc["rows"][0]["artifact_id"]
        assert ledger_mod.append_residual(out, "artifact_parked",
                                          "why", artifact_id=aid)
        rec = ledger_mod.load_ledger(out)["residuals"][-1]
        assert rec == {"kind": "artifact_parked", "message": "why",
                       "artifact_id": aid}
        with pytest.raises(ValueError):
            ledger_mod.append_residual(out, "bad kind", "m")
        monkeypatch.setattr(ledger_mod, "_MAX_APPENDED_RESIDUALS",
                            len(ledger_mod.load_ledger(out)
                                ["residuals"]))
        assert not ledger_mod.append_residual(out, "artifact_parked",
                                              "over")

    def test_rebuild_carries_policy_state_under_sha_proof(self,
                                                          tmp_path):
        out, doc = _build(tmp_path)
        aid = doc["rows"][0]["artifact_id"]
        ledger_mod.set_artifact_policy(
            out, aid, policy={"tier": "T2"},
            reservation={"state": "reserved", "reserved_usd": 5.0})
        ledger_mod.update_engagement_policy(out, {"envelope_usd": 9.0})
        ledger_mod.append_policy_amendment(out, {"kind": "degradation"})
        target = tmp_path / "install"
        doc2 = ledger_mod.build_ledger(target, out)
        row = next(r for r in doc2["rows"] if r["artifact_id"] == aid)
        assert row["policy"] == {"tier": "T2"}
        assert row["reservation"]["reserved_usd"] == 5.0
        assert doc2["policy"]["envelope_usd"] == 9.0
        assert [a["kind"] for a in doc2["policy_amendments"]] \
            == ["degradation"]

    def test_rebuild_resets_policy_when_content_changed(self,
                                                        tmp_path):
        out, doc = _build(tmp_path)
        rows = {r["artifact_id"]: r for r in doc["rows"]}
        aid = sorted(rows)[0]
        for a in rows:
            ledger_mod.set_artifact_policy(out, a,
                                           policy={"tier": "T2"})
        target = tmp_path / "install"
        victim = target / rows[aid]["path"]
        victim.write_bytes(victim.read_bytes() + b"-trojan")
        doc2 = ledger_mod.build_ledger(target, out)
        by_id = {r["artifact_id"]: r for r in doc2["rows"]}
        # sha changed → id changed (sha256 kind) or carry refused:
        # either way no surviving row wears the old policy without
        # the content proof.
        for r in doc2["rows"]:
            if "policy" in r:
                assert r["artifact_id"] != aid
        assert aid not in by_id or "policy" not in by_id[aid]


# ── depth assignment (mechanical, M3) ────────────────────────────────

class TestTierVocabulary:
    def test_tiers_wrap_triage_buckets_never_a_second_vocab(self):
        assert TIER_BUCKET == {
            TIER_T0: TriageBucket.SKIP,
            TIER_T1: TriageBucket.GLANCE,
            TIER_T2: TriageBucket.INVESTIGATE,
            TIER_T3: TriageBucket.DEEP_DIVE,
        }
        assert depth_label(TIER_T3) == "T3:deep_dive"
        assert depth_label(TIER_T0) == "T0:skip"
        # labels fit the ledger's charset-gated depth slot
        for tier in TIER_BUCKET:
            assert ledger_mod._DEPTH_RE.fullmatch(depth_label(tier))


class TestAssignDepth:
    def test_deterministic_over_the_document(self):
        doc = _doc([
            _row("a1", exposure=[_signal()]),
            _row("a2"), _row("a3"), _row("a4"),
        ])
        assert assign_depth(doc) == assign_depth(doc)

    @pytest.mark.parametrize("feature", sorted(
        gov.T3_SIGNAL_FEATURES))
    def test_any_single_signal_earns_t3(self, feature):
        policy = assign_depth(_doc([
            _row("a1", exposure=[_signal(feature)]),
        ]))
        a = policy.by_id()["a1"]
        assert a.tier == TIER_T3 and a.basis == BASIS_SIGNAL
        assert a.signals[0][0] == feature

    def test_elevated_interest_is_signal_grade(self):
        a = assign_depth(_doc([
            _row("a1", elevated_interest=True),
        ])).by_id()["a1"]
        assert a.tier == TIER_T3 and a.basis == BASIS_SIGNAL

    def test_non_signal_exposure_earns_nothing(self):
        a = assign_depth(_doc([
            _row("a1", exposure=[_facts_feature()]),
            _row("a2"),  # keeps the sample off a1 deterministically?
        ])).by_id()["a1"]
        assert a.tier in (TIER_T1, TIER_T2)
        assert a.basis != BASIS_SIGNAL

    def test_floors_score_independent(self):
        policy = assign_depth(_doc([
            _row(f"e{i}") for i in range(10)
        ] + [
            _row("fam", cls="corpus-family"),
            _row("rem", cls="archive-remainder"),
        ]))
        by = policy.by_id()
        for i in range(10):
            assert by[f"e{i}"].floor == TIER_T1
            assert by[f"e{i}"].tier in (TIER_T1, TIER_T2)
        assert by["fam"].tier == TIER_T0
        assert by["rem"].tier == TIER_T0
        # non-analyzable classes are never sampled either
        assert "fam" not in policy.sampled_ids
        assert "rem" not in policy.sampled_ids

    @pytest.mark.parametrize("cls", [
        "elf-linux",    # TIER_FULL
        "elf-kmod",     # TIER_NEAR_FULL
        "pe-exe", "pe-dll", "pe-sys", "macho",  # TIER_CORE
    ])
    def test_every_analysable_format_tier_floors_t1(self, cls):
        """M3b covers ALL analysable format tiers — full, near-full
        and core-capable classes each floor at T1 (one probe per
        class so dropping a tier from the analysable set is caught)."""
        a = assign_depth(_doc([_row("probe", cls=cls)])).by_id()["probe"]
        assert a.floor == TIER_T1
        assert a.tier in (TIER_T1, TIER_T2)

    @pytest.mark.parametrize("cls", ["te", "elf-ebpf"])
    def test_classify_only_classes_default_t0(self, cls):
        a = assign_depth(_doc([_row("probe", cls=cls)])).by_id()["probe"]
        assert a.floor == TIER_T0
        assert a.tier == TIER_T0

    def test_copy_token_rejects_non_ascii_writer_poison(self):
        """The read-side gate mirrors the WRITER charset: non-ASCII
        that Unicode ``isalnum`` would pass (and the validated writer
        then refuse, crashing the run) collapses to the fallback."""
        assert gov._copy_token("évil٣", "unrecognized") \
            == "unrecognized"
        by = assign_depth(_doc([
            _row("a1", exposure=[{
                "feature": "sink_imports",
                "value": ["exec"],
                "extractor": "évil٣",
            }]),
        ])).by_id()
        assert by["a1"].signals == (("sink_imports", "unrecognized"),)

    def test_tampered_extractor_never_crashes_write_policy(
            self, tmp_path):
        """End to end: a hostile extractor string planted in the
        on-disk document degrades to the fallback token and the
        validated writer accepts the policy — never a raised
        ValueError (crash-not-degrade would deny the whole
        engagement)."""
        out, _doc_ = _build(tmp_path, names=("alpha",))
        lp = ledger_mod.ledger_path(out)
        doc = json.loads(lp.read_text())
        doc["rows"][0]["exposure"] = [{
            "feature": "input_channels", "value": ["file"],
            "extractor": "évil٣",
        }]
        lp.write_text(json.dumps(doc))
        slots, fresh = gov.ensure_policy(out, doc)
        assert fresh
        aid = doc["rows"][0]["artifact_id"]
        assert slots[aid]["tier"] == TIER_T3
        assert slots[aid]["signals"][0]["extractor"] == "unrecognized"

    def test_needed_by_t3_promotes_depth_one_only(self):
        doc = _doc(
            [
                _row("cons", exposure=[_signal()],
                     needed=["libmid.so"]),
                _row("mid", needed=["libleaf.so"]),
                _row("leaf"),
            ] + [_row(f"pad{i}") for i in range(6)],
            reverse_needed=[
                {"name": "libmid.so", "providers": ["mid"]},
                {"name": "libleaf.so", "providers": ["leaf"]},
            ],
        )
        by = assign_depth(doc).by_id()
        assert by["mid"].tier == TIER_T2
        assert by["mid"].basis == BASIS_NEEDED_BY_T3
        assert by["mid"].promoted_by == ("cons",)
        # NO transitive cascade: leaf is not promoted through mid
        assert by["leaf"].basis != BASIS_NEEDED_BY_T3

    def test_promotion_never_lowers_a_signal_t3_provider(self):
        doc = _doc(
            [
                _row("cons", exposure=[_signal()], needed=["lib.so"]),
                _row("prov", exposure=[_signal("sink_imports")]),
            ],
            reverse_needed=[{"name": "lib.so",
                             "providers": ["prov"]}],
        )
        by = assign_depth(doc).by_id()
        assert by["prov"].tier == TIER_T3
        assert by["prov"].basis == BASIS_SIGNAL
        assert by["prov"].promoted_by == ("cons",)

    def test_sample_bounded_and_seed_deterministic(self):
        rows = [_row(f"e{i:03d}") for i in range(200)]
        p1 = assign_depth(_doc(rows))
        p2 = assign_depth(_doc(list(reversed(rows))))
        assert p1.sampled_ids == p2.sampled_ids  # row order immaterial
        assert p1.sample_seed == p2.sample_seed
        assert len(p1.sampled_ids) == gov._SAMPLE_MAX
        for aid in p1.sampled_ids:
            assert p1.by_id()[aid].basis == BASIS_SAMPLE
            assert p1.by_id()[aid].tier == TIER_T2
        # floor 1 while any low-tier analyzable artifact exists
        small = assign_depth(_doc([_row("only")]))
        assert len(small.sampled_ids) == 1
        # and zero when nothing is eligible
        none = assign_depth(_doc([_row("f", cls="corpus-family")]))
        assert none.sampled_ids == ()

    def test_scored_low_vs_verified_low(self):
        by = assign_depth(_doc([
            _row("verified", exposure=[_facts_feature()]),
            _row("scored"),
            _row("capped", exposure=[_facts_feature()],
                 caps_hit=["exposure_names"]),
        ] + [_row(f"pad{i}") for i in range(60)])).by_id()
        assert by["verified"].low_exposure_verified is True
        assert by["scored"].low_exposure_verified is False
        assert by["capped"].low_exposure_verified is False
        counts = assign_depth(_doc([
            _row("verified", exposure=[_facts_feature()]),
            _row("scored"),
        ] + [_row(f"pad{i}") for i in range(60)])).counts
        assert counts["verified_low_exposure"] >= 1
        assert counts["scored_low"] >= 1

    def test_hostile_extractor_string_collapses_to_fallback(self):
        by = assign_depth(_doc([
            _row("a1", exposure=[{
                "feature": "input_channels",
                "value": ["network"],
                "extractor": "evil\x1b[31m$(rm)",
            }]),
        ])).by_id()
        assert by["a1"].signals == (("input_channels",
                                     "unrecognized"),)

    def test_malformed_rows_skipped(self):
        policy = assign_depth(_doc([
            {"artifact_id": "../evil", "class": "elf-linux"},
            {"no_id": True},
            "not a dict",
            _row("good"),
        ]))
        assert set(policy.by_id()) == {"good"}


class TestPolicyPersistence:
    def test_write_then_ensure_loads_never_reassigns(self, tmp_path):
        out, doc = _build(tmp_path)
        slots, fresh = gov.ensure_policy(out, doc)
        assert fresh and set(slots) == {
            r["artifact_id"] for r in doc["rows"]}
        doc2 = ledger_mod.load_ledger(out)
        slots2, fresh2 = gov.ensure_policy(out, doc2)
        assert not fresh2
        assert slots2 == gov.load_assignments(doc2)

    def test_amended_slot_survives_resume(self, tmp_path):
        """S15: resume consumes the AMENDED policy, never launch
        policy."""
        out, doc = _build(tmp_path)
        slots, _fresh = gov.ensure_policy(out, doc)
        aid = sorted(slots)[0]
        amended = {**slots[aid], "tier": "T0", "bucket": "skip",
                   "basis": "sample_revoked"}
        ledger_mod.set_artifact_policy(out, aid, policy=amended)
        doc2 = ledger_mod.load_ledger(out)
        slots2, fresh2 = gov.ensure_policy(out, doc2)
        assert not fresh2
        assert slots2[aid]["tier"] == "T0"
        assert slots2[aid]["basis"] == "sample_revoked"

    def test_launch_summary_lands_on_policy_block(self, tmp_path):
        out, doc = _build(tmp_path)
        gov.ensure_policy(out, doc)
        block = ledger_mod.load_engagement_policy(out)
        assert block["policy_version"] == gov.POLICY_VERSION
        assert block["launch"]["sample_seed"]
        assert block["launch"]["counts"]
        # the launch-minted sampling nonce persists on the block
        nonce = block["sample_nonce"]
        assert len(nonce) == 32
        assert all(c in "0123456789abcdef" for c in nonce)

    def test_schedule_order_deepest_first_then_size_then_id(self):
        def slotted(aid, tier, n_signals=0, size=100):
            sig = [{"feature": "input_channels", "extractor": "x"}
                   ] * n_signals
            return _row(aid, size=size,
                        policy={"tier": tier, "signals": sig})
        doc = _doc([
            slotted("small-t1", TIER_T1, size=1),
            slotted("big-t3", TIER_T3, size=9999),
            slotted("sig-t3", TIER_T3, n_signals=2, size=9999),
            slotted("small-t3", TIER_T3, size=5),
            slotted("mid-t2", TIER_T2),
        ])
        assert gov.schedule_order(doc) == [
            "sig-t3", "small-t3", "big-t3", "mid-t2", "small-t1",
        ]

    def test_render_distinguishes_and_escapes(self, tmp_path):
        out, doc = _build(tmp_path)
        gov.ensure_policy(out, doc)
        doc = ledger_mod.load_ledger(out)
        lines = gov.render_policy_lines(doc)
        assert any("verified-low-exposure" in ln and "scored-low"
                   in ln for ln in lines)
        # hostile bytes planted straight into a loaded document must
        # not reach the terminal unescaped
        doc["rows"][0]["policy"]["basis"] = "evil\x1b[2Jbasis"
        for ln in gov.render_policy_lines(doc):
            assert all(c.isprintable() for c in ln), repr(ln)
        assert gov.render_policy_lines({"rows": []}) \
            == ["Depth policy: not assigned"]


class TestSampleNonce:
    def test_minted_once_and_persisted(self, tmp_path):
        out, doc = _build(tmp_path)
        gov.ensure_policy(out, doc)
        nonce = ledger_mod.load_engagement_policy(out)["sample_nonce"]
        assert len(nonce) == 32
        assert all(c in "0123456789abcdef" for c in nonce)
        # a second ensure over the persisted document never re-mints
        gov.ensure_policy(out, ledger_mod.load_ledger(out))
        assert ledger_mod.load_engagement_policy(out)["sample_nonce"] \
            == nonce

    def test_persisted_nonce_reproduces_sample_across_processes(
            self, tmp_path):
        """Resume determinism rides on PERSISTENCE: a second process
        that assigns over the same persisted ledger — slots gone but
        the launch nonce kept — samples the identical subset."""
        names = tuple(f"art{i:02d}" for i in range(30))
        out, doc = _build(tmp_path, names=names)
        slots, fresh = gov.ensure_policy(out, doc)
        assert fresh
        sampled = {a for a, s in slots.items()
                   if s["basis"] == BASIS_SAMPLE}
        assert sampled
        # simulate a fresh process over the persisted document: strip
        # every slot and the launch summary, KEEP the nonce
        lp = ledger_mod.ledger_path(out)
        raw = json.loads(lp.read_text())
        for row in raw["rows"]:
            row.pop("policy", None)
        raw["policy"].pop("launch", None)
        lp.write_text(json.dumps(raw))
        slots2, fresh2 = gov.ensure_policy(out, raw)
        assert fresh2
        assert {a for a, s in slots2.items()
                if s["basis"] == BASIS_SAMPLE} == sampled

    def test_sample_not_a_pure_function_of_the_id_set(self):
        """S-review pin: whoever ships the install tree knows the ids
        — without the launch nonce they could compute the sample
        offline and byte-tweak an artifact until it dodges. Different
        nonces over the SAME id set must be able to differ."""
        rows = [_row(f"e{i:03d}") for i in range(60)]
        p_zero = assign_depth(_doc(rows), sample_nonce="0" * 32)
        p_ff = assign_depth(_doc(rows), sample_nonce="f" * 32)
        assert p_zero.sample_seed != p_ff.sample_seed
        assert p_zero.sampled_ids != p_ff.sampled_ids
        # while the SAME nonce stays deterministic (resume-safe)
        again = assign_depth(_doc(list(reversed(rows))),
                             sample_nonce="0" * 32)
        assert again.sampled_ids == p_zero.sampled_ids


class TestLateJoiners:
    def test_late_rows_get_floors_amended_slots_stay(self, tmp_path):
        """Rows that JOIN after launch (rebuild added an artifact, or
        re-minted an id over changed content) get floors/signals on
        load — never silently unengaged — while amended slots stay
        authoritative and a residual names the late ids."""
        out, doc = _build(tmp_path)
        slots, _fresh = gov.ensure_policy(out, doc)
        aid = sorted(slots)[0]
        amended = {**slots[aid], "tier": "T0", "bucket": "skip",
                   "basis": "sample_revoked"}
        ledger_mod.set_artifact_policy(out, aid, policy=amended)
        # rebuild over a grown, partially-changed install tree:
        # delta is NEW, beta's content change re-mints its id
        target = tmp_path / "install"
        _write_elf(target / "delta")
        (target / "beta").write_bytes(
            (target / "beta").read_bytes() + b"changed")
        doc2 = ledger_mod.build_ledger(target, out)
        slots2, fresh2 = gov.ensure_policy(out, doc2)
        assert not fresh2
        late_ids = sorted(set(slots2) - set(slots))
        assert len(late_ids) == 2  # delta + re-minted beta
        for lid in late_ids:
            assert slots2[lid]["tier"] == TIER_T1
            assert slots2[lid]["floor"] == TIER_T1
        # the amended slot is untouched by the late pass
        assert slots2[aid]["tier"] == "T0"
        assert slots2[aid]["basis"] == "sample_revoked"
        # late rows enter the schedule
        order = gov.schedule_order(ledger_mod.load_ledger(out))
        for lid in late_ids:
            assert lid in order
        residuals = [
            r for r in ledger_mod.load_ledger(out)["residuals"]
            if r["kind"] == "late_policy_assignment"]
        assert len(residuals) == 1
        for lid in late_ids:
            assert lid in residuals[0]["message"]


# ── budget governor (M4) ─────────────────────────────────────────────

class TestShapesAndEstimates:
    def test_parser_shape_from_channel_kinds(self):
        row = _row("a", exposure=[{
            "feature": "input_channels", "value": ["file"],
            "extractor": "x"}])
        assert gov.artifact_shape(row) == gov.SHAPE_PARSER

    def test_runtime_heavy_large_thin_linkage(self):
        row = _row("a", size=9 * 1024 * 1024, needed=["libc.so.6"])
        assert gov.artifact_shape(row) == gov.SHAPE_RUNTIME
        # thick linkage keeps it out of the cheap lane
        row2 = _row("a", size=9 * 1024 * 1024,
                    needed=[f"lib{i}.so" for i in range(5)])
        assert gov.artifact_shape(row2) == gov.SHAPE_BALANCED
        # small body too
        row3 = _row("a", size=1024)
        assert gov.artifact_shape(row3) == gov.SHAPE_BALANCED

    def test_tampered_channel_kinds_degrade_never_raise(self):
        """Channel-kind entries are type-gated on read: unhashable
        tamper (a list/dict inside the value) must not crash the
        estimator, and real kinds still count alongside junk."""
        junk = _row("j", exposure=[{
            "feature": "input_channels",
            "value": [{}, None, 5, ["file"]],
            "extractor": "x",
        }])
        assert gov.artifact_shape(junk) == gov.SHAPE_BALANCED
        mixed = _row("m", exposure=[{
            "feature": "input_channels",
            "value": [{}, "file"],
            "extractor": "x",
        }])
        assert gov.artifact_shape(mixed) == gov.SHAPE_PARSER

    def test_parser_wins_over_runtime_heavy(self):
        row = _row("a", size=9 * 1024 * 1024, exposure=[{
            "feature": "input_channels", "value": ["stream"],
            "extractor": "x"}])
        assert gov.artifact_shape(row) == gov.SHAPE_PARSER

    def test_fallback_estimates_pessimistic_and_shaped(self):
        assert gov.estimate_artifact_usd(_row("a"), TIER_T0) \
            == (0.0, "none")
        usd, source = gov.estimate_artifact_usd(_row("a"), TIER_T3)
        assert (usd, source) == (75.0, "fallback")
        parser = _row("a", exposure=[{
            "feature": "input_channels", "value": ["file"],
            "extractor": "x"}])
        assert gov.estimate_artifact_usd(parser, TIER_T3)[0] \
            == 75.0 * 2.5
        runtime = _row("a", size=9 * 1024 * 1024)
        assert gov.estimate_artifact_usd(runtime, TIER_T3)[0] \
            == 75.0 * 0.4

    def test_scorecard_feeds_cost_high(self, monkeypatch):
        from core.run.estimator import RunEstimate
        seen: dict[str, Any] = {}

        def fake(model, n_findings, *, max_parallel=3,
                 scorecard_path=None):
            seen["args"] = (model, n_findings)
            return RunEstimate(cost_low=1.0, cost_high=4.0,
                               time_low=1, time_high=2,
                               target_type="m (scorecard)")

        monkeypatch.setattr(gov, "estimate_from_scorecard", fake)
        usd, source = gov.estimate_artifact_usd(
            _row("a"), TIER_T2, model="m")
        assert (usd, source) == (4.0, "scorecard")
        assert seen["args"] == ("m", gov._TIER_UNITS[TIER_T2])
        # insufficient history falls back pessimistically
        monkeypatch.setattr(gov, "estimate_from_scorecard",
                            lambda *a, **k: None)
        assert gov.estimate_artifact_usd(
            _row("a"), TIER_T2, model="m") == (8.0, "fallback")


def _t3_slot(slot: dict[str, Any]) -> dict[str, Any]:
    return {**slot, "tier": "T3", "bucket": "deep_dive"}


class TestReservations:
    def _prepared(self, tmp_path, envelope: float = 100.0):
        out, doc = _build(tmp_path)
        slots, _fresh = gov.ensure_policy(out, doc)
        gov.set_envelope(out, envelope)
        ids = sorted(slots)
        for aid in ids:
            ledger_mod.set_artifact_policy(out, aid,
                                           policy=_t3_slot(slots[aid]))
        return out, ids

    def test_reservation_charged_at_launch(self, tmp_path):
        out, ids = self._prepared(tmp_path)
        res = gov.reserve_segment(out, ids[0], 1)
        assert res["state"] == "reserved"
        assert res["reserved_usd"] == 75.0
        assert res["estimate_source"] == "fallback"
        doc = ledger_mod.load_ledger(out)
        assert gov.committed_usd(doc) == 75.0

    def test_envelope_refusal_before_write(self, tmp_path):
        out, ids = self._prepared(tmp_path, envelope=100.0)
        assert gov.reserve_segment(out, ids[0], 1)
        assert gov.reserve_segment(out, ids[1], 1) is None
        doc = ledger_mod.load_ledger(out)
        row = next(r for r in doc["rows"]
                   if r["artifact_id"] == ids[1])
        assert "reservation" not in row
        assert any(r["kind"] == "reservation_refused"
                   for r in doc["residuals"])
        # fits under a raised envelope — the refusal is the envelope,
        # not the artifact
        gov.set_envelope(out, 200.0)
        assert gov.reserve_segment(out, ids[1], 1)

    def test_same_artifact_replaces_never_double_charges(self,
                                                         tmp_path):
        out, ids = self._prepared(tmp_path, envelope=80.0)
        assert gov.reserve_segment(out, ids[0], 1)
        # 75 committed of 80: a second reservation for the SAME
        # artifact replaces (75-75+75 <= 80), it does not stack to 150
        assert gov.reserve_segment(out, ids[0], 2)
        doc = ledger_mod.load_ledger(out)
        assert gov.committed_usd(doc) == 75.0

    def test_reconcile_down_on_clean_close(self, tmp_path):
        out, ids = self._prepared(tmp_path)
        gov.reserve_segment(out, ids[0], 1)
        gov.record_segment_death(out, ids[0])
        rec = gov.reconcile_segment(out, ids[0], 2.5)
        assert rec["state"] == "reconciled"
        assert rec["actual_usd"] == 2.5
        assert rec["deaths"] == 0
        doc = ledger_mod.load_ledger(out)
        assert gov.committed_usd(doc) == 2.5
        # reconciling nothing is a caller bug, not a write
        assert gov.reconcile_segment(out, ids[0], 1.0) is None
        assert gov.reconcile_segment(out, ids[1], 1.0) is None

    def test_unreconciled_deaths_keep_reservation_then_park(
            self, tmp_path):
        out, ids = self._prepared(tmp_path)
        gov.reserve_segment(out, ids[0], 1)
        for i in range(1, PARK_AFTER_DEATHS + 1):
            d = gov.record_segment_death(out, ids[0], detail="oom")
            assert d["deaths"] == i
            assert d["parked"] == (i == PARK_AFTER_DEATHS)
        doc = ledger_mod.load_ledger(out)
        row = next(r for r in doc["rows"]
                   if r["artifact_id"] == ids[0])
        assert row["status"]["state"] == "parked"
        assert row["status"]["detail"].startswith(
            f"unreconciled_deaths:{PARK_AFTER_DEATHS}")
        # the reservation stays charged
        assert row["reservation"]["state"] == "reserved"
        assert gov.committed_usd(doc) == 75.0
        assert any(r["kind"] == "artifact_parked"
                   for r in doc["residuals"])
        assert any(a["kind"] == "artifact_parked"
                   for a in doc["policy_amendments"])
        # and a parked artifact refuses further reservations
        assert gov.reserve_segment(out, ids[0], 2) is None

    def test_reconcile_up_commits_and_leaves_residual(self, tmp_path):
        """An actual ABOVE the reservation still commits — the money
        is already spent, refusing the write would hide it — and the
        excess is durable as a reconcile_over_reservation residual."""
        out, ids = self._prepared(tmp_path, envelope=500.0)
        res = gov.reserve_segment(out, ids[0], 1)
        rec = gov.reconcile_segment(out, ids[0],
                                    res["reserved_usd"] + 25.0)
        assert rec["state"] == "reconciled"
        assert rec["actual_usd"] == res["reserved_usd"] + 25.0
        doc = ledger_mod.load_ledger(out)
        assert gov.committed_usd(doc) == res["reserved_usd"] + 25.0
        over = [r for r in doc["residuals"]
                if r["kind"] == "reconcile_over_reservation"]
        assert len(over) == 1
        assert over[0]["artifact_id"] == ids[0]
        # a clean DOWN reconcile leaves no such residual
        gov.reserve_segment(out, ids[1], 1)
        gov.reconcile_segment(out, ids[1], 2.0)
        doc = ledger_mod.load_ledger(out)
        assert len([r for r in doc["residuals"]
                    if r["kind"] == "reconcile_over_reservation"]) == 1

    def test_deaths_past_park_count_but_never_repark(self, tmp_path):
        """The park is idempotent: deaths beyond PARK_AFTER_DEATHS
        still count (the figure stays honest) without minting a
        duplicate park amendment/residual."""
        out, ids = self._prepared(tmp_path)
        gov.reserve_segment(out, ids[0], 1)
        for _ in range(PARK_AFTER_DEATHS):
            d = gov.record_segment_death(out, ids[0])
        assert d == {"deaths": PARK_AFTER_DEATHS, "parked": True}
        d4 = gov.record_segment_death(out, ids[0])
        assert d4 == {"deaths": PARK_AFTER_DEATHS + 1,
                      "parked": False}
        doc = ledger_mod.load_ledger(out)
        assert len([r for r in doc["residuals"]
                    if r["kind"] == "artifact_parked"]) == 1
        assert len([a for a in doc["policy_amendments"]
                    if a["kind"] == "artifact_parked"]) == 1

    def test_engagement_park_refuses_every_reservation(self,
                                                       tmp_path):
        """Fail closed: an S16 engagement-level park refuses
        per-segment reservations — spend never walks past the park
        that exists to stop it."""
        out, ids = self._prepared(tmp_path, envelope=500.0)
        gov.park_engagement(out, "feasibility_conflict")
        assert gov.reserve_segment(out, ids[0], 1) is None
        doc = ledger_mod.load_ledger(out)
        assert gov.committed_usd(doc) == 0.0
        refusal = [r for r in doc["residuals"]
                   if r["kind"] == "reservation_refused"]
        assert refusal
        assert refusal[-1]["message"] == "engagement is parked"
        assert refusal[-1]["artifact_id"] == ids[0]

    def test_death_without_reservation_is_a_noop(self, tmp_path):
        out, ids = self._prepared(tmp_path)
        assert gov.record_segment_death(out, ids[0]) is None

    def test_committed_clamps_hostile_document_figures(self):
        doc = _doc([
            _row("a", reservation={"state": "reserved",
                                   "reserved_usd": float("inf")}),
            _row("b", reservation={"state": "reconciled",
                                   "actual_usd": -5.0}),
            _row("c", reservation={"state": "reserved",
                                   "reserved_usd": "9" * 400}),
        ])
        total = gov.committed_usd(doc)
        assert total == gov._MAX_USD  # overclaim clamps, never inf


class TestFeasibility:
    def test_fits_tight_conflict_boundaries(self, tmp_path):
        out, doc = _build(tmp_path)
        slots, _fresh = gov.ensure_policy(out, doc)
        for aid in slots:
            ledger_mod.set_artifact_policy(out, aid,
                                           policy=_t3_slot(slots[aid]))
        doc = ledger_mod.load_ledger(out)
        want = gov.policy_want(doc)[0]
        assert want == 225.0  # 3 × T3 fallback
        assert gov.launch_feasibility(doc, want).verdict \
            == VERDICT_FITS
        assert gov.launch_feasibility(doc, want / 2 + 1).verdict \
            == VERDICT_TIGHT
        assert gov.launch_feasibility(doc, want / 2 - 1).verdict \
            == VERDICT_CONFLICT
        assert gov.launch_feasibility(doc, None).verdict \
            == VERDICT_FITS  # uncapped

    def test_unattended_conflict_parks_before_spend(self, tmp_path):
        out, doc = _build(tmp_path)
        slots, _fresh = gov.ensure_policy(out, doc)
        for aid in slots:
            ledger_mod.set_artifact_policy(out, aid,
                                           policy=_t3_slot(slots[aid]))
        doc = ledger_mod.load_ledger(out)
        v = gov.enforce_feasibility(out, doc, 10.0, attended=False)
        assert v.verdict == VERDICT_CONFLICT
        doc = ledger_mod.load_ledger(out)
        assert gov.is_engagement_parked(doc)
        assert doc["policy"]["parked"]["reason"] \
            == "feasibility_conflict"
        assert doc["policy"]["feasibility"]["verdict"] \
            == VERDICT_CONFLICT
        assert any(a["kind"] == "engagement_parked"
                   for a in doc["policy_amendments"])

    def test_attended_conflict_records_but_never_parks(self,
                                                       tmp_path):
        """The structured choice belongs to the CALLER — library code
        only records the verdict."""
        out, doc = _build(tmp_path)
        slots, _fresh = gov.ensure_policy(out, doc)
        for aid in slots:
            ledger_mod.set_artifact_policy(out, aid,
                                           policy=_t3_slot(slots[aid]))
        doc = ledger_mod.load_ledger(out)
        v = gov.enforce_feasibility(out, doc, 10.0, attended=True)
        assert v.verdict == VERDICT_CONFLICT
        doc = ledger_mod.load_ledger(out)
        assert not gov.is_engagement_parked(doc)
        assert doc["policy"]["feasibility"]["verdict"] \
            == VERDICT_CONFLICT

    def test_want_excludes_parked_and_reconciled(self, tmp_path):
        out, doc = _build(tmp_path)
        slots, _fresh = gov.ensure_policy(out, doc)
        ids = sorted(slots)
        for aid in ids:
            ledger_mod.set_artifact_policy(out, aid,
                                           policy=_t3_slot(slots[aid]))
        gov.set_envelope(out, 500.0)
        gov.park_artifact(out, ids[0], "operator")
        gov.reserve_segment(out, ids[1], 1)
        gov.reconcile_segment(out, ids[1], 1.0)
        doc = ledger_mod.load_ledger(out)
        want, by_tier, _src = gov.policy_want(doc)
        assert want == 75.0  # only ids[2] still wants
        assert by_tier == {"T3": 75.0}

    def test_open_reservation_netted_out_of_want(self, tmp_path):
        """S-review pin: a killed run resumes holding an OPEN
        reservation the envelope exactly funds. The reservation is
        already booked in the committed total — counting its estimate
        again in want would double-charge and falsely park the
        resume."""
        out, doc = _build(tmp_path, names=("alpha",))
        slots, _fresh = gov.ensure_policy(out, doc)
        aid = next(iter(slots))
        ledger_mod.set_artifact_policy(out, aid,
                                       policy=_t3_slot(slots[aid]))
        gov.set_envelope(out, 75.0)
        res = gov.reserve_segment(out, aid, 1)
        assert res and res["reserved_usd"] == 75.0
        doc = ledger_mod.load_ledger(out)
        want, _by_tier, _src = gov.policy_want(doc)
        assert want == 0.0  # the open reservation is not re-counted
        # the resume fits and never parks
        v = gov.enforce_feasibility(out, doc, 75.0, attended=False)
        assert v.verdict == VERDICT_FITS
        assert not gov.is_engagement_parked(
            ledger_mod.load_ledger(out))

    def test_feasibility_lines_render_numbers(self, tmp_path):
        v = gov.FeasibilityVerdict(
            verdict=VERDICT_TIGHT, want_usd=42.5, envelope_usd=30.0,
            by_tier={"T3": 40.0, "T1": 2.5},
            estimate_source="fallback")
        lines = v.lines()
        assert "policy wants ~$42.50 vs envelope $30.00 — tight" \
            in lines[0]
        v2 = gov.FeasibilityVerdict(
            verdict=VERDICT_FITS, want_usd=1.0, envelope_usd=None)
        assert "uncapped" in v2.lines()[0]


class TestDegradationLadder:
    def test_rung_one_revokes_sample_then_rung_two_parks(self,
                                                         tmp_path):
        out, doc = _build(tmp_path)
        slots, _fresh = gov.ensure_policy(out, doc)
        sampled = [a for a, s in slots.items()
                   if s["basis"] == BASIS_SAMPLE]
        assert len(sampled) == 1
        step = gov.apply_degradation(out, reason="over_budget")
        assert step == {"action": "sample_revoked",
                        "artifact_id": sampled[0], "tier": TIER_T1}
        doc = ledger_mod.load_ledger(out)
        slot = gov.load_assignments(doc)[sampled[0]]
        assert slot["tier"] == TIER_T1
        assert slot["basis"] == "sample_revoked"
        # S15: the amendment trail records the degradation, and a
        # resume loads the amended slot (pinned above in
        # test_amended_slot_survives_resume)
        assert any(a["kind"] == "degradation"
                   and a["action"] == "sample_revoked"
                   for a in doc["policy_amendments"])
        step2 = gov.apply_degradation(out, reason="over_budget")
        assert step2["action"] == "parked_budget_pressure"
        assert step2["tier"] in gov.TIER_ORDER
        assert step2["basis"]
        doc = ledger_mod.load_ledger(out)
        row = next(r for r in doc["rows"]
                   if r["artifact_id"] == step2["artifact_id"])
        assert row["status"]["state"] == "parked"
        # the park detail stamps what was shed: tier and basis
        assert row["status"]["detail"].startswith(
            "budget_pressure tier=")
        assert f"basis={step2['basis']}" in row["status"]["detail"]
        amendment = next(
            a for a in doc["policy_amendments"]
            if a.get("action") == "parked_budget_pressure")
        assert amendment["tier"] == step2["tier"]
        assert amendment["basis"] == step2["basis"]

    def test_funded_rows_never_degrade(self, tmp_path):
        out, doc = _build(tmp_path)
        slots, _fresh = gov.ensure_policy(out, doc)
        gov.set_envelope(out, 500.0)
        ids = sorted(slots)
        for aid in ids:
            ledger_mod.set_artifact_policy(out, aid,
                                           policy=_t3_slot(slots[aid]))
        gov.reserve_segment(out, ids[0], 1)      # in flight
        gov.reserve_segment(out, ids[1], 1)
        gov.reconcile_segment(out, ids[1], 1.0)  # done
        # drain the ladder: every rung may only ever touch the one
        # unfunded artifact (whether the launch sample landed on it
        # decides HOW MANY rungs it takes, never WHO degrades)
        steps = []
        while (step := gov.apply_degradation(
                out, reason="over_budget")) is not None:
            steps.append(step)
        assert steps
        assert all(s["artifact_id"] == ids[2] for s in steps)
        # the funded rows kept their slots and never parked
        doc = ledger_mod.load_ledger(out)
        for aid in (ids[0], ids[1]):
            row = next(r for r in doc["rows"]
                       if r["artifact_id"] == aid)
            assert row["policy"]["tier"] == "T3"
            assert row.get("status", {}).get("state") != "parked"

    def test_signal_earned_t3_parks_only_after_non_signal(
            self, tmp_path):
        """S-review pin: parser-shaped signal-earned T3 rows carry
        the LARGEST estimates, so a naive largest-first rung sheds
        exactly the hottest artifact at the first park. Rung 2 must
        exhaust every non-signal candidate before a signal-earned T3
        parks — and stamp what it shed."""
        names = ("evilparser", "lib1", "lib2", "lib3", "lib4",
                 "lib5", "lib6")
        out, doc = _build(tmp_path, names=names)
        slots, _fresh = gov.ensure_policy(out, doc)
        evil = next(
            r["artifact_id"] for r in doc["rows"]
            if r["path"].endswith("evilparser"))
        # plant the exposure signal on the row (parser-shaped, so its
        # estimate dwarfs every lib) and the signal-earned T3 slot
        lp = ledger_mod.ledger_path(out)
        raw = json.loads(lp.read_text())
        for row in raw["rows"]:
            if row["artifact_id"] == evil:
                row["exposure"] = [{
                    "feature": "input_channels", "value": ["file"],
                    "extractor": "x",
                }]
        lp.write_text(json.dumps(raw))
        ledger_mod.set_artifact_policy(out, evil, policy={
            **slots[evil], "tier": TIER_T3, "bucket": "deep_dive",
            "basis": BASIS_SIGNAL,
        })
        parked_order = []
        while (step := gov.apply_degradation(
                out, reason="over_budget")) is not None:
            if step["action"] == "parked_budget_pressure":
                parked_order.append(step)
        assert parked_order
        assert parked_order[-1]["artifact_id"] == evil
        assert parked_order[-1]["tier"] == TIER_T3
        assert parked_order[-1]["basis"] == BASIS_SIGNAL
        for step in parked_order[:-1]:
            assert step["artifact_id"] != evil
            assert step["basis"] != BASIS_SIGNAL
        doc = ledger_mod.load_ledger(out)
        row = next(r for r in doc["rows"]
                   if r["artifact_id"] == evil)
        assert "tier=T3" in row["status"]["detail"]
        assert "basis=exposure_signal" in row["status"]["detail"]

    def test_exhausted_ladder_returns_none(self, tmp_path):
        out, doc = _build(tmp_path, names=("alpha",))
        slots, _fresh = gov.ensure_policy(out, doc)
        aid = next(iter(slots))
        gov.park_artifact(out, aid, "operator")
        assert gov.apply_degradation(out, reason="over_budget") \
            is None


class TestEscalations:
    def test_recorded_on_the_amendment_trail(self, tmp_path):
        out, _doc_ = _build(tmp_path)
        assert gov.record_escalation(
            out, kind="journal_index_over_budget", message="m")
        trail = ledger_mod.load_policy_amendments(out)
        assert trail[-1]["kind"] == "escalation"
        assert trail[-1]["escalation"] == "journal_index_over_budget"

    def test_bounded_per_kind(self, tmp_path):
        out, _doc_ = _build(tmp_path)
        for i in range(gov._MAX_SAME_ESCALATIONS):
            assert gov.record_escalation(out, kind="k",
                                         message=f"m{i}")
        assert not gov.record_escalation(out, kind="k", message="over")
        # a DIFFERENT kind still records
        assert gov.record_escalation(out, kind="other", message="m")

    def test_no_ledger_is_a_noop(self, tmp_path):
        assert gov.record_escalation(
            tmp_path, kind="k", message="m") is False

    def test_invalid_kind_refused(self, tmp_path):
        out, _doc_ = _build(tmp_path)
        with pytest.raises(ValueError):
            gov.record_escalation(out, kind="bad kind", message="m")


class TestJournalIndexContact:
    """S9: the coverage journal's index-over-budget refusal surfaces
    as a governor escalation when the project carries a ledger."""

    def _over_budget_merge(self, tmp_path, monkeypatch,
                           with_ledger: bool) -> Path:
        from core.coverage import journal as journal_mod
        project = tmp_path / "project"
        run = project / "run1"
        run.mkdir(parents=True)
        if with_ledger:
            target = tmp_path / "install"
            target.mkdir()
            _write_elf(target / "alpha")
            ledger_mod.build_ledger(target, project)
        entry = journal_mod.ReviewJournalEntry(
            ts=journal_mod.now_iso(), run_id="audit_x",
            file="src/a.c", function="f", verdict="clean",
            source_hash="")
        journal_mod.append_entry(run, entry)

        def boom(path, index, aggregates=None, budget=None):
            raise journal_mod.IndexWriteOverBudget("index too big")

        monkeypatch.setattr(journal_mod, "_write_index", boom)
        assert journal_mod.merge_into_index(project, run) == 0
        return project

    def test_escalation_recorded_when_ledger_present(
            self, tmp_path, monkeypatch):
        project = self._over_budget_merge(tmp_path, monkeypatch,
                                          with_ledger=True)
        trail = ledger_mod.load_policy_amendments(project)
        assert any(a["kind"] == "escalation"
                   and a["escalation"] == "journal_index_over_budget"
                   for a in trail)

    def test_merge_refusal_unchanged_without_ledger(
            self, tmp_path, monkeypatch):
        project = self._over_budget_merge(tmp_path, monkeypatch,
                                          with_ledger=False)
        assert not (project / ledger_mod.LEDGER_FILENAME).exists()

    def test_escalation_failure_never_breaks_the_merge_path(
            self, tmp_path, monkeypatch):
        import core.engagement.governor as gov_mod

        def detonate(*a, **k):
            raise RuntimeError("escalation seam broken")

        monkeypatch.setattr(gov_mod, "record_escalation", detonate)
        # merge still refuses cleanly (returns 0), no raise
        self._over_budget_merge(tmp_path, monkeypatch,
                                with_ledger=True)


class TestPrinciple9:
    def test_policy_records_survive_json_and_stay_token_shaped(
            self, tmp_path):
        out, doc = _build(tmp_path)
        gov.ensure_policy(out, doc)
        raw = ledger_mod.ledger_path(out).read_text(encoding="utf-8")
        parsed = json.loads(raw)
        for row in parsed["rows"]:
            slot = row.get("policy")
            assert slot is not None
            for key, value in slot.items():
                if isinstance(value, str):
                    assert ledger_mod._POLICY_TOKEN_RE.fullmatch(
                        value), (key, value)

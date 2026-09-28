"""Identity-pin verification at the enrichment seam (fd-honest
witness consumption).

The project-store content witness is verified at load time on an open
fd; these tests cover the OTHER half of the window: the oracle's
classify tools re-open the binary BY NAME, so a swap landing between
the witness read and the classify pass would let unverified bytes
drive ``absent``-verdict suppression. The pin — ``(st_dev, st_ino,
st_size, sha256)`` recorded from the very fd the witness hash ran on
— is re-verified bracketing the classify pass, and any failure
DEMOTES the binary (enrichment continues at hint tier; suppression
authority is stripped) rather than refusing the run.

Hermetic: ``classify_binary_evidence`` is mocked (no toolchain, no
sandbox), so the tests exercise exactly the bracket + demotion
plumbing.

Residual stated honestly: the classify tools open by name, so a
swap-in/swap-back pair completing entirely within the classify pass
evades both bracket checks; these tests plant LINGERING swaps.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from unittest.mock import patch

from core.analysis.binary_oracle import (
    BinaryOracleWitness,
    absent_earns_suppression,
    enrich_inventory_with_binary_oracle,
)
from core.hash import sha256_file

_CLASSIFY = "core.analysis.binary_oracle.classify_binary_evidence"


def _inventory() -> dict:
    return {
        "files": [
            {
                "path": "src/a.c",
                "language": "c",
                "items": [
                    {"kind": "function", "name": "live_fn",
                     "metadata": {}},
                    {"kind": "function", "name": "dead_fn",
                     "metadata": {}},
                ],
            },
        ],
    }


def _verdicts(bp: Path) -> dict[str, BinaryOracleWitness]:
    return {
        "live_fn": BinaryOracleWitness(
            "symbol_present", "bid", str(bp), 4096),
        "dead_fn": BinaryOracleWitness("absent", "bid", str(bp)),
    }


def _pin(path: Path) -> tuple[int, int, int, str]:
    st = os.stat(path)
    return (st.st_dev, st.st_ino, st.st_size, sha256_file(path))


def _binary(tmp_path: Path, content: bytes = b"\x7fELF" + b"\x00" * 28,
            ) -> Path:
    b = tmp_path / "app.debug"
    b.write_bytes(content)
    return b


def _dead_entries(inv: dict) -> list[dict]:
    items = inv["files"][0]["items"]
    dead = next(i for i in items if i["name"] == "dead_fn")
    return dead["metadata"]["binary_oracle"]["binaries"]


class TestPinHolds:
    """Preservation direction: a pin that verifies and holds changes
    nothing — full suppression authority, identical verdicts."""

    def test_matching_pin_keeps_full_authority(self, tmp_path):
        b = _binary(tmp_path)
        inv = _inventory()
        with patch(_CLASSIFY, side_effect=lambda names, bp: _verdicts(bp)):
            counts = enrich_inventory_with_binary_oracle(
                inv, [b], identity_pins={str(b): _pin(b)})
        assert counts["classified"] == 2
        entries = _dead_entries(inv)
        assert [e["suppression_grade"] for e in entries] == [True]
        assert absent_earns_suppression(entries) is True
        summary = inv["binary_oracle"]
        assert summary["earns_suppression"] is True
        assert summary["any_identity_demoted"] is False
        assert summary["identity_demoted"] == []

    def test_verdicts_identical_with_and_without_pin(self, tmp_path):
        b = _binary(tmp_path)
        inv_pinned, inv_plain = _inventory(), _inventory()
        with patch(_CLASSIFY, side_effect=lambda names, bp: _verdicts(bp)):
            enrich_inventory_with_binary_oracle(
                inv_pinned, [b], identity_pins={str(b): _pin(b)})
            enrich_inventory_with_binary_oracle(inv_plain, [b])
        # Per-item annotations are byte-identical to the unpinned run.
        assert inv_pinned["files"] == inv_plain["files"]
        assert (inv_pinned["binary_oracle"]["earns_suppression"]
                == inv_plain["binary_oracle"]["earns_suppression"])

    def test_unpinned_paths_verify_nothing(self, tmp_path):
        # No pin for this path (explicit --binary / auto-detect):
        # behaviour is exactly the pre-pin baseline.
        b = _binary(tmp_path)
        inv = _inventory()
        with patch(_CLASSIFY, side_effect=lambda names, bp: _verdicts(bp)):
            enrich_inventory_with_binary_oracle(inv, [b])
        assert absent_earns_suppression(_dead_entries(inv)) is True
        assert inv["binary_oracle"]["any_identity_demoted"] is False


class TestPinFails:
    """Attack direction: the pin fails to verify or to hold across
    the classify pass — DEMOTE, never refuse."""

    def _assert_demoted(self, inv: dict, key: str) -> None:
        entries = _dead_entries(inv)
        # Enrichment CONTINUED (hint tier): the verdict is recorded...
        assert [e["classification"] for e in entries] == ["absent"]
        # ...but carries no suppression authority.
        assert [e["suppression_grade"] for e in entries] == [False]
        assert absent_earns_suppression(entries) is False
        summary = inv["binary_oracle"]
        assert summary["earns_suppression"] is False
        assert summary["any_identity_demoted"] is True
        assert summary["identity_demoted"] == [key]
        # The separate accounting channels stay honest.
        assert summary["any_env_built_guessed"] is False

    def test_none_pin_demotes_but_still_enriches(self, tmp_path):
        # Load-time demotion (witness unverifiable at the store seam)
        # arrives here as a None pin.
        b = _binary(tmp_path)
        inv = _inventory()
        with patch(_CLASSIFY,
                   side_effect=lambda names, bp: _verdicts(bp)) as mock_c:
            enrich_inventory_with_binary_oracle(
                inv, [b], identity_pins={str(b): None})
        assert mock_c.call_count == 1  # classify still ran
        self._assert_demoted(inv, str(b))

    def test_stale_pin_demotes_at_open(self, tmp_path, caplog):
        # Pin no longer matches the file (content changed between the
        # witness read and the enrichment): pre-classify bracket fails.
        b = _binary(tmp_path)
        pin = _pin(b)
        b.write_bytes(b"\x7fELF" + b"\xff" * 28)  # drift
        inv = _inventory()
        with caplog.at_level(logging.WARNING), \
             patch(_CLASSIFY, side_effect=lambda names, bp: _verdicts(bp)):
            enrich_inventory_with_binary_oracle(
                inv, [b], identity_pins={str(b): pin})
        self._assert_demoted(inv, str(b))
        assert any("DEMOTED" in r.getMessage() for r in caplog.records)

    def test_swap_during_classify_demotes(self, tmp_path):
        # THE window this seam closes: pre-check passes, then the slot
        # is swapped (new inode) while the classify tools run — they
        # re-open by name and read the impostor. The post-classify
        # by-name inode check catches the lingering swap.
        b = _binary(tmp_path)
        pin = _pin(b)
        impostor = tmp_path / "impostor.debug"
        impostor.write_bytes(b"\x7fELF" + b"\xee" * 28)

        def swapping_classify(names, bp):
            os.replace(impostor, bp)
            return _verdicts(bp)

        inv = _inventory()
        with patch(_CLASSIFY, side_effect=swapping_classify):
            enrich_inventory_with_binary_oracle(
                inv, [b], identity_pins={str(b): pin})
        self._assert_demoted(inv, str(b))

    def test_inplace_rewrite_during_classify_demotes(self, tmp_path):
        # Same-inode variant: the pinned file is rewritten in place
        # (dev/ino unchanged, so the by-name check alone would pass).
        # The held-fd re-hash catches it.
        b = _binary(tmp_path)
        pin = _pin(b)

        def rewriting_classify(names, bp):
            with open(bp, "r+b") as f:
                f.write(b"\x7fELF" + b"\xee" * 28)  # same length
            return _verdicts(bp)

        inv = _inventory()
        with patch(_CLASSIFY, side_effect=rewriting_classify):
            enrich_inventory_with_binary_oracle(
                inv, [b], identity_pins={str(b): pin})
        self._assert_demoted(inv, str(b))

    def test_demoted_zero_verdict_binary_still_flags_summary(
            self, tmp_path):
        # The summary flag is derived from the demotion set, not from
        # the surviving per-binary records: a demoted binary that
        # produced no verdicts for a sibling's names must still flip
        # ``any_identity_demoted`` alongside its ``identity_demoted``
        # listing — the flag and the list it summarises must agree.
        good = _binary(tmp_path)
        empty = tmp_path / "empty.debug"
        empty.write_bytes(b"\x7fELF" + b"\x11" * 28)

        def classify(names, bp):
            return _verdicts(bp) if bp == good else {}

        inv = _inventory()
        with patch(_CLASSIFY, side_effect=classify):
            enrich_inventory_with_binary_oracle(
                inv, [good, empty], identity_pins={str(empty): None})
        summary = inv["binary_oracle"]
        assert summary["identity_demoted"] == [str(empty)]
        assert summary["any_identity_demoted"] is True
        assert summary["earns_suppression"] is False

    def test_symlink_at_slot_demotes(self, tmp_path):
        # The slot itself became a symlink (even to matching content):
        # the fd-honest pre-open refuses to verify through it.
        real = tmp_path / "real.debug"
        real.write_bytes(b"\x7fELF" + b"\x00" * 28)
        slot = tmp_path / "app.debug"
        slot.write_bytes(b"\x7fELF" + b"\x00" * 28)
        pin = _pin(slot)
        slot.unlink()
        slot.symlink_to(real)
        inv = _inventory()
        with patch(_CLASSIFY, side_effect=lambda names, bp: _verdicts(bp)):
            enrich_inventory_with_binary_oracle(
                inv, [slot], identity_pins={str(slot): pin})
        self._assert_demoted(inv, str(slot))


class TestCacheGradeNotLaundered:
    """The demotion must survive into the cross-run oracle-verdicts
    cache. ``core.audit.build_id_cache.store_oracle_verdicts`` derives
    its payload's ``suppression_grade`` from the SUMMARY ``binaries``
    entries (missing key defaults to full grade) — if the summary
    entries dropped the marker, a demoted binary's ``absent`` verdicts
    would persist at rest with the authority the demotion stripped."""

    _BID = "ab" * 20

    def _cached_grade(self, tmp_path, kwargs_for) -> bool:
        from core.audit.build_id_cache import (
            BuildIDCache,
            store_oracle_verdicts,
        )
        b = _binary(tmp_path)

        def classify(names, bp):
            return {
                "live_fn": BinaryOracleWitness(
                    "symbol_present", self._BID, str(bp), 4096),
                "dead_fn": BinaryOracleWitness(
                    "absent", self._BID, str(bp)),
            }

        inv = _inventory()
        with patch(_CLASSIFY, side_effect=classify):
            enrich_inventory_with_binary_oracle(inv, [b], **kwargs_for(b))
        # The summary entry and the per-item records must agree — the
        # cache writer reads the former, the live gates the latter.
        summary_entry = inv["binary_oracle"]["binaries"][0]
        assert (summary_entry["suppression_grade"]
                == _dead_entries(inv)[0]["suppression_grade"])
        cache = BuildIDCache(cache_dir=tmp_path / "cache")
        assert store_oracle_verdicts(cache, inv,
                                     source_command="test") == 1
        art = cache.get(self._BID, "oracle-verdicts")
        assert isinstance(art, dict)
        data = art["data"]
        assert set(data["verdicts"]) == {"live_fn", "dead_fn"}
        grade = data["suppression_grade"]
        assert isinstance(grade, bool)
        return grade

    def test_identity_demoted_grade_persists_into_cache(self, tmp_path):
        assert self._cached_grade(
            tmp_path,
            lambda b: {"identity_pins": {str(b): None}}) is False

    def test_guessed_build_grade_persists_into_cache(self, tmp_path):
        # Same laundering shape on the guessed-env-build channel
        # (pre-existed the identity seam) — covered by the same
        # summary-entry marker.
        assert self._cached_grade(
            tmp_path,
            lambda b: {"no_suppression_paths": (str(b),)}) is False

    def test_full_authority_grade_persists_into_cache(self, tmp_path):
        assert self._cached_grade(tmp_path, lambda b: {}) is True


class TestPinStillHoldsDeviceHalf:
    """The by-name half of ``_pin_still_holds`` must CONSUME
    st_dev, not just carry it — the
    pin deliberately records the device, and a same-inode-number file
    on another device (mount swap over the slot) must not hold it.
    All other swap tests here are single-filesystem, so only this one
    discriminates the device compare."""

    def test_pin_does_not_hold_across_a_device_change(self, tmp_path):
        from core.analysis.binary_oracle import _pin_still_holds
        b = _binary(tmp_path)
        st = os.stat(b)
        # Correct hash + correct inode number, wrong device: the pin
        # must NOT hold.
        pin = (st.st_dev + 1, st.st_ino, st.st_size, sha256_file(b))
        with open(b, "rb") as fh:
            fh.read()  # position at EOF like the held witness fd
            assert _pin_still_holds(fh, b, pin) is False


class TestWitnessedMissingNarrowsQuantifier:
    """Deleting a witnessed store binary is a NO-RACE move available
    to the same run-dir-write attacker the witness exists to stop.
    The load seam still SKIPS it — demote-not-
    refuse, there is nothing to classify — but the skip must be
    ACCOUNTED: the missing path rides the identity channel as a None
    pin, joins the demotion set, and every SURVIVING record drops
    ``suppression_grade``: the "absent from EVERY declared binary"
    quantifier no longer holds once a witnessed member vanished (the
    same posture as a floor drop of a sibling)."""

    @staticmethod
    def _load(binaries, witnesses):
        from types import SimpleNamespace

        from core.analysis.binary_oracle_cli import _project_binaries

        proj = SimpleNamespace(binaries=binaries,
                               binary_witnesses=witnesses)

        class _Mgr:
            def load(self, name):
                return proj

        identity: dict = {}
        with patch("core.project.project.ProjectManager", _Mgr), \
             patch("core.project.trust._context_project_name",
                   return_value="p"):
            paths, _ = _project_binaries(identity_out=identity)
        return paths, identity

    @staticmethod
    def _setup(tmp_path):
        a = tmp_path / "app_a.debug"
        a.write_bytes(b"\x7fELF" + b"\x00" * 28)
        b2 = tmp_path / "app_b.debug"
        b2.write_bytes(b"\x7fELF" + b"\x01" * 28)
        ka, kb = str(a.resolve()), str(b2.resolve())
        wit = {ka: sha256_file(a), kb: sha256_file(b2)}
        return a, b2, ka, kb, wit

    @staticmethod
    def _inventory():
        return {"files": [{"path": "src/a.c", "language": "c",
                           "items": [{"kind": "function",
                                      "name": "victim_fn",
                                      "metadata": {}}]}]}

    @staticmethod
    def _classify_for(a_key):
        # victim_fn is ABSENT in binary A but ALIVE in binary B.
        def classify(names, bp):
            if str(bp) == a_key:
                return {"victim_fn": BinaryOracleWitness(
                    "absent", "aa" * 20, str(bp))}
            return {"victim_fn": BinaryOracleWitness(
                "symbol_present", "bb" * 20, str(bp), 4096)}
        return classify

    def test_both_present_keep_full_authority(self, tmp_path):
        # Direction 2 (no overreach): with every witnessed binary
        # present and verified, nothing demotes and authority stays.
        from core.analysis.binary_oracle import extract_verdicts
        a, b2, ka, kb, wit = self._setup(tmp_path)
        paths, identity = self._load([ka, kb], wit)
        assert len(paths) == 2
        inv = self._inventory()
        with patch(_CLASSIFY, side_effect=self._classify_for(ka)):
            enrich_inventory_with_binary_oracle(
                inv, paths, identity_pins=identity)
        summary = inv["binary_oracle"]
        assert summary["any_identity_demoted"] is False
        assert summary["earns_suppression"] is True
        # alive-in-any wins: no absent verdict for the live function.
        assert extract_verdicts(inv).get("victim_fn") == (
            "symbol_present")

    def test_deleting_the_alive_binary_cannot_mint_authoritative_absent(
            self, tmp_path):
        # Direction 1 (the launder killed): rm the binary where the
        # function is ALIVE; the survivor's ``absent`` must not earn
        # suppression over the narrowed set.
        from core.analysis.binary_oracle import extract_verdicts
        a, b2, ka, kb, wit = self._setup(tmp_path)
        b2.unlink()  # the attacker's no-race move
        paths, identity = self._load([ka, kb], wit)
        # Demote-not-refuse: the survivor still loads and enriches...
        assert paths == [a.resolve()]
        # ...and the narrowed set is accounted on the identity channel.
        assert kb in identity and identity[kb] is None
        inv = self._inventory()
        with patch(_CLASSIFY, side_effect=self._classify_for(ka)):
            enrich_inventory_with_binary_oracle(
                inv, paths, identity_pins=identity)
        summary = inv["binary_oracle"]
        assert summary["any_identity_demoted"] is True
        assert kb in summary["identity_demoted"]
        assert summary["earns_suppression"] is False
        item = inv["files"][0]["items"][0]
        entries = item["metadata"]["binary_oracle"]["binaries"]
        assert entries
        assert all(e["suppression_grade"] is False for e in entries)
        assert absent_earns_suppression(entries) is False
        # The chokepoint-facing flat view must not carry the absent.
        assert "victim_fn" not in extract_verdicts(inv)


class TestPresentDemotedSiblingNoOverreach:
    """The no-overreach direction around ``witness_missing``: a
    PRESENT identity-demoted sibling must NOT strip the verified
    survivor's per-record grade. Its hint-tier evidence still
    contributes (alive-in-any defeats absence), unlike a MISSING
    member whose evidence vanished with it — only the missing flavor
    narrows the every-binary quantifier for the survivors."""

    def test_present_demoted_sibling_keeps_survivor_grade(
            self, tmp_path):
        a = tmp_path / "app_a.debug"
        a.write_bytes(b"\x7fELF" + b"\x00" * 28)
        b2 = tmp_path / "app_b.debug"
        b2.write_bytes(b"\x7fELF" + b"\x11" * 28)
        ka, kb = str(a.resolve()), str(b2.resolve())
        st = os.stat(a)
        pins = {ka: (st.st_dev, st.st_ino, st.st_size, sha256_file(a)),
                kb: None}  # B is PRESENT but demoted at load

        inv = {"files": [{"path": "s.c", "language": "c", "items": [
            {"kind": "function", "name": "fn", "metadata": {}}]}]}

        def classify(names, bp):
            return {"fn": BinaryOracleWitness(
                "symbol_present", "aa" * 20, str(bp), 4096)}

        with patch(_CLASSIFY, side_effect=classify):
            enrich_inventory_with_binary_oracle(
                inv, [Path(ka), Path(kb)], identity_pins=pins)
        entries = (inv["files"][0]["items"][0]["metadata"]
                   ["binary_oracle"]["binaries"])
        by_bp = {e["path"]: e for e in entries}
        # The demoted sibling loses its grade...
        assert by_bp[kb]["suppression_grade"] is False
        # ...but the verified survivor KEEPS per-record authority.
        assert by_bp[ka]["suppression_grade"] is True


class TestPinnedDeletedAfterLoad:
    """The same deletion, one seam later: the pin VERIFIED at load
    (tuple pin, binary present), and the attacker deletes the binary
    in the load→enrichment window — seconds to minutes in a real run.
    Enrichment's ``is_file()`` usability filter then drops the path
    before classification, so it is neither analysed nor a ``None``
    pin: without accounting, the survivor's ``absent`` quantifies
    over a silently narrowed set and mints full suppression
    authority. A pinned path can only be pinned because it was
    DECLARED for analysis, so pinned-but-not-analysed always means a
    witnessed member vanished — it must join the demotion set exactly
    like the load-time-missing flavor."""

    _H = TestWitnessedMissingNarrowsQuantifier

    def test_deleting_a_pinned_binary_after_load_cannot_mint_absent(
            self, tmp_path):
        from core.analysis.binary_oracle import extract_verdicts
        a, b2, ka, kb, wit = self._H._setup(tmp_path)
        # Load with BOTH binaries present: the witness verifies and
        # both pins come back as tuples.
        paths, identity = self._H._load([ka, kb], wit)
        assert len(paths) == 2
        assert identity[ka] is not None and identity[kb] is not None
        # The attacker's no-race move lands AFTER the load seam.
        b2.unlink()
        inv = self._H._inventory()
        with patch(_CLASSIFY,
                   side_effect=self._H._classify_for(ka)):
            enrich_inventory_with_binary_oracle(
                inv, paths, identity_pins=identity)
        summary = inv["binary_oracle"]
        # The vanished member is accounted on the identity channel...
        assert summary["any_identity_demoted"] is True
        assert kb in summary["identity_demoted"]
        assert summary["earns_suppression"] is False
        # ...and every SURVIVING record loses suppression authority.
        item = inv["files"][0]["items"][0]
        entries = item["metadata"]["binary_oracle"]["binaries"]
        assert entries
        assert all(e["suppression_grade"] is False for e in entries)
        assert absent_earns_suppression(entries) is False
        # The chokepoint-facing flat view must not carry the absent.
        assert "victim_fn" not in extract_verdicts(inv)

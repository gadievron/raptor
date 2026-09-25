"""Tests for core.binary.addrmap — normalized function identity."""

import json
from pathlib import Path

import pytest

from core.binary import addrmap
from core.binary.addrmap import (
    FID_FUZZY_WINDOW_BYTES,
    FidIndex,
    content_anchor,
    from_fid,
    image_base,
    make_fid,
    module_anchor,
    normalise_fid,
    record_fid_misses,
    to_fid,
    translate,
)
from packages.ghidra.model import REDatabase, REFunction


BUILD_ID = "fa1544052f2d4bfa87d3d3bfb1b7b9f4aa11c0de"


def _db(
    functions,
    *,
    base=None,
    tool="ghidra",
    include_base_key=True,
):
    metadata = {}
    if include_base_key:
        metadata["image_base"] = base
    return REDatabase(
        source_tool=tool,
        binary_path="/bin/target",
        functions=[
            REFunction(name=n, address=a, size=s)
            for (n, a, s) in functions
        ],
        metadata=metadata,
    )


class TestAnchor:
    def test_module_anchor_prefers_build_id(self):
        assert module_anchor(
            build_id=BUILD_ID, binary_sha256="ab" * 32,
        ) == BUILD_ID[:16]

    def test_module_anchor_sha_fallback(self):
        assert module_anchor(binary_sha256="ab" * 32) == "ab" * 8

    def test_module_anchor_rejects_junk(self):
        assert module_anchor(build_id="not hex!") is None
        assert module_anchor(build_id="abc") is None  # too short
        assert module_anchor() is None

    def test_content_anchor_build_id(self, monkeypatch, tmp_path):
        binary = tmp_path / "t.bin"
        binary.write_bytes(b"\x7fELF")
        import core.analysis.binary_oracle as oracle
        monkeypatch.setattr(oracle, "read_build_id", lambda _p: BUILD_ID)
        assert content_anchor(binary) == BUILD_ID[:16]

    def test_content_anchor_sha_fallback(self, monkeypatch, tmp_path):
        binary = tmp_path / "t.bin"
        binary.write_bytes(b"\x7fELF junk")
        import core.analysis.binary_oracle as oracle
        monkeypatch.setattr(oracle, "read_build_id", lambda _p: None)
        anchor = content_anchor(binary)
        import hashlib
        assert anchor == hashlib.sha256(b"\x7fELF junk").hexdigest()[:16]

    def test_content_anchor_unreadable_path_uses_known_digest(self):
        anchor = content_anchor(
            Path("/nonexistent/x"), binary_sha256="cd" * 32,
        )
        assert anchor == "cd" * 8

    def test_content_anchor_nothing(self):
        assert content_anchor(Path("/nonexistent/x")) is None

    def test_sandbox_refusal_degrades_to_content_hash(
        self, monkeypatch, tmp_path,
    ):
        # SandboxSetupError is BaseException by design; the anchor
        # probe names it and degrades LOUDLY to the sha256 fallback
        # (no subprocess needed) instead of aborting the run.
        binary = tmp_path / "t.bin"
        binary.write_bytes(b"\x7fELF payload")
        import core.analysis.binary_oracle as oracle
        from core.sandbox.errors import SandboxSetupError

        def refuse(_p):
            raise SandboxSetupError("refused", "hint")

        monkeypatch.setattr(oracle, "read_build_id", refuse)
        import hashlib
        expected = hashlib.sha256(b"\x7fELF payload").hexdigest()[:16]
        assert content_anchor(binary) == expected


class TestFidMintParse:
    def test_roundtrip(self):
        fid = make_fid("fa15440511223344", 0x261DA0, 0x100000)
        assert fid == "fa15440511223344:0x161da0"
        assert from_fid(fid) == ("fa15440511223344", 0x161DA0)

    def test_base_zero_is_recorded(self):
        assert make_fid("aa" * 8, 0x1000, 0) == f"{'aa' * 8}:0x1000"

    def test_fid_mintable_at_the_base(self):
        # rel-vaddr 0 is a valid identity (function AT the image
        # base); a mutation to rel <= 0 silently drops it.
        assert make_fid("aa" * 8, 0x1000, 0x1000) == f"{'aa' * 8}:0x0"

    def test_missing_leg_refuses(self):
        assert make_fid(None, 0x1000, 0) is None
        assert make_fid("aa" * 8, 0x1000, None) is None
        assert make_fid("aa" * 8, None, 0) is None
        assert make_fid("aa" * 8, True, 0) is None

    def test_negative_rel_vaddr_refuses(self):
        # An address below the recorded base means the base does not
        # describe this space — never mint a wrong identity.
        assert make_fid("aa" * 8, 0x100, 0x1000) is None

    def test_from_fid_rejects_junk(self):
        for junk in (None, 7, "", "abc", "xyz:0x10", "aa:0x10",
                     f"{'aa' * 8}:10", f"{'aa' * 8}:0x", "a" * 300):
            assert from_fid(junk) is None, junk

    def test_normalise_fid(self):
        assert normalise_fid(f"{'AA' * 8}:0x0010") == f"{'aa' * 8}:0x10"
        assert normalise_fid("planted\x1b[31m") is None


class TestImageBase:
    def test_redatabase_int(self):
        assert image_base(_db([], base=0x100000)) == 0x100000

    def test_redatabase_base_zero_recorded(self):
        assert image_base(_db([], base=0)) == 0

    def test_redatabase_key_absent_none(self):
        # The objdump fallback importer records no base at all.
        assert image_base(_db([], include_base_key=False)) is None

    def test_hex_string(self):
        # The serialised r2 context map carries a hex string.
        assert image_base({"image_base": "0x100000"}) == 0x100000

    def test_empty_string_none(self):
        assert image_base({"image_base": ""}) is None

    def test_dict_metadata_nesting(self):
        assert image_base({"metadata": {"image_base": 4096}}) == 4096

    def test_junk_none(self):
        assert image_base({"image_base": "planted"}) is None
        assert image_base({"image_base": True}) is None
        assert image_base(None) is None
        assert image_base(object()) is None

    def test_attribute_object(self):
        class Ctx:
            image_base = 0x400000
        assert image_base(Ctx()) == 0x400000

    def test_recorded_marker_false_blocks_object_shape(self):
        # A present-and-falsy marker means the base is a dataclass
        # default, not a fact — the keystone API itself must refuse
        # (a caller reading past the marker minted base-0 identities
        # for degraded runs).
        class Ctx:
            image_base = 0
            image_base_recorded = False
        assert image_base(Ctx()) is None

    def test_recorded_marker_true_allows_object_shape(self):
        class Ctx:
            image_base = 0x400000
            image_base_recorded = True
        assert image_base(Ctx()) == 0x400000

    def test_recorded_marker_false_blocks_dict_shape(self):
        assert image_base(
            {"image_base": "0x0", "image_base_recorded": False},
        ) is None

    def test_recorded_marker_true_allows_dict_shape(self):
        assert image_base(
            {"image_base": "0x400000", "image_base_recorded": True},
        ) == 0x400000

    def test_to_fid_refuses_unrecorded_context(self):
        class Ctx:
            image_base = 0
            image_base_recorded = False
            build_id = BUILD_ID
        assert to_fid(0x1000, Ctx()) is None


class TestToFid:
    def test_from_redatabase(self):
        db = _db([("f", 0x261DA0, 16)], base=0x100000)
        fid = to_fid(0x261DA0, db, anchor="fa15440511223344")
        assert fid == "fa15440511223344:0x161da0"

    def test_manifest_like_object(self):
        class Manifest:
            build_id = BUILD_ID
            binary_sha256 = "ab" * 32
            image_base = 0x1000
        assert to_fid(0x1010, Manifest()) == f"{BUILD_ID[:16]}:0x10"

    def test_manifest_dict(self):
        data = {"build_id": BUILD_ID, "image_base": 0x1000}
        assert to_fid(0x1010, data) == f"{BUILD_ID[:16]}:0x10"

    def test_baseless_producer_refuses(self):
        db = _db([("f", 0x1000, 16)], include_base_key=False)
        assert to_fid(0x1000, db, anchor="aa" * 8) is None


class TestTranslate:
    def test_both_bases_recorded(self):
        # Dual-base fixture: r2 at base 0, Ghidra at 0x100000.
        src = _db([("f", 0x161DA0, 32)], base=0, tool="r2")
        dst = _db([("f", 0x261DA0, 32)], base=0x100000)
        assert translate(0x161DA0, src, dst) == 0x261DA0
        assert translate(0x261DA0, dst, src) == 0x161DA0

    def test_name_resolution(self):
        src = _db([("handler", 0x161DA0, 32)], base=0, tool="r2")
        dst = _db([("handler", 0x261DA0, 32)], base=0x100000)
        assert translate("handler", src, dst) == 0x261DA0

    def test_auto_named_symbol_never_resolves(self):
        src = _db([("fcn.00161da0", 0x161DA0, 32)], base=0, tool="r2")
        src.functions[0].is_auto_named = True
        dst = _db([("g", 0x261DA0, 32)], base=0x100000)
        assert translate("fcn.00161da0", src, dst) is None

    def test_estimator_fallback_one_side_baseless(self):
        names = [("a", 0x1000), ("b", 0x2000), ("c", 0x3000)]
        src = _db(
            [(n, a, 16) for n, a in names],
            include_base_key=False, tool="r2",
        )
        dst = _db(
            [(n, a + 0x100000, 16) for n, a in names], base=0x100000,
        )
        assert translate(0x1000, src, dst) == 0x101000

    def test_no_overlap_refuses(self):
        src = _db([("a", 0x1000, 16)], include_base_key=False, tool="r2")
        dst = _db([("z", 0x101000, 16)], base=0x100000)
        assert translate(0x1000, src, dst) is None

    def test_both_baseless_refuses(self):
        names = [("a", 0x1000), ("b", 0x2000), ("c", 0x3000)]
        src = _db([(n, a, 16) for n, a in names], include_base_key=False)
        dst = _db([(n, a, 16) for n, a in names], include_base_key=False)
        assert translate(0x1000, src, dst) is None

    def test_zero_delta_needs_witnesses(self):
        # Estimator folds "no consistent evidence" into 0; a zero
        # delta is accepted only when same-name addresses agree.
        src = _db(
            [("a", 0x1000, 16), ("b", 0x2000, 16)],
            include_base_key=False, tool="r2",
        )
        dst = _db([("a", 0x1000, 16), ("b", 0x2000, 16)], base=0)
        assert translate(0x1000, src, dst) == 0x1000
        # Disagreeing addresses (estimator vote floor unmet -> 0,
        # zero witnesses) refuse.
        dst_bad = _db(
            [("a", 0x9000, 16), ("b", 0x7000, 16)], base=0,
        )
        assert translate(0x1000, src, dst_bad) is None

    def test_zero_delta_single_witness_refuses(self):
        # Witness floor pin (mutation survivor): exactly ONE
        # agreeing name is a coincidence, not corroboration —
        # the floor is 2.
        src = _db(
            [("a", 0x1000, 16), ("b", 0x2000, 16)],
            include_base_key=False, tool="r2",
        )
        dst = _db([("a", 0x1000, 16), ("b", 0x9000, 16)], base=0)
        assert translate(0x1000, src, dst) is None


class TestFidIndex:
    ANCHOR = "fa15440511223344"

    def _index(self):
        idx = FidIndex()
        idx.add("payload-a", fid=f"{self.ANCHOR}:0x1000", name="alpha")
        idx.add("payload-b", fid=f"{self.ANCHOR}:0x2000", name="beta")
        return idx

    def test_exact(self):
        m = self._index().resolve(fid=f"{self.ANCHOR}:0x1000")
        assert m is not None
        assert (m.payload, m.method) == ("payload-a", "exact")

    def test_fuzzy_within_window(self):
        # The window is EXCLUSIVE: window-1 is the last matching
        # distance (both-direction pin; a mutation to <= would join
        # the next PLT stub slot's entry).
        m = self._index().resolve(
            fid=f"{self.ANCHOR}:0x{0x1000 + FID_FUZZY_WINDOW_BYTES - 1:x}",
        )
        assert m is not None
        assert m.method == "fid_fuzzy"
        assert m.payload == "payload-a"
        assert m.distance == FID_FUZZY_WINDOW_BYTES - 1

    def test_fuzzy_at_window_misses(self):
        # distance == window is exactly the next 16-byte stub slot's
        # entry — must miss (a mutation widening the compare joins
        # adjacent stubs).
        m = self._index().resolve(
            fid=f"{self.ANCHOR}:0x{0x1000 + FID_FUZZY_WINDOW_BYTES:x}",
        )
        assert m is None

    def test_fuzzy_beyond_window_misses(self):
        m = self._index().resolve(
            fid=f"{self.ANCHOR}:0x{0x1000 + FID_FUZZY_WINDOW_BYTES + 1:x}",
        )
        assert m is None

    def test_fuzzy_two_candidates_in_window_refuse(self):
        # Ambiguity refusal, mirroring the name path: nearest-wins
        # silently joined evidence to whichever adjacent tiny
        # function the entry disagreement landed on.
        idx = FidIndex()
        idx.add("near", fid=f"{self.ANCHOR}:0x1008")
        idx.add("far", fid=f"{self.ANCHOR}:0x1010")
        assert idx.resolve(fid=f"{self.ANCHOR}:0x1006") is None

    def test_fuzzy_single_in_window_matches_despite_outside_noise(self):
        idx = FidIndex()
        idx.add("near", fid=f"{self.ANCHOR}:0x1008")
        idx.add("far-outside", fid=f"{self.ANCHOR}:0x1050")
        m = idx.resolve(fid=f"{self.ANCHOR}:0x1006")
        assert m is not None
        assert (m.payload, m.method, m.distance) == ("near", "fid_fuzzy", 2)

    def test_fuzzy_ambiguous_falls_back_to_unique_name(self):
        idx = FidIndex()
        idx.add("near", fid=f"{self.ANCHOR}:0x1008", name="alpha")
        idx.add("far", fid=f"{self.ANCHOR}:0x1010", name="beta")
        m = idx.resolve(fid=f"{self.ANCHOR}:0x1006", name="beta")
        assert m is not None
        assert (m.payload, m.method) == ("far", "name")

    def test_exact_fid_wins_over_name(self):
        # Precedence pin (mutation survivor): a record resolvable by
        # BOTH lanes must take the fid lane.
        idx = FidIndex()
        idx.add("by-fid", fid=f"{self.ANCHOR}:0x1000", name="other")
        idx.add("by-name", fid=f"{self.ANCHOR}:0x9000", name="alpha")
        m = idx.resolve(fid=f"{self.ANCHOR}:0x1000", name="alpha")
        assert m is not None
        assert (m.payload, m.method) == ("by-fid", "exact")

    def test_exact_duplicate_fid_first_wins(self):
        # Determinism pin (mutation survivor): setdefault keeps the
        # FIRST record for a duplicated fid.
        idx = FidIndex()
        idx.add("first", fid=f"{self.ANCHOR}:0x1000")
        idx.add("second", fid=f"{self.ANCHOR}:0x1000")
        m = idx.resolve(fid=f"{self.ANCHOR}:0x1000")
        assert m is not None
        assert m.payload == "first"

    def test_wrong_anchor_never_fuzzy(self):
        m = self._index().resolve(fid=f"{'bb' * 8}:0x1000")
        assert m is None

    def test_name_fallback(self):
        m = self._index().resolve(fid=f"{'bb' * 8}:0x1000", name="beta")
        assert m is not None
        assert (m.payload, m.method) == ("payload-b", "name")

    def test_synthetic_name_excluded(self):
        idx = FidIndex()
        idx.add("p", name="FUN_00161da0")
        assert idx.resolve(name="FUN_00161da0") is None

    def test_ambiguous_name_refuses(self):
        idx = FidIndex()
        idx.add("p1", name="dup")
        idx.add("p2", name="dup")
        assert idx.resolve(name="dup") is None

    def test_malformed_fid_ignored_on_add(self):
        idx = FidIndex()
        idx.add("p", fid="junk", name="ok")
        m = idx.resolve(name="ok")
        assert m is not None
        assert m.method == "name"


class TestMissRecording:
    def test_writes_and_appends(self, tmp_path):
        path = record_fid_misses(
            tmp_path, "bridge_seed", [{"fid": "aa" * 8 + ":0x10"}],
        )
        assert path == tmp_path / "fid-misses.json"
        record_fid_misses(tmp_path, "bridge_seed", [{"name": "beta"}])
        doc = json.loads(path.read_text())
        assert doc["schema_version"] == 1
        assert len(doc["operations"]) == 2
        assert doc["operations"][0]["operation"] == "bridge_seed"
        assert doc["operations"][1]["misses"] == [{"name": "beta"}]

    def test_empty_misses_write_nothing(self, tmp_path):
        assert record_fid_misses(tmp_path, "op", []) is None
        assert not (tmp_path / "fid-misses.json").exists()

    def test_hostile_names_escaped(self, tmp_path):
        record_fid_misses(
            tmp_path, "op", [{"name": "evil\x1b[31mred\nline"}],
        )
        doc = json.loads((tmp_path / "fid-misses.json").read_text())
        recorded = doc["operations"][0]["misses"][0]["name"]
        assert "\x1b" not in recorded
        assert "\n" not in recorded

    def test_hostile_keys_escaped_clipped_and_capped(self, tmp_path):
        # KEYS are caller-shaped too: a hostile binary's bytes can
        # arrive in either position of a miss dict, and uncapped
        # keys were a raw-ESC + growth lane.
        huge_key = "k\x1b[31m" + "A" * 5000
        miss = {huge_key: "v"}
        for i in range(20):
            miss[f"extra{i}"] = "x"
        record_fid_misses(tmp_path, "op", [miss])
        doc = json.loads((tmp_path / "fid-misses.json").read_text())
        entry = doc["operations"][0]["misses"][0]
        assert len(entry) <= 8
        for key in entry:
            assert "\x1b" not in key
            assert len(key) <= 64

    def test_byte_budget_trims_oldest_not_wholesale_reset(
        self, tmp_path, monkeypatch,
    ):
        # The keep-newest trim must engage BEFORE the read bound: a
        # file allowed to cross it made the next append silently
        # reset the whole log.
        monkeypatch.setattr(addrmap, "_MAX_MISSES_FILE_BYTES", 2000)
        for i in range(10):
            record_fid_misses(
                tmp_path, f"op{i}",
                [{"name": "x" * 150} for _ in range(3)],
            )
        doc = json.loads((tmp_path / "fid-misses.json").read_text())
        ops = [op["operation"] for op in doc["operations"]]
        assert ops, "newest operation must always survive"
        assert ops[-1] == "op9"
        assert len(ops) < 10  # oldest trimmed, not everything kept
        raw = (tmp_path / "fid-misses.json").read_text()
        # 2000-byte budget + one always-kept op's slack
        assert len(raw) < 4000

    def test_invalid_operation_collapses(self, tmp_path):
        record_fid_misses(tmp_path, "Bad Op!\x1b", [{"name": "x"}])
        doc = json.loads((tmp_path / "fid-misses.json").read_text())
        assert doc["operations"][0]["operation"] == "unknown"

    def test_per_operation_miss_cap(self, tmp_path):
        misses = [{"name": f"f{i}"} for i in range(600)]
        record_fid_misses(tmp_path, "op", misses)
        doc = json.loads((tmp_path / "fid-misses.json").read_text())
        op = doc["operations"][0]
        assert op["count"] == 600
        assert op["recorded"] == 500
        assert len(op["misses"]) == 500

    def test_operations_cap_keeps_newest(self, tmp_path):
        for i in range(205):
            record_fid_misses(tmp_path, f"op{i}", [{"name": "x"}])
        doc = json.loads((tmp_path / "fid-misses.json").read_text())
        ops = doc["operations"]
        assert len(ops) == 200
        assert ops[-1]["operation"] == "op204"
        assert ops[0]["operation"] == "op5"

    def test_corrupt_existing_starts_fresh(self, tmp_path):
        target = tmp_path / "fid-misses.json"
        target.write_text("{not json")
        record_fid_misses(tmp_path, "op", [{"name": "x"}])
        doc = json.loads(target.read_text())
        assert len(doc["operations"]) == 1

    def test_missing_dir_is_created(self, tmp_path):
        # save_json creates parents; a not-yet-created run subdir is
        # not a failure case.
        missing = tmp_path / "nope"
        path = record_fid_misses(missing, "op", [{"name": "x"}])
        assert path is not None
        assert path.is_file()

    def test_write_failure_never_raises(self, tmp_path, monkeypatch):
        import core.json

        def boom(*_args, **_kwargs):
            raise OSError("disk full")

        monkeypatch.setattr(core.json, "save_json", boom)
        assert record_fid_misses(tmp_path, "op", [{"name": "x"}]) is None


class TestArtifactLockAdoption:
    def test_lock_held_during_write(self, tmp_path, monkeypatch):
        # The miss recorder must serialise through the run-artifact
        # lock seam, not write bare.
        import packages.binary_analysis._artifact_lock as lockmod
        calls = []
        real = lockmod.run_artifacts_lock

        def spy(run_dir):
            calls.append(Path(run_dir))
            return real(run_dir)

        monkeypatch.setattr(lockmod, "run_artifacts_lock", spy)
        record_fid_misses(tmp_path, "op", [{"name": "x"}])
        assert calls == [tmp_path]


class TestPassthroughFid:
    def test_valid_fid_forwards(self):
        from core.binary.addrmap import passthrough_fid
        assert passthrough_fid({"fid": f"{'aa' * 8}:0x10"}) == {
            "fid": f"{'aa' * 8}:0x10",
        }

    def test_junk_collapses_to_absent(self):
        from core.binary.addrmap import passthrough_fid
        for junk in ("evil\x1b[31m", 7, True, "zz:0x10", None):
            assert passthrough_fid({"fid": junk}) == {}, junk
        assert passthrough_fid("not-a-dict") == {}
        assert passthrough_fid({}) == {}


class TestJoinAnomalyRecording:
    """record_join_anomalies mirrors the miss-recording idiom into
    its own ledger (join-anomalies.json)."""

    def test_records_into_own_file(self, tmp_path):
        from core.binary.addrmap import record_join_anomalies
        target = record_join_anomalies(tmp_path, "test-join", [{
            "reason": "identity_kind_mismatch",
            "anchor": "ab" * 8,
            "expected_kind": "elf_build_id",
            "found_kind": "pe_guid_age",
        }])
        assert target == tmp_path / "join-anomalies.json"
        doc = json.loads(target.read_text())
        assert doc["schema_version"] == 1
        op = doc["operations"][0]
        assert op["operation"] == "test-join"
        # Entries live under "anomalies", never "misses" — the
        # ledger is not a miss log and must not read like one.
        assert "misses" not in op
        assert op["anomalies"][0]["reason"] == "identity_kind_mismatch"
        # The miss ledger is untouched — anomalies are a different
        # failure mode and must not masquerade as misses.
        assert not (tmp_path / "fid-misses.json").exists()

    def test_empty_list_writes_nothing(self, tmp_path):
        from core.binary.addrmap import record_join_anomalies
        assert record_join_anomalies(tmp_path, "test-join", []) is None
        assert not (tmp_path / "join-anomalies.json").exists()

    def test_hostile_values_escaped_like_misses(self, tmp_path):
        from core.binary.addrmap import record_join_anomalies
        target = record_join_anomalies(tmp_path, "test-join", [{
            "found_kind": "evil\x1b[31mkind",
        }])
        text = target.read_text()
        assert "\x1b" not in text
        assert "\\x1b" in text


@pytest.mark.parametrize("name", sorted(addrmap.__all__))
def test_public_api_exists(name):
    assert hasattr(addrmap, name)

"""Normalized function identity (fid) at the producer seams.

Producers that RECORD an image base (Ghidra export parse, r2 import)
mint per-record fids; the objdump fallback records no base and stays
fid-free (fail-closed). Old artifacts without fid fields load
unchanged.
"""

from __future__ import annotations

import json

import core.binary.addrmap as addrmap
from packages.ghidra.decomp_tree import write_decomp_tree
from packages.ghidra.model import REDatabase, REFunction
from packages.ghidra.parser import parse_export
from packages.ghidra.r2_import import _context_map_to_redb_dict

ANCHOR = "fa15440511223344"


class TestREFunctionField:
    def test_roundtrip(self):
        f = REFunction(name="g", address=0x1010, size=4,
                       fid=f"{ANCHOR}:0x10")
        d = f.to_dict()
        assert d["fid"] == f"{ANCHOR}:0x10"
        assert REFunction.from_dict(d).fid == f"{ANCHOR}:0x10"

    def test_absent_stays_absent(self):
        # Old artifacts (and base-less producers) carry no fid key.
        f = REFunction(name="g", address=0x1010, size=4)
        assert "fid" not in f.to_dict()
        assert REFunction.from_dict({"name": "g", "address": 4112}).fid is None

    def test_junk_fid_in_planted_cache_collapses(self):
        for junk in ("planted\x1b[31m", 7, True, {"a": 1}, "zz:0x10"):
            f = REFunction.from_dict(
                {"name": "g", "address": 4112, "fid": junk},
            )
            assert f.fid is None, junk

    def test_database_roundtrip_preserves_fid(self):
        db = REDatabase(
            source_tool="ghidra",
            functions=[REFunction(name="g", address=0x1010, size=4,
                                  fid=f"{ANCHOR}:0x10")],
        )
        loaded = REDatabase.from_dict(db.to_dict())
        assert loaded.functions[0].fid == f"{ANCHOR}:0x10"


class TestMergeCarriesFid:
    def test_rebased_secondary_keeps_fid(self):
        # fid is base-RELATIVE module identity: the merge rebases
        # absolute addresses but must not strip identity.
        names = [("a", 0x1000), ("b", 0x2000), ("c", 0x3000)]
        primary = REDatabase(
            source_tool="ghidra",
            functions=[
                REFunction(name=n, address=a + 0x100000, size=16)
                for n, a in names
            ],
            metadata={"image_base": 0x100000},
        )
        secondary = REDatabase(
            source_tool="r2",
            functions=[
                REFunction(name=n, address=a, size=16,
                           fid=f"{ANCHOR}:0x{a:x}")
                for n, a in names
            ]
            + [REFunction(name="r2only", address=0x4000, size=16,
                          fid=f"{ANCHOR}:0x4000")],
            metadata={"image_base": 0},
        )
        merged = primary.merge(secondary)
        by_name = {f.name: f for f in merged.functions}
        assert by_name["r2only"].fid == f"{ANCHOR}:0x4000"
        # rel-vaddr survived the rebase unchanged
        assert by_name["r2only"].address == 0x104000


class TestGhidraExportStamping:
    def test_parse_export_stamps_when_base_recorded(
        self, tmp_path, monkeypatch,
    ):
        monkeypatch.setattr(addrmap, "content_anchor", lambda *_a, **_k: ANCHOR)
        export = {
            "source_tool": "ghidra",
            "binary_path": str(tmp_path / "t.bin"),
            "functions": [
                {"name": "handler", "address": 0x261DA0, "size": 32},
            ],
            "metadata": {"image_base": 0x100000},
        }
        path = tmp_path / "export.json"
        path.write_text(json.dumps(export))
        db = parse_export(path)
        assert db.functions[0].fid == f"{ANCHOR}:0x161da0"

    def test_parse_export_without_base_stays_fid_free(
        self, tmp_path, monkeypatch,
    ):
        monkeypatch.setattr(addrmap, "content_anchor", lambda *_a, **_k: ANCHOR)
        export = {
            "source_tool": "ghidra",
            "binary_path": str(tmp_path / "t.bin"),
            "functions": [
                {"name": "handler", "address": 0x261DA0, "size": 32},
            ],
            "metadata": {},
        }
        path = tmp_path / "export.json"
        path.write_text(json.dumps(export))
        db = parse_export(path)
        assert db.functions[0].fid is None


class TestR2ImportStamping:
    def test_serialised_context_map_mints_and_reads_fids(self, tmp_path):
        ctx = {
            "arch": "x86",
            "bits": 64,
            "binary_format": "elf",
            "image_base": "0x0",
            # Explicit recorded flag: ONLY this authorises treating
            # the serialised base as a fact (fail-closed contract).
            "image_base_recorded": True,
            "content_anchor": ANCHOR,
            "interesting_functions": [
                # Record-carried fid is read verbatim...
                {"name": "carried", "address": "0x1000", "size": 16,
                 "fid": f"{ANCHOR}:0x1000"},
                # ...and records without one are stamped from the
                # recorded base + serialised anchor.
                {"name": "stamped", "address": "0x2000", "size": 16},
            ],
            "imported_functions": [],
        }
        db = _context_map_to_redb_dict(ctx, tmp_path / "t.bin")
        by_name = {f.name: f for f in db.functions}
        assert by_name["carried"].fid == f"{ANCHOR}:0x1000"
        assert by_name["stamped"].fid == f"{ANCHOR}:0x2000"

    def test_junk_record_fid_dropped_then_restamped(self, tmp_path):
        ctx = {
            "arch": "x86",
            "bits": 64,
            "binary_format": "elf",
            "image_base": "0x0",
            "image_base_recorded": True,
            "content_anchor": ANCHOR,
            "interesting_functions": [
                {"name": "f", "address": "0x1000", "size": 16,
                 "fid": "junk\x1b"},
            ],
            "imported_functions": [],
        }
        db = _context_map_to_redb_dict(ctx, tmp_path / "t.bin")
        assert db.functions[0].fid == f"{ANCHOR}:0x1000"

    def test_degraded_run_recorded_false_never_stamps(self, tmp_path):
        # A degraded run serialises image_base "0x0" as a DEFAULT,
        # flagged unrecorded — stamping would mint wrong identities
        # for a non-zero-based binary.
        ctx = {
            "arch": "x86",
            "bits": 64,
            "image_base": "0x0",
            "image_base_recorded": False,
            "content_anchor": ANCHOR,
            "interesting_functions": [
                {"name": "f", "address": "0x1000", "size": 16},
            ],
            "imported_functions": [],
        }
        db = _context_map_to_redb_dict(ctx, tmp_path / "t.bin")
        assert db.functions[0].fid is None

    def test_legacy_map_without_flag_never_mints(self, tmp_path):
        # A LEGACY map (no recorded flag) gives no authority: its
        # image_base may be a serialiser default, and the stamping
        # anchor is RE-DERIVED from the on-disk binary — an
        # is-not-False gate minted stable base-0 identities for real
        # non-PIE binaries. Legacy maps also keep image_base OUT of
        # the RE-database metadata (key absent = no base, the
        # objdump shape).
        ctx = {
            "arch": "x86",
            "bits": 64,
            "image_base": "0x0",
            "content_anchor": ANCHOR,
            "interesting_functions": [
                {"name": "f", "address": "0x1000", "size": 16},
            ],
            "imported_functions": [],
        }
        db = _context_map_to_redb_dict(ctx, tmp_path / "missing.bin")
        assert db.functions[0].fid is None
        assert "image_base" not in db.metadata

    def test_no_anchor_no_base_stays_fid_free(self, tmp_path):
        ctx = {
            "arch": "x86",
            "bits": 64,
            "interesting_functions": [
                {"name": "f", "address": "0x1000", "size": 16},
            ],
            "imported_functions": [],
        }
        db = _context_map_to_redb_dict(ctx, tmp_path / "missing.bin")
        assert db.functions[0].fid is None
        assert "image_base" not in db.metadata


class TestR2LiveImportStamping:
    def _ctx(self, tmp_path, **kw):
        from packages.binary_analysis.radare2_understand import (
            BinaryContextMap,
            FunctionInfo,
        )
        ctx = BinaryContextMap(binary_path=tmp_path / "t.bin", **kw)
        ctx.interesting_functions = [
            FunctionInfo(name="handler", address=0x261DA0, size=32),
        ]
        return ctx

    def test_recorded_base_mints(self, tmp_path):
        from packages.ghidra.r2_import import _context_map_to_redb
        ctx = self._ctx(
            tmp_path,
            image_base=0x100000,
            image_base_recorded=True,
            content_anchor=ANCHOR,
        )
        db = _context_map_to_redb(ctx, tmp_path / "t.bin")
        by_name = {f.name: f for f in db.functions}
        assert by_name["handler"].fid == f"{ANCHOR}:0x161da0"
        assert db.metadata["image_base"] == 0x100000

    def test_unrecorded_default_base_never_mints(self, tmp_path):
        from packages.ghidra.r2_import import _context_map_to_redb
        ctx = self._ctx(tmp_path, content_anchor=ANCHOR)
        db = _context_map_to_redb(ctx, tmp_path / "t.bin")
        assert all(f.fid is None for f in db.functions)
        # ...and the default 0 never lands in metadata as a fact.
        assert "image_base" not in db.metadata


class TestObjdumpFallbackStaysFidFree:
    def test_no_base_no_fid(self):
        # The objdump importer records no image base by design —
        # stamp_redb_fids must refuse even with an anchor supplied.
        db = REDatabase(
            source_tool="objdump",
            binary_path="/bin/t",
            functions=[REFunction(name="f", address=0x1000, size=16)],
            metadata={"tier": "T0"},
        )
        assert addrmap.stamp_redb_fids(db, anchor=ANCHOR) == 0
        assert db.functions[0].fid is None


class TestDecompMapSidecar:
    def test_entries_carry_fid_when_minted(self, tmp_path):
        db = REDatabase(
            source_tool="ghidra",
            binary_path="/fw/demo",
            functions=[
                REFunction(name="a", address=0x1000, size=32,
                           decompilation="void a(void){}",
                           fid=f"{ANCHOR}:0x1000"),
                REFunction(name="b", address=0x1100, size=32,
                           decompilation="void b(void){}"),
            ],
        )
        tree = write_decomp_tree(db, tmp_path)
        side = json.loads(tree.sidecar_path.read_text())
        entries = [e for f in side["files"].values() for e in f]
        by_name = {e["function"]: e for e in entries}
        assert by_name["a"]["fid"] == f"{ANCHOR}:0x1000"
        # additive: fid-free records carry no key (old readers see
        # the exact pre-change shape)
        assert "fid" not in by_name["b"]

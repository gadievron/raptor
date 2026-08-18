"""PARSER_FUNCS seed-set demotion + parser_apis pack contract (WP6).

The category used to be a hardcoded 46-name catalog; it is now a marked
seed set (<= 9 exemplars) unioned with the CVE-corpus-derived data pack
(``data/packs/parser_apis.json``). These tests pin:

  * the seed-set policy (size, membership in the union),
  * no-shrinkage vs the recorded legacy catalog (every pre-migration
    name still resolves through seeds|pack),
  * the shipped pack's schema and provenance discipline.
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from core.function_taxonomy import PARSER_FUNCS, PARSER_SEED_FUNCS

_PACK_PATH = (
    Path(__file__).resolve().parents[1]
    / "data" / "packs" / "parser_apis.json"
)

# The full pre-migration PARSER_FUNCS catalog (recorded 2026-08-16).
# Consumers (fuzz prioritisation, surface classification, Frida hooks)
# depended on every one of these — the seeds|pack union must never
# lose one. Pure test data; grows only if the union ever regresses.
_LEGACY_CATALOG = frozenset({
    "yyparse",
    "XML_Parse", "XML_ParseBuffer",
    "xmlReadMemory", "xmlReadDoc", "xmlReadFile",
    "xmlSAXUserParseMemory", "xmlParseDoc",
    "json_loads", "json_loadb", "json_load_file",
    "json_object_from_file",
    "cJSON_Parse",
    "d2i_X509", "d2i_X509_bio", "d2i_PrivateKey",
    "PEM_read_X509", "PEM_read_PrivateKey",
    "PEM_read_bio_X509", "PEM_read_bio_PrivateKey",
    "lua_load", "lua_loadbuffer",
    "luaL_loadstring", "luaL_dostring", "luaL_dofile",
    "Py_CompileString", "PyRun_String", "PyRun_File",
    "png_read_info", "png_read_image",
    "jpeg_read_header", "jpeg_read_scanlines",
    "TIFFOpen", "TIFFReadDirectory",
    "WebPDecode", "WebPDecodeRGBA", "WebPDecodeBGRA",
    "inflate",
    "BZ2_bzDecompress",
    "lzma_code",
    "LZ4_decompress_safe", "LZ4_decompress_fast",
    "ZSTD_decompress", "ZSTD_decompressStream",
    "BrotliDecoderDecompress", "BrotliDecoderDecompressStream",
})


class SeedSetPolicy(unittest.TestCase):
    def test_seed_set_is_seed_sized(self):
        self.assertLessEqual(len(PARSER_SEED_FUNCS), 9)

    def test_seeds_are_part_of_the_union(self):
        self.assertTrue(PARSER_SEED_FUNCS <= PARSER_FUNCS)

    def test_union_is_larger_than_seeds(self):
        """The pack must actually contribute — a silently-failed pack
        load would leave consumers on 9 names."""
        self.assertGreater(len(PARSER_FUNCS), len(PARSER_SEED_FUNCS))


class NoShrinkage(unittest.TestCase):
    def test_every_legacy_name_still_present(self):
        missing = _LEGACY_CATALOG - PARSER_FUNCS
        self.assertFalse(
            missing,
            f"seeds|pack lost pre-migration names: {sorted(missing)}",
        )


class PackSchema(unittest.TestCase):
    def setUp(self):
        self.pack = json.loads(_PACK_PATH.read_text(encoding="utf-8"))

    def test_pack_identity(self):
        self.assertEqual(self.pack["pack"], "parser_apis")
        self.assertEqual(self.pack["schema"], 1)

    def test_entries_are_well_formed(self):
        for entry in self.pack["entries"]:
            self.assertTrue(
                entry["name"].isidentifier(), entry["name"],
            )
            self.assertTrue(entry["library"], entry["name"])
            self.assertTrue(entry["provenance"], entry["name"])
            for prov in entry["provenance"]:
                self.assertIn(prov, ("legacy-catalog", "cve-fix-diff"))

    def test_cve_provenance_carries_cves(self):
        """cve-fix-diff entries must name at least one CVE (that is the
        provenance); legacy entries may have empty cves."""
        for entry in self.pack["entries"]:
            if entry["provenance"] == ["cve-fix-diff"]:
                self.assertTrue(entry["cves"], entry["name"])

    def test_no_duplicate_names(self):
        names = [e["name"] for e in self.pack["entries"]]
        self.assertEqual(len(names), len(set(names)))

    def test_entries_sorted_for_stable_diffs(self):
        entries = self.pack["entries"]
        keys = [(e["library"], e["name"]) for e in entries]
        self.assertEqual(keys, sorted(keys))


if __name__ == "__main__":
    unittest.main()

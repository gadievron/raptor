"""The script_handler stamp: builder-persisted, one source of truth.

The classification of a script-per-file interstitial span (request
handler vs include/require wiring) is computed ONCE, at inventory
build time, and persisted on the checklist item under the additive
``script_handler`` field. Consumers read the stamp; none recomputes.
These tests pin the producer side: fresh builds stamp both verdict
directions, non-script languages stay unstamped, the SHA-reuse path
backfills pre-stamp entries, and the reader helper refuses forged
non-bool values.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.inventory.builder import build_inventory
from core.inventory.script_handler import (
    SCRIPT_HANDLER_FIELD,
    interstitial_is_handler,
    script_handler_stamp,
    stamp_script_handler_items,
)

_PHP_HANDLER = """\
<?php
/**
 * Module fixture: file-scope request handler.
 */
require_once('lib/common.php');

function helper($x) {
  return htmlspecialchars($x);
}

$cmd = $_POST['cmd'];
process_line($cmd);
"""

_PHP_WIRING = """\
<?php
include_once('lib/common.php');
require_once('lib/auth.php');
declare(strict_types=1);

function helper($x) {
  return trim($x);
}
"""

_C_FILE = """\
#include <stdlib.h>

static int counter;

int bump(void) {
  return ++counter;
}
"""


def _write_tree(tmp_path: Path) -> Path:
    target = tmp_path / "target"
    target.mkdir(exist_ok=True)
    (target / "handler.php").write_text(_PHP_HANDLER)
    (target / "wiring.php").write_text(_PHP_WIRING)
    (target / "count.c").write_text(_C_FILE)
    return target


def _items_by_file(inventory: dict) -> dict[str, list[dict]]:
    return {
        f["path"]: f.get("items", [])
        for f in inventory.get("files", [])
        if "path" in f
    }


def _interstitials(items: list[dict]) -> list[dict]:
    return [it for it in items if it.get("kind") == "interstitial"]


class TestBuilderStamps:
    def test_php_interstitials_are_stamped_both_directions(self, tmp_path):
        # The asserted span split (docblock/require header vs the
        # superglobal-read span) is the tree-sitter extractor's; the
        # regex fallback draws different interstitial boundaries.
        pytest.importorskip("tree_sitter_php")
        target = _write_tree(tmp_path)
        inv = build_inventory(str(target), str(tmp_path / "out"))
        by_file = _items_by_file(inv)

        handler_spans = _interstitials(by_file["handler.php"])
        assert handler_spans, "extractor produced no interstitials"
        stamps = [script_handler_stamp(it) for it in handler_spans]
        # Every PHP interstitial carries a genuine bool stamp.
        assert all(isinstance(s, bool) for s in stamps)
        # The span holding the superglobal read is stamped a handler;
        # the docblock + literal-require header span is not.
        assert any(script_handler_stamp(it) is True
                   for it in handler_spans)
        assert any(script_handler_stamp(it) is False
                   for it in handler_spans)

        wiring_spans = _interstitials(by_file["wiring.php"])
        assert wiring_spans
        assert all(isinstance(script_handler_stamp(it), bool)
                   for it in wiring_spans)
        # Nothing beyond include/declare wiring → stamped False.
        assert all(script_handler_stamp(it) is False
                   for it in wiring_spans)

    def test_non_script_languages_stay_unstamped(self, tmp_path):
        target = _write_tree(tmp_path)
        inv = build_inventory(str(target), str(tmp_path / "out"))
        c_items = _items_by_file(inv)["count.c"]
        assert _interstitials(c_items), "fixture lost its C interstitial"
        for it in c_items:
            assert SCRIPT_HANDLER_FIELD not in it

    def test_sha_reuse_backfills_missing_stamps(self, tmp_path):
        target = _write_tree(tmp_path)
        out = tmp_path / "out"
        build_inventory(str(target), str(out))

        # Simulate a checklist written before the stamp existed.
        ck_path = out / "checklist.json"
        ck = json.loads(ck_path.read_text())
        stripped = 0
        for f in ck.get("files", []):
            for it in f.get("items", []):
                if it.pop(SCRIPT_HANDLER_FIELD, None) is not None:
                    stripped += 1
        assert stripped, "fixture produced no stamps to strip"
        ck_path.write_text(json.dumps(ck))

        # Unchanged tree → every file takes the SHA-reuse path; the
        # backfill restores the stamp without a re-parse.
        inv = build_inventory(str(target), str(out))
        by_file = _items_by_file(inv)
        for path in ("handler.php", "wiring.php"):
            spans = _interstitials(by_file[path])
            assert spans
            assert all(isinstance(script_handler_stamp(it), bool)
                       for it in spans)
        for it in by_file["count.c"]:
            assert SCRIPT_HANDLER_FIELD not in it

    def test_sha_reuse_heals_tampered_stamps(self, tmp_path):
        # The checklist lives in a writable run/cache dir; the SHA
        # match reuses records indefinitely on unchanged files. A
        # tampered stamp must NOT persist: the reuse path re-derives
        # from content, both directions — a flipped true→false (which
        # would write the handler off in every consumer) heals back
        # to true, and a flipped false→true heals back to false.
        target = _write_tree(tmp_path)
        out = tmp_path / "out"
        inv = build_inventory(str(target), str(out))
        truth = {
            (f["path"], it["name"]): it[SCRIPT_HANDLER_FIELD]
            for f in inv["files"]
            for it in f.get("items", [])
            if SCRIPT_HANDLER_FIELD in it
        }
        assert True in truth.values() and False in truth.values()

        ck_path = out / "checklist.json"
        ck = json.loads(ck_path.read_text())
        flipped = 0
        for f in ck.get("files", []):
            for it in f.get("items", []):
                if isinstance(it.get(SCRIPT_HANDLER_FIELD), bool):
                    it[SCRIPT_HANDLER_FIELD] = (
                        not it[SCRIPT_HANDLER_FIELD])
                    flipped += 1
        assert flipped
        ck_path.write_text(json.dumps(ck))

        healed = build_inventory(str(target), str(out))
        for f in healed["files"]:
            for it in f.get("items", []):
                if SCRIPT_HANDLER_FIELD in it:
                    assert it[SCRIPT_HANDLER_FIELD] is truth[
                        (f["path"], it["name"])]


class TestStampHelpers:
    def test_reader_accepts_only_genuine_bools(self):
        assert script_handler_stamp({SCRIPT_HANDLER_FIELD: True}) is True
        assert script_handler_stamp({SCRIPT_HANDLER_FIELD: False}) is False
        # Absent / forged shapes → None (consumer fallback applies).
        assert script_handler_stamp({}) is None
        assert script_handler_stamp({SCRIPT_HANDLER_FIELD: "yes"}) is None
        assert script_handler_stamp({SCRIPT_HANDLER_FIELD: 1}) is None
        assert script_handler_stamp(None) is None
        assert script_handler_stamp("junk") is None

    def test_existing_stamps_are_rederived_not_trusted(self):
        items = [
            {"kind": "interstitial", "name": "interstitial:1-2",
             "line_start": 1, "line_end": 2,
             SCRIPT_HANDLER_FIELD: True},
            {"kind": "interstitial", "name": "interstitial:3-3",
             "line_start": 3, "line_end": 3},
            {"kind": "function", "name": "f",
             "line_start": 4, "line_end": 5},
        ]
        # Content classifies BOTH spans as wiring — the pre-existing
        # True stamp is overwritten (checklists live in writable
        # run/cache dirs; values are re-derived, never trusted), the
        # missing one is filled, and non-interstitials stay untouched.
        content = "include('a.php');\ninclude('b.php');\nrequire('c.php');\n"
        changed = stamp_script_handler_items(items, "php", content)
        assert changed is True
        assert items[0][SCRIPT_HANDLER_FIELD] is False
        assert items[1][SCRIPT_HANDLER_FIELD] is False
        assert SCRIPT_HANDLER_FIELD not in items[2]

    def test_full_stamp_overwrites(self):
        items = [{"kind": "interstitial", "name": "interstitial:1-1",
                  "line_start": 1, "line_end": 1,
                  SCRIPT_HANDLER_FIELD: False}]
        changed = stamp_script_handler_items(
            items, "php", "$x = $_GET['q'];\n")
        assert changed is True
        assert items[0][SCRIPT_HANDLER_FIELD] is True

    def test_non_script_language_is_a_no_op(self):
        items = [{"kind": "interstitial", "name": "interstitial:1-1",
                  "line_start": 1, "line_end": 1}]
        assert stamp_script_handler_items(items, "c", "int x;\n") is False
        assert SCRIPT_HANDLER_FIELD not in items[0]

    def test_classifier_dispatch(self):
        assert interstitial_is_handler("php", "$x = $_GET['q'];\n") is True
        assert interstitial_is_handler(
            "php", "include_once('lib/a.php');\n") is False
        # Non-script languages never classify as handler.
        assert interstitial_is_handler("c", "$x = $_GET['q'];\n") is False
        assert interstitial_is_handler("", "$x = 1;\n") is False

    def test_bool_line_numbers_are_not_spans(self):
        # JSON true/false decode as Python bools; a forged
        # line_start must not slice source as line 1.
        items = [{"kind": "interstitial", "name": "interstitial:1-1",
                  "line_start": True, "line_end": 2}]
        stamp_script_handler_items(items, "php", "$x = $_GET['q'];\n")
        # Unusable span → classified over no source → wiring (False),
        # but still stamped (a bool verdict, not a crash).
        assert items[0][SCRIPT_HANDLER_FIELD] is False


# \n-model layout (the plants live INSIDE line 2's comment):
# 1 <?php
# 2 // banner<FF><FF><FF><FF>
# 3 function helper($x) { return trim($x); }
# 4 $cmd = $_POST['cmd'];
# 5 echo $cmd;
_PHP_FF_PLANTED = (
    "<?php\n"
    "// banner\f\f\f\f\n"
    "function helper($x) { return trim($x); }\n"
    "$cmd = $_POST['cmd'];\n"
    "echo $cmd;\n"
)


class TestStampLineModel:
    """The stamp producer slices content with the items' \\n-counted
    line numbers.  ``str.splitlines()`` also breaks on plantable
    bytes (\\f, \\x85, U+2028 — all legal PHP comment text), so bytes
    planted in an early comment used to shift every later span: the
    handler stamp was derived from substitute (comment/wiring) lines,
    flipped to False for every consumer, and the SHA-reuse re-derive
    reproduced the same wrong verdict on each rebuild."""

    def test_planted_formfeeds_do_not_flip_the_handler_stamp(self):
        from core.inventory.script_handler import (
            stamp_script_handler_items,
        )
        items = [
            {"name": "interstitial:1-2", "kind": "interstitial",
             "line_start": 1, "line_end": 2},
            {"name": "interstitial:4-5", "kind": "interstitial",
             "line_start": 4, "line_end": 5},
        ]
        assert stamp_script_handler_items(items, "php", _PHP_FF_PLANTED)
        stamps = {it["name"]: it["script_handler"] for it in items}
        # The $_POST/echo span stays a handler; the header span,
        # plants and all, stays non-handler.
        assert stamps["interstitial:4-5"] is True
        assert stamps["interstitial:1-2"] is False

    def test_planted_separators_do_not_truncate_a_whole_file_span(self):
        # U+2028 at a comment tail: splitlines() yields extra rows, so
        # a whole-file span sliced [0:N] used to drop the trailing
        # handler lines.
        from core.inventory.script_handler import (
            stamp_script_handler_items,
        )
        content = (
            "<?php\n"
            "// banner\u2028\u2028\n"
            + "include 'a.php';\n" * 6
            + "$c = $_POST['cmd'];\n"
            "system($c);\n"
        )
        items = [{"name": "interstitial:1-10", "kind": "interstitial",
                  "line_start": 1, "line_end": 10}]
        stamp_script_handler_items(items, "php", content)
        assert items[0]["script_handler"] is True

    def test_planted_and_clean_twins_stamp_identically(self, tmp_path):
        # End to end through the builder: the planted file's stamps
        # equal its plant-stripped twin's (plants sit inside one
        # line, so the \n-model spans are identical by construction).
        target = tmp_path / "target"
        target.mkdir()
        (target / "planted.php").write_text(_PHP_FF_PLANTED)
        (target / "clean.php").write_text(_PHP_FF_PLANTED.replace("\f", ""))
        inv = build_inventory(str(target), str(tmp_path / "out"))
        by_file = _items_by_file(inv)

        def stamp_map(path: str) -> dict[str, object]:
            return {it["name"]: script_handler_stamp(it)
                    for it in _interstitials(by_file[path])}

        planted = stamp_map("planted.php")
        assert stamp_map("clean.php") == planted
        assert True in planted.values()  # non-vacuous: handler present


def _interstitial_state(items: list[dict]) -> list[dict]:
    """FULL interstitial item dicts (sorted) — a healed record must
    equal a fresh build's interstitial state field-for-field,
    including builder-stamped siblings like lexical_dead."""
    return sorted(_interstitials(items), key=lambda it: it["name"])


class TestSpanReconciliation:
    """SHA-reuse span self-healing. The stamp re-derivation slices by
    the item's recorded line_start/line_end — sibling coordinates in
    the same writable checklist — so a shifted span would make the
    heal classify wiring-only bytes and durably stamp a real handler
    span False. The reuse path re-derives the interstitial GEOMETRY
    from content first (line arithmetic over the record's other
    items, no parse): tampered spans heal loudly, legitimate reuse
    keeps every item byte-identical."""

    def test_sha_reuse_heals_tampered_spans(self, tmp_path):
        target = _write_tree(tmp_path)
        out = tmp_path / "out"
        inv = build_inventory(str(target), str(out))
        truth = _interstitial_state(_items_by_file(inv)["handler.php"])
        assert any(it.get(SCRIPT_HANDLER_FIELD) is True for it in truth)

        # Shift the True-stamped span onto the wiring-only
        # require_once line (5): without the reconciliation the stamp
        # re-derivation slices line 5, stamps False, and every
        # consumer follows.
        ck_path = out / "checklist.json"
        ck = json.loads(ck_path.read_text())
        shifted = 0
        for f in ck.get("files", []):
            if f.get("path") != "handler.php":
                continue
            for it in f.get("items", []):
                if (it.get("kind") == "interstitial"
                        and it.get(SCRIPT_HANDLER_FIELD) is True):
                    it["line_start"] = it["line_end"] = 5
                    it.pop("span_hash", None)
                    shifted += 1
        assert shifted
        ck_path.write_text(json.dumps(ck))

        healed = build_inventory(str(target), str(out))
        assert _interstitial_state(
            _items_by_file(healed)["handler.php"]) == truth

    def test_heal_restores_builder_sibling_fields(self, tmp_path):
        # A dead if(false) block: the fresh build tags the
        # interstitial that STARTS inside it lexical_dead. Replaced
        # items must re-earn builder-stamped sibling fields too —
        # full-dict equality with the fresh state, not just
        # geometry + stamp.
        php = (
            "<?php\n"
            "require_once('lib/common.php');\n"
            "\n"
            "function helper($x) {\n"
            "  return htmlspecialchars($x);\n"
            "}\n"
            "if (false) {\n"
            "  legacy_handler($_POST['cmd']);\n"
            "}\n"
            "\n"
            "$cmd = $_POST['cmd'];\n"
            "process_line($cmd);\n"
        )
        target = tmp_path / "target"
        target.mkdir()
        (target / "dead.php").write_text(php)
        out = tmp_path / "out"
        inv = build_inventory(str(target), str(out))
        truth = _interstitial_state(_items_by_file(inv)["dead.php"])
        assert any(it.get("lexical_dead") is True for it in truth)

        ck_path = out / "checklist.json"
        ck = json.loads(ck_path.read_text())
        for f in ck.get("files", []):
            for it in f.get("items", []):
                if it.get("kind") == "interstitial":
                    it["line_start"] = it["line_end"] = 2
                    it.pop("span_hash", None)
                    it.pop("lexical_dead", None)
        ck_path.write_text(json.dumps(ck))

        healed = build_inventory(str(target), str(out))
        assert _interstitial_state(
            _items_by_file(healed)["dead.php"]) == truth

    def test_sha_reuse_backfills_missing_interstitials(self, tmp_path):
        # A record written before the interstitial layer existed never
        # re-parses on the SHA fast path — the geometry backfills from
        # content the same way (the carried-gap rule).
        target = _write_tree(tmp_path)
        out = tmp_path / "out"
        inv = build_inventory(str(target), str(out))
        truth = _interstitial_state(_items_by_file(inv)["handler.php"])

        ck_path = out / "checklist.json"
        ck = json.loads(ck_path.read_text())
        for f in ck.get("files", []):
            if f.get("path") == "handler.php":
                f["items"] = [it for it in f.get("items", [])
                              if it.get("kind") != "interstitial"]
        ck_path.write_text(json.dumps(ck))

        healed = build_inventory(str(target), str(out))
        assert _interstitial_state(
            _items_by_file(healed)["handler.php"]) == truth

    def test_legitimate_reuse_is_byte_identical_and_parse_free(
            self, tmp_path, monkeypatch):
        target = _write_tree(tmp_path)
        out = tmp_path / "out"
        inv = build_inventory(str(target), str(out))
        before = {f["path"]: f.get("items") for f in inv["files"]}

        # The reconciliation is line arithmetic only — an unchanged
        # tree must take the SHA-reuse path without any re-parse.
        def _no_parse(*_a, **_k):
            raise AssertionError("reuse path re-parsed a file")

        import core.inventory.builder as builder_mod
        monkeypatch.setattr(builder_mod, "extract_items", _no_parse)
        reused = build_inventory(str(target), str(out))
        after = {f["path"]: f.get("items") for f in reused["files"]}
        for path in ("handler.php", "wiring.php"):
            assert after[path] == before[path]

    def test_reconcile_replaces_shifted_spans_loudly(self, caplog):
        import logging

        from core.inventory.script_handler import (
            reconcile_interstitial_items,
        )
        items = [
            {"kind": "function", "name": "f",
             "line_start": 3, "line_end": 5},
            {"kind": "interstitial", "name": "interstitial:6-7",
             "line_start": 2, "line_end": 2,  # shifted
             SCRIPT_HANDLER_FIELD: False, "span_hash": "0" * 12},
        ]
        content = ("<?php\ninclude 'a.php';\nfunction f($v) {\n"
                   "  return $v;\n}\n$c = $_POST['cmd'];\nsystem($c);\n")
        with caplog.at_level(
                logging.WARNING, logger="core.inventory.script_handler"):
            changed = reconcile_interstitial_items(
                items, "php", content, path="lib/thing.php")
        assert changed is True
        # The warning names the record (escaped path), so an operator
        # can find the healed file without diffing checklists.
        assert any("interstitial spans" in r.getMessage()
                   and "lib/thing.php" in r.getMessage()
                   for r in caplog.records)
        spans = sorted((it["line_start"], it["line_end"])
                       for it in _interstitials(items))
        assert spans == [(1, 2), (6, 7)]
        # Replaced items carry no stale fields; the stamp pass that
        # follows on the reuse path re-derives them.
        assert all(SCRIPT_HANDLER_FIELD not in it and "span_hash" not in it
                   for it in _interstitials(items))
        # Non-interstitial items are inputs, never touched.
        assert items[0] == {"kind": "function", "name": "f",
                            "line_start": 3, "line_end": 5}

    def test_reconcile_keeps_matching_geometry_untouched(self):
        from core.inventory.script_handler import (
            reconcile_interstitial_items,
        )
        items = [
            {"kind": "function", "name": "f",
             "line_start": 3, "line_end": 5},
            {"kind": "interstitial", "name": "interstitial:1-2",
             "line_start": 1, "line_end": 2,
             SCRIPT_HANDLER_FIELD: False, "span_hash": "abc" * 4},
            {"kind": "interstitial", "name": "interstitial:6-7",
             "line_start": 6, "line_end": 7,
             SCRIPT_HANDLER_FIELD: True, "span_hash": "def" * 4},
        ]
        snapshot = [dict(it) for it in items]
        content = ("<?php\ninclude 'a.php';\nfunction f($v) {\n"
                   "  return $v;\n}\n$c = $_POST['cmd'];\nsystem($c);\n")
        assert reconcile_interstitial_items(items, "php", content) is False
        assert items == snapshot

    def test_reconcile_is_a_no_op_outside_script_languages(self):
        from core.inventory.script_handler import (
            reconcile_interstitial_items,
        )
        items = [{"kind": "interstitial", "name": "interstitial:9-9",
                  "line_start": 9, "line_end": 9}]
        snapshot = [dict(it) for it in items]
        assert reconcile_interstitial_items(items, "c", "int x;\n") is False
        assert items == snapshot

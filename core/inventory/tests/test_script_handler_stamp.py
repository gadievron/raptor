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

    def test_only_missing_preserves_existing_stamps(self):
        items = [
            {"kind": "interstitial", "name": "interstitial:1-2",
             "line_start": 1, "line_end": 2,
             SCRIPT_HANDLER_FIELD: True},
            {"kind": "interstitial", "name": "interstitial:3-3",
             "line_start": 3, "line_end": 3},
            {"kind": "function", "name": "f",
             "line_start": 4, "line_end": 5},
        ]
        # Content classifies BOTH spans as wiring — but the existing
        # True stamp must survive only_missing mode.
        content = "include('a.php');\ninclude('b.php');\nrequire('c.php');\n"
        changed = stamp_script_handler_items(
            items, "php", content, only_missing=True)
        assert changed is True
        assert items[0][SCRIPT_HANDLER_FIELD] is True
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

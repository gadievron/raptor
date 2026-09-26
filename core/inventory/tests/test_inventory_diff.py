"""Function-level inventory diff (span-hash based).

The builder stamps a ``span_hash`` per reviewable item and emits
``inventory-diff.json`` whenever it rebuilds against a previous
checklist, carrying function-level ``functions_added`` /
``functions_changed`` keys so the new-code priority signal can boost
exactly the functions that changed — not every function in a changed
file.
"""

import json

import pytest

from core.inventory.builder import build_inventory
from core.inventory.diff import function_level_diff


def _write_v1(src):
    (src / "a.py").write_text(
        "def alpha():\n    return 1\n\n\ndef beta():\n    return 2\n"
    )


def _write_v2(src):
    # alpha changes, beta stays identical, gamma is new, b.py is new.
    (src / "a.py").write_text(
        "def alpha():\n    return 111\n\n\ndef beta():\n    return 2\n"
        "\n\ndef gamma():\n    return 3\n"
    )
    (src / "b.py").write_text("def delta():\n    return 4\n")


def test_span_hashes_stamped_on_items(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    _write_v1(src)
    inv = build_inventory(str(src), str(tmp_path / "out"), parallel=False)
    items = {i["name"]: i for f in inv["files"] for i in f["items"]}
    assert items["alpha"].get("span_hash")
    assert items["beta"].get("span_hash")
    assert items["alpha"]["span_hash"] != items["beta"]["span_hash"]
    assert len(items["alpha"]["span_hash"]) == 12


def test_function_level_diff_detects_exact_changes(tmp_path):
    src = tmp_path / "src"
    out1 = tmp_path / "o1"
    out2 = tmp_path / "o2"
    src.mkdir()
    _write_v1(src)
    old = build_inventory(str(src), str(out1), parallel=False)
    _write_v2(src)
    new = build_inventory(str(src), str(out2), parallel=False)

    fl = function_level_diff(old, new)
    assert "a.py:alpha" in fl["functions_changed"]
    assert "a.py:beta" not in fl["functions_changed"]
    assert "a.py:gamma" in fl["functions_added"]
    assert "b.py:delta" in fl["functions_added"]


def test_builder_writes_inventory_diff_on_rebuild(tmp_path):
    src = tmp_path / "src"
    out = tmp_path / "out"
    src.mkdir()
    _write_v1(src)
    build_inventory(str(src), str(out), parallel=False)
    assert not (out / "inventory-diff.json").exists()  # no previous run

    _write_v2(src)
    build_inventory(str(src), str(out), parallel=False)
    diff = json.loads((out / "inventory-diff.json").read_text())
    assert diff["modified"] == ["a.py"]
    assert diff["added"] == ["b.py"]
    assert "a.py:alpha" in diff["functions_changed"]
    assert "a.py:beta" not in diff["functions_changed"]
    assert "b.py:delta" in diff["functions_added"]

    # Unchanged rebuild resets the diff — a stale artifact must not
    # keep boosting functions that are no longer new.
    build_inventory(str(src), str(out), parallel=False)
    diff = json.loads((out / "inventory-diff.json").read_text())
    assert diff["functions_changed"] == []
    assert diff["functions_added"] == []


def test_missing_hashes_degrade_to_changed(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    _write_v1(src)
    old = build_inventory(str(src), str(tmp_path / "o1"), parallel=False)
    _write_v2(src)
    new = build_inventory(str(src), str(tmp_path / "o2"), parallel=False)

    # Strip old hashes (pre-hash inventory) — every function in the
    # modified file degrades conservatively to changed.
    for f in old["files"]:
        for i in f["items"]:
            i.pop("span_hash", None)
    fl = function_level_diff(old, new)
    assert "a.py:alpha" in fl["functions_changed"]
    assert "a.py:beta" in fl["functions_changed"]


_PHP_V1 = (
    "<?php\n"
    "require_once('lib/common.php');\n"
    "\n"
    "function helper($x) {\n"
    "  return htmlspecialchars($x);\n"
    "}\n"
    "\n"
    "$cmd = $_POST['cmd'];\n"
    "helper($cmd);\n"
)

# Handler span body changes (same span lines); helper unchanged.
_PHP_V2 = _PHP_V1.replace("helper($cmd);", "helper($cmd . 'x');")


def test_stamped_handler_spans_are_hashed_and_diffed(tmp_path):
    # Script-per-file handler spans (interstitials stamped
    # script_handler: true) are reviewable units — the builder hashes
    # them and the function-level diff tracks their changes; wiring
    # spans and pre-stamp interstitials keep the old skip.
    # The asserted span identities are the tree-sitter extractor's;
    # the regex fallback draws different interstitial boundaries.
    pytest.importorskip("tree_sitter_php")
    src = tmp_path / "src"
    src.mkdir()
    (src / "page.php").write_text(_PHP_V1)
    old = build_inventory(str(src), str(tmp_path / "o1"), parallel=False)
    items = {i["name"]: i for f in old["files"] for i in f["items"]}
    handler = next(i for i in items.values()
                   if i.get("script_handler") is True)
    assert handler.get("span_hash") and len(handler["span_hash"]) == 12
    wiring = next(i for i in items.values()
                  if i.get("script_handler") is False)
    assert not wiring.get("span_hash")

    (src / "page.php").write_text(_PHP_V2)
    new = build_inventory(str(src), str(tmp_path / "o2"), parallel=False)
    diff = function_level_diff(old, new)
    changed = set(diff["functions_changed"])
    added = set(diff["functions_added"])
    # The handler span changed (same name, new hash); helper did not.
    assert f"page.php:{handler['name']}" in changed | added
    assert "page.php:helper" not in changed
    assert "page.php:helper" not in added


def test_pre_stamp_interstitials_stay_out_of_diff(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "page.php").write_text(_PHP_V1)
    old = build_inventory(str(src), str(tmp_path / "o1"), parallel=False)
    # Strip the stamps to simulate a pre-stamp old inventory.
    for f in old["files"]:
        for it in f["items"]:
            it.pop("script_handler", None)
    (src / "page.php").write_text(_PHP_V2)
    new = build_inventory(str(src), str(tmp_path / "o2"), parallel=False)
    diff = function_level_diff(old, new)
    # New side is stamped → the handler span surfaces as ADDED (the
    # over-boost direction), never silently suppressed.
    assert any(k.startswith("page.php:interstitial:")
               for k in diff["functions_added"])


def test_sha_reuse_backfills_handler_span_hash(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "page.php").write_text(_PHP_V1)
    out = tmp_path / "out"
    fresh = build_inventory(str(src), str(out), parallel=False)
    fresh_items = {i["name"]: i for f in fresh["files"] for i in f["items"]}
    handler_name = next(n for n, i in fresh_items.items()
                        if i.get("script_handler") is True)
    expected_hash = fresh_items[handler_name]["span_hash"]

    # Simulate a pre-stamp checklist: no stamps, no interstitial hashes.
    ck_path = out / "checklist.json"
    ck = json.loads(ck_path.read_text())
    for f in ck.get("files", []):
        for it in f.get("items", []):
            it.pop("script_handler", None)
            if it.get("kind") == "interstitial":
                it.pop("span_hash", None)
    ck_path.write_text(json.dumps(ck))

    # Unchanged tree → SHA-reuse path → stamp AND hash are backfilled,
    # and the hash equals the fresh-parse one (identical content).
    reused = build_inventory(str(src), str(out), parallel=False)
    items = {i["name"]: i for f in reused["files"] for i in f["items"]}
    assert items[handler_name].get("script_handler") is True
    assert items[handler_name].get("span_hash") == expected_hash

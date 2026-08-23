"""Function-level inventory diff (span-hash based).

The builder stamps a ``span_hash`` per reviewable item and emits
``inventory-diff.json`` whenever it rebuilds against a previous
checklist, carrying function-level ``functions_added`` /
``functions_changed`` keys so the new-code priority signal can boost
exactly the functions that changed — not every function in a changed
file.
"""

import json

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

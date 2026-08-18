"""The per-batch basename index must be a drop-in for the linear scans.

Regression target: _match_to_inventory rebuilt a full basename
list-comp plus a full suffix scan of the inventory set per lookup —
O(reported × inventory) whenever tools report absolute or
build-relative paths (the norm for gcov/semgrep).
"""

from core.coverage.summary import _inventory_name_index, _match_to_inventory

_INV = {
    "src/auth.c",
    "src/db.c",
    "lib/x.py",
    "sublib/x.py",
    "src/notfoo.py",
    "foo.py",
}


def test_index_groups_by_basename():
    idx = _inventory_name_index(_INV)
    assert sorted(idx["x.py"]) == ["lib/x.py", "sublib/x.py"]
    assert idx["auth.c"] == ["src/auth.c"]
    assert "nope.c" not in idx


def test_indexed_matching_equals_linear_matching():
    idx = _inventory_name_index(_INV)
    reported = [
        "src/auth.c",            # exact
        "./src/db.c",            # ./ strip
        "/abs/src/auth.c",       # suffix via unique basename
        "/build/lib/x.py",       # suffix, ambiguous basename
        "sublib/x.py",           # exact despite ambiguous basename
        "foo.py",                # must NOT match src/notfoo.py
        "nope.c",                # no match
        "/somewhere/else/entirely.c",
    ]
    for path in reported:
        assert _match_to_inventory(path, _INV, idx) == \
            _match_to_inventory(path, _INV), path


def test_indexed_lookup_does_not_scan_inventory():
    """With the index supplied, a miss never iterates the inventory."""

    class Explosive(set):
        def __iter__(self):  # pragma: no cover - failure path
            raise AssertionError("inventory scanned despite index")

    inv = Explosive(_INV)
    idx = _inventory_name_index(set(_INV))
    # Non-exact lookups: basename + suffix strategies must use the index.
    assert _match_to_inventory("/abs/src/db.c", inv, idx) == "src/db.c"
    assert _match_to_inventory("missing.c", inv, idx) is None

"""Regeneration retains reviewed pin explanations or requires explicit review."""

from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import sys
from unittest.mock import patch

import pytest

from core.testing.module_views import module_function_view


@pytest.fixture(scope="module")
def census():
    path = Path(__file__).with_name("test_redos_idiom_census.py")
    spec = importlib.util.spec_from_file_location("owned_pin_review_notes", path)
    module = importlib.util.module_from_spec(spec)
    with patch.object(sys, "path", sys.path.copy()):
        spec.loader.exec_module(module)
    return module


def test_absent_prior_file(census, tmp_path):
    rows = {"owned": {"digests": ["a"], "verdict": "linear"}}
    before = deepcopy(rows)
    census._preserve_pin_review_notes(tmp_path / "missing.json", rows)
    assert rows == before


def test_preserves_note_across_measurement_and_digest_order(census, tmp_path):
    path = tmp_path / "pins.json"
    path.write_text(json.dumps({"members": {"owned": {
        "digests": ["b", "a"], "verdict": "linear", "exp": 0.9,
        "note": "Reviewed identifier boundary.",
    }}}))
    before = path.read_bytes()
    row = {"digests": ["a", "b"], "verdict": "linear", "exp": 1.0}
    census._preserve_pin_review_notes(path, {"owned": row})
    assert row["note"] == "Reviewed identifier boundary."
    assert row["exp"] == 1.0
    assert path.read_bytes() == before


@pytest.mark.parametrize("change", ["digest", "verdict", "removed", "blank", "nonstring"])
def test_invalidated_review_is_atomic(census, tmp_path, change):
    old = {"digests": ["a"], "verdict": "linear", "note": "Reviewed."}
    rows = {"first": {"digests": ["a"], "verdict": "linear"},
            "second": {"digests": ["a"], "verdict": "linear"}}
    prior = {"first": dict(old), "second": dict(old)}
    if change == "digest":
        rows["second"]["digests"] = ["b"]
    elif change == "verdict":
        rows["second"]["verdict"] = "noattack"
    elif change == "removed":
        del rows["second"]
    else:
        prior["second"]["note"] = " " if change == "blank" else 7
    path = tmp_path / "pins.json"
    path.write_text(json.dumps({"members": prior}))
    before, original = path.read_bytes(), deepcopy(rows)
    with pytest.raises(ValueError):
        census._preserve_pin_review_notes(path, rows)
    assert path.read_bytes() == before
    assert rows == original


@pytest.mark.parametrize("scan", [False, True], ids=["trailing", "scan"])
@pytest.mark.parametrize("changed", [False, True], ids=["unchanged", "changed"])
def test_real_regeneration_preserves_or_refuses_review(census, tmp_path, scan, changed):
    path = tmp_path / "pins.json"
    key = ("owned.py", "literal")
    path.write_text(json.dumps({"members": {"\x1f".join(key): {
        "digests": ["old" if changed else "owned"],
        "verdict": "noattack", "exp": None, "note": "Literal has no scan lane.",
    }}}))
    before = path.read_bytes()
    members = {key: {"digests": {"owned"}, "rules": {"C"},
                     "sites": [(1, "literal", 0, "search")]}}
    consumer = module_function_view(census, bindings={
        "_SCAN_EXPECTED_FILE" if scan else "_EXPECTED_FILE": path,
        "_scan_restart_members" if scan else "_trailing_span_members": lambda: members,
    })
    regenerate = consumer._regen_scan_expected if scan else consumer._regen_expected
    if changed:
        with pytest.raises(ValueError, match="review note"):
            regenerate(workers=1)
        assert path.read_bytes() == before
    else:
        assert regenerate(workers=1) == 0
        row = json.loads(path.read_text())["members"]["\x1f".join(key)]
        assert row["note"] == "Literal has no scan lane."
        assert row["digests"] == ["owned"]
        assert row["verdict"] == "noattack"

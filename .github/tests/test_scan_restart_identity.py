"""Census pins follow pattern content, independently of table position."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest


@pytest.fixture(scope="module")
def census():
    path = Path(__file__).with_name("test_redos_idiom_census.py")
    spec = importlib.util.spec_from_file_location("scan_identity_census", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _members(census, tmp_path, monkeypatch, entries, prefix=""):
    path = tmp_path / "patterns.py"
    path.write_text(prefix + "import re\nPATTERNS = " + repr(entries) + "\n")
    sites = census._extract_sites(path)
    monkeypatch.setattr(census, "_all_runtime_sites", lambda: sites)
    return census._scan_restart_members()


def _allowlist_sites(census, tmp_path, note):
    path = tmp_path / "metadata.py"
    path.write_text(
        "import re\nROWS = [AllowlistEntry(file='writer.py', func_name='render', "
        "kind='unsanitised_llm_value', detail='body', audit_note=" + note + ")]\n"
    )
    return census._extract_sites(path)


def test_allowlist_prose_is_not_a_regex(census, tmp_path):
    sites = _allowlist_sites(census, tmp_path, repr(r"\s*==0"))
    assert not sites


def test_actual_regex_nested_in_metadata_is_still_checked(census, tmp_path):
    sites = _allowlist_sites(census, tmp_path, "re.compile(" + repr(r"\s*==0") + ")")
    assert len(sites) == 1
    assert sites[0].origin == "call"
    assert census._site_scan_lanes(sites[0])


def test_inserting_unrelated_entry_preserves_existing_pin(census, tmp_path, monkeypatch):
    pattern = r"\s*==0"
    original = _members(census, tmp_path, monkeypatch, [pattern])
    changed = _members(census, tmp_path, monkeypatch, [
        "int counter of timed-out grep batches in the ThreadPoolExecutor",
        pattern,
    ], prefix="\n# An unrelated comment moves source locations too.\n")
    assert len(original) == 1
    assert original.keys() == changed.keys()
    for key in original:
        assert original[key]["digests"] == changed[key]["digests"]


def test_reordering_entries_preserves_pins(census, tmp_path, monkeypatch):
    patterns = [r"\s*==0", r"\s*!=0"]
    original = _members(census, tmp_path, monkeypatch, patterns)
    reordered = _members(census, tmp_path, monkeypatch, list(reversed(patterns)))
    assert len(original) == 2
    assert original.keys() == reordered.keys()


def test_new_or_changed_pattern_requires_a_new_pin(census, tmp_path, monkeypatch):
    original = _members(census, tmp_path, monkeypatch, [r"\s*==0"])
    replaced = _members(census, tmp_path, monkeypatch, [r"\s*!=0"])
    extended = _members(census, tmp_path, monkeypatch, [r"\s*==0", r"\s*!=0"])
    assert len(original) == len(replaced) == 1
    assert original.keys().isdisjoint(replaced)
    assert original.keys() < extended.keys()


def test_duplicate_pattern_shares_pin_but_retains_sites(census, tmp_path, monkeypatch):
    original = _members(census, tmp_path, monkeypatch, [r"\s*==0"])
    duplicate = _members(census, tmp_path, monkeypatch, [r"\s*==0", r"\s*==0"])
    assert original.keys() == duplicate.keys()
    assert len(next(iter(duplicate.values()))["sites"]) == 2

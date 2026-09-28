"""_carry_forward_coverage carries checked_by claim tokens verbatim.

Hermetic: XDG_DATA_HOME points at a per-test tmp dir.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from core.inventory import checklist_mac
from core.inventory.builder import _carry_forward_coverage
from core.inventory.coverage import update_coverage

LABEL = "validate:stage-a"


@pytest.fixture(autouse=True)
def _isolated_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))


def _inventory(sha: str = "aa" * 32) -> dict[str, Any]:
    return {
        "files": [
            {
                "path": "src/a.c",
                "sha256": sha,
                "items": [
                    {"name": "f1", "kind": "function",
                     "line_start": 1, "line_end": 5},
                ],
            },
        ],
    }


def _marked(sha: str = "aa" * 32) -> dict[str, Any]:
    inv = _inventory(sha)
    update_coverage(inv, [{"file": "src/a.c", "function": "f1"}], LABEL)
    return inv


def test_token_carried_for_unchanged_file_and_still_verifies() -> None:
    old = _marked()
    new = _inventory()
    _carry_forward_coverage(old, new)
    fe = new["files"][0]
    f1 = fe["items"][0]
    assert f1["checked_by"] == [LABEL]
    assert checklist_mac.claim_provenance(fe, f1, LABEL) \
        == checklist_mac.CLAIM_VERIFIED


def test_modified_file_carries_nothing() -> None:
    old = _marked()
    new = _inventory(sha="bb" * 32)
    _carry_forward_coverage(old, new, modified={"src/a.c"})
    f1 = new["files"][0]["items"][0]
    assert "checked_by" not in f1
    assert checklist_mac.TOKEN_MAP_KEY not in f1


def test_carried_token_over_moved_content_demotes_not_verifies() -> None:
    """Promotion merges older checklists without a modified-set; a
    claim whose file content moved carries but no longer verifies —
    the import-side demote (stale review credit), never a crash."""
    old = _marked(sha="aa" * 32)
    new = _inventory(sha="bb" * 32)  # same path, different content
    _carry_forward_coverage(old, new)
    fe = new["files"][0]
    f1 = fe["items"][0]
    assert f1["checked_by"] == [LABEL]
    assert checklist_mac.claim_provenance(fe, f1, LABEL) \
        == checklist_mac.CLAIM_TAMPERED


def test_newer_token_wins_merge_and_labels_union() -> None:
    old = _marked()
    old_f1 = old["files"][0]["items"][0]
    update_coverage(old, [{"file": "src/a.c", "function": "f1"}], "agentic")
    new = _marked()  # base has its own fresh token for LABEL
    new_token = new["files"][0]["items"][0][checklist_mac.TOKEN_MAP_KEY][LABEL]
    _carry_forward_coverage(old, new)
    fe = new["files"][0]
    f1 = fe["items"][0]
    assert f1["checked_by"] == [LABEL, "agentic"]
    assert f1[checklist_mac.TOKEN_MAP_KEY][LABEL] == new_token
    assert f1[checklist_mac.TOKEN_MAP_KEY]["agentic"] \
        == old_f1[checklist_mac.TOKEN_MAP_KEY]["agentic"]
    for label in f1["checked_by"]:
        assert checklist_mac.claim_provenance(fe, f1, label) \
            == checklist_mac.CLAIM_VERIFIED


def test_hostile_old_token_map_tolerated() -> None:
    old = _inventory()
    old["files"][0]["items"][0]["checked_by"] = [LABEL]
    old["files"][0]["items"][0][checklist_mac.TOKEN_MAP_KEY] = "junk"
    new = _inventory()
    _carry_forward_coverage(old, new)
    f1 = new["files"][0]["items"][0]
    assert f1["checked_by"] == [LABEL]
    assert checklist_mac.TOKEN_MAP_KEY not in f1


def test_forged_unstamped_label_stays_unstamped_through_carry() -> None:
    """The laundering fence: carrying a planted (token-less) label
    never mints it a token."""
    old = _inventory()
    old["files"][0]["items"][0]["checked_by"] = ["audit"]
    new = _inventory()
    _carry_forward_coverage(old, new)
    fe = new["files"][0]
    f1 = fe["items"][0]
    assert f1["checked_by"] == ["audit"]
    assert checklist_mac.claim_provenance(fe, f1, "audit") \
        == checklist_mac.CLAIM_UNSTAMPED

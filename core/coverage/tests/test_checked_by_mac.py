"""import_checked_by claim-authority tiering.

The checklist is a target-writable artifact; a review-grade
``checked_by`` mark clears the function from store-derived review-gap
views. These tests pin the trust chokepoint: verified claims import at
full authority, forged/tampered/legacy rows demote to the
``<label>:machine`` hint tier loudly, and the import never refuses.

Hermetic: XDG_DATA_HOME points at a per-test tmp dir (the suite
conftest isolates it too; the explicit monkeypatch keeps each test
self-contained).
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import pytest

from core.coverage.importer import import_checked_by
from core.coverage.store import CoverageStore
from core.inventory import checklist_mac
from core.inventory.coverage import update_coverage

LABEL = "validate:stage-a"


@pytest.fixture(autouse=True)
def _isolated_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))


def _store(tmp_path: Path) -> CoverageStore:
    return CoverageStore(tmp_path / "coverage.json", target="zip:abc")


def _checklist() -> dict[str, Any]:
    return {
        "files": [
            {"path": "a.c", "sha256": "aa" * 32, "lines": 100, "items": [
                {"name": "f1", "line_start": 0, "line_end": 20},
                {"name": "f2", "line_start": 30, "line_end": 60},
            ]},
        ],
    }


def _authentic() -> dict[str, Any]:
    cl = _checklist()
    update_coverage(cl, [{"file": "a.c", "function": "f2"}], LABEL)
    return cl


def test_verified_claim_imports_at_full_label(tmp_path: Path) -> None:
    """Round trip: a claim minted by update_coverage imports under its
    own label — write→read semantics unchanged for authenticated rows."""
    s = _store(tmp_path)
    cl = json.loads(json.dumps(_authentic()))   # via-disk shape
    assert import_checked_by(s, cl) == 1
    assert s.who_checked_function("a.c", 30, 60) == {LABEL: "full"}


def test_forged_row_demotes_loudly_and_run_continues(
    tmp_path: Path, caplog: pytest.LogCaptureFixture,
) -> None:
    """Forge: a planted token-less review-grade row imports only at
    the machine hint tier, with a loud structured warning — and the
    import completes (never a refusal)."""
    s = _store(tmp_path)
    cl = _checklist()
    cl["files"][0]["items"][1]["checked_by"] = [LABEL]  # forged
    with caplog.at_level(logging.WARNING):
        assert import_checked_by(s, cl) == 1
    assert s.who_checked_function("a.c", 30, 60) == {f"{LABEL}:machine": "full"}
    assert "machine tier" in caplog.text
    assert "1 unstamped" in caplog.text


def test_tampered_row_demotes_and_is_counted_distinctly(
    tmp_path: Path, caplog: pytest.LogCaptureFixture,
) -> None:
    """Tamper: editing a stamped row's covered fields (here the line
    range — the stretch attack) invalidates its token; the row demotes
    to the hint tier and the warning names it as tampered."""
    s = _store(tmp_path)
    cl = _authentic()
    cl["files"][0]["items"][1]["line_end"] = 99   # stretch over the file
    with caplog.at_level(logging.WARNING):
        assert import_checked_by(s, cl) == 1
    assert s.who_checked_function("a.c", 30, 99) == {f"{LABEL}:machine": "full"}
    assert "1 tampered" in caplog.text


def test_relabelled_token_demotes(tmp_path: Path) -> None:
    """A token minted for one label must not authenticate a
    higher-authority label pasted next to it."""
    s = _store(tmp_path)
    cl = _authentic()
    item = cl["files"][0]["items"][1]
    token = item[checklist_mac.TOKEN_MAP_KEY][LABEL]
    item["checked_by"] = ["audit"]
    item[checklist_mac.TOKEN_MAP_KEY] = {"audit": token}
    assert import_checked_by(s, cl) == 1
    assert s.who_checked_function("a.c", 30, 60) == {"audit:machine": "full"}


def test_legacy_pre_mac_checklist_reads_at_hint_tier(
    tmp_path: Path, caplog: pytest.LogCaptureFixture,
) -> None:
    """Legacy: an entirely pre-MAC checklist imports every row at the
    fenced machine tier — readable, hint-tier authority, no refusal,
    one warning naming the unstamped count."""
    s = _store(tmp_path)
    cl = _checklist()
    cl["files"][0]["items"][0]["checked_by"] = ["agentic"]
    cl["files"][0]["items"][1]["checked_by"] = [LABEL, "audit"]
    with caplog.at_level(logging.WARNING):
        assert import_checked_by(s, cl) == 3
    assert s.who_checked_function("a.c", 0, 20) == {"agentic:machine": "full"}
    assert s.who_checked_function("a.c", 30, 60) == {
        f"{LABEL}:machine": "full", "audit:machine": "full"}
    assert "3 unstamped" in caplog.text
    # Hint tier is still llm-extent examination evidence...
    assert s.function_covered("a.c", 30, 60, category="llm") is True
    # ...but never review credit (scanned depth, not analysed).
    from core.coverage.registry import DEPTH_ANALYSED, classify
    assert classify(f"{LABEL}:machine")[1] != DEPTH_ANALYSED


def test_non_review_grade_labels_import_unchanged(
    tmp_path: Path, caplog: pytest.LogCaptureFixture,
) -> None:
    """Scanned-depth labels grant no review credit, so tiering them
    would be pure label churn — imported as-is, no warning (same rule
    as import_functions_analysed)."""
    s = _store(tmp_path)
    cl = _checklist()
    cl["files"][0]["items"][0]["checked_by"] = ["understand:map"]
    with caplog.at_level(logging.WARNING):
        assert import_checked_by(s, cl) == 1
    assert s.who_checked_function("a.c", 0, 20) == {"understand:map": "full"}
    assert "machine tier" not in caplog.text


def test_mixed_checklist_tiers_per_claim(tmp_path: Path) -> None:
    """Verified and forged claims in one checklist tier independently."""
    s = _store(tmp_path)
    cl = _authentic()
    cl["files"][0]["items"][0]["checked_by"] = ["audit"]   # forged sibling
    assert import_checked_by(s, cl) == 2
    assert s.who_checked_function("a.c", 30, 60) == {LABEL: "full"}
    assert s.who_checked_function("a.c", 0, 20) == {"audit:machine": "full"}

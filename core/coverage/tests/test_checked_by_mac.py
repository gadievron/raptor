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
from core.hash import sha256_bytes
from core.inventory import checklist_mac
from core.inventory.coverage import update_coverage

LABEL = "validate:stage-a"
_SOURCE = "int f1(void) { return 1; }\nint f2(void) { return 2; }\n"


@pytest.fixture(autouse=True)
def _isolated_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))


def _store(tmp_path: Path) -> CoverageStore:
    return CoverageStore(tmp_path / "coverage.json", target="zip:abc")


def _checklist(tmp_path: Path) -> dict[str, Any]:
    """A checklist over a REAL on-disk target whose file-entry sha256
    matches the current source — the shape the builder writes, and the
    shape a verified claim needs to keep full credit through the
    importer's currency gate."""
    target = tmp_path / "target"
    target.mkdir(exist_ok=True)
    src = target / "a.c"
    src.write_text(_SOURCE)
    return {
        "target_path": str(target),
        "files": [
            {"path": "a.c", "sha256": sha256_bytes(src.read_bytes()),
             "lines": 100, "items": [
                 {"name": "f1", "line_start": 0, "line_end": 20},
                 {"name": "f2", "line_start": 30, "line_end": 60},
             ]},
        ],
    }


def _authentic(tmp_path: Path) -> dict[str, Any]:
    cl = _checklist(tmp_path)
    update_coverage(cl, [{"file": "a.c", "function": "f2"}], LABEL)
    return cl


def test_verified_claim_imports_at_full_label(tmp_path: Path) -> None:
    """Round trip: a claim minted by update_coverage imports under its
    own label — write→read semantics unchanged for authenticated rows."""
    s = _store(tmp_path)
    cl = json.loads(json.dumps(_authentic(tmp_path)))   # via-disk shape
    assert import_checked_by(s, cl) == 1
    assert s.who_checked_function("a.c", 30, 60) == {LABEL: "full"}


def test_forged_row_demotes_loudly_and_run_continues(
    tmp_path: Path, caplog: pytest.LogCaptureFixture,
) -> None:
    """Forge: a planted token-less review-grade row imports only at
    the machine hint tier, with a loud structured warning — and the
    import completes (never a refusal)."""
    s = _store(tmp_path)
    cl = _checklist(tmp_path)
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
    cl = _authentic(tmp_path)
    cl["files"][0]["items"][1]["line_end"] = 99   # stretch over the file
    with caplog.at_level(logging.WARNING):
        assert import_checked_by(s, cl) == 1
    assert s.who_checked_function("a.c", 30, 99) == {f"{LABEL}:machine": "full"}
    assert "1 tampered" in caplog.text


def test_relabelled_token_demotes(tmp_path: Path) -> None:
    """A token minted for one label must not authenticate a
    higher-authority label pasted next to it."""
    s = _store(tmp_path)
    cl = _authentic(tmp_path)
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
    cl = _checklist(tmp_path)
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
    cl = _checklist(tmp_path)
    cl["files"][0]["items"][0]["checked_by"] = ["understand:map"]
    with caplog.at_level(logging.WARNING):
        assert import_checked_by(s, cl) == 1
    assert s.who_checked_function("a.c", 0, 20) == {"understand:map": "full"}
    assert "machine tier" not in caplog.text


def test_mixed_checklist_tiers_per_claim(tmp_path: Path) -> None:
    """Verified and forged claims in one checklist tier independently."""
    s = _store(tmp_path)
    cl = _authentic(tmp_path)
    cl["files"][0]["items"][0]["checked_by"] = ["audit"]   # forged sibling
    assert import_checked_by(s, cl) == 2
    assert s.who_checked_function("a.c", 30, 60) == {LABEL: "full"}
    assert s.who_checked_function("a.c", 0, 20) == {"audit:machine": "full"}


# --- currency gate: verified claims still need CURRENT source ------------
# Both directions of the gate: test_verified_claim_imports_at_full_label
# above is the current→full-credit direction; the tests below pin
# stale/unverifiable→demoted.


def test_stale_replay_demotes_loudly(
    tmp_path: Path, caplog: pytest.LogCaptureFixture,
) -> None:
    """Wholesale replay: a genuinely minted historical file entry (old
    sha256 + old lines + genuine token) pasted into a current run's
    checklist VERIFIES — but the source has changed since, so the
    currency gate demotes it to the hint tier, counted as stale."""
    s = _store(tmp_path)
    cl = json.loads(json.dumps(_authentic(tmp_path)))
    # Source changes after the review was stamped; the replayed entry
    # still carries the review-time sha256 and a genuine token.
    (tmp_path / "target" / "a.c").write_text(_SOURCE + "int f3(void);\n")
    with caplog.at_level(logging.WARNING):
        assert import_checked_by(s, cl) == 1
    assert s.who_checked_function("a.c", 30, 60) == {f"{LABEL}:machine": "full"}
    assert "1 stale" in caplog.text
    assert "0 tampered" in caplog.text


def test_missing_source_demotes_stale(
    tmp_path: Path, caplog: pytest.LogCaptureFixture,
) -> None:
    """A verified claim whose source file is gone (deleted/renamed —
    or a replayed checklist naming a file this tree never had) cannot
    be confirmed current: fail-closed to the hint tier."""
    s = _store(tmp_path)
    cl = _authentic(tmp_path)
    (tmp_path / "target" / "a.c").unlink()
    with caplog.at_level(logging.WARNING):
        assert import_checked_by(s, cl) == 1
    assert s.who_checked_function("a.c", 30, 60) == {f"{LABEL}:machine": "full"}
    assert "1 stale" in caplog.text


def test_stripped_target_path_demotes_stale(tmp_path: Path) -> None:
    """``target_path`` rides in the same attacker-writable artifact as
    the claims — stripping it must not bypass the currency gate (the
    journal fold's keep-credit-on-missing-evidence carve-out would be
    a replay channel here)."""
    s = _store(tmp_path)
    cl = _authentic(tmp_path)
    del cl["target_path"]
    assert import_checked_by(s, cl) == 1
    assert s.who_checked_function("a.c", 30, 60) == {f"{LABEL}:machine": "full"}


def test_stripped_file_sha_is_tampered_not_current(tmp_path: Path) -> None:
    """The entry's ``sha256`` is inside the MAC payload: stripping it
    to dodge the currency comparison invalidates the token itself."""
    s = _store(tmp_path)
    cl = _authentic(tmp_path)
    del cl["files"][0]["sha256"]
    assert import_checked_by(s, cl) == 1
    assert s.who_checked_function("a.c", 30, 60) == {f"{LABEL}:machine": "full"}

"""update_coverage mints a MAC token per appended checked_by claim.

Hermetic: XDG_DATA_HOME points at a per-test tmp dir.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from core.inventory import checklist_mac
from core.inventory.coverage import update_coverage


@pytest.fixture(autouse=True)
def _isolated_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))


def _inventory() -> dict[str, Any]:
    return {
        "target_path": "/tgt",
        "files": [
            {
                "path": "src/a.c",
                "sha256": "aa" * 32,
                "items": [
                    {"name": "f1", "kind": "function",
                     "line_start": 1, "line_end": 5},
                    {"name": "f2", "kind": "function",
                     "line_start": 7, "line_end": 20},
                ],
            },
        ],
    }


def test_mark_mints_verifiable_token() -> None:
    inv = _inventory()
    update_coverage(
        inv, [{"file": "src/a.c", "function": "f1"}], "validate:stage-a")
    fe = inv["files"][0]
    f1, f2 = fe["items"]
    assert f1["checked_by"] == ["validate:stage-a"]
    assert checklist_mac.claim_provenance(fe, f1, "validate:stage-a") \
        == checklist_mac.CLAIM_VERIFIED
    # Unmarked sibling stays token-free.
    assert checklist_mac.TOKEN_MAP_KEY not in f2
    assert "checked_by" not in f2


def test_remark_same_label_no_duplicate_and_still_verified() -> None:
    inv = _inventory()
    for _ in range(2):
        update_coverage(
            inv, [{"file": "src/a.c", "function": "f1"}], "validate:stage-a")
    fe = inv["files"][0]
    f1 = fe["items"][0]
    assert f1["checked_by"] == ["validate:stage-a"]
    assert list(f1[checklist_mac.TOKEN_MAP_KEY]) == ["validate:stage-a"]
    assert checklist_mac.claim_provenance(fe, f1, "validate:stage-a") \
        == checklist_mac.CLAIM_VERIFIED


def test_second_label_gets_its_own_token() -> None:
    inv = _inventory()
    update_coverage(
        inv, [{"file": "src/a.c", "function": "f1"}], "validate:stage-a")
    update_coverage(
        inv, [{"file": "src/a.c", "function": "f1"}], "agentic")
    fe = inv["files"][0]
    f1 = fe["items"][0]
    assert f1["checked_by"] == ["validate:stage-a", "agentic"]
    for label in f1["checked_by"]:
        assert checklist_mac.claim_provenance(fe, f1, label) \
            == checklist_mac.CLAIM_VERIFIED


def test_unusable_key_persists_unstamped(tmp_path: Path) -> None:
    """No usable key = persist unstamped, never a write failure — the
    mark itself still lands (unstamped tier at import time)."""
    key = tmp_path / "xdg" / "raptor" / "checklist-mac.key"
    key.parent.mkdir(parents=True)
    key.write_bytes(b"k" * 32)
    key.chmod(0o644)  # group/other-readable: refused
    inv = _inventory()
    update_coverage(
        inv, [{"file": "src/a.c", "function": "f1"}], "validate:stage-a")
    f1 = inv["files"][0]["items"][0]
    assert f1["checked_by"] == ["validate:stage-a"]
    assert checklist_mac.TOKEN_MAP_KEY not in f1


def test_json_round_trip_keeps_claim_verified() -> None:
    """write -> read semantics: a checklist serialised and reloaded
    verifies identically (canonical claim uses JSON-stable scalars)."""
    inv = _inventory()
    update_coverage(
        inv, [{"file": "src/a.c", "function": "f2"}], "validate:stage-b")
    reloaded = json.loads(json.dumps(inv))
    fe = reloaded["files"][0]
    f2 = fe["items"][1]
    assert checklist_mac.claim_provenance(fe, f2, "validate:stage-b") \
        == checklist_mac.CLAIM_VERIFIED


def test_incremental_update_hashes_touched_claims_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Scale contract: marking k functions performs exactly k claim
    hashes over ~claim-sized payloads — the MAC layer never re-hashes
    the (arbitrarily large) checklist on a touch."""
    files = []
    pad = "p" * 512  # bulk per item so the artifact dwarfs the claims
    for i in range(400):
        files.append({
            "path": f"src/dir{i % 20}/f{i}.c",
            "sha256": f"{i:02x}" * 32,
            "items": [
                {"name": f"fn_{i}_{j}", "kind": "function",
                 "line_start": j * 10 + 1, "line_end": j * 10 + 9,
                 "signature": pad}
                for j in range(5)
            ],
        })
    inv = {"target_path": "/tgt", "files": files}
    serialised_bytes = len(json.dumps(inv).encode("utf-8"))
    assert serialised_bytes > 1_000_000  # the artifact is genuinely big

    hashed: list[int] = []
    real = checklist_mac.claim_sha256

    def counting(claim: dict) -> str:
        from core.json.utils import dumps_canonical
        hashed.append(len(dumps_canonical(claim).encode("utf-8")))
        return real(claim)

    monkeypatch.setattr(checklist_mac, "claim_sha256", counting)
    update_coverage(
        inv,
        [{"file": "src/dir0/f0.c", "function": "fn_0_1"},
         {"file": "src/dir1/f21.c", "function": "fn_21_3"},
         {"file": "src/dir2/f42.c", "function": "fn_42_0"}],
        "validate:stage-a",
    )
    assert len(hashed) == 3          # one claim hash per touched row
    assert sum(hashed) < 4096        # claim-sized payloads, not the file
    assert sum(hashed) * 100 < serialised_bytes

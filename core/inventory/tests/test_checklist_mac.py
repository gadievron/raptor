"""Tests for core/inventory/checklist_mac.py — claim mint/verify/tier
semantics and the key-file contract.

Hermetic: every test points XDG_DATA_HOME at a per-test tmp dir so no
real per-user key is read or created.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from core.inventory import checklist_mac

FE = {"path": "src/auth.c", "sha256": "ab" * 32, "sloc": 100}
ITEM = {
    "name": "check_pw",
    "kind": "function",
    "line_start": 10,
    "line_end": 42,
    "checked_by": ["validate:stage-a"],
}
LABEL = "validate:stage-a"


@pytest.fixture(autouse=True)
def _isolated_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    monkeypatch.setattr(checklist_mac, "_warned_paths", set())


def test_mint_verify_round_trip() -> None:
    token = checklist_mac.mint_checked_claim(FE, ITEM, LABEL)
    assert token is not None
    assert checklist_mac.verify_checked_claim(FE, ITEM, LABEL, token)


@pytest.mark.parametrize("field,value", [
    ("name", "other_fn"),
    ("line_start", 11),
    ("line_end", 999),
    ("kind", "macro"),
])
def test_edited_item_field_fails_verification(field: str, value) -> None:
    token = checklist_mac.mint_checked_claim(FE, ITEM, LABEL)
    tampered = dict(ITEM)
    tampered[field] = value
    assert not checklist_mac.verify_checked_claim(FE, tampered, LABEL, token)


def test_moved_file_content_fails_verification() -> None:
    """The claim binds the file entry's content sha256 — a token
    replayed against a since-changed file must demote (stale review
    credit does not survive source change)."""
    token = checklist_mac.mint_checked_claim(FE, ITEM, LABEL)
    changed = dict(FE)
    changed["sha256"] = "cd" * 32
    assert not checklist_mac.verify_checked_claim(changed, ITEM, LABEL, token)


def test_label_is_bound() -> None:
    """A token minted for one label never authenticates another —
    the label is what grades the claim's authority."""
    token = checklist_mac.mint_checked_claim(FE, ITEM, LABEL)
    assert not checklist_mac.verify_checked_claim(FE, ITEM, "audit", token)


def test_class_disambiguation_bound() -> None:
    """Same-named methods of different classes are distinct claims."""
    a = dict(ITEM, metadata={"class_name": "A"})
    b = dict(ITEM, metadata={"class_name": "B"})
    token = checklist_mac.mint_checked_claim(FE, a, LABEL)
    assert checklist_mac.verify_checked_claim(FE, a, LABEL, token)
    assert not checklist_mac.verify_checked_claim(FE, b, LABEL, token)


def test_unrelated_fields_do_not_break_tokens() -> None:
    """Enriching non-claim fields (signature, sloc, checked_by list
    order) must not invalidate a stamped claim — RMW writers and
    merges touch those freely."""
    token = checklist_mac.mint_checked_claim(FE, ITEM, LABEL)
    enriched_fe = dict(FE, sloc=999, language="c")
    enriched_item = dict(
        ITEM, signature="int check_pw(char*)",
        checked_by=["understand:map", LABEL],
    )
    assert checklist_mac.verify_checked_claim(
        enriched_fe, enriched_item, LABEL, token)


def test_claim_provenance_tri_state() -> None:
    item = dict(ITEM)
    assert checklist_mac.claim_provenance(FE, item, LABEL) \
        == checklist_mac.CLAIM_UNSTAMPED
    token = checklist_mac.mint_checked_claim(FE, item, LABEL)
    item[checklist_mac.TOKEN_MAP_KEY] = {LABEL: token}
    assert checklist_mac.claim_provenance(FE, item, LABEL) \
        == checklist_mac.CLAIM_VERIFIED
    item[checklist_mac.TOKEN_MAP_KEY] = {LABEL: "0" * 64}
    assert checklist_mac.claim_provenance(FE, item, LABEL) \
        == checklist_mac.CLAIM_TAMPERED


def test_claim_provenance_tolerates_hostile_token_map() -> None:
    for hostile in (["x"], "x", 7, {LABEL: 7}, {LABEL: None}):
        item = dict(ITEM)
        item[checklist_mac.TOKEN_MAP_KEY] = hostile
        assert checklist_mac.claim_provenance(FE, item, LABEL) \
            == checklist_mac.CLAIM_UNSTAMPED


def test_verify_never_raises_on_garbage() -> None:
    assert not checklist_mac.verify_checked_claim(FE, ITEM, LABEL, None)
    assert not checklist_mac.verify_checked_claim(FE, ITEM, LABEL, "")
    assert not checklist_mac.verify_checked_claim(FE, ITEM, LABEL, "zz")


# ---------------------------------------------------------------------------
# Key-file contract
# ---------------------------------------------------------------------------


def test_own_key_file_created_not_journal_key(tmp_path: Path) -> None:
    """Per-purpose key: minting creates checklist-mac.key and never
    touches (or reuses) the journal purpose's key file."""
    assert checklist_mac.mint_checked_claim(FE, ITEM, LABEL) is not None
    raptor_dir = tmp_path / "xdg" / "raptor"
    assert (raptor_dir / "checklist-mac.key").is_file()
    assert not (raptor_dir / "journal-mac.key").exists()


def test_created_key_is_exactly_key_len_bytes(tmp_path: Path) -> None:
    """Key length, lower direction of the _KEY_LEN pin: the lazily
    created key is exactly 32 bytes (HMAC-SHA256 security level)."""
    checklist_mac.mint_checked_claim(FE, ITEM, LABEL)
    key = tmp_path / "xdg" / "raptor" / "checklist-mac.key"
    assert key.stat().st_size == 32


@pytest.mark.parametrize("length", [16, 64])
def test_wrong_length_key_refuses(tmp_path: Path, length: int) -> None:
    """Key length, both directions of the _KEY_LEN pin: a stale
    shorter OR longer key file refuses (mint returns None — persist
    unstamped) instead of minting under a weak or nonstandard key."""
    key = tmp_path / "xdg" / "raptor" / "checklist-mac.key"
    key.parent.mkdir(parents=True)
    key.write_bytes(b"k" * length)
    key.chmod(0o600)
    # Age it past the freshness window so the wrong length reads as a
    # stale torn key (immediate refusal), not a concurrent creator.
    os.utime(key, (1, 1))
    assert checklist_mac.mint_checked_claim(FE, ITEM, LABEL) is None
    assert not checklist_mac.key_usable()


def test_exposed_key_refuses_and_verification_demotes(
    tmp_path: Path,
) -> None:
    """A group/other-readable key is never used: mint returns None,
    and verification of a previously minted token fails — the
    caller's demote path, never an exception."""
    token = checklist_mac.mint_checked_claim(FE, ITEM, LABEL)
    key = tmp_path / "xdg" / "raptor" / "checklist-mac.key"
    key.chmod(0o644)
    assert checklist_mac.mint_checked_claim(FE, ITEM, LABEL) is None
    assert not checklist_mac.verify_checked_claim(FE, ITEM, LABEL, token)


def test_deleting_key_demotes_to_unstamped_then_rekeys(
    tmp_path: Path,
) -> None:
    """Reset semantics: deleting the key invalidates old tokens
    (tampered/demote on verify) and new mints re-key lazily."""
    old = checklist_mac.mint_checked_claim(FE, ITEM, LABEL)
    (tmp_path / "xdg" / "raptor" / "checklist-mac.key").unlink()
    fresh = checklist_mac.mint_checked_claim(FE, ITEM, LABEL)
    assert fresh is not None
    assert fresh != old
    assert not checklist_mac.verify_checked_claim(FE, ITEM, LABEL, old)
    assert checklist_mac.verify_checked_claim(FE, ITEM, LABEL, fresh)

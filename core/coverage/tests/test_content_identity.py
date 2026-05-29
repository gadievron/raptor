"""Tests for the content-equivalence id (Phase 3, step e2): git-X ≡ zip-X
derived from the inventory's {relpath -> sha256} set."""

from __future__ import annotations

from core.coverage.store import CoverageStore, content_identity


def _checklist(files):
    """files: list of (path, sha256)."""
    return {"files": [{"path": p, "sha256": s, "lines": 10} for p, s in files]}


def test_same_content_same_id_regardless_of_order():
    a = _checklist([("a.c", "h1"), ("b.c", "h2")])
    b = _checklist([("b.c", "h2"), ("a.c", "h1")])      # different file order
    assert content_identity(a) == content_identity(b)
    assert content_identity(a).startswith("content:")


def test_git_checkout_and_zip_of_same_source_match():
    # The acquisition differs (git vs zip) but the analyzed file set + content
    # SHAs are identical -> same content id. This is the git-X ≡ zip-X property.
    git_inv = _checklist([("src/main.c", "aaa"), ("src/util.c", "bbb")])
    zip_inv = _checklist([("src/main.c", "aaa"), ("src/util.c", "bbb")])
    assert content_identity(git_inv) == content_identity(zip_inv)


def test_different_content_different_id():
    base = _checklist([("a.c", "h1"), ("b.c", "h2")])
    changed = _checklist([("a.c", "h1"), ("b.c", "DIFFERENT")])   # b.c edited
    added = _checklist([("a.c", "h1"), ("b.c", "h2"), ("c.c", "h3")])  # extra file
    assert content_identity(base) != content_identity(changed)
    assert content_identity(base) != content_identity(added)


def test_empty_inventory_is_none():
    assert content_identity({"files": []}) is None
    assert content_identity({}) is None


def test_files_without_sha_are_ignored():
    # Only analyzed files with a content SHA contribute.
    a = _checklist([("a.c", "h1")])
    b = {"files": [{"path": "a.c", "sha256": "h1"}, {"path": "gen.c"}]}  # no sha
    assert content_identity(a) == content_identity(b)


def test_store_records_and_persists_content_id(tmp_path):
    s = CoverageStore(tmp_path / "coverage.json")
    cid = s.set_content_id(_checklist([("a.c", "h1")]))
    assert cid and cid.startswith("content:")
    s.save()
    assert CoverageStore(tmp_path / "coverage.json").content_id == cid

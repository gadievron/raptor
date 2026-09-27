"""Frame-authentication tests for the checklist substrate.

Two directions, per the frame contract
(``core/inventory/checklist_frame_mac.py``):

* REFUSE — tampered frames (shard swapped with a correctly
  recomputed sha256, index rows added/removed/reordered, in-place
  single-file edits, malformed tokens) read as empty / truncate the
  walk / refuse the read-modify-write. Attribution alone is not the
  bar here: the checklist steers WHICH functions get reviewed, and a
  refused frame costs one mechanical rebuild.
* ACCEPT — authenticated round-trips through the writer chokepoint,
  legacy unstamped frames (demoted with the era-fenced warning),
  relocated frames (valid MAC minted for a different slot — demoted,
  never refused), and stamped frames whose key later becomes
  unusable (environmental breakage demotes, never reads as tamper).
"""

import hashlib
import json
import os
import shutil
from pathlib import Path
from typing import Any
from unittest import mock

import pytest

import core.inventory as inv
from core.inventory import (
    iter_checklist_items,
    read_checklist,
    read_checklist_meta,
    save_checklist,
    update_checklist,
)
from core.inventory import checklist_frame_mac as cm


@pytest.fixture(autouse=True)
def _hermetic(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Per-test key isolation + fresh warn-once registries."""
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    cm._warned_unstamped.clear()
    cm._warned_relocated.clear()
    cm._warned_key_paths.clear()
    cm._warned_absent_key.clear()


def _doc(n: int) -> dict[str, Any]:
    return {
        "target_path": "/target",
        "files": [
            {
                "path": f"src/f{i}.c",
                "sloc": 10,
                "items": [{
                    "name": f"fn{i}", "kind": "function",
                    "line_start": 1, "line_end": 5,
                }],
            }
            for i in range(n)
        ],
    }


def _force_sharded(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(inv, "_MAX_CHECKLIST_BYTES", 256)
    monkeypatch.setattr(inv, "_CHECKLIST_SHARD_TARGET_BYTES", 400)


def _out(tmp_path: Path, name: str = "run") -> Path:
    out = tmp_path / name
    out.mkdir()
    return out


def _shard_content(files: list[dict[str, Any]]) -> bytes:
    return (json.dumps({"files": files}, separators=(",", ":"))
            + "\n").encode("utf-8")


def _row(name: str, files: list[dict[str, Any]],
         content: bytes) -> dict[str, Any]:
    return {
        "path": name,
        "file_count": len(files),
        "item_count": sum(
            len(f.get("items", [])) for f in files if isinstance(f, dict)),
        "sloc": sum(
            f.get("sloc", 0) for f in files if isinstance(f, dict)),
        "bytes": len(content),
        "sha256": hashlib.sha256(content).hexdigest(),
    }


def _write_unstamped_sharded(out: Path, doc: dict[str, Any]) -> Path:
    """Hand-build a token-less sharded layout (a pre-MAC artifact)."""
    shard_dir = out / "checklist"
    shard_dir.mkdir(parents=True)
    files = doc["files"]
    content = _shard_content(files)
    (shard_dir / "shard-part-00.json").write_bytes(content)
    rows = [_row("shard-part-00.json", files, content)]
    index = {
        "schema_version": 1,
        "meta": {k: v for k, v in doc.items() if k != "files"},
        "totals": {
            "files": rows[0]["file_count"],
            "items": rows[0]["item_count"],
            "sloc": rows[0]["sloc"],
            "bytes": rows[0]["bytes"],
        },
        "shards": rows,
    }
    (shard_dir / "index.json").write_text(json.dumps(index))
    return shard_dir / "index.json"


def _rewrite_first_shard(out: Path,
                         replacement: list[dict[str, Any]]) -> None:
    """Swap the first shard's body, recomputing sha256/bytes/counts
    and totals SELF-CONSISTENTLY — everything an attacker without the
    key can do."""
    shard_dir = out / "checklist"
    index_path = shard_dir / "index.json"
    index = json.loads(index_path.read_text())
    row = index["shards"][0]
    content = _shard_content(replacement)
    (shard_dir / row["path"]).write_bytes(content)
    index["shards"][0] = _row(row["path"], replacement, content)
    index["totals"] = {
        "files": sum(r["file_count"] for r in index["shards"]),
        "items": sum(r["item_count"] for r in index["shards"]),
        "sloc": sum(r["sloc"] for r in index["shards"]),
        "bytes": sum(r["bytes"] for r in index["shards"]),
    }
    index_path.write_text(json.dumps(index))


EVIL = [{
    "path": "evil.c", "sloc": 1,
    "items": [{"name": "backdoor", "kind": "function",
               "line_start": 1, "line_end": 2}],
}]


# ── Refuse direction ─────────────────────────────────────────────────

def test_shard_swap_with_recomputed_sha256_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """HEADLINE: a shard body replaced wholesale with a correctly
    recomputed per-shard sha256 (no key) must be refused by every
    accessor — per-shard hashes are source currency, the frame MAC is
    the authentication."""
    _force_sharded(monkeypatch)
    out = _out(tmp_path)
    save_checklist(out, _doc(12))
    assert (out / "checklist" / "index.json").is_file()
    baseline = read_checklist(out)
    assert len(baseline.get("files", [])) == 12  # sanity: frame reads

    _rewrite_first_shard(out, EVIL)

    assert read_checklist(out) == {}
    assert read_checklist_meta(out) == {}
    walked = [item.get("name")
              for _, _, item in iter_checklist_items(str(out))]
    assert walked == []
    with pytest.raises(ValueError, match="integrity"):
        update_checklist(out, lambda d: d)


def test_index_row_removal_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _force_sharded(monkeypatch)
    out = _out(tmp_path)
    save_checklist(out, _doc(12))
    index_path = out / "checklist" / "index.json"
    index = json.loads(index_path.read_text())
    assert len(index["shards"]) >= 2
    del index["shards"][0]
    index_path.write_text(json.dumps(index))
    assert read_checklist(out) == {}
    assert read_checklist_meta(out) == {}


def test_index_row_reorder_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _force_sharded(monkeypatch)
    out = _out(tmp_path)
    save_checklist(out, _doc(12))
    index_path = out / "checklist" / "index.json"
    index = json.loads(index_path.read_text())
    assert len(index["shards"]) >= 2
    index["shards"] = list(reversed(index["shards"]))
    index_path.write_text(json.dumps(index))
    assert read_checklist(out) == {}


def test_index_row_addition_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _force_sharded(monkeypatch)
    out = _out(tmp_path)
    save_checklist(out, _doc(12))
    shard_dir = out / "checklist"
    index_path = shard_dir / "index.json"
    pristine = index_path.read_text()

    index = json.loads(pristine)
    content = _shard_content(EVIL)
    (shard_dir / "shard-extra-999.json").write_bytes(content)
    index["shards"].append(_row("shard-extra-999.json", EVIL, content))
    index_path.write_text(json.dumps(index))
    assert read_checklist(out) == {}

    # The pristine manifest still verifies: refusal was the MAC, not
    # collateral state.
    index_path.write_text(pristine)
    (shard_dir / "shard-extra-999.json").unlink()
    assert len(read_checklist(out)["files"]) == 12


def test_single_file_in_place_tamper_refused(
    tmp_path: Path, caplog: pytest.LogCaptureFixture,
) -> None:
    out = _out(tmp_path)
    save_checklist(out, _doc(3))
    path = out / "checklist.json"
    on_disk = json.loads(path.read_text())
    on_disk["files"].extend(EVIL)
    path.write_text(json.dumps(on_disk))

    with caplog.at_level("WARNING", logger="core.inventory"):
        assert read_checklist(out) == {}
    assert "FAILED frame authentication" in caplog.text
    assert read_checklist_meta(out) == {}
    assert list(iter_checklist_items(str(out))) == []
    with pytest.raises(ValueError, match="frame authentication"):
        update_checklist(out, lambda d: d)


def test_malformed_token_refused(tmp_path: Path) -> None:
    out = _out(tmp_path)
    doc = _doc(2)
    doc[cm.FRAME_TOKEN_KEY] = "stamped-honest"
    (out / "checklist.json").write_text(json.dumps(doc))
    assert read_checklist(out) == {}
    doc[cm.FRAME_TOKEN_KEY] = {"slot": "/somewhere"}  # no mac
    (out / "checklist.json").write_text(json.dumps(doc))
    assert read_checklist(out) == {}


# ── Accept direction ─────────────────────────────────────────────────

def test_single_file_round_trip_authenticated(tmp_path: Path) -> None:
    out = _out(tmp_path)
    doc = _doc(3)
    save_checklist(out, doc)
    on_disk = json.loads((out / "checklist.json").read_text())
    token = on_disk.get(cm.FRAME_TOKEN_KEY)
    assert isinstance(token, dict)
    assert set(token) == {"slot", "mac"}
    assert token["slot"] == str(out.resolve())
    # The caller's dict is never left carrying the token.
    assert cm.FRAME_TOKEN_KEY not in doc

    with mock.patch.object(cm, "logger") as log:
        data = read_checklist(out)
    assert not log.warning.called
    assert not log.info.called
    assert cm.FRAME_TOKEN_KEY not in data
    assert data == doc  # save stamped provenance in place; token popped

    meta = read_checklist_meta(out)
    assert meta["target_path"] == "/target"
    assert cm.FRAME_TOKEN_KEY not in meta
    names = {item["name"] for _, _, item in iter_checklist_items(str(out))}
    assert names == {"fn0", "fn1", "fn2"}


def test_sharded_round_trip_authenticated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _force_sharded(monkeypatch)
    out = _out(tmp_path)
    doc = _doc(12)
    save_checklist(out, doc)
    index = json.loads((out / "checklist" / "index.json").read_text())
    assert set(index[cm.FRAME_TOKEN_KEY]) == {"slot", "mac"}
    assert index[cm.FRAME_TOKEN_KEY]["slot"] == str(out.resolve())
    assert cm.FRAME_TOKEN_KEY not in index["meta"]

    with mock.patch.object(cm, "logger") as log:
        data = read_checklist(out)
    assert not log.warning.called
    assert cm.FRAME_TOKEN_KEY not in data
    assert sorted(f["path"] for f in data["files"]) == sorted(
        f["path"] for f in doc["files"])
    assert read_checklist_meta(out)["target_path"] == "/target"


def test_update_checklist_restamps(tmp_path: Path) -> None:
    out = _out(tmp_path)
    save_checklist(out, _doc(2))

    def add(current: dict[str, Any]) -> dict[str, Any]:
        assert cm.FRAME_TOKEN_KEY not in current  # transforms never see it
        current["files"].extend(EVIL)
        return current

    update_checklist(out, add)
    with mock.patch.object(cm, "logger") as log:
        data = read_checklist(out)
    assert not log.warning.called
    assert len(data["files"]) == 3


def test_legacy_unstamped_sharded_accepted_with_warning(
    tmp_path: Path,
) -> None:
    out = _out(tmp_path)
    _write_unstamped_sharded(out, _doc(3))
    with mock.patch.object(cm, "logger") as log:
        data = read_checklist(out)
    assert len(data["files"]) == 3
    assert log.warning.called  # in-era mtime: the loud demotion
    assert not log.info.called
    # Warn-once per artifact path.
    with mock.patch.object(cm, "logger") as log2:
        assert len(read_checklist(out)["files"]) == 3
    assert not log2.warning.called


def test_pre_era_unstamped_logs_quietly(tmp_path: Path) -> None:
    out = _out(tmp_path)
    index_path = _write_unstamped_sharded(out, _doc(3))
    old = cm.FRAME_MAC_ERA_START - 86400
    os.utime(index_path, (old, old))
    with mock.patch.object(cm, "logger") as log:
        data = read_checklist(out)
    assert len(data["files"]) == 3
    assert log.info.called
    assert not log.warning.called


def test_legacy_unstamped_single_file_accepted(tmp_path: Path) -> None:
    out = _out(tmp_path)
    (out / "checklist.json").write_text(json.dumps(_doc(2)))
    with mock.patch.object(cm, "logger") as log:
        data = read_checklist(out)
    assert len(data["files"]) == 2
    assert log.warning.called


def test_stripped_token_lands_legacy(tmp_path: Path) -> None:
    out = _out(tmp_path)
    save_checklist(out, _doc(3))
    path = out / "checklist.json"
    on_disk = json.loads(path.read_text())
    del on_disk[cm.FRAME_TOKEN_KEY]
    path.write_text(json.dumps(on_disk))
    with mock.patch.object(cm, "logger") as log:
        data = read_checklist(out)
    assert len(data["files"]) == 3  # accepted at legacy tier
    assert log.warning.called  # in-era: stripped tokens stay visible


def test_relocated_single_file_demotes_with_warning(
    tmp_path: Path,
) -> None:
    a = _out(tmp_path, "a")
    save_checklist(a, _doc(2))
    b = _out(tmp_path, "b")
    shutil.copy2(a / "checklist.json", b / "checklist.json")
    with mock.patch.object(cm, "logger") as log:
        data = read_checklist(b)
    assert len(data["files"]) == 2  # demoted, never refused
    assert log.warning.called
    assert "different slot" in log.warning.call_args[0][0]
    # The original still reads verified.
    with mock.patch.object(cm, "logger") as log2:
        assert len(read_checklist(a)["files"]) == 2
    assert not log2.warning.called


def test_relocated_sharded_demotes_with_warning(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _force_sharded(monkeypatch)
    a = _out(tmp_path, "a")
    save_checklist(a, _doc(12))
    b = _out(tmp_path, "b")
    shutil.copytree(a / "checklist", b / "checklist")
    with mock.patch.object(cm, "logger") as log:
        data = read_checklist(b)
    assert len(data["files"]) == 12
    assert log.warning.called
    assert "different slot" in log.warning.call_args[0][0]


def test_unusable_key_persists_unstamped(tmp_path: Path) -> None:
    key = cm._key_path()
    key.parent.mkdir(parents=True)
    key.write_bytes(b"k" * 32)
    key.chmod(0o644)  # group/other-readable: refused, never replaced
    out = _out(tmp_path)
    save_checklist(out, _doc(2))
    on_disk = json.loads((out / "checklist.json").read_text())
    assert cm.FRAME_TOKEN_KEY not in on_disk  # persisted unstamped
    data = read_checklist(out)
    assert len(data["files"]) == 2
    assert key.read_bytes() == b"k" * 32  # suspect key never replaced


def test_key_breakage_demotes_stamped_frame(tmp_path: Path) -> None:
    """A stamped frame whose key later becomes unusable reads at the
    legacy tier — environmental key breakage is not frame tamper."""
    out = _out(tmp_path)
    save_checklist(out, _doc(2))
    assert cm.FRAME_TOKEN_KEY in json.loads(
        (out / "checklist.json").read_text())
    cm._key_path().chmod(0o644)
    with mock.patch.object(cm, "logger") as log:
        data = read_checklist(out)
    assert len(data["files"]) == 2  # demoted, not refused
    assert log.warning.called


def test_deleted_key_demotes_to_legacy_tier(
    tmp_path: Path, caplog: pytest.LogCaptureFixture,
) -> None:
    """Deleting the key file is documented reset semantics: stamped
    frames demote to the unstamped legacy tier (served, warned) —
    verify-side key access is read-only, so verification can never
    mint a fresh key under which every previously stamped frame
    reads tampered."""
    out = _out(tmp_path)
    save_checklist(out, _doc(2))
    cm._key_path().unlink()

    with caplog.at_level("INFO"):
        data = read_checklist(out)
    assert len(data["files"]) == 2  # served at legacy tier, never refused
    assert "deleted or rotated" in caplog.text
    # An absent key is not evidence of frame tamper: the tamper
    # refusal (and its wording) must not fire here.
    assert "FAILED frame authentication" not in caplog.text
    assert not cm._key_path().exists()  # the verify minted nothing

    # RMW succeeds, re-keys lazily on the WRITE side, and re-stamps.
    update_checklist(out, lambda d: d)
    assert cm._key_path().is_file()
    on_disk = json.loads((out / "checklist.json").read_text())
    assert set(on_disk[cm.FRAME_TOKEN_KEY]) == {"slot", "mac"}
    with mock.patch.object(cm, "logger") as log:
        assert len(read_checklist(out)["files"]) == 2
    assert not log.warning.called  # verified again under the new key


def test_wrong_key_content_still_tampered(tmp_path: Path) -> None:
    """A key file PRESENT with different bytes (stale restore, a
    foreign install's key copied in) is a usable key whose MAC
    rejects the token: TAMPERED, refused — only the ABSENT-key case
    demotes to the legacy tier."""
    out = _out(tmp_path)
    save_checklist(out, _doc(2))
    key = cm._key_path()
    key.write_bytes(bytes(32))  # right length, wrong key bytes
    assert read_checklist(out) == {}
    with pytest.raises(ValueError, match="frame authentication"):
        update_checklist(out, lambda d: d)


def test_rmw_restamps_legacy_frame(tmp_path: Path) -> None:
    """A legacy unstamped frame is re-stamped by the next legitimate
    read-modify-write (the documented laundering residual for
    STRIPPED tokens — tampered frames never reach this: the RMW
    refuses them)."""
    out = _out(tmp_path)
    (out / "checklist.json").write_text(json.dumps(_doc(2)))
    update_checklist(out, lambda d: d)
    on_disk = json.loads((out / "checklist.json").read_text())
    assert set(on_disk[cm.FRAME_TOKEN_KEY]) == {"slot", "mac"}
    with mock.patch.object(cm, "logger") as log:
        assert len(read_checklist(out)["files"]) == 2
    assert not log.warning.called


def test_single_to_sharded_transition_stays_authenticated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(inv, "_MAX_CHECKLIST_BYTES", 800)
    monkeypatch.setattr(inv, "_CHECKLIST_SHARD_TARGET_BYTES", 400)
    out = _out(tmp_path)
    save_checklist(out, _doc(1))
    assert (out / "checklist.json").is_file()
    update_checklist(out, lambda d: _doc(12))
    index = json.loads((out / "checklist" / "index.json").read_text())
    assert cm.FRAME_TOKEN_KEY not in index["meta"]
    assert set(index[cm.FRAME_TOKEN_KEY]) == {"slot", "mac"}
    with mock.patch.object(cm, "logger") as log:
        assert len(read_checklist(out)["files"]) == 12
    assert not log.warning.called


def test_stale_token_never_rides_into_sharded_meta(tmp_path: Path) -> None:
    """Belt-and-braces on the sharded writer: a document arriving
    with a (stale/planted) token must not embed it in the
    MAC-covered index meta."""
    out = _out(tmp_path)
    doc = _doc(2)
    doc[cm.FRAME_TOKEN_KEY] = {"slot": "/elsewhere", "mac": "00" * 32}
    inv._write_sharded_checklist(out / "checklist.json", doc)
    index = json.loads((out / "checklist" / "index.json").read_text())
    assert cm.FRAME_TOKEN_KEY not in index["meta"]
    assert index[cm.FRAME_TOKEN_KEY]["slot"] == str(out.resolve())


# ── Module-level tier semantics ──────────────────────────────────────

def test_frame_provenance_tiers(tmp_path: Path) -> None:
    doc: dict[str, Any] = {"a": 1, "files": []}
    slot = str(tmp_path.resolve())
    token = cm.mint_frame(doc, slot, cm.FORM_SINGLE)
    assert token is not None
    stamped = {**doc, cm.FRAME_TOKEN_KEY: token}
    assert cm.frame_provenance(
        stamped, slot, cm.FORM_SINGLE) == cm.FRAME_VERIFIED
    # Same install, different slot: relocated (distinguishable from
    # content tamper).
    other = str((tmp_path / "other").resolve())
    assert cm.frame_provenance(
        stamped, other, cm.FORM_SINGLE) == cm.FRAME_RELOCATED
    # Form confusion is tamper: a single-file token cannot be
    # replayed as a sharded index at the same slot.
    assert cm.frame_provenance(
        stamped, slot, cm.FORM_SHARDED) == cm.FRAME_TAMPERED
    mutated = {**stamped, "a": 2}
    assert cm.frame_provenance(
        mutated, slot, cm.FORM_SINGLE) == cm.FRAME_TAMPERED
    assert cm.frame_provenance(
        doc, slot, cm.FORM_SINGLE) == cm.FRAME_UNSTAMPED

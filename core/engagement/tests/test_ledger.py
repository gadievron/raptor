"""Tests for the engagement artifact ledger (``core.engagement.ledger``).

Fixture install trees are crafted in-test: ELF binaries via the
composable builders in ``core.binary.tests.test_elf_facts`` (never a
host compiler), archives via ``zipfile``/``tarfile``, corpora as plain
data files. The sandboxed build-id probe is stubbed autouse for
hermeticity (the same discipline as the ELF facts tests) — identity
falls to the sha256 leg, which is exactly the fallback contract.
"""

from __future__ import annotations

import io
import json
import os
import struct
import tarfile
import zipfile
from pathlib import Path

import pytest

from core.binary import elf as elf_mod
from core.binary.identity import KIND_SHA256, ContentIdentity
from core.binary.tests.test_elf_facts import (
    _build_elf64_facts,
    _dyn,
    _standard_fixture,
    _strtab,
    _DT_NULL,
    _DT_SONAME,
    _GLOBAL_FUNC,
    _PT_DYNAMIC,
    _SYM,
)
from core.engagement import ledger as ledger_mod
from core.engagement.ledger import (
    CLASS_ARCHIVE,
    CLASS_ARCHIVE_REMAINDER,
    CLASS_CORPUS_FAMILY,
    CLASS_ELF_EBPF,
    FORMAT_TIER_BY_CLASS,
    STATUS_STATES,
    TARGET_DERIVED_FIELD_UNIVERSE,
    LedgerCaps,
    build_ledger,
    checklist_slot_path,
    list_artifact_checklists,
    load_ledger,
    read_artifact_checklist,
    render_artifact_lines,
    render_status_lines,
    set_artifact_status,
    write_artifact_checklist,
)


@pytest.fixture(autouse=True)
def _stub_build_id(monkeypatch):
    """No sandboxed readelf in unit tests (CI runners may refuse) —
    ELF identity degrades to the content hash, per the front door."""
    monkeypatch.setattr(elf_mod, "_read_build_id",
                        lambda p: (None, None))


# ── fixture builders ─────────────────────────────────────────────────

def _provider_lib() -> bytes:
    """ELF64 lib: soname ``libfoo.so.1``, one export, two imports
    (``recv`` → network channel, ``memcpy`` → sink import)."""
    dynstr, off = _strtab([
        b"libfoo.so.1", b"handler", b"recv", b"memcpy",
    ])
    dynsym = (
        _SYM.pack(0, 0, 0, 0, 0, 0)
        + _SYM.pack(off[b"handler"], _GLOBAL_FUNC, 0, 1, 0, 0)   # export
        + _SYM.pack(off[b"recv"], _GLOBAL_FUNC, 0, 0, 0, 0)      # import
        + _SYM.pack(off[b"memcpy"], _GLOBAL_FUNC, 0, 0, 0, 0)    # import
    )
    dynamic = _dyn([
        (_DT_SONAME, off[b"libfoo.so.1"]),
        (_DT_NULL, 0),
    ])
    return _build_elf64_facts(
        [
            (b".dynstr", 3, dynstr, 0, 0),
            (b".dynsym", 11, dynsym, 1, 24),
            (b".dynamic", 6, dynamic, 1, 16),
        ],
        phdr_types=(_PT_DYNAMIC,),
    )


def _kmod_with_ioctl() -> bytes:
    """ELF with an exported ``unlocked_ioctl`` — written as ``.ko`` it
    classifies ``elf-kmod`` and matches the linux driver catalog."""
    dynstr, off = _strtab([b"unlocked_ioctl"])
    dynsym = (
        _SYM.pack(0, 0, 0, 0, 0, 0)
        + _SYM.pack(off[b"unlocked_ioctl"], _GLOBAL_FUNC, 0, 1, 0, 0)
    )
    return _build_elf64_facts(
        [
            (b".dynstr", 3, dynstr, 0, 0),
            (b".dynsym", 11, dynsym, 1, 24),
        ],
        phdr_types=(_PT_DYNAMIC,),
    )


def _ebpf_header() -> bytes:
    """Minimal ELF64 header with e_machine = EM_BPF (247)."""
    return (
        b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8
        + struct.pack("<HHIQQQIHHHHHH",
                      1, 247, 1, 0, 0, 0, 0, 64, 0, 0, 64, 0, 0)
    )


def _zip_bytes(members: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return buf.getvalue()


def _tar_bytes(members: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _encrypted_zip_bytes() -> bytes:
    """Zip whose ``enc.txt`` central-directory flag bits declare
    encryption (stdlib can't WRITE encrypted zips, so patch the flag —
    the same fixture idiom as ``core/zip``'s battery)."""
    raw = bytearray(_zip_bytes({"enc.txt": b"secret", "ok.txt": b"fine"}))
    pos = 0
    while True:
        pos = raw.find(b"PK\x01\x02", pos)
        if pos < 0:
            break
        name_len = int.from_bytes(raw[pos + 28:pos + 30], "little")
        if bytes(raw[pos + 46:pos + 46 + name_len]) == b"enc.txt":
            raw[pos + 8] |= 0x01
        pos += 4
    return bytes(raw)


def _install_tree(root: Path) -> None:
    (root / "bin").mkdir(parents=True)
    (root / "lib").mkdir()
    (root / "modules").mkdir()
    (root / "channels").mkdir()
    (root / "bin" / "app").write_bytes(_standard_fixture())
    (root / "bin" / "app").chmod(0o755)
    (root / "lib" / "libfoo.so.1").write_bytes(_provider_lib())
    (root / "modules" / "netdrv.ko").write_bytes(_kmod_with_ioctl())
    (root / "modules" / "filter.bpf.o").write_bytes(_ebpf_header())
    (root / "bundle.zip").write_bytes(_zip_bytes({
        "inner/readme.txt": b"hello",
        "inner/member.elf": _standard_fixture(),
    }))
    for i in range(5):
        (root / "channels" / f"chan_{i:03d}.dat").write_bytes(
            b"CHNL" + bytes([i]) * 16)


def _build(tmp_path: Path, **caps) -> tuple[dict, Path, Path]:
    target = tmp_path / "install"
    out = tmp_path / "out"
    if not target.exists():
        _install_tree(target)
    doc = build_ledger(target, out, caps=LedgerCaps(**caps)
                       if caps else None)
    return doc, target, out


def _rows_by_class(doc: dict) -> dict[str, list[dict]]:
    grouped: dict[str, list[dict]] = {}
    for row in doc["rows"]:
        grouped.setdefault(row["class"], []).append(row)
    return grouped


# ── enumeration shape ────────────────────────────────────────────────

class TestEnumeration:
    def test_classes_and_tiers(self, tmp_path):
        doc, _target, _out = _build(tmp_path)
        grouped = _rows_by_class(doc)
        assert "elf-linux" in grouped          # app + libfoo + zip member
        assert "elf-kmod" in grouped
        assert CLASS_ELF_EBPF in grouped
        assert CLASS_ARCHIVE in grouped
        assert CLASS_CORPUS_FAMILY in grouped
        for row in doc["rows"]:
            assert row["format_tier"] == FORMAT_TIER_BY_CLASS.get(
                row["class"], "declared_degraded")
            assert row["status"]["state"] == "inventoried"
            assert ledger_mod._ARTIFACT_ID_RE.fullmatch(
                row["artifact_id"]), row["artifact_id"]

    def test_counts_match_rows(self, tmp_path):
        doc, _target, _out = _build(tmp_path)
        assert doc["counts"]["rows"] == len(doc["rows"])
        assert sum(doc["counts"]["by_class"].values()) == len(doc["rows"])

    def test_elf_links_recorded(self, tmp_path):
        doc, _target, _out = _build(tmp_path)
        app = next(r for r in doc["rows"] if r["path"] == "bin/app")
        assert app["links"]["needed"] == ["libfoo.so.1", "libbar.so.2"]
        assert app["links"]["soname"] == "libself.so.3"

    def test_family_clustering(self, tmp_path):
        doc, _target, _out = _build(tmp_path)
        families = _rows_by_class(doc)[CLASS_CORPUS_FAMILY]
        chan = [f for f in families
                if f["family"]["member_count"] == 5]
        assert chan, "the five chan_NNN.dat files must share one family"
        fam = chan[0]["family"]
        # magic4 | validated ext | template — the corpus_profile vocab.
        assert fam["key"].startswith(b"CHNL".hex() + "|dat|")
        assert 0 < len(fam["examples_escaped"]) <= 8

    def test_output_dir_nested_in_target_is_skipped(self, tmp_path):
        target = tmp_path / "install"
        _install_tree(target)
        out = target / "raptor-out"
        out.mkdir()
        (out / "decoy.json").write_text("{}")
        doc = build_ledger(target, out)
        assert not any("raptor-out" in (r.get("path") or "")
                       for r in doc["rows"])

    def test_ebpf_is_classification_row_only(self, tmp_path):
        doc, _target, _out = _build(tmp_path)
        row = _rows_by_class(doc)[CLASS_ELF_EBPF][0]
        assert row["exposure"] == []
        assert row["links"] is None
        assert row["format_tier"] == "classify_only"
        assert row["identity"]["kind"] == KIND_SHA256

    def test_non_regular_file_is_a_residual(self, tmp_path):
        target = tmp_path / "install"
        _install_tree(target)
        os.mkfifo(target / "channels" / "pipe")
        doc = build_ledger(target, tmp_path / "out")
        kinds = {r["kind"] for r in doc["residuals"]}
        assert "non_regular_file" in kinds

    def test_symlink_skips_are_a_counted_residual(self, tmp_path):
        target = tmp_path / "install"
        target.mkdir()
        (target / "real.txt").write_bytes(b"data")
        (target / "inside").symlink_to(target / "real.txt")
        (target / "outside").symlink_to("/etc/passwd")
        doc = build_ledger(target, tmp_path / "out")
        residual = next(r for r in doc["residuals"]
                        if r["kind"] == "symlinks_skipped")
        assert residual["message"].startswith("2 symlink(s)")
        # Counted, never followed, never exemplified: no row for
        # either link name (link names are attacker-chosen).
        assert not any((r.get("path") or "") in ("inside", "outside")
                       for r in doc["rows"])


# ── exposure features (mechanical, extractor-cited) ─────────────────

class TestExposure:
    def test_every_feature_cites_an_extractor(self, tmp_path):
        doc, _target, _out = _build(tmp_path)
        seen = 0
        for row in doc["rows"]:
            for feature in row["exposure"]:
                seen += 1
                assert feature["extractor"], feature
        assert seen > 0

    def test_input_channels_and_sinks(self, tmp_path):
        doc, _target, _out = _build(tmp_path)
        lib = next(r for r in doc["rows"]
                   if r["path"] == "lib/libfoo.so.1")
        by_name = {f["feature"]: f for f in lib["exposure"]}
        assert by_name["input_channels"]["value"] == ["network"]
        assert by_name["input_channels"]["extractor"] == (
            "packages.binary_analysis.input_channels"
            ".recover_static_channels")
        assert by_name["sink_imports"]["value"]["names"] == ["memcpy"]

    def test_driver_entry_catalog_match(self, tmp_path):
        doc, _target, _out = _build(tmp_path)
        kmod = next(r for r in doc["rows"]
                    if r["path"] == "modules/netdrv.ko")
        by_name = {f["feature"]: f for f in kmod["exposure"]}
        assert by_name["driver_entry_symbols"]["value"] == [
            "unlocked_ioctl"]
        assert by_name["driver_entry_symbols"]["extractor"] == (
            "packages.binary_analysis.ingress.driver_entry_catalogs")


# ── identity collision (M2) ──────────────────────────────────────────

class TestIdentityCollision:
    def test_collision_demotes_both_and_flags(self, tmp_path, monkeypatch):
        target = tmp_path / "install"
        (target / "bin").mkdir(parents=True)
        (target / "bin" / "a").write_bytes(_standard_fixture())
        (target / "bin" / "b").write_bytes(_provider_lib())

        forged = "ab" * 20
        real = ledger_mod.content_identity

        def _forge(path, **kwargs):
            if Path(path).name in ("a", "b"):
                return ContentIdentity(
                    "elf_build_id", forged, forged[:16])
            return real(path, **kwargs)

        monkeypatch.setattr(ledger_mod, "content_identity", _forge)
        doc = build_ledger(target, tmp_path / "out")
        rows = [r for r in doc["rows"]
                if r["path"] in ("bin/a", "bin/b")]
        assert len(rows) == 2
        for row in rows:
            assert row["identity"]["kind"] == KIND_SHA256
            assert row["elevated_interest"] is True
            assert row["elevated_interest_reason"] == (
                "identity_collision:elf_build_id")
            assert row["artifact_id"].startswith("sha256-")
        assert len({r["artifact_id"] for r in rows}) == 2
        assert doc["collisions"] == [{
            "identity_kind": "elf_build_id",
            "anchor": forged[:16],
            "artifact_ids": sorted(r["artifact_id"] for r in rows),
            "unverified_artifact_ids": [],
        }]
        # Alias-proof widening: demoted ids carry the FULL digest.
        for row in rows:
            assert row["artifact_id"] == (
                "sha256-" + row["identity"]["sha256"])

    def test_duplicate_content_is_not_a_collision(self, tmp_path):
        target = tmp_path / "install"
        target.mkdir()
        (target / "a.so").write_bytes(_provider_lib())
        (target / "b.so").write_bytes(_provider_lib())
        doc = build_ledger(target, tmp_path / "out")
        assert doc["collisions"] == []
        ids = [r["artifact_id"] for r in doc["rows"]
               if r["class"] == "elf-linux"]
        assert len(ids) == 2 and len(set(ids)) == 1
        assert not any(r["elevated_interest"] for r in doc["rows"])

    def test_anchor_alias_forgery_is_detected_and_demoted(
            self, tmp_path, monkeypatch):
        """Two DIFFERENT forged build-id values sharing a 16-hex
        prefix alias to one artifact-id anchor. Grouping by full value
        would miss this entirely (both rows would silently share one
        artifact id / checklist slot); the collision detector must key
        on (kind, anchor) and demote both to alias-proof full-digest
        ids."""
        target = tmp_path / "install"
        (target / "bin").mkdir(parents=True)
        (target / "bin" / "a").write_bytes(_standard_fixture())
        (target / "bin" / "b").write_bytes(_provider_lib())

        prefix = "ab" * 8                      # shared 16-hex anchor
        forged = {"a": prefix + "1" * 24, "b": prefix + "2" * 24}
        real = ledger_mod.content_identity

        def _forge(path, **kwargs):
            name = Path(path).name
            if name in forged:
                return ContentIdentity(
                    "elf_build_id", forged[name], prefix)
            return real(path, **kwargs)

        monkeypatch.setattr(ledger_mod, "content_identity", _forge)
        doc = build_ledger(target, tmp_path / "out")
        rows = [r for r in doc["rows"]
                if r["path"] in ("bin/a", "bin/b")]
        assert len(rows) == 2
        ids = {r["artifact_id"] for r in rows}
        assert len(ids) == 2, "aliased rows must not share one id"
        for row in rows:
            assert row["identity"]["kind"] == KIND_SHA256
            assert row["elevated_interest"] is True
            assert row["artifact_id"] == (
                "sha256-" + row["identity"]["sha256"])
        assert doc["collisions"] == [{
            "identity_kind": "elf_build_id",
            "anchor": prefix,
            "artifact_ids": sorted(ids),
            "unverified_artifact_ids": [],
        }]

    def test_unhashable_collision_member_is_rekeyed(
            self, tmp_path, monkeypatch):
        """A collision-group member whose content hash could not be
        read cannot prove which side of the collision it is — it must
        be stripped of the forged identity and re-keyed from its path,
        never left wearing the colliding artifact id un-flagged."""
        target = tmp_path / "install"
        (target / "bin").mkdir(parents=True)
        (target / "bin" / "a").write_bytes(_standard_fixture())
        (target / "bin" / "b").write_bytes(_provider_lib())

        forged = "ef" * 20
        real_ident = ledger_mod.content_identity
        real_sha = ledger_mod._sha256_or_none

        def _forge(path, **kwargs):
            if Path(path).name in ("a", "b"):
                return ContentIdentity(
                    "elf_build_id", forged, forged[:16])
            return real_ident(path, **kwargs)

        def _sha(path):
            if Path(path).name == "b":
                return None                    # unreadable hash
            return real_sha(path)

        monkeypatch.setattr(ledger_mod, "content_identity", _forge)
        monkeypatch.setattr(ledger_mod, "_sha256_or_none", _sha)
        doc = build_ledger(target, tmp_path / "out")
        row_a = next(r for r in doc["rows"] if r["path"] == "bin/a")
        row_b = next(r for r in doc["rows"] if r["path"] == "bin/b")
        # The hashable member demotes to the full content digest.
        assert row_a["artifact_id"] == (
            "sha256-" + row_a["identity"]["sha256"])
        # The unhashable member is flagged AND loses the forged
        # identity — re-keyed from its path, alias-proof by salt.
        assert row_b["elevated_interest"] is True
        assert row_b["elevated_interest_reason"] == (
            "identity_collision_unverifiable:elf_build_id")
        assert row_b["identity"] is None
        assert row_b["artifact_id"].startswith("unverified-")
        assert doc["collisions"] == [{
            "identity_kind": "elf_build_id",
            "anchor": forged[:16],
            "artifact_ids": [row_a["artifact_id"]],
            "unverified_artifact_ids": [row_b["artifact_id"]],
        }]


# ── archives (S14, both directions) ─────────────────────────────────

class TestArchives:
    def test_children_enter_with_provenance(self, tmp_path):
        doc, _target, _out = _build(tmp_path)
        archive = _rows_by_class(doc)[CLASS_ARCHIVE][0]
        children = [r for r in doc["rows"]
                    if (r["provenance"] or {}).get("parent")
                    == archive["artifact_id"]]
        assert {r["path"] for r in children} >= {
            "inner/member.elf"}
        member = next(r for r in children
                      if r["path"] == "inner/member.elf")
        assert member["class"] == "elf-linux"
        assert member["provenance"]["origin"] == "archive_member"

    def test_compliant_archive_not_truncated(self, tmp_path):
        doc, _target, _out = _build(tmp_path)
        assert not any(r["kind"] == "archive_truncated"
                       for r in doc["residuals"])
        assert CLASS_ARCHIVE_REMAINDER not in _rows_by_class(doc)

    def test_zip_overcap_truncates_with_residual(self, tmp_path):
        target = tmp_path / "install"
        target.mkdir()
        target.joinpath("big.zip").write_bytes(_zip_bytes({
            f"member_{i}.txt": b"x" * 32 for i in range(6)
        }))
        doc = build_ledger(target, tmp_path / "out",
                           caps=LedgerCaps(max_archive_children=2))
        residual = next(r for r in doc["residuals"]
                        if r["kind"] == "archive_truncated")
        assert residual["total"] == 6          # zip EOCD knows M
        assert "of 6 members" in residual["message"]
        remainder = _rows_by_class(doc)[CLASS_ARCHIVE_REMAINDER][0]
        assert remainder["artifact_id"].endswith("-remainder")
        assert remainder["family"]["member_count"] == (
            6 - residual["extracted"])

    def test_tar_overcap_keeps_extracted_prefix(self, tmp_path):
        target = tmp_path / "install"
        target.mkdir()
        target.joinpath("big.tar").write_bytes(_tar_bytes({
            f"member_{i}.txt": b"x" * 32 for i in range(6)
        }))
        doc = build_ledger(target, tmp_path / "out",
                           caps=LedgerCaps(max_archive_children=3))
        residual = next(r for r in doc["residuals"]
                        if r["kind"] == "archive_truncated")
        assert residual["extracted"] >= 1      # tar streams: partial
        assert residual["total"] is None       # no cheap tar total
        assert "of unknown members" in residual["message"]

    def test_depth_cap_declines_nested_archive(self, tmp_path):
        inner = _zip_bytes({"deep.txt": b"deep"})
        target = tmp_path / "install"
        target.mkdir()
        target.joinpath("outer.zip").write_bytes(
            _zip_bytes({"nested.zip": inner}))
        doc = build_ledger(target, tmp_path / "out")   # depth cap 1
        nested = next(r for r in doc["rows"]
                      if (r["provenance"] or {}).get("origin")
                      == "archive_member")
        assert nested["class"] == CLASS_ARCHIVE
        assert nested["expanded"] is False
        assert any(r["kind"] == "archive_depth_capped"
                   for r in doc["residuals"])
        assert not any(r["path"] == "deep.txt" for r in doc["rows"])

    def test_family_from_archive_member_keeps_origin(self, tmp_path):
        doc, _target, _out = _build(tmp_path)
        families = _rows_by_class(doc)[CLASS_CORPUS_FAMILY]
        txt = next(f for f in families
                   if "readme.txt" in "".join(
                       f["family"]["examples_escaped"]))
        assert txt["provenance"]["origin"] == "archive_member"
        assert txt["provenance"]["origins"] == ["archive_member"]

    def test_no_expand_classifies_only(self, tmp_path):
        doc, _target, _out = _build(tmp_path, expand_archives=False)
        archive = _rows_by_class(doc)[CLASS_ARCHIVE][0]
        assert archive["expanded"] is False
        assert not any(
            (r["provenance"] or {}).get("origin") == "archive_member"
            for r in doc["rows"])

    def test_hostile_member_drop_flags_the_archive(self, tmp_path):
        """A traversal-named member the extractor refuses must not
        vanish silently: counted residual with the reason, AND the
        archive row itself flagged — a member that disappears between
        the archive and the ledger is exactly where a hostile payload
        hides."""
        target = tmp_path / "install"
        target.mkdir()
        target.joinpath("evil.zip").write_bytes(_zip_bytes({
            "../escape.txt": b"evil",
            "ok.txt": b"fine",
        }))
        doc = build_ledger(target, tmp_path / "out")
        archive = _rows_by_class(doc)[CLASS_ARCHIVE][0]
        assert archive["expanded"] is True
        assert "archive_members_dropped" in archive["caps_hit"]
        assert archive["elevated_interest"] is True
        assert archive["elevated_interest_reason"] == (
            "hostile_archive_members:path_traversal")
        residual = next(r for r in doc["residuals"]
                        if r["kind"] == "archive_members_dropped")
        assert residual["artifact_id"] == archive["artifact_id"]
        assert residual["dropped"] == 1
        assert residual["reasons"] == {"path_traversal": 1}
        assert "path_traversal: 1" in residual["message"]

    def test_oversized_member_drop_is_counted_not_hostile(self, tmp_path):
        target = tmp_path / "install"
        target.mkdir()
        target.joinpath("big-member.zip").write_bytes(_zip_bytes({
            "huge.bin": b"x" * 64,
            "ok.txt": b"tiny",
        }))
        doc = build_ledger(target, tmp_path / "out",
                           caps=LedgerCaps(max_archive_member_bytes=8))
        archive = _rows_by_class(doc)[CLASS_ARCHIVE][0]
        assert "archive_members_dropped" in archive["caps_hit"]
        # An over-cap member is an operator-cap effect, not a hostile
        # name — counted, but the row is not flagged.
        assert archive["elevated_interest"] is False
        residual = next(r for r in doc["residuals"]
                        if r["kind"] == "archive_members_dropped")
        assert residual["reasons"] == {"oversized": 1}

    def test_encrypted_member_drop_is_counted_not_hostile(self, tmp_path):
        target = tmp_path / "install"
        target.mkdir()
        target.joinpath("enc.zip").write_bytes(_encrypted_zip_bytes())
        doc = build_ledger(target, tmp_path / "out")
        archive = _rows_by_class(doc)[CLASS_ARCHIVE][0]
        assert archive["expanded"] is True
        assert "archive_members_dropped" in archive["caps_hit"]
        assert archive["elevated_interest"] is False
        residual = next(r for r in doc["residuals"]
                        if r["kind"] == "archive_members_dropped")
        assert residual["reasons"] == {"encrypted": 1}

    def test_truncation_residual_names_the_cap(self, tmp_path):
        # Children cap: the residual and caps_hit name the exact
        # operator lever (the pre-fix record said 'archive_children'
        # for BOTH cap kinds — a wrong remediation hint).
        children_target = tmp_path / "children"
        children_target.mkdir()
        children_target.joinpath("many.zip").write_bytes(_zip_bytes({
            f"member_{i}.txt": b"x" * 32 for i in range(6)
        }))
        doc = build_ledger(children_target, tmp_path / "out-children",
                           caps=LedgerCaps(max_archive_children=2))
        residual = next(r for r in doc["residuals"]
                        if r["kind"] == "archive_truncated")
        assert residual["cap"] == "max_archive_children"
        assert "(cap: max_archive_children)" in residual["message"]
        assert "archive_children" in doc["caps_hit"]

        bytes_target = tmp_path / "bytes"
        bytes_target.mkdir()
        bytes_target.joinpath("fat.zip").write_bytes(_zip_bytes({
            f"member_{i}.txt": b"x" * 100 for i in range(6)
        }))
        doc = build_ledger(bytes_target, tmp_path / "out-bytes",
                           caps=LedgerCaps(max_archive_total_bytes=64))
        residual = next(r for r in doc["residuals"]
                        if r["kind"] == "archive_truncated")
        assert residual["cap"] == "max_archive_total_bytes"
        assert "(cap: max_archive_total_bytes)" in residual["message"]
        assert "archive_total_bytes" in doc["caps_hit"]

    def test_remainder_row_respects_row_budget(self, tmp_path,
                                               monkeypatch):
        """At the row-budget edge the truncation residual still lands
        but the remainder row must NOT breach the budget."""
        target = tmp_path / "install"
        target.mkdir()
        target.joinpath("big.zip").write_bytes(_zip_bytes({
            f"member_{i}.txt": b"x" * 32 for i in range(6)
        }))
        monkeypatch.setattr(ledger_mod, "MAX_LEDGER_ROWS", 1)
        doc = build_ledger(target, tmp_path / "out",
                           caps=LedgerCaps(max_archive_children=2))
        assert any(r["kind"] == "archive_truncated"
                   for r in doc["residuals"])
        assert any(r["kind"] == "rows_truncated"
                   for r in doc["residuals"])
        assert CLASS_ARCHIVE_REMAINDER not in _rows_by_class(doc)
        assert len(doc["rows"]) == 1


# ── reverse DT_NEEDED index ──────────────────────────────────────────

class TestReverseIndex:
    def test_provider_and_consumer_join(self, tmp_path):
        doc, _target, _out = _build(tmp_path)
        app = next(r for r in doc["rows"] if r["path"] == "bin/app")
        lib = next(r for r in doc["rows"]
                   if r["path"] == "lib/libfoo.so.1")
        entry = next(e for e in doc["reverse_needed"]
                     if e["name"] == "libfoo.so.1")
        assert lib["artifact_id"] in entry["providers"]
        assert app["artifact_id"] in entry["consumers"]
        # A needed name nothing provides stays honest: empty providers.
        dangling = next(e for e in doc["reverse_needed"]
                        if e["name"] == "libbar.so.2")
        assert dangling["providers"] == []

    def test_entries_stamp_derived_from_target(self, tmp_path):
        """M1 at the document level: ``name`` is a raw DT_NEEDED /
        soname string from target bytes — every entry must say so."""
        doc, _target, _out = _build(tmp_path)
        assert doc["reverse_needed"]
        for entry in doc["reverse_needed"]:
            assert entry["derived_from_target"] == ["name"]


# ── M1: derived_from_target + render escaping ───────────────────────

class TestProvenanceAndRender:
    def test_rows_stamp_derived_fields(self, tmp_path):
        doc, _target, _out = _build(tmp_path)
        universe = set(TARGET_DERIVED_FIELD_UNIVERSE)
        for row in doc["rows"]:
            stamped = row["derived_from_target"]
            assert set(stamped) <= universe
            if row.get("path"):
                assert "path" in stamped
            if (row.get("links") or {}).get("needed"):
                assert "links.needed" in stamped
            if (row.get("family") or {}).get("key"):
                assert "family.key" in stamped

    def test_render_escapes_hostile_names(self, tmp_path):
        target = tmp_path / "install"
        target.mkdir()
        hostile = "evil\x1b[31mred.dat"
        (target / hostile).write_bytes(b"CHNL data")
        out = tmp_path / "out"
        doc = build_ledger(target, out)
        for line in render_status_lines(doc, out):
            assert all(c.isprintable() for c in line), line
        for row in doc["rows"]:
            for line in render_artifact_lines(row):
                assert all(c.isprintable() for c in line), line
        family = _rows_by_class(doc)[CLASS_CORPUS_FAMILY][0]
        assert any("\\x1b" in e
                   for e in family["family"]["examples_escaped"])

    def test_render_escapes_hostile_identity(self, tmp_path):
        """The identity line is escape-at-render like every other row
        field: a forged identity value (or a kind that ever carries
        target bytes) must reach the terminal inert."""
        doc, _target, _out = _build(tmp_path)
        row = dict(doc["rows"][0])
        row["identity"] = {
            "kind": "elf_build_id\x1b[31m",
            "value": "abcd\x1b]0;pwn\x07",
            "anchor": "abcd",
            "sha256": None,
        }
        lines = render_artifact_lines(row)
        ident_line = next(ln for ln in lines if "identity:" in ln)
        assert "\\x1b" in ident_line
        for line in lines:
            assert all(c.isprintable() for c in line), line

    def test_render_escapes_rewritten_document_fields(self, tmp_path):
        """Render reads ledger.json back from the run output dir — a
        target-writable surface. Vocabulary fields (class, tier,
        state, identity_kind, by_class keys) are closed at BUILD time
        but arrive from the DOCUMENT at render time: a rewritten row
        must reach the terminal inert, not as live ESC/CSI/OSC."""
        esc_title = "\x1b]0;pwned\x07evil"
        esc_csi = "\x1b[2J\x1b[H FAKE-CLEAN"
        doc = {
            "counts": {"rows": 1, "by_class": {esc_csi: 1}},
            "target_root": "/tmp/benign",
            "rows": [{
                "artifact_id": esc_title,
                "class": esc_csi,
                "format_tier": "\x1b[8mHIDDEN",
                "path": "bin/app",
                "status": {"state": "\x1b[31mforged",
                           "updated_at": "\x1b[31mt0",
                           "depth": "T\x1b[31m2"},
                "identity": {"kind": "buildid", "value": "aa"},
                "size_bytes": 1,
                "exposure": [{"feature": "net\x1b[31m",
                              "value": "x",
                              "extractor": "elf\x1b[31m"}],
                "provenance": {"origin": "archive_member",
                               "parent": "p\x1b[31m.zip",
                               "member_path": "m"},
                "derived_from_target": ["path", "x\x1b[31m"],
            }],
            "residuals": [],
            "collisions": [
                {"identity_kind": "\x1b]0;boom\x07buildid",
                 "artifact_ids": ["a"]},
            ],
        }
        out = tmp_path / "out"
        out.mkdir()
        for line in render_status_lines(doc, out):
            assert "\x1b" not in line and "\x07" not in line, line
        for line in render_artifact_lines(doc["rows"][0]):
            assert "\x1b" not in line and "\x07" not in line, line

    def test_render_escapes_rewritten_family_examples(self, tmp_path):
        """family.examples_escaped promises write-time escaping in its
        NAME, but the values arrive from the run-dir document — a
        rewritten ledger.json omits the escaping, so the e.g. lines
        must re-escape at render (idempotent for honest entries, like
        the router's consumption side)."""
        row = {
            "artifact_id": "corpusfam",
            "class": "corpus_family",
            "format_tier": "corpus",
            "path": None,
            "size_bytes": 0,
            "status": {"state": "pending", "updated_at": "t0"},
            "family": {
                "key": "k",
                "member_count": 2,
                "examples_escaped": ["\x1b]0;pwned\x07ex1",
                                     "\x1b[2Jex2"],
            },
        }
        lines = render_artifact_lines(row)
        example_lines = [ln for ln in lines if "e.g." in ln]
        assert len(example_lines) == 2
        assert any("pwned" in ln for ln in example_lines)  # content kept
        for line in lines:
            assert "\x1b" not in line and "\x07" not in line, line

    def test_status_table_row_cap_elides(self, tmp_path, monkeypatch):
        doc, _target, out = _build(tmp_path)
        monkeypatch.setattr(ledger_mod, "MAX_STATUS_TABLE_ROWS", 2)
        lines = render_status_lines(doc, out)
        assert any("elided" in line for line in lines)


# ── status write-back + rebuild stickiness ──────────────────────────

class TestStatusWriteback:
    def test_roundtrip_and_validation(self, tmp_path):
        doc, _target, out = _build(tmp_path)
        artifact_id = doc["rows"][0]["artifact_id"]
        assert set_artifact_status(
            out, artifact_id, "in_progress",
            detail="chain segment 1", depth="T2")
        reloaded = load_ledger(out)
        row = next(r for r in reloaded["rows"]
                   if r["artifact_id"] == artifact_id)
        assert row["status"]["state"] == "in_progress"
        assert row["status"]["depth"] == "T2"
        with pytest.raises(ValueError):
            set_artifact_status(out, artifact_id, "EXPLOITED")
        with pytest.raises(ValueError):
            set_artifact_status(out, "../evil", "parked")
        with pytest.raises(ValueError):
            set_artifact_status(out, artifact_id, "parked",
                                depth="T2\x1b[31m")
        assert not set_artifact_status(
            out, "sha256-0000000000000000", "parked")

    def test_rebuild_preserves_writeback(self, tmp_path):
        doc, target, out = _build(tmp_path)
        artifact_id = doc["rows"][0]["artifact_id"]
        set_artifact_status(out, artifact_id, "analysed")
        doc2 = build_ledger(target, out)
        row = next(r for r in doc2["rows"]
                   if r["artifact_id"] == artifact_id)
        assert row["status"]["state"] == "analysed"

    def test_states_vocabulary_is_closed(self):
        assert "inventoried" in STATUS_STATES
        assert all(s == s.lower() for s in STATUS_STATES)

    def test_trojan_rebuild_does_not_inherit_status(
            self, tmp_path, monkeypatch):
        """Status carry is gated on the content hash: a replaced
        artifact wearing the SAME persisted identity (a trojaned
        rebuild carrying the previous build-id) must not inherit
        ``verdicted`` — the carry is refused, the row is flagged, and
        a residual records the reset."""
        target = tmp_path / "install"
        target.mkdir()
        (target / "tool").write_bytes(_standard_fixture())
        forged = "cd" * 20
        monkeypatch.setattr(
            ledger_mod, "content_identity",
            lambda path, **kwargs: ContentIdentity(
                "elf_build_id", forged, forged[:16]))
        out = tmp_path / "out"
        doc = build_ledger(target, out)
        aid = next(r["artifact_id"] for r in doc["rows"]
                   if r["path"] == "tool")
        assert set_artifact_status(out, aid, "verdicted")

        # Same path, same forged identity — DIFFERENT bytes.
        (target / "tool").write_bytes(_provider_lib())
        doc2 = build_ledger(target, out)
        row = next(r for r in doc2["rows"] if r["path"] == "tool")
        assert row["artifact_id"] == aid          # identity persisted
        assert row["status"]["state"] == "inventoried"
        assert row["elevated_interest"] is True
        assert row["elevated_interest_reason"] == (
            "status_carry_refused:content_changed")
        residual = next(r for r in doc2["residuals"]
                        if r["kind"] == "status_carry_refused")
        assert residual["artifact_id"] == aid
        # The refusal is persisted, not just returned.
        reloaded = load_ledger(out)
        row = next(r for r in reloaded["rows"] if r["path"] == "tool")
        assert row["status"]["state"] == "inventoried"

    def test_family_row_status_carries_without_content_hash(
            self, tmp_path):
        """Rows with no content hash by construction (corpus families
        — ids derive from the family key) carry status on id alone;
        they hold no per-binary verdict to trojan."""
        doc, target, out = _build(tmp_path)
        fam = _rows_by_class(doc)[CLASS_CORPUS_FAMILY][0]
        assert set_artifact_status(out, fam["artifact_id"], "parked")
        doc2 = build_ledger(target, out)
        row = next(r for r in doc2["rows"]
                   if r["artifact_id"] == fam["artifact_id"])
        assert row["status"]["state"] == "parked"
        assert not any(r["kind"] == "status_carry_refused"
                       for r in doc2["residuals"])

    def test_rebuild_survives_corrupt_prior_ledger(self, tmp_path):
        """A corrupted prior ledger (non-dict rows) costs the carry,
        never the rebuild."""
        doc, target, out = _build(tmp_path)
        lp = ledger_mod.ledger_path(out)
        lp.write_text(json.dumps(
            {"rows": ["not-a-dict", 42, None, {"artifact_id": "x"}]}),
            encoding="utf-8")
        doc2 = build_ledger(target, out)          # must not raise
        assert doc2["counts"]["rows"] == doc["counts"]["rows"]


# ── per-artifact checklist slots ─────────────────────────────────────

class TestChecklistSlots:
    def test_roundtrip_stamps_identity(self, tmp_path):
        out = tmp_path / "out"
        out.mkdir()
        checklist = {
            "total_items": 7,
            "files": [{"path": "binary:app", "items": []}],
        }
        slot = write_artifact_checklist(out, "sha256-abcdef0123456789",
                                        checklist)
        assert slot == checklist_slot_path(out,
                                           "sha256-abcdef0123456789")
        loaded = read_artifact_checklist(out, "sha256-abcdef0123456789")
        assert loaded["artifact_id"] == "sha256-abcdef0123456789"
        assert loaded["total_items"] == 7
        # The binary_builder file-key convention rides through intact.
        assert loaded["files"][0]["path"] == "binary:app"
        assert list_artifact_checklists(out) == [
            "sha256-abcdef0123456789"]

    def test_same_stem_different_artifacts_do_not_collide(self, tmp_path):
        out = tmp_path / "out"
        out.mkdir()
        write_artifact_checklist(
            out, "sha256-" + "1" * 16,
            {"total_items": 1, "files": [{"path": "binary:app"}]})
        write_artifact_checklist(
            out, "sha256-" + "2" * 16,
            {"total_items": 2, "files": [{"path": "binary:app"}]})
        first = read_artifact_checklist(out, "sha256-" + "1" * 16)
        second = read_artifact_checklist(out, "sha256-" + "2" * 16)
        assert first["total_items"] == 1
        assert second["total_items"] == 2

    def test_hostile_artifact_id_refused(self, tmp_path):
        with pytest.raises(ValueError):
            checklist_slot_path(tmp_path, "../../etc/passwd")
        with pytest.raises(ValueError):
            checklist_slot_path(tmp_path, "UPPER-Case")

    def test_status_table_reads_denominator(self, tmp_path):
        doc, _target, out = _build(tmp_path)
        artifact_id = doc["rows"][0]["artifact_id"]
        write_artifact_checklist(out, artifact_id,
                                 {"total_items": 42, "files": []})
        lines = render_status_lines(doc, out)
        assert any("42" in line and artifact_id[:26] in line
                   for line in lines)

    # ── frame authentication on the slot (key isolation + warn-once
    #    resets come from this suite's autouse conftest fixture) ──────

    def test_write_mints_verified_frame_reader_pops_token(
            self, tmp_path):
        from core.inventory import checklist_frame_mac as cm
        from core.json import load_json
        out = tmp_path / "out"
        out.mkdir()
        aid = "sha256-" + "a" * 16
        slot = write_artifact_checklist(
            out, aid, {"total_items": 3, "files": []})
        raw = load_json(slot)
        assert cm.frame_provenance(
            raw, cm.frame_binding(slot), cm.FORM_SINGLE,
        ) == cm.FRAME_VERIFIED
        loaded = read_artifact_checklist(out, aid)
        assert loaded["total_items"] == 3
        assert cm.FRAME_TOKEN_KEY not in loaded

    def test_tampered_slot_refused(self, tmp_path, caplog):
        """An in-place edit under a kept token reads as absent — the
        safe degrade direction for a coverage denominator — with a
        loud refusal in the log."""
        from core.json import load_json, save_json
        out = tmp_path / "out"
        out.mkdir()
        aid = "sha256-" + "b" * 16
        slot = write_artifact_checklist(
            out, aid, {"total_items": 3, "files": []})
        doc = load_json(slot)
        doc["total_items"] = 9999
        save_json(slot, doc)
        with caplog.at_level("WARNING", logger="core.engagement"):
            assert read_artifact_checklist(out, aid) is None
        assert "FAILED frame authentication" in caplog.text

    def test_unstamped_in_era_slot_demoted_not_refused(
            self, tmp_path, caplog):
        """A bare write that bypasses the stamping writer (the
        pre-fix shape) still reads — at legacy tier, with the in-era
        demotion warning."""
        from core.json import save_json
        out = tmp_path / "out"
        out.mkdir()
        aid = "sha256-" + "c" * 16
        slot = checklist_slot_path(out, aid)
        slot.parent.mkdir(parents=True, exist_ok=True)
        save_json(slot, {"artifact_id": aid, "total_items": 5,
                         "files": []})
        with caplog.at_level("INFO"):
            loaded = read_artifact_checklist(out, aid)
        assert loaded["total_items"] == 5
        assert any(
            "no integrity token" in rec.getMessage()
            and rec.levelname == "WARNING"
            for rec in caplog.records)

    def test_cross_slot_copy_lands_relocated(
            self, tmp_path, caplog):
        """A frame minted for a sibling slot must not verify here:
        demoted with the relocated warning, never refused — every
        slot holds a different artifact."""
        import shutil
        out = tmp_path / "out"
        out.mkdir()
        src_id = "sha256-" + "d" * 16
        dst_id = "sha256-" + "e" * 16
        src = write_artifact_checklist(
            out, src_id, {"total_items": 4, "files": []})
        shutil.copy2(src, checklist_slot_path(out, dst_id))
        with caplog.at_level("WARNING"):
            loaded = read_artifact_checklist(out, dst_id)
        assert loaded is not None
        assert loaded["total_items"] == 4
        assert "minted for a different slot" in caplog.text

    def test_stale_input_token_never_reserialised(
            self, tmp_path):
        """A token riding in on the input document is replaced by a
        fresh mint — never re-serialised as this writer's own."""
        from core.inventory import checklist_frame_mac as cm
        from core.json import load_json
        out = tmp_path / "out"
        out.mkdir()
        aid = "sha256-" + "f" * 16
        stale = {"slot": "/somewhere/else", "mac": "00" * 32}
        slot = write_artifact_checklist(
            out, aid,
            {"total_items": 6, "files": [],
             cm.FRAME_TOKEN_KEY: dict(stale)})
        raw = load_json(slot)
        assert raw[cm.FRAME_TOKEN_KEY] != stale
        assert cm.frame_provenance(
            raw, cm.frame_binding(slot), cm.FORM_SINGLE,
        ) == cm.FRAME_VERIFIED

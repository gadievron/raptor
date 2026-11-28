"""Tests for the traced-build binary content ledger
(core.analysis.binary_build_ledger): capture delta semantics, the
fail-closed load lattice, consultation flagging, and the pinned
growth/DoS limits."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

import core.analysis.binary_build_ledger as ledger_mod
from core.analysis.binary_build_ledger import (
    LEDGER_ENTRY_CAP,
    MAX_HASH_BYTES,
    SNAPSHOT_FILE_CAP,
    build_produced_candidates,
    ledger_path,
    load_build_ledger,
    record_build_delta,
    snapshot_repo_binaries,
)
from core.hash import sha256_file


@pytest.fixture(autouse=True)
def _xdg_home(tmp_path, monkeypatch):
    """Point the ledger dir at a per-test XDG data home."""
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))


@pytest.fixture(autouse=True)
def _all_pre_carriers_untracked(monkeypatch):
    """Hermetic provenance partition: the real ``_filter_locally_built``
    spawns sandboxed git against the repo, and these tmp repos are not
    git repos anyway (the conservative split would exempt nothing).
    The suite pins ledger mechanics, so the partition defaults to
    'every pre-carrier is untracked' — the exemption-earning shape.
    Provenance-direction tests (TestPreBuildProvenance) override it."""
    import core.analysis.binary_oracle_cli as oracle_cli
    monkeypatch.setattr(
        oracle_cli, "_filter_locally_built",
        lambda repo, candidates: (list(candidates), []))


def _elf(path: Path, payload: bytes) -> Path:
    """A minimal +x ELF-magic file the auto-detect walk classifies as
    an executable candidate."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"\x7fELF" + payload)
    path.chmod(0o755)
    return path


def _repo_with_build(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    (repo / "build").mkdir(parents=True)
    return repo


class TestSnapshot:
    def test_snapshot_hashes_candidates(self, tmp_path):
        repo = _repo_with_build(tmp_path)
        b = _elf(repo / "build" / "app", b"one")
        snap = snapshot_repo_binaries(repo)
        assert snap is not None
        assert snap[str(b)] == sha256_file(b)

    def test_snapshot_cap_returns_none(self, tmp_path, monkeypatch):
        repo = _repo_with_build(tmp_path)
        for i in range(4):
            _elf(repo / "build" / f"app{i}", bytes([i]))
        monkeypatch.setattr(ledger_mod, "SNAPSHOT_FILE_CAP", 3)
        assert snapshot_repo_binaries(repo) is None

    def test_oversized_file_skipped_at_capture(self, tmp_path, monkeypatch):
        repo = _repo_with_build(tmp_path)
        big = _elf(repo / "build" / "big", b"xxxx")
        small = _elf(repo / "build" / "small", b"y")
        monkeypatch.setattr(ledger_mod, "MAX_HASH_BYTES",
                            os.stat(big).st_size - 1)
        snap = snapshot_repo_binaries(repo)
        assert snap is not None
        assert str(big) not in snap
        assert str(small) in snap

    def test_missing_repo_is_empty_not_failed(self, tmp_path):
        assert snapshot_repo_binaries(tmp_path / "nope") == {}


class TestRecordAndLoad:
    def test_delta_roundtrip(self, tmp_path):
        repo = _repo_with_build(tmp_path)
        pre_bin = _elf(repo / "build" / "old", b"pre-existing")
        pre = snapshot_repo_binaries(repo)
        new_bin = _elf(repo / "build" / "planted", b"build-made")
        post = snapshot_repo_binaries(repo)
        assert record_build_delta(repo, pre, post) == 1
        view = load_build_ledger(repo)
        assert view.status == "ok"
        assert sha256_file(new_bin) in view.hashes
        assert sha256_file(pre_bin) not in view.hashes

    def test_overwrite_in_place_is_captured(self, tmp_path):
        # A build that OVERWRITES a pre-existing operator binary must
        # still be captured — the record is content, never path.
        repo = _repo_with_build(tmp_path)
        b = _elf(repo / "build" / "app", b"operator-built")
        pre = snapshot_repo_binaries(repo)
        _elf(repo / "build" / "app", b"swapped-by-build")
        post = snapshot_repo_binaries(repo)
        assert record_build_delta(repo, pre, post) == 1
        assert sha256_file(b) in load_build_ledger(repo).hashes

    def test_dedupe_by_hash_across_runs(self, tmp_path):
        repo = _repo_with_build(tmp_path)
        _elf(repo / "build" / "app", b"content")
        post = snapshot_repo_binaries(repo)
        assert record_build_delta(repo, {}, post) == 1
        # Same content again (second run, no pre inventory of it).
        assert record_build_delta(repo, {}, post) == 0
        raw = ledger_path(repo).read_text()
        assert len(raw.splitlines()) == 1

    def test_pre_none_overcaptures(self, tmp_path):
        repo = _repo_with_build(tmp_path)
        b = _elf(repo / "build" / "app", b"whatever")
        post = snapshot_repo_binaries(repo)
        assert record_build_delta(repo, None, post) == 1
        assert sha256_file(b) in load_build_ledger(repo).hashes

    def test_post_none_marks_capture_incomplete(self, tmp_path):
        repo = _repo_with_build(tmp_path)
        assert record_build_delta(repo, {}, None) == 0
        view = load_build_ledger(repo)
        assert view.status == "unverifiable"
        assert "inventory" in (view.reason or "")

    def test_unverifiable_ledger_stops_accruing(self, tmp_path):
        repo = _repo_with_build(tmp_path)
        record_build_delta(repo, {}, None)
        size = ledger_path(repo).stat().st_size
        _elf(repo / "build" / "app", b"later")
        post = snapshot_repo_binaries(repo)
        assert record_build_delta(repo, {}, post) == 0
        assert ledger_path(repo).stat().st_size == size

    def test_entry_cap_overflows_to_incomplete(self, tmp_path, monkeypatch):
        repo = _repo_with_build(tmp_path)
        monkeypatch.setattr(ledger_mod, "LEDGER_ENTRY_CAP", 2)
        post = {f"/x/{i}": f"{i:064x}" for i in range(3)}
        assert record_build_delta(repo, {}, post) == 0
        view = load_build_ledger(repo)
        assert view.status == "unverifiable"
        assert "cap" in (view.reason or "")

    def test_limits_are_pinned(self):
        # Growth/DoS limits are churn-prone; the rationale lives on
        # the constants — a change must be deliberate (re-pin here).
        assert LEDGER_ENTRY_CAP == 4096
        assert SNAPSHOT_FILE_CAP == 1024
        assert MAX_HASH_BYTES == 1 << 30

    def test_absent_ledger_loads_absent(self, tmp_path):
        assert load_build_ledger(tmp_path / "repo").status == "absent"

    def test_relative_xdg_data_home_is_ignored(self, tmp_path, monkeypatch):
        # The XDG basedir spec requires ignoring relative values: a
        # cwd-relative ledger dir would split capture from
        # consultation (different cwds) and drop stray trees wherever
        # the process runs.
        monkeypatch.setenv("XDG_DATA_HOME", "relative-xdg")
        monkeypatch.setattr(
            Path, "home", classmethod(lambda cls: tmp_path / "home"))
        d = ledger_mod._ledger_dir()
        assert d.is_absolute()
        assert d == tmp_path / "home" / ".local" / "share" / "raptor" / "build-ledger"

    def test_unresolvable_home_reads_absent_not_unverifiable(
        self, tmp_path, monkeypatch,
    ):
        # HOME unset + no passwd entry (DynamicUser-style runner): no
        # location this install could have written a ledger to exists,
        # so the ledger is ABSENT — demoting every auto-detected
        # binary there would be a suppression regression, not safety.
        repo = _repo_with_build(tmp_path)
        b = _elf(repo / "build" / "app", b"x")
        monkeypatch.delenv("XDG_DATA_HOME", raising=False)
        monkeypatch.setattr(
            Path, "home",
            classmethod(lambda cls: (_ for _ in ()).throw(
                RuntimeError("no home"))))
        view = load_build_ledger(repo)
        assert view.status == "absent"
        flagged, reason = build_produced_candidates(repo, [b])
        assert flagged == [] and reason is None


class TestPreBuildProvenance:
    """The pre-build exemption is provenance-gated: only hashes whose
    pre-build carriers include an UNTRACKED path escape recording."""

    def test_tracked_pre_carrier_does_not_exempt(self, tmp_path, monkeypatch):
        """The finding's repro: the repo COMMITS a crafted ELF, and its
        build step copies it byte-identical to an untracked path. The
        copy's hash must record (authority demoted) even though the
        content was present pre-build."""
        import core.analysis.binary_oracle_cli as oracle_cli
        repo = _repo_with_build(tmp_path)
        template = _elf(repo / "build" / "payload-template", b"crafted")
        pre = snapshot_repo_binaries(repo)
        copy = _elf(repo / "build" / "mytool", b"crafted")
        other = _elf(repo / "build" / "other", b"fresh")
        post = snapshot_repo_binaries(repo)
        tracked = {template}
        monkeypatch.setattr(
            oracle_cli, "_filter_locally_built",
            lambda repo_, candidates: (
                [c for c in candidates if c not in tracked],
                [c for c in candidates if c in tracked],
            ))
        assert record_build_delta(repo, pre, post) == 2
        view = load_build_ledger(repo)
        assert sha256_file(copy) in view.hashes
        assert sha256_file(other) in view.hashes

    def test_untracked_pre_carrier_still_exempts(self, tmp_path):
        """A legitimate operator-built (untracked) binary present
        before the build keeps its exemption; only the build's own
        output records."""
        repo = _repo_with_build(tmp_path)
        mine = _elf(repo / "build" / "mine", b"operator-built")
        pre = snapshot_repo_binaries(repo)
        made = _elf(repo / "build" / "made", b"by-the-build")
        post = snapshot_repo_binaries(repo)
        assert record_build_delta(repo, pre, post) == 1
        view = load_build_ledger(repo)
        assert sha256_file(made) in view.hashes
        assert sha256_file(mine) not in view.hashes

    def test_partition_failure_exempts_nothing(self, tmp_path, monkeypatch):
        """A failing provenance partition must over-capture (record the
        pre-existing content too — safe direction), never skip
        recording via the outer never-raise handler (fail-open)."""
        import core.analysis.binary_oracle_cli as oracle_cli
        repo = _repo_with_build(tmp_path)
        mine = _elf(repo / "build" / "mine", b"operator-built")
        pre = snapshot_repo_binaries(repo)
        post = snapshot_repo_binaries(repo)

        def _boom(repo_, candidates):
            msg = "partition broke"
            raise RuntimeError(msg)

        monkeypatch.setattr(oracle_cli, "_filter_locally_built", _boom)
        assert record_build_delta(repo, pre, post) == 1
        assert sha256_file(mine) in load_build_ledger(repo).hashes

    def test_partition_receives_pre_carrier_paths(self, tmp_path, monkeypatch):
        """The exemption consults the binary oracle's provenance filter
        (single doctrine source) with the repo and every pre-build
        carrier path."""
        import core.analysis.binary_oracle_cli as oracle_cli
        repo = _repo_with_build(tmp_path)
        a = _elf(repo / "build" / "a", b"one")
        b = _elf(repo / "build" / "b", b"two")
        pre = snapshot_repo_binaries(repo)
        post = snapshot_repo_binaries(repo)
        calls: list[tuple[Path, set[Path]]] = []

        def _recording(repo_, candidates):
            calls.append((repo_, set(candidates)))
            return list(candidates), []

        monkeypatch.setattr(
            oracle_cli, "_filter_locally_built", _recording)
        assert record_build_delta(repo, pre, post) == 0
        assert calls == [(Path(repo), {a, b})]


class TestDualKeyIdentity:
    def test_ledger_paths_two_keys_path_first(self, tmp_path):
        repo = _repo_with_build(tmp_path)
        paths = ledger_mod.ledger_paths(repo)
        assert len(paths) == 2
        assert paths[0] == ledger_path(repo)
        assert paths[0] != paths[1]

    def test_records_land_in_both_key_files(self, tmp_path):
        repo = _repo_with_build(tmp_path)
        _elf(repo / "build" / "app", b"content")
        post = snapshot_repo_binaries(repo)
        assert record_build_delta(repo, {}, post) == 1
        for p in ledger_mod.ledger_paths(repo):
            assert p.is_file()
            assert len(p.read_text().splitlines()) == 1

    def test_moved_repo_keeps_identity(self, tmp_path):
        # The evasion the alias key closes: record under one path,
        # move the repo — the path key reads absent there, but the
        # repo root keeps its inode, so the alias key still carries
        # the record and consultation keeps flagging.
        repo = _repo_with_build(tmp_path)
        _elf(repo / "build" / "planted", b"build-made")
        post = snapshot_repo_binaries(repo)
        assert record_build_delta(repo, {}, post) == 1
        moved = tmp_path / "repo-moved"
        repo.rename(moved)
        view = load_build_ledger(moved)
        assert view.status == "ok"
        assert sha256_file(moved / "build" / "planted") in view.hashes
        flagged, reason = build_produced_candidates(
            moved, [moved / "build" / "planted"])
        assert flagged == [moved / "build" / "planted"]
        assert reason is None

    def test_rebuild_after_move_backfills_the_new_path_key(
        self, tmp_path,
    ):
        # Appends dedupe per key FILE, not against the merged union:
        # after a move, a deterministic rebuild reproduces hashes the
        # alias already carries, and those must STILL land in the new
        # path-key file. Union-deduped appends would skip them,
        # leaving the path file empty — and a later alias-identity
        # loss (device renumber, recycled inode) would then consult
        # that empty file alone and read the build-produced binary as
        # eligible for absent suppression again (fail-open).
        repo = _repo_with_build(tmp_path)
        _elf(repo / "build" / "planted", b"build-made")
        post = snapshot_repo_binaries(repo)
        assert record_build_delta(repo, {}, post) == 1
        moved = tmp_path / "repo-moved"
        repo.rename(moved)
        new_path_key = ledger_mod.ledger_paths(moved)[0]
        assert not new_path_key.exists()
        post2 = snapshot_repo_binaries(moved)
        # No NEW content — the rebuild reproduced the recorded hash —
        # but the new path key gets backfilled all the same.
        assert record_build_delta(moved, {}, post2) == 0
        digest = sha256_file(moved / "build" / "planted")
        solo = ledger_mod._load_ledger_file(new_path_key)
        assert solo.status == "ok"
        assert digest in solo.hashes

    def test_copied_repo_loses_identity(self, tmp_path):
        # cp -r mints fresh inodes: both keys are new, the ledger
        # reads absent — the accepted identity loss (same reach the
        # path key alone had).
        import shutil
        repo = _repo_with_build(tmp_path)
        _elf(repo / "build" / "planted", b"build-made")
        post = snapshot_repo_binaries(repo)
        assert record_build_delta(repo, {}, post) == 1
        copied = tmp_path / "repo-copy"
        shutil.copytree(repo, copied)
        assert load_build_ledger(copied).status == "absent"

    def test_unverifiable_alias_file_poisons_merge_naming_it(
        self, tmp_path,
    ):
        repo = _repo_with_build(tmp_path)
        _elf(repo / "build" / "app", b"content")
        post = snapshot_repo_binaries(repo)
        assert record_build_delta(repo, {}, post) == 1
        alias = ledger_mod.ledger_paths(repo)[1]
        with open(alias, "a") as f:
            f.write("not json\n")
        view = load_build_ledger(repo)
        assert view.status == "unverifiable"
        assert str(alias) in (view.reason or "")

    def test_unstatable_repo_falls_back_to_path_key(self, tmp_path):
        missing = tmp_path / "never-existed"
        assert ledger_mod.ledger_paths(missing) == [ledger_path(missing)]


class TestLoadFailClosed:
    def _seed_ok(self, repo: Path) -> None:
        record_build_delta(repo, {}, {"/x/a": "ab" * 32})

    def test_malformed_line_unverifiable(self, tmp_path):
        repo = _repo_with_build(tmp_path)
        self._seed_ok(repo)
        with open(ledger_path(repo), "a") as f:
            f.write("not json\n")
        assert load_build_ledger(repo).status == "unverifiable"

    def test_unknown_schema_unverifiable(self, tmp_path):
        repo = _repo_with_build(tmp_path)
        path = ledger_path(repo)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(
            {"v": 99, "kind": "build-binary", "sha256": "ab" * 32}) + "\n")
        assert load_build_ledger(repo).status == "unverifiable"

    def test_bad_sha_unverifiable(self, tmp_path):
        repo = _repo_with_build(tmp_path)
        path = ledger_path(repo)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(
            {"v": 1, "kind": "build-binary", "sha256": "ZZ" * 32}) + "\n")
        assert load_build_ledger(repo).status == "unverifiable"

    def test_symlink_ledger_unverifiable(self, tmp_path):
        repo = _repo_with_build(tmp_path)
        real = tmp_path / "elsewhere.jsonl"
        real.write_text("")
        path = ledger_path(repo)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.symlink_to(real)
        assert load_build_ledger(repo).status == "unverifiable"

    def test_group_writable_ledger_unverifiable(self, tmp_path):
        repo = _repo_with_build(tmp_path)
        self._seed_ok(repo)
        ledger_path(repo).chmod(0o666)
        assert load_build_ledger(repo).status == "unverifiable"


class TestConsultation:
    def test_hash_match_flagged_others_not(self, tmp_path):
        repo = _repo_with_build(tmp_path)
        operator_bin = _elf(repo / "build" / "mine", b"operator")
        pre = snapshot_repo_binaries(repo)
        planted = _elf(repo / "build" / "planted", b"by-the-build")
        record_build_delta(repo, pre, snapshot_repo_binaries(repo))
        flagged, reason = build_produced_candidates(
            repo, [operator_bin, planted])
        assert flagged == [planted]
        assert reason is None

    def test_absent_ledger_flags_nothing(self, tmp_path):
        repo = _repo_with_build(tmp_path)
        b = _elf(repo / "build" / "app", b"x")
        flagged, reason = build_produced_candidates(repo, [b])
        assert flagged == [] and reason is None

    def test_unverifiable_ledger_flags_everything(self, tmp_path):
        repo = _repo_with_build(tmp_path)
        b = _elf(repo / "build" / "app", b"x")
        path = ledger_path(repo)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("garbage\n")
        flagged, reason = build_produced_candidates(repo, [b])
        assert flagged == [b]
        assert reason is not None and "unverifiable" in reason

    def test_unhashable_candidate_flagged(self, tmp_path, monkeypatch):
        # A candidate exceeding the hash budget can't be proven NOT
        # build-produced — symmetric fail-closed with the capture skip.
        repo = _repo_with_build(tmp_path)
        big = _elf(repo / "build" / "big", b"xxxxxxxx")
        record_build_delta(repo, {}, {"/x/a": "ab" * 32})
        monkeypatch.setattr(ledger_mod, "MAX_HASH_BYTES",
                            os.stat(big).st_size - 1)
        flagged, reason = build_produced_candidates(repo, [big])
        assert flagged == [big] and reason is None

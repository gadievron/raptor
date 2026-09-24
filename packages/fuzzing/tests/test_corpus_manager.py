"""Tests for the corpus manager's seed writers.

The corpus dir is inside the campaign's (target-writable) output
scope: the flat-name validation stops traversal-shaped NAMES, but a
symlink PLANTED at a valid seed name would still route a plain
``write_bytes`` anywhere on disk. Writes must be exclusive-create
(lstat-honest replace of whatever occupies the name).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from packages.fuzzing.corpus_manager import CorpusManager


class TestAddSeed:
    def test_round_trip(self, tmp_path: Path):
        mgr = CorpusManager(tmp_path / "corpus")
        seed = mgr.add_seed(b"payload", "seed0")
        assert seed.read_bytes() == b"payload"

    def test_re_add_overwrites_own_seed(self, tmp_path: Path):
        mgr = CorpusManager(tmp_path / "corpus")
        mgr.add_seed(b"one", "seed0")
        seed = mgr.add_seed(b"two", "seed0")
        assert seed.read_bytes() == b"two"

    def test_rejects_traversal_names(self, tmp_path: Path):
        mgr = CorpusManager(tmp_path / "corpus")
        with pytest.raises(ValueError):
            mgr.add_seed(b"x", "../evil")

    def test_planted_symlink_at_seed_name_never_followed(
        self, tmp_path: Path,
    ):
        mgr = CorpusManager(tmp_path / "corpus")
        victim = tmp_path / "victim"
        victim.write_text("do not touch")
        (mgr.corpus_dir / "seed0").symlink_to(victim)

        seed = mgr.add_seed(b"payload", "seed0")

        assert victim.read_text() == "do not touch"
        assert not seed.is_symlink()
        assert seed.read_bytes() == b"payload"

    def test_planted_dangling_symlink_never_materialised(
        self, tmp_path: Path,
    ):
        mgr = CorpusManager(tmp_path / "corpus")
        victim = tmp_path / "victim"
        (mgr.corpus_dir / "seed0").symlink_to(victim)

        mgr.add_seed(b"payload", "seed0")

        assert not victim.exists()


class TestCreateFromDirectory:
    def test_copies_regular_files(self, tmp_path: Path):
        src = tmp_path / "src"
        src.mkdir()
        (src / "a").write_bytes(b"aa")
        mgr = CorpusManager(tmp_path / "corpus")
        assert mgr.create_from_directory(src) == 1
        assert (mgr.corpus_dir / "a").read_bytes() == b"aa"

    def test_planted_symlink_at_dest_name_never_followed(
        self, tmp_path: Path,
    ):
        src = tmp_path / "src"
        src.mkdir()
        (src / "a").write_bytes(b"aa")
        mgr = CorpusManager(tmp_path / "corpus")
        victim = tmp_path / "victim"
        victim.write_text("do not touch")
        (mgr.corpus_dir / "a").symlink_to(victim)

        assert mgr.create_from_directory(src) == 1

        assert victim.read_text() == "do not touch"
        assert not (mgr.corpus_dir / "a").is_symlink()
        assert (mgr.corpus_dir / "a").read_bytes() == b"aa"

    def test_planted_intermediate_dir_symlink_never_traversed(
        self, tmp_path: Path,
    ):
        """The exclusive create hardens only the FINAL component: a
        planted INTERMEDIATE directory symlink (corpus_dir/sub aimed
        at an operator dir) plus a repo seed named sub/<victim-name>
        would otherwise carry the mkdir and the seed write outside
        the corpus — unlinking and overwriting the operator file."""
        attacker_dir = tmp_path / "attacker_dir"
        attacker_dir.mkdir()
        operator_file = attacker_dir / "authorized_keys"
        operator_file.write_text("operator key\n")

        src = tmp_path / "src"
        (src / "sub").mkdir(parents=True)
        (src / "sub" / "authorized_keys").write_bytes(b"ATTACKERKEY\n")

        mgr = CorpusManager(tmp_path / "corpus")
        (mgr.corpus_dir / "sub").symlink_to(attacker_dir)

        count = mgr.create_from_directory(src)

        assert operator_file.read_text() == "operator key\n"
        assert count == 0
        assert not (attacker_dir / ".atomic-authorized_keys").exists()

"""Release-tag path-safety of the compat-matrix dev tool.

Tags come from the LIVE releases API and become URL components, pin
keys, and path components under the workdir. The shape gate at the
derivation chokepoint plus the resolve-and-contain cleanup keep a
hostile tag from ever aiming ``unlink``/``rmtree`` outside the
matrix's own scratch — including on the ``--require-pinned`` refusal
branch, whose per-tag cleanup runs without any download. These tests
drive ``main()`` with a stubbed releases API — no network.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "compat_matrix.py"


@pytest.fixture(scope="module")
def cm():
    spec = importlib.util.spec_from_file_location(
        "compat_matrix_tags", _SCRIPT,
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("tag", [
    "v4.0.458",
    "4.0.458",
    "v2.0.1+build.7",
    "v1.2.3-rc1",
    "V1_2",
])
def test_tag_gate_accepts_version_shaped_tags(cm, tag):
    assert cm._TAG_RE.fullmatch(tag)


@pytest.mark.parametrize("tag", [
    "../victim",
    "..",
    "a/b",
    "a\\b",
    "-flag",
    "",
    ".hidden",
    "v1\n",
    "v1 2",
    "vé1",          # ASCII class only — no unicode letters
    "v" + "a" * 65,      # bounded
    "v1\x00",
])
def test_tag_gate_rejects_separator_and_shape_abuse(cm, tag):
    assert not cm._TAG_RE.fullmatch(tag)


def _seed_victims(scratch: Path) -> tuple[Path, Path, Path]:
    work = scratch / "work"
    work.mkdir(parents=True)
    victim = scratch / "victim"
    victim.mkdir()
    (victim / "data.txt").write_text("do not delete\n")
    victim_zip = scratch / "victim.zip"
    victim_zip.write_text("zip placeholder\n")
    return work, victim, victim_zip


def test_hostile_tag_never_reaches_filesystem(cm, tmp_path, monkeypatch):
    # The refusal branch's cleanup used to fire on tag-derived paths:
    # a "../victim" tag deleted the workdir's SIBLING dir and zip even
    # under --require-pinned.
    work, victim, victim_zip = _seed_victims(tmp_path)
    monkeypatch.setattr(cm, "_newest_tags", lambda n: ["../victim"])
    monkeypatch.setattr(sys, "argv", [
        "compat_matrix", "--workdir", str(work), "--require-pinned",
    ])
    rc = cm.main()
    assert rc == 1  # the refused tag is a failed row, not a crash
    assert victim.exists()
    assert (victim / "data.txt").exists()
    assert victim_zip.exists()


def test_hostile_tag_row_is_a_loud_refusal(cm, tmp_path, monkeypatch, capsys):
    work, _victim, _zip = _seed_victims(tmp_path)
    monkeypatch.setattr(cm, "_newest_tags", lambda n: ["../victim"])
    monkeypatch.setattr(sys, "argv", [
        "compat_matrix", "--workdir", str(work), "--require-pinned",
    ])
    cm.main()
    out = capsys.readouterr().out
    assert "refused hostile release tag" in out


def test_contained_cleanup_refuses_symlink_out_of_workdir(cm, tmp_path):
    # Belt-and-braces beneath the tag gate: a validated tag whose tree
    # was swapped for a symlink out of the workdir must not be
    # followed by the rmtree.
    work = tmp_path / "work"
    work.mkdir()
    victim = tmp_path / "victim"
    victim.mkdir()
    (victim / "data.txt").write_text("keep\n")
    tree = work / "v1.0.0"
    tree.symlink_to(victim)
    archive = work / "v1.0.0.zip"
    archive.write_text("x")
    cm._contained_cleanup(work, archive, tree)
    assert victim.exists()
    assert (victim / "data.txt").exists()
    assert not archive.exists()  # the contained artifact IS deleted


def test_contained_cleanup_deletes_contained_tree(cm, tmp_path):
    work = tmp_path / "work"
    work.mkdir()
    tree = work / "v1.0.0"
    tree.mkdir()
    (tree / "f").write_text("x")
    archive = work / "v1.0.0.zip"
    archive.write_text("x")
    cm._contained_cleanup(work, archive, tree)
    assert not tree.exists()
    assert not archive.exists()


def test_require_pinned_with_empty_pins_warns(cm, tmp_path, monkeypatch,
                                              capsys):
    work, _victim, _zip = _seed_victims(tmp_path)
    monkeypatch.setattr(cm, "_load_pins", lambda: {})
    monkeypatch.setattr(cm, "_newest_tags", lambda n: [])
    monkeypatch.setattr(sys, "argv", [
        "compat_matrix", "--workdir", str(work), "--require-pinned",
    ])
    cm.main()
    out = capsys.readouterr().out
    assert "empty pins file" in out

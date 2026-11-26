"""Symlink-race containment for the write path's directory creation.

``annotation_path`` resolve()-checks the parent, but the check is
point-in-time: a same-privilege writer swapping an intermediate
directory for a symlink between the check and the write used to have
the by-name mkdir and lock-file O_CREAT follow the link — file litter
at an attacker-chosen location outside the base, even though the
content write itself was later refused by the under-lock re-check.
The anchored parent walk must refuse the swapped component BEFORE
anything is created.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from core.annotations import Annotation, write_annotation
from core.annotations import storage


def test_raced_symlink_dir_creates_nothing_outside_base(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    base = tmp_path / "annotations"
    base.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    real = storage.annotation_path

    def check_then_swap(base_dir: Path, source_file: str) -> Path:
        # Emulate the race winner: the containment check passes, then
        # the intermediate directory turns into a symlink out of the
        # base before the writer touches the filesystem.
        path = real(base_dir, source_file)
        victim = Path(base_dir) / "sub"
        if not victim.is_symlink():
            victim.symlink_to(outside, target_is_directory=True)
        return path

    monkeypatch.setattr(storage, "annotation_path", check_then_swap)
    with pytest.raises(ValueError):
        write_annotation(
            base, Annotation(file="sub/x.py", function="f", body="note"),
        )
    assert list(outside.iterdir()) == [], (
        "write refusal still littered files through the symlinked "
        "directory"
    )

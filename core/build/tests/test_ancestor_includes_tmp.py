"""_discover_ancestor_includes must never adopt a shared temp root's include/.

/tmp, /var/tmp and the system temp dir are world-writable: ANY local
user can pre-create ``<temp-root>/include/stdio.h`` and, for a target
extracted directly under the temp root, have it injected ahead of
system headers into every synthesised TU compile. Only the shared
roots themselves are blocked — an ``include/`` inside an
operator-owned subtree of the temp dir stays eligible (targets are
routinely extracted to ``/tmp/<dir>/``).
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from core.build.build_detector import BuildDetector


def _make_include(root: Path) -> None:
    (root / "include").mkdir(parents=True)
    (root / "include" / "poison.h").write_text("// header")


class TestTempRootAncestorBlocked:
    def test_system_tempdir_include_not_adopted(self, tmp_path, monkeypatch):
        # Simulate a target living directly under the system temp
        # dir with a pre-created <tempdir>/include next to it.
        fake_tmp = tmp_path / "faketmp"
        _make_include(fake_tmp)
        repo = fake_tmp / "target"
        repo.mkdir()
        monkeypatch.setattr(tempfile, "gettempdir", lambda: str(fake_tmp))

        found = BuildDetector(repo)._discover_ancestor_includes()
        assert str(fake_tmp / "include") not in found

    def test_symlinked_include_resolving_into_tempdir_rejected(
        self, tmp_path, monkeypatch,
    ):
        # include/ at a legitimate ancestor, but symlinked to the
        # shared temp root's include — the RESOLVED path must be
        # re-checked.
        fake_tmp = tmp_path / "faketmp"
        _make_include(fake_tmp)
        monkeypatch.setattr(tempfile, "gettempdir", lambda: str(fake_tmp))

        proj = tmp_path / "proj"
        (proj / "lib").mkdir(parents=True)
        (proj / "include").symlink_to(fake_tmp / "include")

        found = BuildDetector(proj / "lib")._discover_ancestor_includes()
        assert str((fake_tmp / "include").resolve()) not in found

    def test_operator_owned_subtree_include_still_found(self, tmp_path):
        """Two-direction: a normal sibling include/ at an ancestor
        (not a shared temp root) is still discovered."""
        proj = tmp_path / "proj"
        _make_include(proj)
        (proj / "lib").mkdir()

        found = BuildDetector(proj / "lib")._discover_ancestor_includes()
        assert str((proj / "include").resolve()) in found

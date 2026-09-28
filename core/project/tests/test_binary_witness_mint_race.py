"""The witness mint must hash the file it checked.

``/project binary add`` promotes bytes to durable suppression
authority. Checking the path with ``is_file()`` and then hashing it
BY NAME spans a swap window: a symlink landed between the check and
the hash points the digest at attacker-chosen bytes while the check
verdict still reads regular-file. The mint now performs ONE gated
open (O_NOFOLLOW, fstat-on-fd, digest of the same fd via
``sha256_fileobj``) that carries check and digest together. The swap
is driven deterministically by wrapping the live traversal seams
(swap-then-delegate) — an ordering hook, not a timing race: on the
fixed mint the swap lands before its single open (ELOOP refusal); a
regression back to a check-then-hash-by-name shape would hash the
swapped bytes and mint, failing the test.
"""

import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import core.hash as hash_mod
import core.source as source_mod
from core.project.project import ProjectManager


class MintSwapWindowTest(unittest.TestCase):

    def setUp(self):
        self.tmpdir = TemporaryDirectory()
        root = Path(self.tmpdir.name)
        self.mgr = ProjectManager(projects_dir=root / "projects")
        self.target = root / "code"
        self.target.mkdir()
        self.mgr.create("myapp", str(self.target),
                        output_dir=str(root / "output"))
        self.bin_path = root / "app.debug"
        self.bin_path.write_bytes(b"\x7fELF" + b"\x00" * 28)
        self.victim = root / "victim.bytes"
        self.victim.write_bytes(b"attacker-chosen contents")

    def tearDown(self):
        self.tmpdir.cleanup()

    def _run(self, *argv):
        from core.project.cli import main
        with patch("core.project.cli.ProjectManager",
                   return_value=self.mgr), \
             patch.object(sys, "argv", ["raptor-project", *argv]):
            main()

    def _swap(self) -> None:
        """The attacker's move inside the check-to-hash window."""
        if not self.bin_path.is_symlink():
            self.bin_path.unlink()
            self.bin_path.symlink_to(self.victim)

    def test_swap_between_check_and_hash_mints_nothing(self):
        """A symlink swapped in after the add-time check must refuse
        — not mint a witness for bytes the check never saw."""
        real_by_name = hash_mod.sha256_file
        real_open = getattr(source_mod, "open_regular_gated", None)

        def swapping_by_name(path, *a, **kw):
            self._swap()
            return real_by_name(path, *a, **kw)

        def swapping_open(path, *a, **kw):
            self._swap()
            return real_open(path, *a, **kw)

        # Wrap whichever traversal seam the mint consults (the CLI
        # imports at call time), so the swap fires exactly at the
        # first path traversal after any earlier by-name check: on
        # the fixed mint that is its single gated open (must refuse
        # via O_NOFOLLOW); on a check-then-hash regression it is the
        # by-name hash (would mint the victim's digest — red).
        patches = [patch.object(hash_mod, "sha256_file",
                                swapping_by_name)]
        if real_open is not None:
            patches.append(patch.object(source_mod,
                                        "open_regular_gated",
                                        swapping_open))
        with patches[0]:
            if len(patches) > 1:
                with patches[1]:
                    self._run("binary", "add", str(self.bin_path),
                              "myapp")
            else:
                self._run("binary", "add", str(self.bin_path), "myapp")

        p = self.mgr.load("myapp")
        resolved = str(Path(self.tmpdir.name).resolve() / "app.debug")
        self.assertNotIn(resolved, p.binaries)
        self.assertEqual(p.binary_witnesses, {})

    def test_honest_add_still_mints(self):
        """No swap: the add must keep pinning the real digest."""
        self._run("binary", "add", str(self.bin_path), "myapp")
        p = self.mgr.load("myapp")
        resolved = str(self.bin_path.resolve())
        self.assertIn(resolved, p.binaries)
        digest = p.binary_witnesses.get(resolved)
        self.assertIsNotNone(digest)
        import hashlib
        self.assertEqual(
            digest,
            hashlib.sha256(b"\x7fELF" + b"\x00" * 28).hexdigest())

    def test_mint_digests_the_gated_fd_not_the_name(self):
        """Swap-AFTER-open: the attacker replaces the file right
        after the mint's gated open
        returns; a regression digesting a second by-name open would
        mint the ATTACKER's bytes under the operator's trust
        assertion. Fd-honest minting pins the bytes the gate actually
        opened."""
        import hashlib
        import os
        original = b"\x7fELF" + b"\x00" * 28
        attacker = b"\x7fELF" + b"\xaa" * 28
        impostor = Path(self.tmpdir.name) / "impostor.debug"
        impostor.write_bytes(attacker)

        real_open = source_mod.open_regular_gated

        def swap_after_open(path, *a, **kw):
            fh = real_open(path, *a, **kw)
            os.replace(impostor, self.bin_path)  # lands AFTER the open
            return fh

        with patch.object(source_mod, "open_regular_gated",
                          swap_after_open):
            self._run("binary", "add", str(self.bin_path), "myapp")

        p = self.mgr.load("myapp")
        key = str(self.bin_path.resolve())
        self.assertIn(key, p.binaries)
        minted = p.binary_witnesses.get(key)
        # The witness must be the digest of the bytes the gate OPENED
        # — never the attacker bytes now sitting at the name.
        self.assertEqual(minted,
                         hashlib.sha256(original).hexdigest())
        self.assertNotEqual(minted,
                            hashlib.sha256(attacker).hexdigest())

    def test_non_regular_path_refuses_without_hanging(self):
        """A FIFO at the add path mints nothing — and the gated open
        (O_NONBLOCK) cannot be wedged by it."""
        fifo = Path(self.tmpdir.name) / "pipe.debug"
        import os
        os.mkfifo(fifo)
        self._run("binary", "add", str(fifo), "myapp")
        p = self.mgr.load("myapp")
        self.assertEqual(p.binaries, [])
        self.assertEqual(p.binary_witnesses, {})


if __name__ == "__main__":
    unittest.main()

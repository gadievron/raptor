#!/usr/bin/env python3
"""Read-side guard on the row-MAC key.

Regression: creation set 0700/0600 with ``O_EXCL``, but READING an
existing key enforced nothing — a bare ``read_bytes()`` followed
symlinks and accepted any mode/owner. An exposed key means forged row
MACs, i.e. attacker-minted "verified" rows mechanically replayed into
sweeps. Reads now refuse symlinks (``O_NOFOLLOW`` + fstat), foreign
owners and group/other-readable modes; refusal never uses the key,
never replaces it, warns loudly once, and demotes to hint-only.
"""

import logging
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from core.sage import rowmac

_FIELDS = {"kind": "test_row", "value": "x"}


class _KeyDirCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.key_path = Path(self._tmp.name) / "raptor" / "rowmac.key"
        patcher = patch(
            "core.sage.rowmac._key_path", return_value=self.key_path,
        )
        patcher.start()
        self.addCleanup(patcher.stop)
        # warn-once state is per-path/per-process; isolate per test.
        rowmac._warned_paths.clear()

    def _make_key(self, mode=0o600) -> bytes:
        self.key_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        data = os.urandom(32)
        self.key_path.write_bytes(data)
        self.key_path.chmod(mode)
        return data


class TestHealthyKey(_KeyDirCase):
    def test_0600_key_mints_and_verifies(self):
        self._make_key(0o600)
        token = rowmac.mint(_FIELDS)
        self.assertTrue(rowmac.verify(_FIELDS, token))

    def test_absent_key_is_created_and_usable(self):
        token = rowmac.mint(_FIELDS)
        self.assertTrue(rowmac.verify(_FIELDS, token))
        self.assertTrue(self.key_path.is_file())
        self.assertEqual(
            os.stat(self.key_path).st_mode & 0o777, 0o600,
        )


class TestPermissiveKey(_KeyDirCase):
    def test_group_other_readable_key_refused(self):
        original = self._make_key(0o644)
        with self.assertRaises(RuntimeError):
            rowmac.mint(_FIELDS)
        self.assertFalse(rowmac.verify(_FIELDS, "0" * 64))
        # The suspect key is never replaced (re-keying would mask
        # tampering) and never modified.
        self.assertEqual(self.key_path.read_bytes(), original)
        self.assertEqual(os.stat(self.key_path).st_mode & 0o777, 0o644)

    def test_refusal_warns_loudly_exactly_once(self):
        self._make_key(0o644)
        with self.assertLogs("raptor.core.sage.rowmac", level=logging.WARNING) as cm:
            with self.assertRaises(RuntimeError):
                rowmac.mint(_FIELDS)
            rowmac.verify(_FIELDS, "0" * 64)
            rowmac.verify(_FIELDS, "0" * 64)
        warnings = [
            r for r in cm.records if r.levelno >= logging.WARNING
        ]
        self.assertEqual(len(warnings), 1, cm.output)
        msg = warnings[0].getMessage()
        self.assertIn("chmod 600", msg)
        self.assertIn(str(self.key_path), msg)

    def test_group_readable_only_also_refused(self):
        self._make_key(0o640)
        self.assertFalse(rowmac.verify(_FIELDS, "0" * 64))

    def test_stamp_falls_back_to_unstamped_via_hooks_wrapper(self):
        """hooks._stamp_row treats a mint failure as store-unstamped
        (the safe direction) — the pipeline never breaks."""
        self._make_key(0o644)
        from core.sage.hooks import _stamp_row

        content = "Validation verdict: x ||verdict=confirmed||"
        self.assertEqual(
            _stamp_row("validation_verdict", content, dict(_FIELDS)),
            content,
        )


class TestSymlinkKey(_KeyDirCase):
    def test_symlinked_key_refused_and_not_replaced(self):
        self.key_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        target = Path(self._tmp.name) / "attacker-controlled"
        target.write_bytes(b"k" * 32)
        target.chmod(0o600)
        self.key_path.symlink_to(target)

        with self.assertRaises(RuntimeError):
            rowmac.mint(_FIELDS)
        self.assertFalse(rowmac.verify(_FIELDS, "0" * 64))
        # Still a symlink to the same place: refusal never rewrites.
        self.assertTrue(self.key_path.is_symlink())
        self.assertEqual(os.readlink(self.key_path), str(target))

    def test_symlink_refusal_names_symlink_investigation(self):
        self.key_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        target = Path(self._tmp.name) / "attacker-controlled"
        target.write_bytes(b"k" * 32)
        self.key_path.symlink_to(target)
        with self.assertLogs("raptor.core.sage.rowmac", level=logging.WARNING) as cm:
            rowmac.verify(_FIELDS, "0" * 64)
        self.assertTrue(any("symlink" in o for o in cm.output), cm.output)


class TestWrongOwner(_KeyDirCase):
    def test_foreign_owner_refused(self):
        original = self._make_key(0o600)
        real_fstat = os.fstat

        def _foreign(fd):
            st = real_fstat(fd)
            values = list(st)
            values[4] = st.st_uid + 1  # st_uid slot
            return os.stat_result(values)

        with patch("core.sage.rowmac.os.fstat", side_effect=_foreign):
            with self.assertRaises(RuntimeError):
                rowmac.mint(_FIELDS)
            self.assertFalse(rowmac.verify(_FIELDS, "0" * 64))
        self.assertEqual(self.key_path.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()

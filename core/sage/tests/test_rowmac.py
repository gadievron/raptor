#!/usr/bin/env python3
"""Robustness tests for core/sage/rowmac.py (row MAC mint/verify/stamp/strip)."""

import os
import secrets
import stat
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from core.sage import rowmac


class TestKeyPathResolution(unittest.TestCase):
    """The key resolves to the XDG data dir, never the repo tree.

    Pure path computation — nothing is created on disk.
    """

    def test_honours_xdg_data_home(self):
        with patch.dict(os.environ, {"XDG_DATA_HOME": "/custom/data"}):
            self.assertEqual(
                rowmac._key_path(),
                Path("/custom/data/raptor/rowmac.key"),
            )

    def test_defaults_to_local_share_outside_repo(self):
        with patch.dict(os.environ, {"HOME": "/home/testuser"}):
            os.environ.pop("XDG_DATA_HOME", None)
            resolved = rowmac._key_path()
        self.assertEqual(
            resolved,
            Path("/home/testuser/.local/share/raptor/rowmac.key"),
        )
        # Sandboxed children can hold repo-root read; the key must
        # never resolve into the checkout.
        repo_root = Path(rowmac.__file__).resolve().parents[2]
        self.assertNotIn(repo_root, resolved.parents)


class RowMacKeyTmpDirCase(unittest.TestCase):
    """Base: point the key path at a per-test temp directory."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.key_path = Path(self.tmp.name) / "sage-state" / "rowmac.key"
        patcher = patch(
            "core.sage.rowmac._key_path", return_value=self.key_path
        )
        patcher.start()
        self.addCleanup(patcher.stop)


class TestMintVerify(RowMacKeyTmpDirCase):
    def test_roundtrip(self):
        fields = {"kind": "codeql_build", "cmd": "make all", "langs": "cpp"}
        token = rowmac.mint(fields)
        self.assertRegex(token, r"^[0-9a-f]{64}$")
        self.assertTrue(rowmac.verify(fields, token))

    def test_any_field_change_fails(self):
        fields = {"kind": "afl_flags", "strategy": "explore", "flags": "-p explore"}
        token = rowmac.mint(fields)
        for key in fields:
            altered = dict(fields)
            altered[key] = altered[key] + "x"
            self.assertFalse(rowmac.verify(altered, token))

    def test_missing_or_extra_field_fails(self):
        fields = {"a": "1", "b": "2"}
        token = rowmac.mint(fields)
        self.assertFalse(rowmac.verify({"a": "1"}, token))
        self.assertFalse(rowmac.verify({"a": "1", "b": "2", "c": "3"}, token))

    def test_empty_or_malformed_token_fails(self):
        fields = {"a": "1"}
        self.assertFalse(rowmac.verify(fields, None))
        self.assertFalse(rowmac.verify(fields, ""))
        self.assertFalse(rowmac.verify(fields, "not-hex"))
        self.assertFalse(rowmac.verify(fields, "0" * 64))

    def test_token_case_and_whitespace_tolerated(self):
        fields = {"a": "1"}
        token = rowmac.mint(fields)
        self.assertTrue(rowmac.verify(fields, token.upper()))
        self.assertTrue(rowmac.verify(fields, f"  {token}  "))

    def test_insertion_order_irrelevant(self):
        token_ab = rowmac.mint({"a": "1", "b": "2"})
        token_ba = rowmac.mint({"b": "2", "a": "1"})
        self.assertEqual(token_ab, token_ba)


class TestEncodingInjectivity(RowMacKeyTmpDirCase):
    """Distinct field maps must never share a token."""

    def test_value_containing_separator_does_not_collide(self):
        # A value that spells out another key=value pair must not
        # collide with the map that actually has that pair.
        joined = rowmac.mint({"cmd": "make, langs=cpp", "langs": ""})
        split = rowmac.mint({"cmd": "make", "langs": "cpp"})
        self.assertNotEqual(joined, split)

    def test_delimiter_style_value_does_not_collide(self):
        smuggled = rowmac.mint({"verdict": "clean||src=abc"})
        real = rowmac.mint({"verdict": "clean", "src": "abc"})
        self.assertNotEqual(smuggled, real)

    def test_key_value_boundary_shift_does_not_collide(self):
        self.assertNotEqual(
            rowmac.mint({"ab": "c"}),
            rowmac.mint({"a": "bc"}),
        )

    def test_field_content_swap_does_not_collide(self):
        # Same multiset of strings distributed differently across
        # fields (a reordering of the values, not just of insertion).
        self.assertNotEqual(
            rowmac.mint({"a": "x", "b": "y"}),
            rowmac.mint({"a": "y", "b": "x"}),
        )

    def test_empty_map_and_empty_field(self):
        self.assertNotEqual(
            rowmac.mint({}),
            rowmac.mint({"": ""}),
        )


class TestStampStrip(RowMacKeyTmpDirCase):
    def test_stamp_strip_roundtrip(self):
        fields = {"kind": "finding_verdict", "verdict": "false_positive"}
        content = "Finding verdict: fp=abcd ||verdict=false_positive||"
        stamped = rowmac.stamp(content, fields)
        clean, token = rowmac.strip(stamped)
        self.assertEqual(clean, content)
        self.assertTrue(rowmac.verify(fields, token))

    def test_strip_idempotent(self):
        stamped = rowmac.stamp("row text", {"a": "1"})
        clean1, token1 = rowmac.strip(stamped)
        clean2, token2 = rowmac.strip(clean1)
        self.assertEqual(clean1, clean2)
        self.assertIsNotNone(token1)
        self.assertIsNone(token2)

    def test_tokenless_row_passes_through(self):
        self.assertEqual(rowmac.strip("plain row"), ("plain row", None))
        self.assertEqual(rowmac.strip(""), ("", None))

    def test_mid_content_token_not_consumed(self):
        text = f"quoted [mac:{'a' * 64}] then more prose"
        clean, token = rowmac.strip(text)
        self.assertEqual(clean, text)
        self.assertIsNone(token)

    def test_multiline_content_supported(self):
        fields = {"kind": "study_concept", "concept": "c1", "src": "abc"}
        content = "Concept [c1] in scope: desc\n  Source hash: abc"
        clean, token = rowmac.strip(rowmac.stamp(content, fields))
        self.assertEqual(clean, content)
        self.assertTrue(rowmac.verify(fields, token))


class TestKeyLifecycle(RowMacKeyTmpDirCase):
    def test_lazy_create_permissions(self):
        rowmac.mint({"a": "1"})
        self.assertTrue(self.key_path.is_file())
        self.assertEqual(len(self.key_path.read_bytes()), 32)
        key_mode = stat.S_IMODE(self.key_path.stat().st_mode)
        dir_mode = stat.S_IMODE(self.key_path.parent.stat().st_mode)
        self.assertEqual(key_mode, 0o600)
        self.assertEqual(dir_mode, 0o700)

    def test_concurrent_first_create_converges_on_one_key(self):
        n = 8
        barrier = threading.Barrier(n)
        results = []
        lock = threading.Lock()

        def worker():
            barrier.wait()
            key = rowmac._load_or_create_key()
            with lock:
                results.append(key)

        threads = [threading.Thread(target=worker) for _ in range(n)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(results), n)
        self.assertEqual(len(set(results)), 1)
        self.assertEqual(len(results[0]), 32)
        self.assertEqual(self.key_path.read_bytes(), results[0])

    def test_key_deletion_demotes_without_error(self):
        fields = {"kind": "sca_outcome", "name": "pkg", "verdict": "malicious_confirmed"}
        token = rowmac.mint(fields)
        self.key_path.unlink()
        # verify recreates a fresh key and simply fails — the demote path.
        self.assertFalse(rowmac.verify(fields, token))
        # New mints work against the fresh key.
        token2 = rowmac.mint(fields)
        self.assertTrue(rowmac.verify(fields, token2))
        self.assertNotEqual(token, token2)

    def test_key_replacement_fails_old_tokens(self):
        fields = {"kind": "audit_hypothesis", "status": "clean"}
        token = rowmac.mint(fields)
        self.key_path.write_bytes(secrets.token_bytes(32))
        self.assertFalse(rowmac.verify(fields, token))

    def test_existing_key_reused_not_rotated(self):
        token1 = rowmac.mint({"a": "1"})
        key_bytes = self.key_path.read_bytes()
        token2 = rowmac.mint({"a": "1"})
        self.assertEqual(token1, token2)
        self.assertEqual(self.key_path.read_bytes(), key_bytes)

    def test_verify_never_raises_when_key_dir_unusable(self):
        # A plain file where the .sage directory should be makes key
        # creation impossible; verify must fail closed, not raise.
        blocked = Path(self.tmp.name) / "blocked"
        blocked.write_text("not a directory")
        with patch(
            "core.sage.rowmac._key_path",
            return_value=blocked / "rowmac.key",
        ):
            self.assertFalse(rowmac.verify({"a": "1"}, "0" * 64))


if __name__ == "__main__":
    unittest.main()


class TestShortOrEmptyKeyRefused(RowMacKeyTmpDirCase):
    """A zero/short key file (ENOSPC or a kill between the O_EXCL
    create and the write) must be refused like _REFUSED — silently
    HMAC'ing with an empty/truncated key makes every token forgeable,
    re-enabling the poisoned-row mechanical effect."""

    def setUp(self):
        super().setUp()
        rowmac._warned_paths.clear()
        self.key_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)

    def test_empty_key_file_refused(self):
        self.key_path.touch(mode=0o600)
        self.assertIsNone(rowmac._load_or_create_key())

    def test_short_key_file_refused(self):
        self.key_path.write_bytes(b"short")
        self.key_path.chmod(0o600)
        self.assertIsNone(rowmac._load_or_create_key())

    def test_mint_refuses_on_short_key(self):
        self.key_path.write_bytes(b"\x00" * 8)
        self.key_path.chmod(0o600)
        with self.assertRaises(RuntimeError):
            rowmac.mint({"a": "1"})

    def test_verify_demotes_on_short_key(self):
        self.key_path.write_bytes(b"\x00" * 8)
        self.key_path.chmod(0o600)
        self.assertFalse(rowmac.verify({"a": "1"}, "deadbeef" * 8))

    def test_short_key_never_used_never_replaced(self):
        self.key_path.write_bytes(b"short")
        self.key_path.chmod(0o600)
        with self.assertRaises(RuntimeError):
            rowmac.mint({"a": "1"})
        # The suspect key is left in place for investigation.
        self.assertEqual(self.key_path.read_bytes(), b"short")

    def test_refusal_is_loud(self):
        self.key_path.touch(mode=0o600)
        with self.assertLogs("raptor.core.sage.rowmac",
                             level="WARNING") as cm:
            rowmac._load_or_create_key()
        joined = " ".join(cm.output)
        self.assertIn("refusing key", joined)

"""Tests for _tighten_config_perms() — auto-chmod of ~/.config/raptor/models.json."""

from pkgutil import resolve_name as _mock_owner
from core.testing.module_bindings import mock_module_attribute


import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from core.startup.init import _tighten_config_perms


from core.testing.module_bindings import patch_module_attribute
import pytest


@pytest.fixture(autouse=True)
def _isolate_os_fault_patches(monkeypatch):
    """Keep process and path simulations on the module under test."""
    import core.startup.init as consumer

    patch_module_attribute(monkeypatch, consumer, "os", "getuid", consumer.os.getuid)


class TestTightenConfigPerms(unittest.TestCase):

    def _make_file(self, d: Path, mode: int) -> Path:
        p = d / "models.json"
        p.write_text("{}")
        os.chmod(p, mode)
        return p

    def test_missing_file_returns_none(self):
        with TemporaryDirectory() as d:
            p = Path(d) / "does-not-exist"
            self.assertIsNone(_tighten_config_perms(p))

    def test_already_tight_returns_none(self):
        with TemporaryDirectory() as d:
            p = self._make_file(Path(d), 0o600)
            self.assertIsNone(_tighten_config_perms(p))
            self.assertEqual(p.stat().st_mode & 0o777, 0o600)

    def test_group_readable_gets_tightened(self):
        with TemporaryDirectory() as d:
            p = self._make_file(Path(d), 0o640)
            notice = _tighten_config_perms(p)
            self.assertIsNotNone(notice)
            self.assertTrue(notice.startswith("tightened"))
            self.assertIn("was 640", notice)
            self.assertEqual(p.stat().st_mode & 0o777, 0o600)

    def test_world_readable_gets_tightened(self):
        with TemporaryDirectory() as d:
            p = self._make_file(Path(d), 0o664)
            notice = _tighten_config_perms(p)
            self.assertTrue(notice.startswith("tightened"))
            self.assertIn("was 664", notice)
            self.assertEqual(p.stat().st_mode & 0o777, 0o600)

    def test_idempotent(self):
        with TemporaryDirectory() as d:
            p = self._make_file(Path(d), 0o644)
            _tighten_config_perms(p)
            self.assertIsNone(_tighten_config_perms(p))
            self.assertEqual(p.stat().st_mode & 0o777, 0o600)

    def test_not_owned_warns_no_chmod(self):
        """If getuid() doesn't match st_uid, we warn and don't touch it."""
        with TemporaryDirectory() as d:
            p = self._make_file(Path(d), 0o664)
            fake_uid = p.stat().st_uid + 1
            with mock_module_attribute(_mock_owner('core.startup.init'), 'os', 'getuid', return_value=fake_uid):
                notice = _tighten_config_perms(p)
            self.assertIsNotNone(notice)
            self.assertTrue(notice.startswith("\u26a0"))
            self.assertIn("not owned", notice)
            self.assertEqual(p.stat().st_mode & 0o777, 0o664)

    def test_symlink_to_permissive_target_warns_no_chmod(self):
        """Never chmod through a symlink; target may not be ours."""
        with TemporaryDirectory() as d:
            dp = Path(d)
            target = self._make_file(dp, 0o664)
            link = dp / "models.json.link"
            link.symlink_to(target)
            notice = _tighten_config_perms(link)
            self.assertIsNotNone(notice)
            self.assertTrue(notice.startswith("\u26a0"))
            self.assertIn("symlink", notice)
            self.assertEqual(target.stat().st_mode & 0o777, 0o664)

    def test_chmod_failure_falls_back_to_warning(self):
        # Patch `os.fchmod` (the new TOCTOU-safe call site) instead
        # of `os.chmod`. Pre-fix the function used `os.chmod` which
        # follows symlinks; batch 250 switched to open(O_NOFOLLOW)
        # + fchmod to close the swap-symlink-mid-call race.
        with TemporaryDirectory() as d:
            p = self._make_file(Path(d), 0o644)
            with mock_module_attribute(_mock_owner('core.startup.init'), 'os', 'fchmod', side_effect=PermissionError("denied")):
                notice = _tighten_config_perms(p)
            self.assertTrue(notice.startswith("\u26a0"))
            self.assertIn("chmod failed", notice)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "platform lacks mkfifo")
    def test_fifo_warns_without_opening(self):
        # A FIFO with no writer blocks any O_RDONLY open forever \u2014
        # the guard must refuse before reaching the open.
        with TemporaryDirectory() as d:
            p = Path(d) / "models.json"
            os.mkfifo(p, 0o644)
            notice = _tighten_config_perms(p)
            self.assertIsNotNone(notice)
            self.assertTrue(notice.startswith("\u26a0"))
            self.assertIn("not a regular file", notice)

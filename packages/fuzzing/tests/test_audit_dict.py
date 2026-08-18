"""Tests for /fuzz's discovery of audit-generated dictionaries (P39)."""

from __future__ import annotations

import sys
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from packages.fuzzing.audit_dict import (
    DICT_FILENAME,
    MAX_DICT_BYTES,
    discover_audit_dict,
)


def _write_dict(run_dir: Path, content: str = 'magic="\\xde\\xad"\n'):
    run_dir.mkdir(parents=True, exist_ok=True)
    path = run_dir / DICT_FILENAME
    path.write_text(content)
    return path


class TestDiscoverAuditDict:
    def test_own_run_dir_wins(self, tmp_path):
        own = tmp_path / "fuzz_run"
        own_dict = _write_dict(own)
        _write_dict(tmp_path / "audit_run")
        assert discover_audit_dict(own) == own_dict

    def test_newest_sibling_selected(self, tmp_path):
        own = tmp_path / "fuzz_run"
        own.mkdir()
        old = _write_dict(tmp_path / "audit_old")
        new = _write_dict(tmp_path / "audit_new")
        past = time.time() - 3600
        import os

        os.utime(old, (past, past))
        assert discover_audit_dict(own) == new

    def test_nothing_found_returns_none(self, tmp_path):
        own = tmp_path / "fuzz_run"
        own.mkdir()
        assert discover_audit_dict(own) is None

    def test_none_out_dir(self):
        assert discover_audit_dict(None) is None

    def test_oversized_dict_rejected(self, tmp_path):
        own = tmp_path / "fuzz_run"
        _write_dict(own, "x" * (MAX_DICT_BYTES + 1))
        assert discover_audit_dict(own) is None

    def test_empty_dict_rejected(self, tmp_path):
        own = tmp_path / "fuzz_run"
        _write_dict(own, "")
        assert discover_audit_dict(own) is None


class TestResolveDictPath:
    def test_operator_dict_wins(self, tmp_path):
        import raptor_fuzzing

        args = SimpleNamespace(dict=str(tmp_path / "mine.dict"))
        with patch(
            "packages.fuzzing.audit_dict.discover_audit_dict",
        ) as mock_discover:
            resolved = raptor_fuzzing._resolve_dict_path(args, tmp_path)
        assert resolved == tmp_path / "mine.dict"
        mock_discover.assert_not_called()

    def test_falls_back_to_discovery(self, tmp_path):
        import raptor_fuzzing

        own = tmp_path / "fuzz_run"
        found = _write_dict(own)
        args = SimpleNamespace(dict=None)
        assert raptor_fuzzing._resolve_dict_path(args, own) == found

    def test_no_dict_anywhere_is_none(self, tmp_path):
        import raptor_fuzzing

        own = tmp_path / "fuzz_run"
        own.mkdir()
        args = SimpleNamespace(dict=None)
        assert raptor_fuzzing._resolve_dict_path(args, own) is None

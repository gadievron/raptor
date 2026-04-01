"""Tests for CodeQL database manager build command handling."""

import stat
import subprocess as sp
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from packages.codeql.build_detector import BuildSystem
from packages.codeql.database_manager import DatabaseManager


@pytest.fixture
def db_manager(tmp_path):
    """Create a DatabaseManager with a fake codeql binary."""
    with patch.object(DatabaseManager, '__init__', lambda self: None):
        mgr = DatabaseManager()
        mgr.codeql_cli = "/usr/bin/codeql"
        mgr.cache_dir = tmp_path / "cache"
        mgr.cache_dir.mkdir()
        return mgr


def _run_create(db_manager, tmp_path, command, language="javascript"):
    """Run create_database and capture the subprocess command and script state."""
    bs = BuildSystem(type="npm", command=command, working_dir=tmp_path,
                     env_vars={}, confidence=1.0, detected_files=[])
    captured = {"cmd": [], "script_content": None, "script_mode": None}

    def fake_run(cmd, **kwargs):
        # Only capture the database create call, not codeql version etc.
        if "database" in cmd or "create" in cmd:
            captured["cmd"] = list(cmd)
            for arg in cmd:
                p = Path(str(arg))
                if p.name.startswith(".raptor_codeql_build_") and p.exists():
                    captured["script_content"] = p.read_text()
                    captured["script_mode"] = p.stat().st_mode
        r = MagicMock()
        r.returncode = 0
        r.stdout = "2.16.0"
        return r

    db_path = tmp_path / "db"
    with patch('subprocess.run', side_effect=fake_run), \
         patch.object(db_manager, '_count_database_files', return_value=0), \
         patch.object(db_manager, 'save_metadata'), \
         patch.object(db_manager, 'get_cached_database', return_value=None), \
         patch.object(db_manager, 'compute_repo_hash', return_value='abc'), \
         patch.object(db_manager, 'get_database_dir', return_value=db_path):
        db_manager.create_database(tmp_path, language, bs)

    return captured


class TestBuildScript:
    """CodeQL --command is always wrapped in a build script."""

    def test_simple_command_passed_directly(self, db_manager, tmp_path):
        """Single-word commands like 'make' pass through without a script."""
        c = _run_create(db_manager, tmp_path, "make")
        assert c["script_content"] is None
        idx = c["cmd"].index("--command")
        assert c["cmd"][idx + 1] == "make"

    def test_shell_operators_wrapped(self, db_manager, tmp_path):
        c = _run_create(db_manager, tmp_path, "npm install && npm run build")
        assert "npm install && npm run build" in c["script_content"]

    def test_or_operator_wrapped(self, db_manager, tmp_path):
        c = _run_create(db_manager, tmp_path, "pip install -e . || pip install -r requirements.txt")
        assert "||" in c["script_content"]

    def test_script_has_shebang(self, db_manager, tmp_path):
        c = _run_create(db_manager, tmp_path, "cmake . && make")
        assert c["script_content"].startswith("#!/bin/bash\n")

    def test_script_is_executable(self, db_manager, tmp_path):
        c = _run_create(db_manager, tmp_path, "npm install && npm run build")
        assert c["script_mode"] & stat.S_IEXEC

    def test_script_passed_as_command_arg(self, db_manager, tmp_path):
        c = _run_create(db_manager, tmp_path, "cmake . && make")
        assert "--command" in c["cmd"]
        idx = c["cmd"].index("--command")
        assert ".raptor_codeql_build_" in c["cmd"][idx + 1]

    def test_no_command_equals_format(self, db_manager, tmp_path):
        """Never uses --command=value (the old broken format)."""
        c = _run_create(db_manager, tmp_path, "make")
        assert not any(arg.startswith("--command=") for arg in c["cmd"])

    def test_script_cleaned_up_after_success(self, db_manager, tmp_path):
        _run_create(db_manager, tmp_path, "npm install && npm run build")
        assert not list(tmp_path.glob(".raptor_codeql_build_*"))

    def test_script_cleaned_up_on_failure(self, db_manager, tmp_path):
        bs = BuildSystem(type="npm", command="npm install", working_dir=tmp_path,
                         env_vars={}, confidence=1.0, detected_files=[])

        def fake_run(cmd, **kwargs):
            r = MagicMock()
            r.returncode = 1
            r.stderr = "fail"
            return r

        db_path = tmp_path / "db"
        with patch('subprocess.run', side_effect=fake_run), \
             patch.object(db_manager, '_count_database_files', return_value=0), \
             patch.object(db_manager, 'save_metadata'), \
             patch.object(db_manager, 'get_cached_database', return_value=None), \
             patch.object(db_manager, 'compute_repo_hash', return_value='abc'), \
             patch.object(db_manager, 'get_database_dir', return_value=db_path):
            db_manager.create_database(tmp_path, "javascript", bs)

        assert not list(tmp_path.glob(".raptor_codeql_build_*"))

    def test_script_cleaned_up_on_timeout(self, db_manager, tmp_path):
        bs = BuildSystem(type="npm", command="npm install", working_dir=tmp_path,
                         env_vars={}, confidence=1.0, detected_files=[])

        db_path = tmp_path / "db"
        with patch('subprocess.run', side_effect=sp.TimeoutExpired("cmd", 60)), \
             patch.object(db_manager, 'get_cached_database', return_value=None), \
             patch.object(db_manager, 'compute_repo_hash', return_value='abc'), \
             patch.object(db_manager, 'get_database_dir', return_value=db_path):
            db_manager.create_database(tmp_path, "javascript", bs)

        assert not list(tmp_path.glob(".raptor_codeql_build_*"))

    def test_empty_command_no_script(self, db_manager, tmp_path):
        bs = BuildSystem(type="no-build", command="", working_dir=tmp_path,
                         env_vars={}, confidence=1.0, detected_files=[])

        captured_cmd = []

        def fake_run(cmd, **kwargs):
            nonlocal captured_cmd
            captured_cmd = list(cmd)
            r = MagicMock()
            r.returncode = 0
            return r

        db_path = tmp_path / "db"
        with patch('subprocess.run', side_effect=fake_run), \
             patch.object(db_manager, '_count_database_files', return_value=0), \
             patch.object(db_manager, 'save_metadata'), \
             patch.object(db_manager, 'get_cached_database', return_value=None), \
             patch.object(db_manager, 'compute_repo_hash', return_value='abc'), \
             patch.object(db_manager, 'get_database_dir', return_value=db_path):
            db_manager.create_database(tmp_path, "python", bs)

        assert "--command" not in captured_cmd
        assert not list(tmp_path.glob(".raptor_codeql_build_*"))

"""Traced-build wrapper placement: the shell-compound build wrapper must
be exec-visible inside the sandbox WITHOUT living in a mount the traced
build can write.

The sandbox's mount namespace exposes the mounted host trees only —
target= (the repo, read) and output= (the staging DB parent, rw) plus
the tool_paths dirs (read-only, exec-capable binds). The wrapper's
directory rides in via tool_paths: visible to CodeQL's tracer, immutable
to the repo-controlled build, and never inside the rw output mount
(a wrapper dir under a target-writable mount is a cross-run
symlink-plant window against the parent's unsandboxed
mkdir/mkstemp/write). These tests are fully mocked — no codeql CLI, no
sandbox, no network.
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# packages/codeql/tests/test_traced_build_wrapper_location.py -> repo root
sys.path.insert(0, str(Path(__file__).parents[3]))

from core.build.build_detector import BuildSystem
from packages.codeql.database_manager import DatabaseManager


@pytest.fixture
def db_manager(tmp_path):
    """DatabaseManager with a fake codeql binary (no __init__ probing)."""
    with patch.object(DatabaseManager, '__init__', lambda self: None):
        mgr = DatabaseManager()
        mgr.codeql_cli = "/usr/bin/codeql"
        mgr.db_root = tmp_path / "cache"
        mgr.db_root.mkdir()
        return mgr


def _compound_build_system(tmp_path):
    # `&&` forces the wrapper-script path: codeql splits --command on
    # whitespace without shell interpretation, so shell operators need
    # the bash wrapper.
    return BuildSystem(
        type="make", command="make clean && make -j2", working_dir=tmp_path,
        env_vars={}, confidence=1.0, detected_files=[],
    )


def _run_traced_create(db_manager, tmp_path):
    """Run a traced create with a capturing fake sandbox.

    The repo tree and the DB cache slot are deliberately DISJOINT dirs
    (like production: the cache never lives inside the scanned repo) so
    the containment assertions can tell the mounts apart.
    """
    captured: dict = {}
    repo = tmp_path / "repo"
    repo.mkdir(exist_ok=True)

    def fake_run(cmd, **kwargs):
        if "database" in cmd and "create" in cmd:
            captured["cmd"] = list(cmd)
            captured["kwargs"] = dict(kwargs)
            if "--command" in cmd:
                script = Path(cmd[cmd.index("--command") + 1])
                # Recorded at exec time: the wrapper must exist on the
                # host while the sandboxed build runs.
                captured["script_exists_at_exec"] = script.exists()
        r = MagicMock()
        r.returncode = 0
        r.stdout = ""
        r.stderr = ""
        return r

    db_path = db_manager.db_root / "abc" / "cpp-db"
    db_path.parent.mkdir(parents=True, exist_ok=True)
    with patch('core.sandbox.run', side_effect=fake_run), \
         patch.object(db_manager, 'get_codeql_version', return_value="2.26.3"), \
         patch.object(db_manager, '_count_database_files', return_value=0), \
         patch.object(db_manager, 'save_metadata'), \
         patch.object(db_manager, 'get_cached_database', return_value=None), \
         patch.object(db_manager, 'compute_repo_hash', return_value='abc'), \
         patch.object(db_manager, 'get_database_dir', return_value=db_path):
        result = db_manager.create_database(
            repo, "cpp", _compound_build_system(repo),
            traced_build=True,
        )
    return result, captured


def _wrapper_path(captured) -> Path:
    cmd = captured["cmd"]
    assert "--command" in cmd
    return Path(cmd[cmd.index("--command") + 1])


class TestTracedBuildWrapperLocation:
    def test_wrapper_dir_is_passed_via_tool_paths(self, db_manager, tmp_path):
        result, captured = _run_traced_create(db_manager, tmp_path)
        assert result.success
        script = _wrapper_path(captured)
        tool_paths = [Path(p) for p in captured["kwargs"]["tool_paths"]]
        # The load-bearing invariant: the wrapper's own directory is one
        # of the tool_paths binds, so the mount namespace exposes it to
        # CodeQL's tracer (read-only, exec-capable).
        assert script.parent in tool_paths
        assert captured["script_exists_at_exec"] is True
        # The codeql install dir bind survives alongside.
        assert Path(db_manager.codeql_cli).resolve().parent in tool_paths

    def test_wrapper_never_inside_sandbox_rw_or_target_mounts(
            self, db_manager, tmp_path):
        # The rw output= mount belongs to the traced build; a wrapper
        # dir inside it (or the repo) would be writable by
        # repo-controlled code — persistence surface plus a symlink-
        # plant window against the parent's unsandboxed
        # mkdir/mkstemp/write on the next run.
        _result, captured = _run_traced_create(db_manager, tmp_path)
        script = _wrapper_path(captured)
        output_mount = Path(captured["kwargs"]["output"]).resolve()
        target_mount = Path(captured["kwargs"]["target"]).resolve()
        wrapper_dir = script.parent.resolve()
        assert not wrapper_dir.is_relative_to(output_mount)
        assert not wrapper_dir.is_relative_to(target_mount)

    def test_wrapper_lives_under_the_managed_db_root_scratch(
            self, db_manager, tmp_path):
        _result, captured = _run_traced_create(db_manager, tmp_path)
        script = _wrapper_path(captured)
        assert script.parent == db_manager.db_root / "tmp"

    def test_wrapper_removed_after_run(self, db_manager, tmp_path):
        _result, captured = _run_traced_create(db_manager, tmp_path)
        script = _wrapper_path(captured)
        assert not script.exists()

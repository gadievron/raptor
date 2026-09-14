"""Synthesised-build cleanup must survive a database-creation failure.

The cleanup paths (.raptor_build_* script + build dir) live UNDER the
scanned repo. If an exception escapes create_databases_parallel and
the sweep is skipped, the build script leaks into the target tree and
the next scan inventories RAPTOR's own build script as project source
(the scenario core/build's test_synthesis_failure_cleanup.py pins for
the synthesis phase; this pins the consumer's database-creation
phase).
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

from core.build.build_detector import BuildSystem


def _agent(tmp_path: Path):
    from packages.codeql.agent import CodeQLAgent
    agent = CodeQLAgent.__new__(CodeQLAgent)
    agent.repo_path = tmp_path
    agent.out_dir = tmp_path / "out"
    agent.start_time = 0.0
    agent.language_detector = MagicMock()
    agent.build_detector = MagicMock()
    agent.database_manager = MagicMock()
    agent.query_runner = MagicMock()
    return agent


def test_cleanup_paths_swept_when_database_creation_raises(tmp_path):
    script = tmp_path / ".raptor_build_abc.py"
    script.write_text("print('build')\n", encoding="utf-8")
    build_dir = tmp_path / ".raptor_build_dir"
    build_dir.mkdir()
    (build_dir / "obj.o").write_text("", encoding="utf-8")

    agent = _agent(tmp_path)
    agent.build_detector.detect_build_system.return_value = None
    agent.build_detector.synthesise_build_command.return_value = BuildSystem(
        type="synthesised",
        command=f"python3 {script}",
        working_dir=tmp_path,
        env_vars={},
        confidence=0.7,
        detected_files=[],
        cleanup_paths=[script, build_dir],
    )
    agent.database_manager.create_databases_parallel.side_effect = (
        RuntimeError("database creation exploded")
    )

    with patch(
        "core.sage.hooks.recall_context_for_codeql_build", return_value=[],
    ):
        result = agent.run_autonomous_analysis(
            languages=["cpp"], traced_build=True,
        )

    # The workflow-level handler converts the exception into a failure
    # result; the synthesised artifacts must still be gone from the
    # scanned repo.
    assert result.success is False
    assert not script.exists(), (
        "synthesised build script leaked into the scanned repo after a "
        "database-creation failure"
    )
    assert not build_dir.exists(), (
        "synthesised build dir leaked into the scanned repo after a "
        "database-creation failure"
    )


def test_cleanup_paths_swept_on_success(tmp_path):
    """Control: the sweep still runs on the successful path."""
    script = tmp_path / ".raptor_build_ok.py"
    script.write_text("print('build')\n", encoding="utf-8")

    agent = _agent(tmp_path)
    agent.build_detector.detect_build_system.return_value = None
    agent.build_detector.synthesise_build_command.return_value = BuildSystem(
        type="synthesised",
        command=f"python3 {script}",
        working_dir=tmp_path,
        env_vars={},
        confidence=0.7,
        detected_files=[],
        cleanup_paths=[script],
    )
    agent.database_manager.create_databases_parallel.return_value = {}

    with patch(
        "core.sage.hooks.recall_context_for_codeql_build", return_value=[],
    ):
        agent.run_autonomous_analysis(languages=["cpp"], traced_build=True)

    assert not script.exists()

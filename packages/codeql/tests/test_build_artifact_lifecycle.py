"""The workflow owns build scratch even before database creation starts."""

from unittest.mock import patch

import pytest

from core.build.build_detector import BuildSystem
from packages.codeql.tests.test_cleanup_paths_exception_safe import _agent


@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("stage", ["detect", "synthesise", "validate", "database"])
def test_workflow_failure_reclaims_previously_owned_build(tmp_path, error, stage):
    script = tmp_path / ".raptor_build_first.py"
    script.write_text("build")
    build_dir = tmp_path / ".raptor_build_first"
    build_dir.mkdir()
    (build_dir / "object.o").write_bytes(b"object")
    build = BuildSystem(
        "synthesised", "build", tmp_path, {}, 0.7, [], [script, build_dir]
    )
    agent = _agent(tmp_path)
    failure = error("later stage failed")
    if stage == "validate":
        agent.build_detector.detect_build_system.return_value = build
        agent.build_detector.validate_build_command.side_effect = failure
    elif stage == "database":
        agent.build_detector.detect_build_system.return_value = None
        agent.build_detector.synthesise_build_command.return_value = build
        agent.database_manager.create_databases_parallel.side_effect = failure
    else:
        agent.build_detector.detect_build_system.side_effect = [
            None,
            failure if stage == "detect" else None,
        ]
        agent.build_detector.synthesise_build_command.side_effect = [build, failure]
    with patch("core.sage.hooks.recall_context_for_codeql_build", return_value=[]):
        if error is RuntimeError:
            result = agent.run_autonomous_analysis(
                languages=["cpp", "java"], traced_build=True
            )
            assert not result.success
        else:
            with pytest.raises(error) as caught:
                agent.run_autonomous_analysis(
                    languages=["cpp", "java"], traced_build=True
                )
            assert caught.value is failure
    assert not script.exists()
    assert not build_dir.exists()


@pytest.mark.parametrize("mode", [0, 0o500, 0o555])
def test_workflow_reclaims_restricted_build_after_database_use(tmp_path, mode):
    from core.testing.restricted_tree import restricted_tree

    agent = _agent(tmp_path)
    build_dir = tmp_path / ".raptor_build_objects"
    with restricted_tree(build_dir, mode):
        build = BuildSystem("synthesised", "build", tmp_path, {}, 0.7, [], [build_dir])
        agent.build_detector.detect_build_system.return_value = None
        agent.build_detector.synthesise_build_command.return_value = build

        def create(*args, **kwargs):
            assert build_dir.exists(), (
                "scratch must survive until database creation finishes"
            )
            return {}

        agent.database_manager.create_databases_parallel.side_effect = create
        with patch("core.sage.hooks.recall_context_for_codeql_build", return_value=[]):
            result = agent.run_autonomous_analysis(languages=["cpp"], traced_build=True)
        assert not result.success  # No database in this fixture.
        assert not build_dir.exists()


def test_rejected_detected_build_still_releases_owned_artifacts(tmp_path):
    script = tmp_path / ".raptor_build_rejected.py"
    script.write_text("build")
    build = BuildSystem("synthesised", "build", tmp_path, {}, 0.7, [], [script])
    agent = _agent(tmp_path)
    agent.build_detector.detect_build_system.return_value = build
    agent.build_detector.validate_build_command.return_value = False
    agent.database_manager.create_databases_parallel.return_value = {}
    with patch("core.sage.hooks.recall_context_for_codeql_build", return_value=[]):
        agent.run_autonomous_analysis(languages=["cpp"], traced_build=True)
    assert not script.exists()


def test_workflow_retries_only_failed_removals(tmp_path, monkeypatch):
    from pathlib import Path

    first = tmp_path / ".raptor_build_busy.py"
    second = tmp_path / ".raptor_build_other.py"
    first.write_text("first")
    second.write_text("second")
    build = BuildSystem("synthesised", "build", tmp_path, {}, 0.7, [], [first, second])
    agent = _agent(tmp_path)
    agent.build_detector.detect_build_system.return_value = None
    agent.build_detector.synthesise_build_command.return_value = build
    agent.database_manager.create_databases_parallel.return_value = {}
    unlink = Path.unlink
    attempts = []

    def busy_once(path, *args, **kwargs):
        if path in (first, second):
            attempts.append(path)
            if path == first and attempts.count(first) == 1:
                raise PermissionError("busy")
        return unlink(path, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", busy_once)
    with patch("core.sage.hooks.recall_context_for_codeql_build", return_value=[]):
        agent.run_autonomous_analysis(languages=["cpp"], traced_build=True)
    assert attempts == [first, second, first]
    assert not first.exists()
    assert not second.exists()

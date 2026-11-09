"""Workflow errors survive secondary build-scratch cleanup interruptions."""
from unittest.mock import patch

import pytest

from core.build import artifacts
from core.build.build_detector import BuildSystem
from packages.codeql.tests.test_cleanup_paths_exception_safe import _agent


@pytest.mark.parametrize('stage', ['validate', 'database'])
@pytest.mark.parametrize('primary_type', [KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize('cleanup_type', [RuntimeError, KeyboardInterrupt, SystemExit])
def test_workflow_preserves_primary_and_attempts_remaining_paths(tmp_path, monkeypatch, stage, primary_type, cleanup_type):
    held = tmp_path / '.raptor_build_objects'
    held.mkdir()
    other = tmp_path / '.raptor_build_script.py'
    other.write_text('owned script')
    build = BuildSystem('synthesised', 'build', tmp_path, {}, 0.7, [], [held, other])
    agent = _agent(tmp_path)
    primary = primary_type('owned workflow failure')
    secondary = cleanup_type('owned cleanup interruption')
    agent.build_detector.detect_build_system.return_value = build
    if stage == 'validate':
        agent.build_detector.validate_build_command.side_effect = primary
    else:
        agent.build_detector.validate_build_command.return_value = True
        agent.database_manager.create_databases_parallel.side_effect = primary
    remove = artifacts.rmtree_hardened
    attempts = []

    def cleanup(path):
        attempts.append(path)
        if len(attempts) == 1:
            raise secondary
        return remove(path)

    with monkeypatch.context() as scope:
        scope.setattr(artifacts, 'rmtree_hardened', cleanup)
        with patch('core.sage.hooks.recall_context_for_codeql_build', return_value=[]):
            with pytest.raises(primary_type) as caught:
                agent.run_autonomous_analysis(languages=['cpp'], traced_build=True)
        assert caught.value is primary
        assert not other.exists()
    if held.exists():
        assert remove(held)


def test_new_workflow_cleanup_cancellation_still_propagates(tmp_path, monkeypatch):
    held = tmp_path / '.raptor_build_objects'
    held.mkdir()
    other = tmp_path / '.raptor_build_script.py'
    other.write_text('owned script')
    build = BuildSystem('synthesised', 'build', tmp_path, {}, 0.7, [], [held, other])
    agent = _agent(tmp_path)
    agent.build_detector.detect_build_system.return_value = None
    agent.build_detector.synthesise_build_command.return_value = build
    agent.database_manager.create_databases_parallel.return_value = {}
    failure = KeyboardInterrupt('new cleanup cancellation')
    remove = artifacts.rmtree_hardened
    attempts = []

    def cleanup(path):
        attempts.append(path)
        if len(attempts) == 1:
            raise failure
        return remove(path)

    monkeypatch.setattr(artifacts, 'rmtree_hardened', cleanup)
    with patch('core.sage.hooks.recall_context_for_codeql_build', return_value=[]):
        with pytest.raises(KeyboardInterrupt) as caught:
            agent.run_autonomous_analysis(languages=['cpp'], traced_build=True)
    assert caught.value is failure
    assert not other.exists()
    assert not held.exists()

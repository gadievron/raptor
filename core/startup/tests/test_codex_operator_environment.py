"""Restore fake operator settings through real, live broker IPC."""
import json
import os
import subprocess
import sys

import pytest

from core.config import RaptorConfig
from core.project import sessions
from core.startup import codex_environment as environment
from core.startup import codex_operator_environment as operator
from core.startup.tests.test_codex_broker import host  # noqa: F401

pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='live Linux owner fixture')


def test_operator_vocabulary_reuses_shared_policy(monkeypatch):
    for key in (*RaptorConfig.LLM_API_KEY_VARS, *RaptorConfig.LLM_ROUTING_ENV_VARS,
                'RAPTOR_CONFIG', 'RAPTOR_OUT_DIR', 'RAPTOR_BEDROCK_MODEL'):
        assert operator.allowed_name(key)
    for key in ('BASH_ENV', 'PYTHONPATH', 'LD_PRELOAD', 'RAPTOR_SESSION_TOKEN',
                'RAPTOR_LLM_TOKEN_FD', 'RAPTOR_LLM_SOCKET', 'RAPTOR_DIR'):
        assert not operator.allowed_name(key)


@pytest.mark.parametrize('hidden_owner', [False, True])
def test_filtered_dispatch_recovers_launch_settings(request, monkeypatch, hidden_owner):
    # Set before starting the broker so filtering happens after publication.
    values = {'RAPTOR_CONFIG': '/operator/models.json',
              'RAPTOR_OUT_DIR': '/operator/results', 'GEMINI_API_KEY': 'fake-key',
              'AWS_PROFILE': 'fixture-profile', 'RAPTOR_CC_MODEL': 'fixture-model'}
    for key, value in values.items():
        monkeypatch.setenv(key, value)
    monkeypatch.delenv('OPENAI_API_KEY', raising=False)
    sid, process, _credential = request.getfixturevalue('host')
    for key in values:
        monkeypatch.delenv(key)
    monkeypatch.setenv('OPENAI_API_KEY', 'stale-caller-value')
    if hidden_owner:
        monkeypatch.setattr(sessions, 'resolve_codex_owner_pid', lambda: None)
    restored = environment.restore(sid)
    assert {key: restored[key] for key in values} == values
    assert 'OPENAI_API_KEY' not in os.environ
    context_file = environment._context_directory() / environment._name(sid, process.pid)
    assert 'fake-key' not in context_file.read_text()
    assert 'RAPTOR_CONFIG' not in context_file.read_text()


def test_two_independent_filtered_processes_use_the_same_snapshot(request, monkeypatch):
    monkeypatch.setenv('RAPTOR_CONFIG', '/operator/models.json')
    monkeypatch.setenv('GEMINI_API_KEY', 'fake-key')
    sid, _process, _credential = request.getfixturevalue('host')
    code = ('import sys, os, json; sys.path.insert(0, sys.argv[1]); '
            'import core.startup.process_init; '
            'print(json.dumps([os.environ.get("RAPTOR_CONFIG"), '
            'os.environ.get("GEMINI_API_KEY")]))')
    env = {'HOME': os.environ['HOME'], 'PATH': os.environ['PATH'],
           'CODEX_THREAD_ID': sid, 'RAPTOR_CODEX_ENVIRONMENT': '1'}
    for _ in range(2):
        result = subprocess.run([sys.executable, '-I', '-c', code, str(environment.ROOT)],
                                env=env, capture_output=True, text=True, timeout=10)
        assert result.returncode == 0, result.stderr
        assert json.loads(result.stdout) == ['/operator/models.json', 'fake-key']


def test_trusted_credentials_are_still_stripped_from_target_environments(request, monkeypatch):
    monkeypatch.setenv('GEMINI_API_KEY', 'fake-key')
    monkeypatch.setenv('AWS_PROFILE', 'fixture-profile')
    sid, _process, _credential = request.getfixturevalue('host')
    environment.restore(sid)
    target = RaptorConfig.get_safe_env()
    RaptorConfig.strip_llm_env_vars(target)
    assert 'GEMINI_API_KEY' not in target
    assert 'AWS_PROFILE' not in target

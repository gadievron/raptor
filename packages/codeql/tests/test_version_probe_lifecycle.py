"""CodeQL compatibility and database metadata use the same version facts."""

import os
import subprocess
from unittest.mock import Mock

import pytest

from core.run import toolprobe
from packages.codeql import version_probe
from packages.codeql.database_manager import DatabaseManager
from packages.codeql.query_runner import QueryRunner


@pytest.mark.parametrize('stdout,stderr,expected', [
    pytest.param('CodeQL command-line toolchain release 2.20.1.\n', '', '2.20.1', id='stdout'),
    pytest.param('', 'CodeQL command-line toolchain release 2.20.1.\n', '2.20.1', id='stderr'),
    pytest.param('Java 21.0.2\n', 'CodeQL command-line toolchain release 2.14.6.\n',
                 '2.14.6', id='dependency-version'),
    pytest.param('21.0.2\n', 'CodeQL command-line toolchain release 2.14.6.\n',
                 '2.14.6', id='named-banner-preferred'),
    pytest.param('2.20.1\n', '', '2.20.1', id='bare-wrapper'),
    pytest.param('Java 21.0.2\n', '', None, id='dependency-only'),
    pytest.param('CodeQL command-line toolchain release 2.20.1.\n',
                 'CodeQL command-line toolchain release 2.14.6.\n', None, id='conflicting-banners'),
    pytest.param('CodeQL command-line toolchain release 2.20.1-rc1.\n', '', None, id='prerelease'),
    pytest.param('garbage' * 10000, '2.20.1', None, id='oversized-output'),
])
def test_version_parser_accepts_only_unambiguous_codeql_facts(stdout, stderr, expected):
    assert version_probe.parse_version_output(stdout, stderr) == expected


@pytest.fixture
def binary(tmp_path):
    path = tmp_path / 'codeql'
    path.write_text('#!/bin/sh\nexit 0\n')
    path.chmod(0o755)
    return path


def test_query_cache_retries_failure_and_invalidates_launcher_replacement(binary, monkeypatch):
    from core.config import RaptorConfig
    monkeypatch.setattr(RaptorConfig, 'CODEQL_THREAT_MODELS_ENABLED', True)
    monkeypatch.setattr(RaptorConfig, 'CODEQL_THREAT_MODELS', ('local',))
    runner = QueryRunner(codeql_cli=str(binary))
    read = Mock(side_effect=[None, '2.20.1', '2.14.6'])
    monkeypatch.setattr(version_probe, 'read_codeql_version', read)
    assert runner.active_threat_models() == ()
    assert runner.active_threat_models() == ('local',)
    assert runner._codeql_version() == '2.20.1'
    assert runner.active_threat_models() == ('local',)
    before = binary.stat()
    replacement = binary.with_name('replacement')
    replacement.write_bytes(binary.read_bytes())
    os.utime(replacement, ns=(before.st_atime_ns, before.st_mtime_ns))
    replacement.replace(binary)
    assert runner.active_threat_models() == ()
    assert runner._codeql_version() == '2.14.6'
    assert read.call_count == 3


def test_all_codeql_consumers_use_the_shared_reader(binary, monkeypatch):
    import packages.codeql as codeql
    runner = QueryRunner(codeql_cli=str(binary))
    manager = DatabaseManager.__new__(DatabaseManager)
    manager.codeql_cli = str(binary)
    read = Mock(return_value='2.20.1')
    monkeypatch.setattr(version_probe, 'read_codeql_version', read)
    monkeypatch.setattr(codeql, '_resolve_cli', lambda: str(binary))
    assert runner._codeql_version() == manager.get_codeql_version() == codeql.version() == '2.20.1'
    assert len(read.call_args_list) == 3
    assert all(call.args == (str(binary),) for call in read.call_args_list)


def test_shared_probe_keeps_resolved_path_safe_env_root_cwd_and_temporary_wrapper(binary, monkeypatch):
    wrapped = []
    calls = []
    wrapper_path = binary.with_name('trusted-wrapper')
    wrapper_path.write_text('#!/bin/sh\nexit 0\n')
    wrapper_path.chmod(0o755)
    def wrapper(command):
        wrapped.append(command)
        return [str(wrapper_path), *command]
    def run(command, **kwargs):
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(command, 0,
            stdout='CodeQL command-line toolchain release 2.20.1.\n', stderr='')
    monkeypatch.setattr(version_probe, 'temporary_command', wrapper)
    monkeypatch.setattr(toolprobe.subprocess, 'run', run)
    monkeypatch.setenv('LD_PRELOAD', '/hostile/inject.so')
    assert version_probe.read_codeql_version(str(binary)) == '2.20.1'
    assert wrapped == [[str(binary), 'version']]
    command, options = calls[0]
    assert command == [str(wrapper_path), str(binary), 'version']
    assert options['cwd'] == os.sep and options['timeout'] == 10
    assert 'LD_PRELOAD' not in options['env']


def test_failed_probe_banner_is_not_a_usable_version(binary, monkeypatch):
    monkeypatch.setattr(toolprobe.subprocess, 'run', lambda command, **kwargs:
        subprocess.CompletedProcess(command, 1,
            stdout='CodeQL command-line toolchain release 9.0.0.\n', stderr='failed'))
    assert version_probe.read_codeql_version(str(binary)) is None

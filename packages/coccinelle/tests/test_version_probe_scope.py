"""Rule sweeps reuse only successful versions of the same pinned executable."""

import os
import subprocess
from unittest.mock import Mock

import pytest

from core.analysis.rule_versions import rule_version_refusal
from core.run.toolprobe import ToolInfo
from packages.coccinelle import runner


@pytest.fixture
def binary(tmp_path, monkeypatch):
    path = tmp_path / 'spatch'
    path.write_text('initial')
    path.chmod(0o755)
    monkeypatch.setattr(runner, '_spatch_path', lambda: str(path))
    return path


@pytest.mark.parametrize('stdout,stderr,returncode,expected', [
    pytest.param('spatch version 1.3 compiled with OCaml\n', '', 0,
                 '1.3 compiled with OCaml', id='stdout-banner'),
    pytest.param('', 'spatch version 1.3.0\n', 0, '1.3.0', id='stderr-banner'),
    pytest.param('4.14.1\n', 'spatch version 1.1.1\n', 0, '1.1.1', id='ignore-dependency-version'),
    pytest.param('spatch version 9.0.0\n', '', 1, None, id='failed-probe'),
    pytest.param('spatch version 9.0.0\n', '', None, None, id='incomplete-probe'),
    pytest.param('4.14.1\n', '', 0, None, id='unrecognized-banner'),
    pytest.param('spatch version 1.3.0-rc1\n', '', 0, None, id='prerelease'),
    pytest.param('spatch version 1.3\n', 'spatch version 1.1.1\n', 0,
                 None, id='conflicting-banners'),
    pytest.param('spatch version 1.3\n', 'spatch version 1.3.0 compiled with OCaml\n', 0,
                 '1.3', id='equivalent-banners'),
])
def test_only_successful_unambiguous_spatch_versions_are_accepted(binary, monkeypatch, stdout, stderr,
                                                                 returncode, expected):
    probe = Mock(return_value=ToolInfo('spatch', str(binary), stdout=stdout, stderr=stderr,
                                     returncode=returncode))
    monkeypatch.setattr(runner, 'probe', probe)
    assert runner.version() == expected
    probe.assert_called_once_with(str(binary))


def test_success_is_reused_only_within_the_current_sweep(binary, monkeypatch):
    version = Mock(return_value='1.3')
    monkeypatch.setattr(runner, 'version', version)
    installed = runner._rule_version_probe()
    for _ in range(100):
        assert installed() == '1.3'
    version.assert_called_once()
    assert runner._rule_version_probe()() == '1.3'
    assert version.call_count == 2


@pytest.mark.parametrize('first', [None, 'unknown'], ids=['failed', 'unparseable'])
def test_unsuccessful_answers_are_not_sticky(binary, monkeypatch, first):
    version = Mock(side_effect=[first, '1.3'])
    monkeypatch.setattr(runner, 'version', version)
    installed = runner._rule_version_probe()
    assert installed() == first
    assert installed() == installed() == '1.3'
    assert version.call_count == 2


@pytest.mark.parametrize('replace', [False, True], ids=['in-place-rewrite', 'atomic-replacement'])
def test_executable_changes_invalidate_even_when_size_and_mtime_match(binary, monkeypatch, replace):
    version = Mock(side_effect=['1.3', '1.1.1'])
    monkeypatch.setattr(runner, 'version', version)
    installed = runner._rule_version_probe()
    assert installed() == '1.3'
    before = binary.stat()
    if replace:
        replacement = binary.with_name('replacement')
        replacement.write_text('changed')
        replacement.replace(binary)
    else:
        binary.write_text('changed')
    os.utime(binary, ns=(before.st_atime_ns, before.st_mtime_ns))
    assert binary.stat().st_size == before.st_size
    assert binary.stat().st_mtime_ns == before.st_mtime_ns
    refusal = rule_version_refusal('// raptor-min-version: 1.3.0\n@r@', installed)
    assert refusal and 'installed 1.1.1' in refusal
    assert version.call_count == 2


def test_binary_disappearance_does_not_reuse_the_old_answer(binary, monkeypatch):
    version = Mock(side_effect=['1.3', None])
    monkeypatch.setattr(runner, 'version', version)
    installed = runner._rule_version_probe()
    assert installed() == '1.3'
    binary.unlink()
    assert installed() is None
    assert version.call_count == 2


def test_change_during_probe_cannot_authorize_a_rule(binary, monkeypatch):
    calls = []
    def version():
        calls.append(1)
        if len(calls) == 1:
            binary.write_text('changed')
            return '1.3'
        return '1.1.1'
    monkeypatch.setattr(runner, 'version', version)
    installed = runner._rule_version_probe()
    assert installed() is None
    assert installed() == '1.1.1'
    assert len(calls) == 2



@pytest.mark.parametrize('mode', ['sequential', 'batch', 'batch-retry'])
def test_rule_sweeps_share_one_successful_probe_through_fallbacks(binary, tmp_path, monkeypatch, mode):
    source = tmp_path / 'target.c'
    source.write_text('void f() {}')
    rules = tmp_path / 'rules'
    rules.mkdir()
    for name, minimum in [('first', '1.3.0'), ('second', '1.3.0'), ('future', '1.4.0')]:
        (rules / f'{name}.cocci').write_text(
            f'// raptor-min-version: {minimum}\n@{name}@\nposition p;\n@@\nfoo@p(...)\n')
    monkeypatch.setattr(runner, 'is_available', lambda: True)
    version = Mock(return_value='1.3')
    monkeypatch.setattr(runner, 'version', version)
    calls = []
    def execute(cmd, **kwargs):
        calls.append(cmd)
        status = 1 if mode == 'batch-retry' and len(calls) == 1 else 0
        return subprocess.CompletedProcess(cmd, status, stdout='', stderr='')
    if mode == 'sequential':
        results = {result.rule: result for result in runner.run_rules(source, rules, subprocess_runner=execute)}
    else:
        results = runner.run_rules_batched(source, sorted(rules.glob('*.cocci')), subprocess_runner=execute)
    assert results['first'].ok and results['second'].ok
    assert not results['future'].ok and 'requires tool >= 1.4.0' in results['future'].errors[0]
    assert len(calls) == (3 if mode == 'batch-retry' else 1 if mode == 'batch' else 2)
    assert version.call_count == 1


def test_undeclared_rules_never_probe_the_version(binary, tmp_path, monkeypatch):
    rules = tmp_path / 'rules'
    rules.mkdir()
    for name in ['first', 'second']:
        (rules / f'{name}.cocci').write_text(f'@{name}@\nposition p;\n@@\nfoo@p(...)\n')
    source = tmp_path / 'target.c'
    source.write_text('void f() {}')
    monkeypatch.setattr(runner, 'is_available', lambda: True)
    version = Mock(side_effect=AssertionError('undeclared rules must not probe'))
    monkeypatch.setattr(runner, 'version', version)
    def execute(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, 0, stdout='', stderr='')
    results = runner.run_rules(source, rules, subprocess_runner=execute)
    assert len(results) == 2 and all(result.ok for result in results)
    version.assert_not_called()

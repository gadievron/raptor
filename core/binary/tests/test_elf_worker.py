"""A compromised ELF worker cannot send objects or unbounded facts to its parent."""
from dataclasses import asdict
import json
from pathlib import Path
import subprocess

import pytest

from core.binary import elf_worker as worker


def facts(**changes):
    result = dict(arch='amd64', bits=64, endian='little', os_abi='SYSV', relro='Full',
                  pie=True, nx=True, canary=True, fortify=True, has_gnu_stack=True,
                  checksec='RELRO: Full\nNX: enabled')
    result.update(changes)
    return result


def test_flat_scalar_record_and_unknown_nx_are_supported():
    value = facts(nx=None)
    result = worker._decode_facts(json.dumps(value).encode())
    assert result is not None and asdict(result) == value


@pytest.mark.parametrize('change', [
    {'bits': True}, {'bits': 128}, {'arch': '\x1b[2J'}, {'arch': 'a' * 65},
    {'pie': 1}, {'canary': 'true'}, {'fortify': []}, {'nx': 0}, {'endian': 'native'},
    {'relro': False}, {'os_abi': 'x' * 129}, {'checksec': 'x' * (worker._MAX_CHECKSEC_CHARS + 1)},
])
def test_bad_field_cannot_be_consumed(change):
    assert worker._decode_facts(json.dumps(facts(**change)).encode()) is None


@pytest.mark.parametrize('payload', [
    b'not JSON', b'[]', b'null', b'\xff', b'{"arch":"amd64","arch":"i386"}',
    b'[' * 10000 + b']' * 10000,
    json.dumps(dict(facts(), __reduce__=['os.system', 'owned'])).encode(),
])
def test_protocol_shapes_duplicates_and_depth_are_refused(payload):
    assert worker._decode_facts(payload) is None


def test_oversized_complete_prefix_is_refused():
    payload = json.dumps(facts()).encode()
    assert worker._decode_facts(payload + b' ' * worker._MAX_REPLY_BYTES) is None


def test_terminal_controls_in_checksec_are_escaped():
    result = worker._decode_facts(json.dumps(facts(checksec='ok\n\x1b]52;c;owned\x07')).encode())
    assert result is not None
    assert '\x1b' not in result.checksec and '\x07' not in result.checksec
    assert '\n' in result.checksec


@pytest.mark.parametrize('mode', ['success', 'nonzero', 'timeout', 'invalid', 'refusal'])
def test_request_policy_and_cleanup(tmp_path, monkeypatch, mode):
    from core import sandbox
    binary = tmp_path / 'source' / 'fixture'
    binary.parent.mkdir()
    binary.write_bytes(b'owned input')
    seen = []
    def run(command, **options):
        seen.append(options)
        assert command[0] == '/usr/bin/env'
        assert '-I' in command and '-B' in command
        assert str(worker._WORKER) in command
        assert options['target'] == options['output'] == options['cwd']
        assert Path(options['output']).is_dir()
        assert options['readable_paths'] == [str(binary.parent)]
        assert options['restrict_reads'] and options['fake_home'] and options['strip_trust_markers']
        assert options['_untrusted_workload'] and options['exclude_tmp_baseline']
        assert options['stdin'] == subprocess.DEVNULL
        assert options['start_new_session']
        assert options['limits']['memory_mb'] == 2048
        assert options['limits']['cpu_seconds'] == 10
        assert options['max_capture_bytes'] == worker._MAX_REPLY_BYTES + 1
        if mode == 'timeout':
            raise subprocess.TimeoutExpired(command, options['timeout'])
        if mode == 'refusal':
            raise sandbox.SandboxSetupError('owned refusal')
        return subprocess.CompletedProcess(command, 1 if mode == 'nonzero' else 0,
                                           b'bad' if mode == 'invalid' else json.dumps(facts()).encode(), b'')
    monkeypatch.setattr(sandbox, 'run', run)
    if mode == 'refusal':
        with pytest.raises(sandbox.SandboxSetupError, match='owned refusal'):
            worker.inspect_elf(binary)
    else:
        assert (worker.inspect_elf(binary) is not None) == (mode == 'success')
    assert seen and not Path(seen[0]['output']).exists()


def test_over_budget_or_nonregular_input_never_launches(tmp_path, monkeypatch):
    from core import sandbox
    def refuse(*args, **kwargs):
        pytest.fail('worker launched over rejected input')
    monkeypatch.setattr(sandbox, 'run', refuse)
    binary = tmp_path / 'large'
    with binary.open('wb') as stream:
        stream.truncate(worker.MAX_ELF_INPUT_BYTES + 1)
    assert worker.inspect_elf(binary) is None
    assert worker.inspect_elf(tmp_path) is None
    assert worker.inspect_elf(tmp_path / 'absent') is None


def test_user_site_is_declared_without_importing_it(tmp_path, monkeypatch):
    from core import sandbox
    binary = tmp_path / 'source' / 'fixture'
    binary.parent.mkdir()
    binary.write_bytes(b'owned')
    packages = tmp_path / 'installed-packages'
    packages.mkdir()
    marker = tmp_path / 'parent-hook-ran'
    (packages / 'owned.pth').write_text('import pathlib; pathlib.Path(' + repr(str(marker)) + ').write_text("owned")\n')
    monkeypatch.setattr(worker.site, 'getusersitepackages', lambda: str(packages))
    def run(command, **options):
        assert str(packages) in options['tool_paths'] and str(packages) in command
        return subprocess.CompletedProcess(command, 0, json.dumps(facts()).encode(), b'')
    monkeypatch.setattr(sandbox, 'run', run)
    assert worker.inspect_elf(binary)
    assert not marker.exists(), 'user-site startup hook ran in the parent'


def test_feasibility_has_no_parent_side_pwntools_imports():
    import ast
    root = Path(__file__).resolve().parents[3] / 'packages/exploit_feasibility'
    for name in ('analyzer.py', 'constants.py', 'strategies.py'):
        tree = ast.parse((root / name).read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                assert not (node.module or '').startswith(('pwn', 'elftools')), (name, node.lineno)
            if isinstance(node, ast.Import):
                assert not any(alias.name.startswith(('pwn', 'elftools')) for alias in node.names), (name, node.lineno)


def test_descriptor_input_reads_pinned_inode_without_reopening_alias(tmp_path):
    import os
    from core.binary._elf_worker_child import _DescriptorInput
    target = tmp_path / 'fixture'
    target.write_bytes(b'validated input')
    fd = os.open(target, os.O_RDONLY)
    try:
        replacement = tmp_path / 'replacement'
        replacement.write_bytes(b'replacement input')
        replacement.replace(target)
        argument = _DescriptorInput(os.dup(fd))
        assert os.fspath(argument) == 'input.elf'
        with open(argument, 'rb') as parsed:
            assert parsed.read() == b'validated input'
        # Closing the parser's duplicate does not close the validation fd.
        assert os.fstat(fd).st_size == len(b'validated input')
        assert target.read_bytes() == b'replacement input'
    finally:
        os.close(fd)


@pytest.mark.parametrize('platform', ['linux', 'darwin'])
@pytest.mark.parametrize('error_type', [OSError, ValueError])
def test_address_space_refusal_is_advisory_only_on_darwin(monkeypatch, capsys, platform, error_type):
    from core.binary import _elf_worker_child as child
    calls = []
    def limit(resource_id, value):
        calls.append((resource_id, value))
        if resource_id == child.resource.RLIMIT_AS:
            raise error_type('owned address-space refusal')
    monkeypatch.setattr(child.sys, 'platform', platform)
    monkeypatch.setattr(child, '_limit', limit)
    if platform == 'darwin':
        child._install_limits()
        assert calls == [(child.resource.RLIMIT_AS, 2048 * 1024 * 1024),
                         (child.resource.RLIMIT_CPU, 10)]
        assert 'memory bound is best effort' in capsys.readouterr().err
    else:
        with pytest.raises(error_type, match='owned address-space refusal'):
            child._install_limits()
        assert len(calls) == 1
        assert not capsys.readouterr().err


@pytest.mark.parametrize('platform', ['linux', 'darwin'])
def test_cpu_refusal_still_aborts_worker(monkeypatch, platform):
    from core.binary import _elf_worker_child as child
    calls = []
    def limit(resource_id, value):
        calls.append((resource_id, value))
        if resource_id == child.resource.RLIMIT_CPU:
            raise ValueError('owned CPU refusal')
    monkeypatch.setattr(child.sys, 'platform', platform)
    monkeypatch.setattr(child, '_limit', limit)
    with pytest.raises(ValueError, match='owned CPU refusal'):
        child._install_limits()
    assert calls == [(child.resource.RLIMIT_AS, 2048 * 1024 * 1024),
                     (child.resource.RLIMIT_CPU, 10)]


@pytest.mark.parametrize('error,expected', [
    (ModuleNotFoundError('owned', name='pwnlib'), 'ModuleNotFoundError (pwnlib)'),
    (ImportError('owned', name='dependency'), 'ImportError (dependency)'),
], ids=['missing-pwntools', 'broken-dependency'])
def test_dependency_failure_is_distinct_from_parser_failure(monkeypatch, capsys, error, expected):
    from core.binary import _elf_worker_child as child
    def fail(*args):
        raise error
    monkeypatch.setattr(child, '_collect', fail)
    monkeypatch.setattr(child.sys, 'argv', ['worker', 'fixture', '', '1024'])
    assert child.main() == 1
    captured = capsys.readouterr()
    assert not captured.out
    assert captured.err == 'ELF worker dependency import failed: ' + expected + '\n'


def test_parser_failure_does_not_claim_missing_dependency(monkeypatch, capsys):
    from core.binary import _elf_worker_child as child
    def fail(*args):
        raise ValueError('owned parser failure')
    monkeypatch.setattr(child, '_collect', fail)
    monkeypatch.setattr(child.sys, 'argv', ['worker', 'fixture', '', '1024'])
    assert child.main() == 1
    captured = capsys.readouterr()
    assert not captured.out
    assert captured.err == 'ELF worker failed: ValueError\n'

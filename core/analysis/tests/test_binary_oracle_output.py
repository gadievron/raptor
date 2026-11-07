"""The binary oracle consumes bytes, never child-selected output paths."""

import io
import os
from pathlib import Path
import subprocess

import pytest

from core.analysis import binary_oracle as oracle

from core.testing.module_bindings import patch_module_attribute


def _writer(monkeypatch, payload, *, status=0, stderr=''):
    from core import sandbox
    def run(command, **kwargs):
        descriptor, = kwargs['pass_fds']
        os.write(descriptor, payload)
        return subprocess.CompletedProcess(command, status, '', stderr)
    monkeypatch.setattr(sandbox, 'run', run)


def test_stream_preserves_universal_newlines_and_decode_replacement(monkeypatch):
    _writer(monkeypatch, b'first\r\nsecond\rthird\ninvalid:\xff\nlast')
    assert list(oracle._stream(['objdump', 'owned'], timeout=5)) == [
        'first', 'second', 'third', 'invalid:\ufffd', 'last']


def test_output_path_replacement_cannot_redirect_parent_read(tmp_path, monkeypatch):
    from core import sandbox
    secret = tmp_path / 'owned-secret'
    secret.write_text('SHOULD NEVER BE CONSUMED\n')
    def run(command, **kwargs):
        directory = Path(kwargs['output'])
        replacement = next((path for path in directory.iterdir() if path.name.startswith('stdout')),
                           directory / 'stdout.txt')
        if kwargs.get('pass_fds'):
            os.write(kwargs['pass_fds'][0], b'owned stdout\n')
        else:
            # The retired pathname-based implementation fails this test by
            # consuming the replacement after the child exits successfully.
            replacement.write_bytes(b'owned stdout\n')
        replacement.unlink(missing_ok=True)
        replacement.symlink_to(secret)
        return subprocess.CompletedProcess(command, 0, '', '')
    monkeypatch.setattr(sandbox, 'run', run)
    assert list(oracle._stream(['objdump', 'owned'], timeout=5)) == ['owned stdout']
    assert secret.read_text() == 'SHOULD NEVER BE CONSUMED\n'


def test_reader_does_not_share_the_childs_seek_offset(tmp_path):
    with (tmp_path / 'owned-output').open('w+b') as output:
        output.write(b'owned bytes\n')
        output.flush()
        output.seek(1024 * 1024)
        with io.BufferedReader(oracle._OwnedOutputReader(output.fileno())) as reader:
            assert reader.read() == b'owned bytes\n'
        assert output.tell() == 1024 * 1024
        assert not output.closed


@pytest.mark.parametrize('mode', ['success', 'timeout', 'early-close', 'nonzero'])
def test_stream_closes_owned_descriptor_and_scratch(monkeypatch, mode):
    from core import sandbox
    files, directories, delegated = [], [], []
    original = oracle.tempfile.NamedTemporaryFile
    def temporary(*args, **kwargs):
        output = original(*args, **kwargs)
        files.append(output)
        return output
    def run(command, **kwargs):
        directories.append(Path(kwargs['output']))
        descriptor, = kwargs['pass_fds']
        info = os.fstat(descriptor)
        delegated.append((descriptor, info.st_dev, info.st_ino))
        os.write(kwargs['pass_fds'][0], b'first\nsecond\n')
        if mode == 'timeout':
            raise subprocess.TimeoutExpired(command, 5)
        return subprocess.CompletedProcess(command, 1 if mode == 'nonzero' else 0, '', '')
    patch_module_attribute(monkeypatch, oracle, 'tempfile', 'NamedTemporaryFile', temporary)
    monkeypatch.setattr(sandbox, 'run', run)
    iterator = oracle._stream(['objdump', 'owned'], timeout=5)
    if mode == 'early-close':
        assert next(iterator) == 'first'
        iterator.close()
    else:
        assert list(iterator) == (['first', 'second'] if mode == 'success' else [])
    assert files and all(output.closed for output in files)
    for descriptor, device, inode in delegated:
        try:
            current = os.fstat(descriptor)
        except OSError:
            continue
        assert (current.st_dev, current.st_ino) != (device, inode), 'delegated file leaked'
    assert directories and not any(path.exists() for path in directories)


def _partial_dwarf():
    return (b'<1><10>: Abbrev Number: 1 (DW_TAG_subprogram)\n'
            b' <11> DW_AT_name : already_parsed\n'
            b' <12> DW_AT_low_pc : 0x1000\n'
            b'<1><20>: Abbrev Number: 1 (DW_TAG_subprogram)\n')


def test_oversized_late_record_discards_prior_dwarf(monkeypatch):
    monkeypatch.setattr(oracle, '_MAX_STREAM_LINE_CHARS', 128)
    _writer(monkeypatch, _partial_dwarf() + b'x' * 129 + b'\n')
    assert oracle._parse_dwarf(Path('/owned/input')) == ({}, [])


def test_oversized_output_cannot_license_absent_suppression(tmp_path, monkeypatch):
    binary = tmp_path / 'input'
    binary.write_bytes(b'owned input')
    monkeypatch.setattr(oracle, '_MAX_STREAM_LINE_CHARS', 128)
    patch_module_attribute(monkeypatch, oracle, "shutil", "which", lambda tool: '/usr/bin/' + tool)
    monkeypatch.setattr(oracle, 'read_build_id', lambda path: 'owned-build-id')
    monkeypatch.setattr(oracle, '_nm_symbols_status', lambda path: ({'present': 123}, True))
    monkeypatch.setattr(oracle, '_dynamic_nm_symbols', lambda path: {})
    _writer(monkeypatch, _partial_dwarf() + b'x' * 129 + b'\n')
    result = oracle.classify_binary_evidence(['present', 'missing'], binary)
    assert result['present'].classification == 'symbol_present'
    assert result['missing'].classification == 'absent'
    assert result['missing'].tier == 'symbol_only'


def test_delegated_output_stays_above_closed_stdio(tmp_path):
    import json
    import sys
    from core.security.env_sanitisation import safe_subprocess_env
    root = Path(__file__).resolve().parents[3]
    home, scratch = tmp_path / 'home', tmp_path / 'scratch'
    home.mkdir()
    scratch.mkdir()
    report = tmp_path / 'report.json'
    program = r'''
import json, os, subprocess, sys, traceback
sys.path.insert(0, sys.argv[1])
from core import sandbox
from core.analysis import binary_oracle as oracle
report = open(sys.argv[2], 'w')
def run(command, **kwargs):
    descriptor, = kwargs['pass_fds']
    assert descriptor >= 3
    assert not os.get_inheritable(descriptor)
    for number in (0, 1, 2):
        try: os.fstat(number)
        except OSError: pass
        else: raise AssertionError('closed stdio was not restored')
    os.write(descriptor, b'owned stdout\n')
    return subprocess.CompletedProcess(command, 0, '', '')
sandbox.run = run
for descriptor in (0, 1, 2): os.close(descriptor)
try: result = {'lines': list(oracle._stream(['objdump', 'owned'], timeout=5))}
except BaseException: result = {'error': traceback.format_exc()}
json.dump(result, report)
report.close()
'''
    env = safe_subprocess_env(strip_target_markers=True)
    env.update(HOME=str(home), TMPDIR=str(scratch))
    result = subprocess.run([sys.executable, '-I', '-c', program, str(root), str(report)],
                            cwd=home, env=env, capture_output=True, text=True, timeout=20)
    assert result.returncode == 0, result.stderr
    assert json.loads(report.read_text()) == {'lines': ['owned stdout']}

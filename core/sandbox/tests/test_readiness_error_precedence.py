"""Readiness owners preserve active failures through native pipe retirement."""

import ast
import errno
import os
from pathlib import Path
import sys
from types import ModuleType

import pytest

from core.sandbox import _spawn as spawn
from core.sandbox.errors import SandboxSetupError


pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='Linux readiness owner')


def _readiness_block(site, reader, private_os):
    # Exercise the production block and its nested owner verbatim, without
    # launching a setup child or recreating the readiness implementation.
    tree = ast.parse(Path(spawn.__file__).read_text())
    descriptor = 'p_ready_r' if site == 'child' else 't_ready_r'
    blocks = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Try):
            continue
        cleanup = node.finalbody + node.orelse
        for handler in node.handlers:
            cleanup += handler.body
        if (f'os.set_blocking({descriptor}, False)' in ast.unparse(node)
                and f'_close_parent_fd({descriptor})' in ast.unparse(
                    ast.Module(body=cleanup, type_ignores=[]))):
            blocks.append(node)
    owners = [node for node in ast.walk(tree)
              if isinstance(node, ast.FunctionDef) and node.name == '_close_parent_fd']
    assert len(blocks) == len(owners) == 1
    wrapper = ast.parse('def exercise():\n    pass\n').body[0]
    wrapper.body = blocks
    wrapper.end_lineno = blocks[0].end_lineno
    bindings = dict(vars(spawn))
    owned = {reader}
    bindings.update(os=private_os, _parent_fds=owned,
                    close_death_w=lambda fd: False, **{descriptor: reader})
    module = ast.fix_missing_locations(ast.Module(body=[owners[0], wrapper], type_ignores=[]))
    exec(compile(module, spawn.__file__, 'exec'), bindings)
    return bindings['exercise'], owned


@pytest.mark.parametrize('site', ['child', 'tracer'])
@pytest.mark.parametrize('primary_kind', ['setup', 'interrupt', 'none', 'ambient'])
@pytest.mark.parametrize('cleanup_type', [OSError, KeyboardInterrupt], ids=['io', 'interrupt'])
def test_readiness_cleanup_preserves_operation_or_fresh_error(site, primary_kind, cleanup_type):
    primary = {'setup': SandboxSetupError('owned readiness refusal'),
               'interrupt': KeyboardInterrupt('owned readiness interruption'),
               'none': None, 'ambient': None}[primary_kind]
    cleanup = cleanup_type('owned post-close interruption')
    reader, writer = os.pipe()
    identities = {fd: (os.fstat(fd).st_dev, os.fstat(fd).st_ino) for fd in (reader, writer)}
    operations = []
    private_os = ModuleType('owned_readiness_os')
    vars(private_os).update(vars(os))

    def set_blocking(fd, value):
        assert fd == reader and value is False
        os.set_blocking(fd, value)
        operations.append('flags')
        if primary is not None:
            raise primary

    def read(fd, size):
        assert fd == reader and size == 1
        data = os.read(fd, size)
        assert data == b'R'
        operations.append('read')
        return data

    def close(fd):
        assert fd == reader
        os.close(fd)
        operations.append('close')
        raise cleanup

    private_os.set_blocking = set_blocking
    private_os.read = read
    private_os.close = close
    try:
        os.write(writer, b'R')
        exercise, owned = _readiness_block(site, reader, private_os)
        expected = primary if primary is not None else cleanup
        if primary_kind == 'ambient':
            try:
                raise ValueError('owned caller exception already being handled')
            except ValueError:
                with pytest.raises(BaseException) as caught:
                    exercise()
        else:
            with pytest.raises(BaseException) as caught:
                exercise()
        assert caught.value is expected
        assert not owned
        assert operations == (['flags', 'close'] if primary is not None
                              else ['flags', 'read', 'close'])
        with pytest.raises(OSError) as closed:
            os.fstat(reader)
        assert closed.value.errno == errno.EBADF
        assert os.fstat(writer)
    finally:
        for fd, identity in identities.items():
            try:
                info = os.fstat(fd)
            except OSError as error:
                if error.errno != errno.EBADF:
                    raise
                continue
            if (info.st_dev, info.st_ino) == identity:
                os.close(fd)

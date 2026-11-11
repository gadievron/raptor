"""Release-pipe cleanup preserves write errors and fresh close failures."""

import ast
import errno
import os
from pathlib import Path
import signal
import sys
from types import ModuleType

import pytest

from core.sandbox import _spawn as spawn


pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='Linux release pipe')


def _go_block(writer, private_os):
    tree = ast.parse(Path(spawn.__file__).read_text())
    blocks = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Try):
            continue
        cleanup = node.finalbody + node.orelse
        for handler in node.handlers:
            cleanup += handler.body
        if ('os.write(p_go_w,' in ast.unparse(node)
                and '_close_parent_fd(p_go_w)' in ast.unparse(
                    ast.Module(body=cleanup, type_ignores=[]))):
            blocks.append(node)
    owners = [node for node in ast.walk(tree)
              if isinstance(node, ast.FunctionDef) and node.name == '_close_parent_fd']
    assert len(blocks) == len(owners) == 1
    wrapper = ast.parse('def exercise():\n    pass\n').body[0]
    wrapper.body = blocks
    wrapper.end_lineno = blocks[0].end_lineno
    owned = {writer}
    bindings = dict(vars(spawn))
    bindings.update(os=private_os, _parent_fds=owned, p_go_w=writer,
                    close_death_w=lambda fd: False)
    module = ast.fix_missing_locations(ast.Module(body=[owners[0], wrapper], type_ignores=[]))
    exec(compile(module, spawn.__file__, 'exec'), bindings)
    return bindings['exercise'], owned


@pytest.mark.parametrize('mode', ['broken-pipe', 'interrupt', 'none', 'ambient'])
@pytest.mark.parametrize('cleanup_type', [OSError, KeyboardInterrupt], ids=['io', 'interrupt'])
def test_release_pipe_preserves_operation_or_fresh_error(mode, cleanup_type):
    assert signal.getsignal(signal.SIGPIPE) == signal.SIG_IGN
    primary = KeyboardInterrupt('owned write interruption')
    cleanup = cleanup_type('owned post-close interruption')
    reader, writer = os.pipe()
    identities = {fd: (os.fstat(fd).st_dev, os.fstat(fd).st_ino) for fd in (reader, writer)}
    operations, broken = [], []
    private_os = ModuleType('owned_release_os')
    vars(private_os).update(vars(os))

    def write(fd, data):
        assert fd == writer and data == b'G'
        operations.append('write')
        try:
            written = os.write(fd, data)
        except BrokenPipeError as error:
            broken.append(error)
            raise
        assert written == 1
        if mode == 'interrupt':
            raise primary
        return written

    def close(fd):
        assert fd == writer
        os.close(fd)
        operations.append('close')
        raise cleanup

    private_os.write = write
    private_os.close = close
    try:
        if mode == 'broken-pipe':
            os.close(reader)
        exercise, owned = _go_block(writer, private_os)
        if mode == 'ambient':
            try:
                raise ValueError('owned caller exception already being handled')
            except ValueError:
                with pytest.raises(BaseException) as caught:
                    exercise()
        else:
            with pytest.raises(BaseException) as caught:
                exercise()
        if mode == 'broken-pipe':
            assert len(broken) == 1 and broken[0].errno == errno.EPIPE
            assert caught.value is broken[0]
        else:
            assert not broken
            assert caught.value is (primary if mode == 'interrupt' else cleanup)
            assert os.read(reader, 1) == b'G'
        assert operations == ['write', 'close']
        assert not owned
        with pytest.raises(OSError) as closed:
            os.fstat(writer)
        assert closed.value.errno == errno.EBADF
        assert signal.getsignal(signal.SIGPIPE) == signal.SIG_IGN
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

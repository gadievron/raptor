"""Exercise real checked-hash caches without importing compiled sources."""
import importlib.util
import marshal
from pathlib import Path
import py_compile
from types import CodeType

import pytest

from core.testing.module_bindings import mock_module_attribute

SPEC = importlib.util.spec_from_file_location(
    'checked_bytecode', Path(__file__).resolve().parents[1] / 'compile_checked_bytecode.py',
)
compiler = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(compiler)


def cache_path(source):
    return Path(importlib.util.cache_from_source(str(source)))


def test_warm_cache_survives_mtime_churn_and_rebuilds_only_changed_source(tmp_path):
    first, second = tmp_path / 'first.py', tmp_path / 'second.py'
    first.write_text('value = 1\n')
    second.write_text('value = 2\n')
    assert compiler.main([str(tmp_path)]) == 0
    first.touch()
    second.touch()
    with mock_module_attribute(compiler, 'compileall', 'compile_file',
                               wraps=compiler.compileall.compile_file) as compile_file:
        assert compiler.main([str(tmp_path)]) == 0
        compile_file.assert_not_called()
        first.write_text('value = 3\n')
        assert compiler.main([str(tmp_path)]) == 0
        assert compile_file.call_args_list[0].args == (str(first),)
        assert compile_file.call_count == 1
    code = marshal.loads(cache_path(first).read_bytes()[16:])
    assert isinstance(code, CodeType)
    assert 3 in code.co_consts


@pytest.mark.parametrize('damage', ['magic', 'hash', 'truncated', 'payload', 'timestamp', 'unchecked'])
def test_invalid_cache_is_rebuilt_as_checked_hash(tmp_path, damage):
    source = tmp_path / 'example.py'
    source.write_text('value = 42\n')
    assert compiler.main([str(source)]) == 0
    pyc = cache_path(source)
    data = pyc.read_bytes()
    if damage == 'magic':
        pyc.write_bytes(b'bad!' + data[4:])
    elif damage == 'hash':
        pyc.write_bytes(data[:8] + b'wrong!!!' + data[16:])
    elif damage == 'truncated':
        pyc.write_bytes(data[:17])
    elif damage == 'payload':
        pyc.write_bytes(data[:16] + marshal.dumps(42))
    else:
        mode = (py_compile.PycInvalidationMode.TIMESTAMP if damage == 'timestamp'
                else py_compile.PycInvalidationMode.UNCHECKED_HASH)
        py_compile.compile(str(source), invalidation_mode=mode, doraise=True)
    assert not compiler.is_current(source)
    with mock_module_attribute(compiler, 'compileall', 'compile_file',
                               wraps=compiler.compileall.compile_file) as compile_file:
        assert compiler.main([str(source)]) == 0
        compile_file.assert_called_once()
    assert pyc.read_bytes()[4:8] == b'\x03\x00\x00\x00'
    assert compiler.is_current(source)


def test_syntax_and_missing_roots_fail(tmp_path):
    source = tmp_path / 'broken.py'
    source.write_text('def broken(\n')
    assert compiler.main([str(source)]) == 1
    assert not compiler.is_current(source)
    assert compiler.main([str(tmp_path / 'missing')]) == 1
    assert compiler.main([]) == 1


def test_scan_avoids_cache_and_directory_symlinks_without_executing_source(tmp_path):
    tree = tmp_path / 'source with spaces'
    tree.mkdir()
    marker = tmp_path / 'executed'
    source = tree / 'example.py'
    source.write_text(f'from pathlib import Path\nPath({str(marker)!r}).touch()\n')
    ignored = tree / '__pycache__'
    ignored.mkdir()
    (ignored / 'broken.py').write_text('def invalid(\n')
    external = tmp_path / 'outside'
    external.mkdir()
    (external / 'broken.py').write_text('def invalid(\n')
    (tree / 'linked').symlink_to(external, target_is_directory=True)
    assert compiler.main([str(tree)]) == 0
    assert compiler.is_current(source)
    assert not marker.exists()
    assert not cache_path(external / 'broken.py').exists()

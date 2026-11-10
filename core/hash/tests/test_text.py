"""Native text hashing declines foreign protocols without invoking them."""
import builtins
import hashlib
from pathlib import Path
from types import SimpleNamespace, ModuleType

import pytest

from core.hash import text as original
from core.testing.module_views import module_function_view


@pytest.mark.parametrize('size', [0, 1, 262143, 262144, 262145, 327681])
def test_native_threshold_and_digest(size):
    text = 'a' * size
    result = original.try_sha256_ascii(text, hashlib)
    eligible = (size >= original._MIN_CHARS
                and original._NATIVE_SHA256 is not None
                and hashlib.sha256 is original._NATIVE_SHA256)
    assert result == (hashlib.sha256(text.encode()).hexdigest() if eligible else None)


@pytest.mark.parametrize('text', ['é' * 300000, 'x' * 300000 + '\udcff'])
def test_non_ascii_declines_without_partial_encoding(text):
    assert original.try_sha256_ascii(text, hashlib) is None


def test_foreign_protocols_are_not_probed():
    class Text(str):
        def encode(self, *args):
            pytest.fail('adapter encode was invoked by eligibility')

        def isascii(self):
            pytest.fail('adapter isascii was invoked by eligibility')

    class Backend(ModuleType):
        def __getattribute__(self, name):
            pytest.fail('backend attribute lookup was invoked by eligibility')

    assert original.try_sha256_ascii(Text('x' * 300000), hashlib) is None
    assert original.try_sha256_ascii('x' * 300000, Backend('owned')) is None


def test_absent_native_constructor_declines():
    view = module_function_view(original, bindings={'_NATIVE_SHA256': None})
    assert view.try_sha256_ascii('x' * 300000, hashlib) is None


@pytest.mark.parametrize('constructor', [lambda data: None, hashlib.sha1])
def test_adapted_backend_before_private_import_is_not_trusted(constructor):
    def imports(name, *args, **kwargs):
        if name == '_hashlib':
            return SimpleNamespace(openssl_sha256=constructor)
        return builtins.__import__(name, *args, **kwargs)

    namespace = {'__name__': original.__name__, '__package__': original.__package__,
                 '__builtins__': dict(vars(builtins), __import__=imports)}
    exec(compile(Path(original.__file__).read_text(), original.__file__, 'exec'), namespace)
    assert namespace['_NATIVE_SHA256'] is None
    assert namespace['try_sha256_ascii']('x' * 300000, hashlib) is None
    assert namespace['try_sha256_utf8_replace']('é' * 300000, hashlib) is None


@pytest.mark.parametrize('kind', ['object', 'str-subclass'])
def test_native_constructor_metadata_is_not_compared(kind, tmp_path):
    import os
    import subprocess
    import sys

    from core.testing.standalone_cli import run_standalone_cli

    root = Path(__file__).resolve().parents[3]
    code = """
import _hashlib
import hashlib
from pathlib import Path
from core.hash import text
calls = []
class Metadata:
    def __eq__(self, other):
        calls.append('eq')
        raise RuntimeError('metadata callback')
class TextMetadata(str):
    def __eq__(self, other):
        calls.append('eq')
        raise RuntimeError('metadata callback')
previous = _hashlib.openssl_sha256.__module__
try:
    _hashlib.openssl_sha256.__module__ = Metadata() if sys.argv[1] == 'object' else TextMetadata('_hashlib')
    namespace = {'__name__': text.__name__, '__package__': text.__package__}
    exec(compile(Path(text.__file__).read_text(), text.__file__, 'exec'), namespace)
    assert namespace['_NATIVE_SHA256'] is None
    source = 'a' * 300000
    assert namespace['try_sha256_ascii'](source, hashlib) is None
    from core.coverage import journal_mac
    from core.json import dumps_canonical
    from core.testing.module_views import module_function_view
    consumer = module_function_view(journal_mac, bindings={
        'try_sha256_ascii': namespace['try_sha256_ascii'],
    })
    row = {'body': source, journal_mac.TOKEN_KEY: 'excluded-token'}
    expected = hashlib.sha256(dumps_canonical({'body': source}).encode('utf-8')).hexdigest()
    assert consumer.row_sha256(row) == expected
    assert calls == []
finally:
    _hashlib.openssl_sha256.__module__ = previous
"""
    env = dict(os.environ, HOME=str(tmp_path), XDG_CONFIG_HOME=str(tmp_path / 'config'),
               XDG_CACHE_HOME=str(tmp_path / 'cache'), XDG_DATA_HOME=str(tmp_path / 'data'))
    result = run_standalone_cli(
        [sys.executable, '-I', '-c', f'import sys; sys.path.insert(0, {str(root)!r})\n' + code, kind],
        cwd=tmp_path, env=env, stdin=subprocess.DEVNULL,
        capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize('fragment', ['é', '🙂', '\ud800', '\udcff', '\ud800\udfff', '\0'])
def test_replace_encoding_across_chunk_boundaries(fragment):
    # Put the fragment on both sides of an encoding chunk boundary. Surrogate
    # pairs remain two replacement bytes, including when split across chunks.
    text = ('a' * (original._CHUNK_CHARS - 1) + fragment) * 5
    result = original.try_sha256_utf8_replace(text, hashlib)
    eligible = (original._NATIVE_SHA256 is not None
                and hashlib.sha256 is original._NATIVE_SHA256
                and not any(0xd800 <= ord(char) <= 0xdfff for char in fragment))
    assert result == (hashlib.sha256(text.encode('utf-8', 'replace')).hexdigest()
                      if eligible else None)


def test_replace_helper_declines_adapters_and_borrowed_hash_backend():
    class Text(str):
        def encode(self, *args):
            pytest.fail('foreign encoder called by eligibility')

        def __getitem__(self, key):
            pytest.fail('foreign slice called by eligibility')

    class Backend(ModuleType):
        def __getattribute__(self, name):
            pytest.fail('foreign backend looked up by eligibility')

    assert original.try_sha256_utf8_replace(Text('é' * 300000), hashlib) is None
    assert original.try_sha256_utf8_replace('é' * 300000, Backend('owned')) is None
    view = module_function_view(original, bindings={'_NATIVE_SHA256': None})
    assert view.try_sha256_utf8_replace('é' * 300000, hashlib) is None


@pytest.mark.parametrize('size', [0, 262143, 262144, 262145])
def test_replace_helper_threshold(size):
    text = 'é' * size
    value = original.try_sha256_utf8_replace(text, hashlib)
    eligible = (size >= original._MIN_CHARS
                and original._NATIVE_SHA256 is not None
                and hashlib.sha256 is original._NATIVE_SHA256)
    assert value == (hashlib.sha256(text.encode('utf-8', 'replace')).hexdigest()
                     if eligible else None)

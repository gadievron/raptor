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

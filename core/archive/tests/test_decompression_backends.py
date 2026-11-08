"""Zstandard fallback is an import decision, never a second attempt after IO."""
from types import ModuleType

import pytest

from core.archive import compression
from core.archive.errors import ArchiveError
from core.testing.module_views import scoped_function_imports


def modules():
    # Distinct module names keep a missing fake attribute from resolving
    # through the host's compression.zstd in sys.modules.
    return {'compression': ModuleType('owned_compression_fixture'),
            'zstandard': ModuleType('owned_zstandard_fixture')}


@pytest.mark.parametrize('entry', ['direct', 'registry'])
@pytest.mark.parametrize('available', [False, True], ids=['fallback', 'native'])
def test_backend_selection_and_registry_use_private_imports(tmp_path, entry, available):
    source = tmp_path / 'source'
    source.write_bytes(b'payload')
    calls = []
    inherited_registry = compression._OPENERS
    inherited_opener = compression._zstd_open
    with scoped_function_imports(compression, ('_zstd_open',), modules(), registries=('_OPENERS',)) as imports:
        native = ModuleType('owned_native_zstd')
        def open_native(path, mode):
            calls.append(('native', path, mode))
            return path.open(mode)
        def open_fallback(path, mode):
            calls.append(('fallback', path, mode))
            return path.open(mode)
        native.open = open_native
        if available:
            imports.compression.zstd = native
        imports.zstandard.open = open_fallback
        assert compression._OPENERS is not inherited_registry
        assert compression._OPENERS['zst'] is compression._zstd_open
        if entry == 'direct':
            with compression._zstd_open(source) as reader:
                assert reader.read() == b'payload'
        else:
            assert compression.decompress_single(source, 'zst') == b'payload'
    assert calls == [('native' if available else 'fallback', source, 'rb')]
    assert compression._OPENERS is inherited_registry
    assert compression._zstd_open is inherited_opener


@pytest.mark.parametrize('entry', ['direct', 'registry'])
@pytest.mark.parametrize('failure_type', [OSError, ValueError, RuntimeError, KeyboardInterrupt, SystemExit])
def test_native_open_failure_does_not_invoke_fallback(tmp_path, entry, failure_type):
    failure = failure_type('native open failed')
    calls = []
    with scoped_function_imports(compression, ('_zstd_open',), modules(), registries=('_OPENERS',)) as imports:
        native = ModuleType('owned_native_zstd')
        def fail(*args, **kwargs):
            calls.append('native')
            raise failure
        def unexpected(*args, **kwargs):
            calls.append('fallback')
            raise AssertionError('operational failure invoked fallback')
        native.open = fail
        imports.compression.zstd = native
        imports.zstandard.open = unexpected
        expected = ArchiveError if entry == 'registry' and isinstance(failure, Exception) else failure_type
        with pytest.raises(expected) as caught:
            if entry == 'direct':
                compression._zstd_open(tmp_path / 'missing')
            else:
                compression.decompress_single(tmp_path / 'missing', 'zst')
        if expected is ArchiveError:
            assert caught.value.__cause__ is failure
        else:
            assert caught.value is failure
    assert calls == ['native']


@pytest.mark.parametrize('failure_type', [OSError, RuntimeError])
def test_native_import_error_other_than_importerror_does_not_fall_back(tmp_path, failure_type):
    failure = failure_type('native initialisation failed')
    calls = []
    with scoped_function_imports(compression, ('_zstd_open',), modules(), registries=('_OPENERS',)) as imports:
        def unavailable(name):
            if name == 'zstd':
                raise failure
            raise AttributeError(name)
        def unexpected(*args, **kwargs):
            calls.append(True)
            raise AssertionError('native initialisation invoked fallback')
        imports.compression.__getattr__ = unavailable
        imports.zstandard.open = unexpected
        with pytest.raises(failure_type) as caught:
            compression._zstd_open(tmp_path / 'missing')
        assert caught.value is failure
    assert calls == []

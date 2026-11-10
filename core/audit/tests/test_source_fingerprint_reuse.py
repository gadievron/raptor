"""Reusing local digests must retain the existing cache-key bytes."""

import hashlib
import random

import pytest

from core.audit.detector_cache import file_content_sha
from core.audit.prep_cache import source_fingerprint, source_fingerprint_from_hashes


@pytest.mark.parametrize("sources", [
    {}, {"a.c": ""}, {"a.c": "int f(void) { return 1; }\r\n"},
    {"é/🙂.py": "x = 'é🙂'\n", "nul\0.c": "a\0b"},
    {"\ud800.c": "unpaired surrogate \udfff", "z.c": "a\rb\n"},
    {"a.c": "same", "b.c": "same"},
])
def test_byte_identical_to_original_fingerprint(sources):
    hashes = {path: file_content_sha(text) for path, text in sources.items()}
    assert source_fingerprint_from_hashes(hashes) == source_fingerprint(sources)
    assert source_fingerprint_from_hashes(dict(reversed(list(hashes.items())))) == source_fingerprint(sources)


def test_randomized_differential():
    rng = random.Random(318)
    alphabet = "abc\r\n\0é🙂\ud800"
    for _ in range(200):
        sources = {f"{i}/file.c": ''.join(rng.choice(alphabet) for _ in range(rng.randrange(100)))
                   for i in range(rng.randrange(20))}
        hashes = {path: file_content_sha(text) for path, text in sources.items()}
        assert source_fingerprint_from_hashes(hashes) == source_fingerprint(sources)


def test_uses_binary_digest_not_hexadecimal_text():
    digest = hashlib.sha256(b"hello").digest()
    expected = hashlib.sha256(b"a.c\0" + digest).hexdigest()
    assert source_fingerprint_from_hashes({"a.c": digest.hex()}) == expected


def test_no_second_source_encoding():
    class CountedText(str):
        encodings = 0

        def encode(self, *args, **kwargs):
            self.encodings += 1
            return super().encode(*args, **kwargs)

    source = CountedText("a large immutable source string")
    hashes = {"a.c": file_content_sha(source)}
    assert source.encodings == 1
    source_fingerprint_from_hashes(hashes)
    assert source.encodings == 1


@pytest.mark.parametrize("digest", ["", "00" * 31, "00" * 33, "not-hex"],
                         ids=['empty', 'too-short', 'too-long', 'non-hex'])
def test_invalid_digests_fail_explicitly(digest):
    with pytest.raises(ValueError):
        source_fingerprint_from_hashes({"a.c": digest})


@pytest.mark.parametrize('fragment', ['plain', 'é🙂', '\ud800\udfff', '\0\r\n'])
def test_large_source_hash_keeps_replacement_encoding_and_cache_framing(fragment):
    sources = {'large.c': ('a' * 65535 + fragment) * 5, 'small.c': 'small'}
    expected = {path: hashlib.sha256(text.encode('utf-8', 'replace')).hexdigest()
                for path, text in sources.items()}
    actual = {path: file_content_sha(text) for path, text in sources.items()}
    assert actual == expected
    assert source_fingerprint_from_hashes(actual) == source_fingerprint(sources)


def test_large_source_adapter_retains_one_original_encode_call():
    calls = []

    class Source(str):
        def encode(self, *args, **kwargs):
            calls.append((args, kwargs))
            return b'owned adapter bytes'

        def __getitem__(self, key):
            pytest.fail('source adapter sliced')

    value = Source('é' * 300000)
    assert file_content_sha(value) == hashlib.sha256(b'owned adapter bytes').hexdigest()
    assert calls == [(('utf-8', 'replace'), {})]


def test_source_hash_foreign_backend_keeps_lookup_encode_call_order_and_error():
    from core.audit import detector_cache
    from core.testing.module_views import module_function_view

    calls = []
    sentinel = RuntimeError('owned encoding failure')

    class Source(str):
        def encode(self, *args):
            calls.append('encode')
            raise sentinel

    class Backend:
        @property
        def sha256(self):
            calls.append('lookup')
            return lambda data: pytest.fail('constructor reached after encoding failure')

    view = module_function_view(detector_cache, bindings={'hashlib': Backend()})
    with pytest.raises(RuntimeError) as raised:
        view.file_content_sha(Source('é' * 300000))
    assert raised.value is sentinel
    assert calls == ['lookup', 'encode']


def test_shared_encoder_changes_invalidate_detector_code_identity():
    from core.audit import detector_cache
    from core.testing.module_views import module_function_view

    source_bytes = {'core.hash.text': b'owned encoder version one'}
    view = module_function_view(detector_cache, bindings={
        'import_closure': lambda *args, **kwargs: frozenset(),
        '_detector_modules_memo': [],
        '_module_fp_memo': {},
        '_module_source_bytes': lambda name: source_bytes.get(name, b'other glue'),
    })
    assert 'core.hash.text' in view.detector_modules()
    before = view.detector_set_fingerprint()
    source_bytes['core.hash.text'] = b'owned encoder version two'
    view._module_fp_memo.clear()
    assert view.detector_set_fingerprint() != before


def test_registered_replacement_policy_retains_original_encoding_behavior(tmp_path):
    # Registry replacement is confined to a child process; the worker's codec
    # registry is never borrowed or mutated. Some Python UTF-8 encoders bypass
    # registered handlers for builtin error names; retain the original behaviour
    # whether the handler is consulted or the builtin replacement is used.
    import os
    from pathlib import Path
    import subprocess
    import sys

    from core.testing.standalone_cli import run_standalone_cli

    root = Path(__file__).resolve().parents[3]
    code = """
import codecs
import hashlib
from core.audit.detector_cache import file_content_sha
from core.hash.text import try_sha256_utf8_replace
source = 'a' * 300000 + '\\ud800'
calls = []
original = codecs.lookup_error('replace')
def handler(error):
    calls.append((len(error.object), error.start, error.end))
    return ('length=' + str(len(error.object)), error.end)
try:
    codecs.register_error('replace', handler)
    expected = hashlib.sha256(source.encode('utf-8', 'replace')).hexdigest()
    expected_calls = list(calls)
    calls.clear()
    assert try_sha256_utf8_replace(source, hashlib) is None
    assert calls == []
    assert file_content_sha(source) == expected
    assert calls == expected_calls
finally:
    codecs.register_error('replace', original)
"""
    env = dict(os.environ, HOME=str(tmp_path), XDG_CONFIG_HOME=str(tmp_path / 'config'),
               XDG_CACHE_HOME=str(tmp_path / 'cache'), XDG_DATA_HOME=str(tmp_path / 'data'))
    result = run_standalone_cli(
        [sys.executable, '-I', '-c', f'import sys; sys.path.insert(0, {str(root)!r})\n' + code],
        cwd=tmp_path, env=env, capture_output=True, text=True,
        stdin=subprocess.DEVNULL, timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr

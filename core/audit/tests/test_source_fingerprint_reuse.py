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

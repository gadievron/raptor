"""Bounded UTF-8 encoding for large native ASCII SHA-256 inputs.

This optional fast path hashes already-serialised text. Callers retain their
original expression when it returns None, preserving foreign encoders and
hash providers. It does not change sha256_string's surrogateescape contract.
"""

from __future__ import annotations

import hashlib
from types import BuiltinFunctionType, ModuleType
from typing import TYPE_CHECKING, cast

if TYPE_CHECKING:
    from collections.abc import Callable
    from _hashlib import HASH

_NATIVE_SHA256: Callable[[], HASH] | None = None
try:
    from _hashlib import openssl_sha256 as _openssl_sha256
except ImportError:
    pass
else:
    if (type(_openssl_sha256) is BuiltinFunctionType
            and _openssl_sha256.__module__ == "_hashlib"
            and _openssl_sha256.__name__ == "openssl_sha256"):
        _NATIVE_SHA256 = _openssl_sha256
    del _openssl_sha256

_HASHLIB_MODULE = hashlib
_TEXT_TYPE = str
_TYPE_IMPL = type
_LEN_IMPL = len
_RANGE_IMPL = range
_CHUNK_CHARS = 64 * 1024
_MIN_CHARS = 256 * 1024


def try_sha256_ascii(text: object, backend: object) -> str | None:
    """Hash large native ASCII text, or decline without provider callbacks.

Only the native hashlib module with its unchanged OpenSSL constructor is
admitted. Unknown backends, text adapters, small and non-ASCII strings stay
with the caller's original UTF-8 expression, including its error behaviour.
"""
    native = _NATIVE_SHA256
    if native is None or _TYPE_IMPL(text) is not _TEXT_TYPE:
        return None
    native_text = cast(str, text)
    if (_LEN_IMPL(native_text) < _MIN_CHARS or not native_text.isascii()
            or backend is not _HASHLIB_MODULE
            or _TYPE_IMPL(backend) is not ModuleType):
        return None
    constructor = _HASHLIB_MODULE.__dict__.get("sha256")
    if constructor is native and native is not None:
        digest = native()
        for offset in _RANGE_IMPL(0, _LEN_IMPL(native_text), _CHUNK_CHARS):
            digest.update(native_text[offset:offset + _CHUNK_CHARS].encode("utf-8"))
        return digest.hexdigest()
    # A borrowed callable may have a destructor; release it before fallback.
    del constructor
    return None

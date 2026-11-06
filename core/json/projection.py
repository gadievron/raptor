"""Strict bounded JSON-object projection, decoding top-level array rows one at a time.

Consumers can discard or compact large inventory rows while retaining a digest
of the complete original UTF-8 input. Discarded values receive the same duplicate
key, finite-number, Unicode and depth checks as retained values.
"""
from __future__ import annotations

import codecs
import hashlib
import json
import math

from core.json.utils import _reject_non_finite



def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _validate(value, depth=0, max_depth=128):
    pending = [(value, depth)]
    while pending:
        value, depth = pending.pop()
        if depth > max_depth:
            raise ValueError(f"JSON value nesting exceeds {max_depth}")
        if isinstance(value, dict):
            pending.extend((v, depth + 1) for v in value.values())
            pending.extend((k, depth + 1) for k in value)
        elif isinstance(value, list):
            pending.extend((v, depth + 1) for v in value)
        elif isinstance(value, float) and not math.isfinite(value):
            raise ValueError("non-finite JSON value")
        elif isinstance(value, str):
            value.encode("utf-8")


class _Reader:
    def __init__(self, stream, max_bytes, max_depth):
        self.max_depth = max_depth
        self.stream = stream
        self.max_bytes = max_bytes
        self.total = 0
        self.digest = hashlib.sha256()
        self.utf8 = codecs.getincrementaldecoder("utf-8-sig")("strict")
        self.decoder = json.JSONDecoder(object_pairs_hook=_unique, parse_constant=_reject_non_finite)
        self.buffer = ""
        self.eof = False

    def more(self, size=65536):
        if self.eof:
            return
        raw = self.stream.read(min(size, self.max_bytes - self.total + 1))
        self.total += len(raw)
        if self.total > self.max_bytes:
            raise ValueError("JSON input exceeds byte budget")
        self.digest.update(raw)
        self.eof = not raw
        self.buffer += self.utf8.decode(raw, final=self.eof)

    def peek(self):
        while True:
            self.buffer = self.buffer.lstrip(" \t\r\n")
            if self.buffer or self.eof:
                return self.buffer[:1]
            self.more()

    def expect(self, token):
        if self.peek() != token:
            raise ValueError("invalid JSON object/array separator")
        self.buffer = self.buffer[1:]

    def value(self, depth=0):
        self.peek()
        size = 65536
        while True:
            try:
                value, end = self.decoder.raw_decode(self.buffer)
            except json.JSONDecodeError:
                if self.eof:
                    raise ValueError("invalid or truncated JSON value") from None
            except RecursionError:
                raise ValueError("JSON value exceeds nesting limit") from None
            else:
                if end < len(self.buffer) and self.buffer[end] in " \t\r\n,:]}":
                    break
                if self.eof:
                    if end != len(self.buffer):
                        raise ValueError("invalid JSON value delimiter")
                    break
            self.more(size)
            size = min(size * 2, 8 * 1024 * 1024)
        self.buffer = self.buffer[end:]
        _validate(value, depth, self.max_depth)
        return value


def project_object(stream, *, max_bytes, projectors=None, observe=None, max_depth=128):
    """Return (projected object, original SHA-256), consuming through EOF.

    ``projectors`` maps top-level array names to row callables; a callable
    returning ``None`` discards that row. ``observe(key, value)`` sees every
    complete scalar/top-level-array row before projection. Neither callback
    runs on invalid JSON values. The caller owns and closes the binary stream.
    """
    if type(max_bytes) is not int or max_bytes < 1:
        raise ValueError("JSON projection requires a positive byte budget")
    if type(max_depth) is not int or not 1 <= max_depth <= 128:
        raise ValueError("JSON depth budget must be between 1 and 128")
    reader = _Reader(stream, max_bytes, max_depth)
    result = {}
    reader.expect("{")
    if reader.peek() != "}":
        while True:
            key = reader.value(1)
            if not isinstance(key, str) or key in result:
                raise ValueError("invalid or duplicate JSON object key")
            reader.expect(":")
            if reader.peek() == "[":
                reader.expect("[")
                rows = []
                project = (projectors or {}).get(key)
                count = 0
                if reader.peek() != "]":
                    while True:
                        value = reader.value(2)
                        if observe:
                            observe(key, value)
                        value = project(value) if project else value
                        if value is not None or project is None:
                            rows.append(value)
                        count += 1
                        if count > 1_000_000:
                            raise ValueError("JSON array exceeds row budget")
                        if reader.peek() == "]":
                            break
                        reader.expect(",")
                reader.expect("]")
                result[key] = rows
            else:
                value = reader.value(1)
                if observe:
                    observe(key, value)
                result[key] = value
            if reader.peek() == "}":
                break
            reader.expect(",")
    reader.expect("}")
    if reader.peek():
        raise ValueError("trailing JSON content")
    return result, reader.digest.hexdigest()

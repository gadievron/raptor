"""Bounded, read-only SBOM and evidence inputs; no extraction or external lookups."""
from __future__ import annotations

from contextlib import ExitStack, contextmanager
import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import zipfile

from core.json.projection import project_object
from core.source.beneath import open_regular_beneath
from core.source.gated import open_regular_gated
from core.source.streams import preserving_stream_error
from core.zip import bomb_shaped_reason, is_safe_member, peek_eocd

MAX_DOCUMENT_BYTES = 96 * 1024 * 1024
MAX_NOTICE_BYTES = 8 * 1024 * 1024
MAX_ARCHIVE_BYTES = 2 * 1024 * 1024 * 1024
SHA256 = re.compile(r"[a-f0-9]{64}\Z")


class Source:
    """Own the held archive/directory input for one operation."""

    def __init__(self, path: Path):
        self.path = path
        self.stack = ExitStack()
        self.archive = None
        self.bundle = path.is_dir() or path.suffix.lower() == ".zip"

    def __enter__(self):
        self._lifetime = preserving_stream_error(self.stack)
        self._lifetime.__enter__()
        try:
            if self.bundle and not self.path.is_dir():
                stream = self.stack.enter_context(open_regular_gated(self.path))
                summary = peek_eocd(stream)
                if summary is None or bomb_shaped_reason(summary):
                    raise ValueError("invalid or oversized evidence ZIP directory")
                self.archive = self.stack.enter_context(zipfile.ZipFile(stream))
                entries = self.archive.infolist()
                names = [item.filename for item in entries]
                if len(entries) > 10_000 or len(set(names)) != len(names):
                    raise ValueError("duplicate or excessive ZIP entries")
                if sum(item.file_size for item in entries) > MAX_ARCHIVE_BYTES:
                    raise ValueError("evidence ZIP exceeds total uncompressed size budget")
                if any(not is_safe_member(item, max_size=MAX_DOCUMENT_BYTES) for item in entries):
                    raise ValueError("unsafe or oversized evidence ZIP member")
            return self
        except BaseException as error:
            self._lifetime.__exit__(type(error), error, error.__traceback__)
            raise

    def __exit__(self, *args):
        return self._lifetime.__exit__(*args)

    def contains(self, name):
        if self.archive is not None:
            return name in self.archive.namelist()
        if self.bundle:
            from core.security.capped_read import path_may_exist
            return path_may_exist(self.path / name)
        return False

    @contextmanager
    def open(self, name="", max_bytes=MAX_DOCUMENT_BYTES):
        name = str(name)
        relative = PurePosixPath(name)
        if relative.is_absolute() or ".." in relative.parts or "\\" in name:
            raise ValueError("unsafe evidence reference")
        if not self.bundle:
            if name not in {"", "."}:
                raise ValueError("a standalone snapshot has no retained notice store; use its original SBOM/evidence input")
            stream = open_regular_gated(self.path)
        elif self.archive is not None:
            try:
                info = self.archive.getinfo(name)
            except KeyError:
                raise FileNotFoundError("missing evidence member: " + name) from None
            if info.file_size > max_bytes:
                raise ValueError("evidence member exceeds read budget")
            stream = self.archive.open(info)
        else:
            stream = open_regular_beneath(self.path.resolve(), name, "rb")
            if stream is None:
                raise ValueError("missing, nonregular or symlinked evidence member: " + name)
        with preserving_stream_error(stream):
            if self.archive is None and os.fstat(stream.fileno()).st_size > max_bytes:
                raise ValueError("evidence member exceeds read budget")
            yield stream

    def read(self, name, max_bytes=MAX_DOCUMENT_BYTES, *, raise_on_refusal=True):
        try:
            with self.open(name, max_bytes) as stream:
                raw = stream.read(max_bytes + 1)
        except (OSError, ValueError):
            raise
        except Exception as error:
            raise ValueError("unreadable evidence member: " + str(name)) from error
        if len(raw) > max_bytes:
            raise ValueError("evidence member exceeds read budget")
        return raw

    def read_json(self, name="", *, projectors=None, observe=None, max_bytes=MAX_DOCUMENT_BYTES):
        try:
            with self.open(name, max_bytes) as stream:
                return project_object(stream, max_bytes=max_bytes,
                                      projectors=projectors, observe=observe, max_depth=64)
        except (OSError, ValueError):
            raise
        except Exception as error:
            raise ValueError("unreadable evidence JSON member: " + str(name)) from error

    def blob(self, sha256):
        if not isinstance(sha256, str) or not SHA256.fullmatch(sha256):
            raise ValueError("invalid notice fingerprint")
        raw = self.read("prepared/notices/sha256/" + sha256, MAX_NOTICE_BYTES)
        if hashlib.sha256(raw).hexdigest() != sha256:
            raise ValueError("retained notice checksum mismatch")
        return raw

"""Bounded, read-only SBOM and evidence inputs; no extraction or external lookups."""
from __future__ import annotations

from contextlib import ExitStack
import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import zipfile

from core.oci.evidence import read_catalogue
from core.security.capped_read import read_capped
from core.source.beneath import open_regular_beneath
from core.source.gated import open_regular_gated
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
        except BaseException:
            self.stack.close()
            raise

    def __exit__(self, *args):
        return self.stack.__exit__(*args)

    def contains(self, name):
        if self.archive is not None:
            return name in self.archive.namelist()
        if self.bundle:
            from core.security.capped_read import path_may_exist
            return path_may_exist(self.path / name)
        return False

    def read(self, name, max_bytes=MAX_DOCUMENT_BYTES, *, raise_on_refusal=True):
        """Read one selected member; never materialise or extract the archive."""
        name = str(name)
        relative = PurePosixPath(name)
        if relative.is_absolute() or ".." in relative.parts or "\\" in name:
            raise ValueError("unsafe evidence reference")
        if not self.bundle:
            if name not in {"", "."}:
                raise ValueError("a standalone snapshot has no retained notice store; use its original SBOM/evidence input")
            return read_capped(self.path, max_bytes, follow_symlinks=True, raise_on_refusal=True)
        if self.archive is not None:
            try:
                info = self.archive.getinfo(name)
            except KeyError:
                raise FileNotFoundError("missing evidence member: " + name) from None
            if info.file_size > max_bytes:
                raise ValueError("evidence member exceeds read budget")
            try:
                with self.archive.open(info) as stream:
                    raw = stream.read(max_bytes + 1)
            except Exception as error:
                # ZIP codecs use several unrelated exception classes for
                # malformed/encrypted/unsupported members. Keep the domain
                # error contract at this one stdlib I/O boundary.
                raise ValueError("unreadable evidence ZIP member: " + name) from error
        else:
            stream = open_regular_beneath(self.path.resolve(), name, "rb")
            if stream is None:
                raise ValueError("missing, nonregular or symlinked evidence member: " + name)
            with stream:
                if os.fstat(stream.fileno()).st_size > max_bytes:
                    raise ValueError("evidence member exceeds read budget")
                raw = stream.read(max_bytes + 1)
        if len(raw) > max_bytes:
            raise ValueError("evidence member exceeds read budget")
        return raw

    def read_json(self, name=""):
        raw = self.read(name)
        # The shared catalogue decoder rejects duplicate keys and non-finite
        # values. UTF-8 decoding rejects foreign encodings and malformed bytes.
        value = read_catalogue(raw.decode("utf-8-sig"))
        return value, hashlib.sha256(raw).hexdigest()

    def blob(self, sha256):
        if not isinstance(sha256, str) or not SHA256.fullmatch(sha256):
            raise ValueError("invalid notice fingerprint")
        raw = self.read("prepared/notices/sha256/" + sha256, MAX_NOTICE_BYTES)
        if hashlib.sha256(raw).hexdigest() != sha256:
            raise ValueError("retained notice checksum mismatch")
        return raw

#!/usr/bin/env python3
"""Remove Windows-only packaging helpers from the Linux container filesystem."""
from __future__ import annotations

import argparse
import ast
import base64
import posixpath
import csv
import io
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import struct
import shutil
import tempfile
import zipfile
import sys

MAX_HELPER_BYTES = 8 * 1024 * 1024


def helper_family(path: str) -> tuple[str, str] | None:
    """Recognize packaging resource directories, independently of versions."""
    match = re.search(
        r"/(?:site|dist)-packages/(?:pip/_vendor/|pipenv/patched/pip/_vendor/)?distlib/([^/]+\.exe)$",
        path,
    )
    if match:
        return "distlib", match[1]
    match = re.search(r"/(?:site|dist)-packages/setuptools/([^/]+\.exe)$", path)
    if match:
        return "setuptools", match[1]
    match = re.search(r"/node_modules/pnpm/dist/vendor/([^/]+\.exe)$", path)
    if match:
        return "pnpm", match[1]
    return None


def known_helper(family: str, name: str) -> bool:
    patterns = {
        "distlib": r"[tw](?:32|64)(?:-arm)?\.exe",
        "setuptools": r"(?:cli|gui)(?:-(?:32|64|arm64))?\.exe",
        "pnpm": r"fastlist-[0-9][0-9A-Za-z.+-]*-(?:x64|x86|arm64)\.exe",
    }
    return re.fullmatch(patterns[family], name) is not None


def measure(path: Path) -> tuple[os.stat_result, str]:
    """Verify a bounded regular PE resource without executing or following it."""
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    with os.fdopen(os.open(path, flags), "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or not 88 <= info.st_size <= MAX_HELPER_BYTES:
            raise ValueError(f"unexpected helper type or size: {path}")
        header = stream.read(64)
        if len(header) != 64 or header[:2] != b"MZ":
            raise ValueError(f"helper is not a Windows PE binary: {path}")
        offset = struct.unpack_from("<I", header, 60)[0]
        if not 64 <= offset <= info.st_size - 24:
            raise ValueError(f"invalid PE header offset: {path}")
        stream.seek(offset)
        pe = stream.read(24)
        if len(pe) != 24 or pe[:4] != b"PE\0\0":
            raise ValueError(f"invalid PE header: {path}")
        if struct.unpack_from("<H", pe, 4)[0] not in {0x14C, 0x8664, 0xAA64}:
            raise ValueError(f"unexpected PE architecture: {path}")
        stream.seek(0)
        digest = hashlib.sha256()
        size = 0
        while chunk := stream.read(65536):
            size += len(chunk)
            if size > MAX_HELPER_BYTES:
                raise ValueError(f"helper grew past size budget: {path}")
            digest.update(chunk)
        after = os.fstat(stream.fileno())
        if (size, after.st_size, after.st_mtime_ns, after.st_ctime_ns) != (
            info.st_size, info.st_size, info.st_mtime_ns, info.st_ctime_ns,
        ):
            raise ValueError(f"helper changed during inspection: {path}")
        return info, digest.hexdigest()


def wheel_helpers(path: Path) -> list[dict]:
    """Plan removals inside unsigned wheels; never extract archive paths."""
    if path.is_symlink():
        raise ValueError(f"symlink wheel: {path}")
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > 256 * 1024 * 1024:
        raise ValueError(f"unexpected wheel size or type: {path}")
    removed = []
    with zipfile.ZipFile(path) as archive:
        entries = archive.infolist()
        if len(entries) > 20000 or sum(entry.file_size for entry in entries) > 256 * 1024 * 1024:
            raise ValueError(f"wheel expansion budget exceeded: {path}")
        names = set()
        for entry in entries:
            parts = PurePosixPath(entry.filename).parts
            if (entry.filename in names or not parts or entry.filename.startswith("/")
                    or ".." in parts or "\\" in entry.filename
                    or stat.S_ISLNK(entry.external_attr >> 16)):
                raise ValueError(f"unsafe or duplicate wheel member: {path}")
            names.add(entry.filename)
            family = helper_family("/site-packages/" + entry.filename)
            if family is None:
                continue
            kind, name = family
            if not known_helper(kind, name):
                raise ValueError(f"unreviewed wheel helper: {entry.filename}")
            if entry.file_size > MAX_HELPER_BYTES:
                raise ValueError(f"wheel helper exceeds size budget: {entry.filename}")
            # Reuse the regular-resource inspection without allocating a policy cap.
            with tempfile.TemporaryDirectory(prefix="wheel-pe-") as temporary:
                candidate = Path(temporary) / name
                with archive.open(entry) as source, candidate.open("xb") as target:
                    shutil.copyfileobj(source, target, 65536)
                measured, sha = measure(candidate)
            if measured.st_size != entry.file_size:
                raise ValueError(f"wheel helper size mismatch: {entry.filename}")
            removed.append({"member": entry.filename, "family": kind,
                            "sha256": sha, "bytes": entry.file_size})
        if removed:
            wheel_record(archive, {row["member"] for row in removed})
    return removed


def wheel_record(archive: zipfile.ZipFile, removed: set[str]) -> tuple[str, bytes]:
    records = [entry for entry in archive.infolist() if entry.filename.endswith(".dist-info/RECORD")
               and len(PurePosixPath(entry.filename).parts) == 2]
    if len(records) != 1 or records[0].file_size > 4 * 1024 * 1024:
        raise ValueError("wheel requires one bounded RECORD")
    record = records[0].filename
    if any(name in archive.namelist() for name in (record + ".jws", record + ".p7s")):
        raise ValueError("refusing to change a signed wheel")
    rows = list(csv.reader(io.StringIO(archive.read(record).decode("utf-8"))))
    names = [row[0] for row in rows if len(row) == 3]
    expected = {entry.filename for entry in archive.infolist() if not entry.is_dir()}
    if len(names) != len(rows) or len(set(names)) != len(names) or set(names) != expected:
        raise ValueError("wheel RECORD must describe every file exactly once")
    out = io.StringIO(newline="")
    writer = csv.writer(out, lineterminator="\n")
    for row in rows:
        if row[0] not in removed:
            writer.writerow([record, "", ""] if row[0] == record else row)
    return record, out.getvalue().encode("utf-8")


def rewrite_wheel(path: Path, removed: list[dict]) -> None:
    """Keep all other wheel members and update its unsigned RECORD atomically."""
    info = path.stat()
    descriptor, temporary = tempfile.mkstemp(prefix=".linux-wheel-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as output:
            os.fchmod(output.fileno(), stat.S_IMODE(info.st_mode))
            os.fchown(output.fileno(), info.st_uid, info.st_gid)
            with zipfile.ZipFile(path) as source, zipfile.ZipFile(output, "w") as target:
                rejected = {row["member"] for row in removed}
                record, content = wheel_record(source, rejected)
                target.comment = source.comment
                for entry in source.infolist():
                    if entry.filename in rejected:
                        continue
                    if entry.filename == record:
                        target.writestr(entry, content)
                    else:
                        with source.open(entry) as original, target.open(entry, "w") as copied:
                            shutil.copyfileobj(original, copied, 65536)
            output.flush()
            os.fsync(output.fileno())
        current = path.stat()
        if (current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns, current.st_ctime_ns) != (
            info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns,
        ):
            raise ValueError(f"wheel changed during rewrite: {path}")
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def file_sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def bundle_checksum(path: Path) -> tuple[Path, bytes, ast.Constant] | None:
    """Bind a virtualenv seed to its literal checksum before changing it."""
    if path.parent.parts[-4:] != ("virtualenv", "seed", "wheels", "embed"):
        return None
    manifest = path.parent / "__init__.py"
    if manifest.is_symlink() or manifest.stat().st_size > 1024 * 1024:
        raise ValueError(f"invalid virtualenv bundle manifest: {manifest}")
    source = manifest.read_bytes()
    tables = []
    for node in ast.parse(source).body:
        targets = node.targets if isinstance(node, ast.Assign) else [node.target] if isinstance(node, ast.AnnAssign) else []
        if any(isinstance(target, ast.Name) and target.id == "BUNDLE_SHA256" for target in targets):
            tables.append(node.value)
    if not tables:
        return None  # Older virtualenv releases do not have a bundle checksum table.
    if len(tables) != 1 or not isinstance(tables[0], ast.Dict):
        raise ValueError("unrecognized virtualenv checksum schema")
    matches = [value for key, value in zip(tables[0].keys, tables[0].values)
               if isinstance(key, ast.Constant) and key.value == path.name]
    if (len(matches) != 1 or not isinstance(matches[0], ast.Constant)
            or not isinstance(matches[0].value, str) or matches[0].value != file_sha(path)):
        raise ValueError(f"original virtualenv seed checksum mismatch: {path}")
    return manifest, source, matches[0]


def atomic_bytes(path: Path, data: bytes) -> None:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode):
        raise ValueError(f"metadata is not regular: {path}")
    descriptor, temporary = tempfile.mkstemp(prefix=".linux-resource-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as output:
            os.fchmod(output.fileno(), stat.S_IMODE(info.st_mode))
            os.fchown(output.fileno(), info.st_uid, info.st_gid)
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def refresh_bundle_checksum(path: Path, binding: tuple[Path, bytes, ast.Constant] | None) -> list[Path]:
    if binding is None:
        return []
    manifest, _, _ = binding
    # Other seeds in this same manifest may already have been transformed.
    source = manifest.read_bytes()
    tree = ast.parse(source)
    candidates = [value for node in tree.body if isinstance(node, (ast.Assign, ast.AnnAssign))
                  for target in (node.targets if isinstance(node, ast.Assign) else [node.target])
                  if isinstance(target, ast.Name) and target.id == "BUNDLE_SHA256"
                  and isinstance(node.value, ast.Dict)
                  for key, value in zip(node.value.keys, node.value.values)
                  if isinstance(key, ast.Constant) and key.value == path.name]
    if (len(candidates) != 1 or not isinstance(candidates[0], ast.Constant)
            or candidates[0].value != binding[2].value):
        raise ValueError("virtualenv bundle table changed during cleanup")
    node = candidates[0]
    lines = source.splitlines(keepends=True)
    start = sum(map(len, lines[:node.lineno - 1])) + node.col_offset
    end = sum(map(len, lines[:node.end_lineno - 1])) + node.end_col_offset
    atomic_bytes(manifest, source[:start] + json.dumps(file_sha(path)).encode() + source[end:])
    changed = [manifest]
    # A precompiled table must not retain the old wheel hashes.
    for cache in (manifest.parent / "__pycache__").glob("__init__.*.pyc"):
        if cache.is_symlink() or not cache.is_file():
            raise ValueError(f"unexpected bundle bytecode cache: {cache}")
        cache.unlink()
        changed.append(cache)
    return changed


def refresh_installed_records(records: list[Path], changed: set[Path]) -> None:
    """Keep installed inventories consistent with the platform-filtered files."""
    if not changed:
        return
    normalized = {posixpath.normpath(str(path)): path for path in changed}
    for record in records:
        if record.is_symlink() or record.stat().st_size > 8 * 1024 * 1024:
            raise ValueError(f"invalid installed RECORD: {record}")
        rows = list(csv.reader(io.StringIO(record.read_text(encoding="utf-8"))))
        if any(len(row) != 3 for row in rows):
            raise ValueError(f"invalid installed RECORD rows: {record}")
        revised, dirty = [], False
        for row in rows:
            path = normalized.get(posixpath.normpath(str(record.parent.parent / row[0])))
            if path is None:
                revised.append(row)
                continue
            dirty = True
            if path.exists():
                digest = base64.urlsafe_b64encode(bytes.fromhex(file_sha(path))).rstrip(b"=").decode()
                revised.append([row[0], "sha256=" + digest, str(path.stat().st_size)])
        if dirty:
            output = io.StringIO(newline="")
            csv.writer(output, lineterminator="\n").writerows(revised)
            atomic_bytes(record, output.getvalue().encode("utf-8"))


def prune(root: Path, *, check: bool = False) -> list[dict]:
    if sys.platform != "linux":
        raise ValueError("Windows helper cleanup supports Linux images only")
    if root.is_symlink() or not root.is_dir():
        raise ValueError("cleanup root must be a real directory")
    planned = []
    wheels = []
    records = []
    for relative in ("usr/local", "usr/lib/node_modules", "root/.local/share/uv/tools", "usr/share/python-wheels"):
        directory = root / relative
        ancestor = root
        for component in Path(relative).parts:
            ancestor /= component
            if ancestor.is_symlink():
                raise ValueError(f"symlink at helper search root: {ancestor}")
        for parent, directories, names in os.walk(directory, followlinks=False):
            directories.sort()
            for name in sorted(names):
                path = Path(parent) / name
                relative_path = "/" + path.relative_to(root).as_posix()
                if name == "RECORD" and path.parent.name.endswith(".dist-info"):
                    records.append(path)
                if name.endswith(".whl"):
                    removed = wheel_helpers(path)
                    if removed:
                        wheels.append((path, removed, bundle_checksum(path)))
                family = helper_family(relative_path)
                if family is None:
                    continue
                kind, filename = family
                if not known_helper(kind, filename):
                    raise ValueError(f"unreviewed Windows helper name: {relative_path}")
                info, sha = measure(path)
                planned.append((path, info, {"path": relative_path, "family": kind,
                                            "sha256": sha, "bytes": info.st_size}))
    if check and (planned or wheels):
        raise ValueError("Windows helpers remain in Linux image")
    for path, info, _ in planned:
        current = path.lstat()
        if (current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns) != (
            info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
        ):
            raise ValueError(f"helper changed before removal: {path}")
        path.unlink()
    changed = {path for path, _, _ in planned}
    for path, removed, binding in wheels:
        rewrite_wheel(path, removed)
        changed.add(path)
        changed.update(refresh_bundle_checksum(path, binding))
    refresh_installed_records(records, changed)
    return [row for _, _, row in planned] + [
        {"archive": "/" + path.relative_to(root).as_posix(), **row}
        for path, removed, _ in wheels for row in removed
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("/"))
    parser.add_argument("--check", action="store_true", help="refuse any remaining helper; never remove files")
    args = parser.parse_args()
    try:
        removed = prune(args.root, check=args.check)
    except (OSError, ValueError) as exc:
        parser.exit(1, f"Windows helper cleanup failed: {exc}\n")
    print(json.dumps({"removed": removed, "count": len(removed)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

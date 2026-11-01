#!/usr/bin/env python3
"""Install a pinned CodeQL CLI for this user on first invocation (Linux only).

This launcher ships in the image; the CodeQL distribution does not. Downloads
come directly from GitHub and must match the pinned release asset's SHA-256.
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from urllib.request import urlopen
import tarfile

# The manifest is copied beside this launcher in the image, and lives beside
# this script in source checkouts. SCA updates its release pins as generic data.
try:
    with Path(__file__).resolve().with_name('github-release-pins.json').open(encoding='utf-8') as _stream:
        _manifest = json.loads(_stream.read(64 * 1024))
    _pins = _manifest['tools']['codeql']
    if _manifest['schema_version'] != 1 or (_pins['repository'] != 'github/codeql-action'
            or _pins.get('release_tag_prefix') != 'codeql-bundle-v'):
        raise ValueError('expected schema v1 and the official CodeQL repository')
    RELEASE_TAG = _pins['version']
    if not RELEASE_TAG.startswith('codeql-bundle-v'):
        raise ValueError('expected an official CodeQL bundle release tag')
    VERSION = RELEASE_TAG.removeprefix('codeql-bundle-v')
    if not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', VERSION):
        raise ValueError('invalid CodeQL release version')
    ASSETS = {arch: (asset['name'], asset['sha256'], asset['size'])
              for arch, asset in _pins['assets'].items()}
    if set(ASSETS) != {'x86_64', 'aarch64'}:
        raise ValueError('both supported CodeQL architectures are required')
    for _arch, (_name, _digest, _size) in ASSETS.items():
        if (_name != {'x86_64': 'codeql-bundle-linux64.tar.gz', 'aarch64': 'codeql-bundle-linux-arm64.tar.gz'}[_arch]
                or not re.fullmatch(r'[0-9a-f]{64}', _digest)
                or type(_size) is not int or not 0 < _size <= 2 * 1024**3):
            raise ValueError('invalid CodeQL archive name, SHA-256, or size')
except (OSError, ValueError, KeyError, TypeError, AttributeError) as _exc:
    raise SystemExit(f'CodeQL release pins unavailable or invalid: {_exc}. Rebuild the container image.') from _exc
TERMS_URL = f"https://github.com/github/codeql-cli-binaries/blob/v{VERSION}/LICENSE.md"
MAX_DOWNLOAD_SECONDS = 900
MAX_EXTRACTED_BYTES = 4 * 1024**3


def _asset() -> tuple[str, str, int]:
    machine = platform.machine().lower()
    machine = {"amd64": "x86_64", "arm64": "aarch64"}.get(machine, machine)
    if sys.platform != "linux" or machine not in ASSETS:
        raise RuntimeError(f"CodeQL first-use installation does not support {sys.platform}/{machine}")
    return ASSETS[machine]


def _cache_root() -> Path:
    root = Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache")
    if not root.is_absolute():
        raise RuntimeError("XDG_CACHE_HOME must be an absolute path")
    return root / "raptor" / "codeql"


def _installed_path(target: Path, digest: str) -> Path | None:
    marker = target / ".raptor-install.json"
    cli = target / "codeql"
    try:
        if (target.is_symlink() or marker.is_symlink() or not marker.is_file()
                or cli.is_symlink()):
            return None
        with marker.open(encoding="utf-8") as stream:
            metadata = json.loads(stream.read(4096))
        if metadata == {"version": VERSION, "sha256": digest} and cli.is_file() and os.access(cli, os.X_OK):
            return cli
    except (OSError, ValueError):
        pass
    return None


def _download(path: Path, asset: str, digest: str, expected_size: int) -> None:
    url = f"https://github.com/github/codeql-action/releases/download/{RELEASE_TAG}/{asset}"
    hasher = hashlib.sha256()
    received = 0
    started = time.monotonic()
    with urlopen(url, timeout=60) as response, path.open("xb") as output:
        if not response.geturl().startswith("https://"):
            raise RuntimeError("refusing a non-HTTPS CodeQL download redirect")
        while chunk := response.read(1024 * 1024):
            received += len(chunk)
            if received > expected_size or time.monotonic() - started > MAX_DOWNLOAD_SECONDS:
                raise RuntimeError("CodeQL download exceeded its size or time limit")
            hasher.update(chunk)
            output.write(chunk)
    if received != expected_size or hasher.hexdigest() != digest:
        raise RuntimeError("CodeQL archive size/SHA-256 verification failed; nothing installed")


def _extract(archive: Path, destination: Path) -> Path:
    """Extract bounded regular files, then safe internal hardlinks/symlinks."""
    root = (destination / 'codeql').resolve()
    seen = set()
    links = []
    total = 0
    with tarfile.open(archive, 'r:gz') as bundle:
        for member in bundle:
            name = PurePosixPath(member.name)
            if (name.is_absolute() or not name.parts or name.parts[0] != 'codeql'
                    or '..' in name.parts or '\\' in member.name or name in seen):
                raise RuntimeError('unsafe or duplicate path in CodeQL bundle')
            seen.add(name)
            total += member.size
            if len(seen) > 100_000 or member.size < 0 or total > MAX_EXTRACTED_BYTES:
                raise RuntimeError('CodeQL bundle exceeds extraction bounds')
            target = destination.joinpath(*name.parts)
            if member.issym() or member.islnk():
                link = member.linkname
                if not link or len(link) > 4096 or link.startswith('/') or '\\' in link or '\x00' in link:
                    raise RuntimeError('unsafe link in CodeQL bundle')
                source = (target.parent / link if member.issym() else destination / link)
                source = Path(os.path.abspath(source))
                if not source.is_relative_to(root):
                    raise RuntimeError('CodeQL bundle link escapes the distribution')
                links.append((target, link, source, member.issym()))
            elif member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            elif member.isfile():
                target.parent.mkdir(parents=True, exist_ok=True)
                if shutil.disk_usage(destination).free < member.size + 64 * 1024**2:
                    raise RuntimeError('insufficient disk space to extract the CodeQL bundle')
                with bundle.extractfile(member) as source, target.open('xb') as output:
                    shutil.copyfileobj(source, output)
                target.chmod(0o755 if member.mode & 0o111 else 0o644)
            else:
                raise RuntimeError('unsupported file type in CodeQL bundle')
    # All data writes precede link creation. No link may be another entry's
    # parent, and hardlinks may only target existing regular archive files.
    link_paths = {target for target, _, _, _ in links}
    for target, _, source, symbolic in links:
        if any(parent in link_paths for parent in target.parents):
            raise RuntimeError('CodeQL bundle contains a nested link')
        if not symbolic and (source in link_paths or not source.is_file()):
            raise RuntimeError('CodeQL bundle hardlink target is not a regular file')
    for target, link, source, symbolic in sorted(links, key=lambda item: item[3]):
        target.parent.mkdir(parents=True, exist_ok=True)
        if symbolic:
            target.symlink_to(link)
        else:
            os.link(source, target, follow_symlinks=False)
    for target, _, _, _ in links:
        if not target.resolve(strict=False).is_relative_to(root):
            raise RuntimeError('CodeQL bundle link escapes the distribution')
    return destination / 'codeql'


def _copy_verified_archive(source: Path, destination: Path | None, digest: str, size: int) -> None:
    """Verify a regular local file while copying the exact bytes to private staging."""
    fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as incoming:
        info = os.fstat(incoming.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size != size:
            raise RuntimeError('local CodeQL bundle is not a regular file of the pinned size')
        hasher = hashlib.sha256()
        received = 0
        output = destination.open('xb') if destination is not None else None
        try:
            while chunk := incoming.read(1024 * 1024):
                received += len(chunk)
                if received > size:
                    raise RuntimeError('local CodeQL bundle exceeds the pinned size')
                hasher.update(chunk)
                if output is not None:
                    output.write(chunk)
        finally:
            if output is not None:
                output.close()
        if received != size or hasher.hexdigest() != digest:
            raise RuntimeError('local CodeQL bundle SHA-256 verification failed; nothing installed')


def ensure_installed(*, force: bool = False, install: bool = True, local_archive: Path | None = None) -> Path:
    asset, digest, size = _asset()
    cache = _cache_root()
    target = cache / VERSION / asset.removesuffix(".tar.gz") / "codeql"
    if cache.exists() and (cache.is_symlink() or cache.stat().st_uid != os.getuid()
                           or cache.stat().st_mode & 0o022):
        raise RuntimeError(f"CodeQL cache must be a private, user-owned directory: {cache}")
    existing = _installed_path(target, digest)
    if existing:
        if local_archive is not None:
            _copy_verified_archive(local_archive, None, digest, size)
        return existing
    if not install:
        raise RuntimeError('CodeQL is not installed; run codeql --raptor-install before probing its version')
    if local_archive is None and os.environ.get('RAPTOR_CODEQL_OFFLINE', '').lower() in ('1', 'true', 'yes'):
        raise RuntimeError('offline mode: import the pinned bundle with codeql --raptor-install-from <archive.tar.gz>')
    if local_archive is None and not force and os.environ.get("RAPTOR_CODEQL_AUTO_INSTALL", "1").lower() in ("0", "false", "no"):
        raise RuntimeError("automatic CodeQL installation disabled; run codeql --raptor-install to install explicitly")
    cache.mkdir(parents=True, exist_ok=True, mode=0o700)
    if cache.is_symlink() or cache.stat().st_uid != os.getuid() or cache.stat().st_mode & 0o022:
        raise RuntimeError(f"CodeQL cache must be a private, user-owned directory: {cache}")
    fd = os.open(cache / ".install.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as lock:
        if not stat.S_ISREG(os.fstat(lock.fileno()).st_mode):
            raise RuntimeError("CodeQL installation lock is not a regular file")
        fcntl.flock(lock, fcntl.LOCK_EX)
        existing = _installed_path(target, digest)
        if existing:
            if local_archive is not None:
                _copy_verified_archive(local_archive, None, digest, size)
            return existing
        if target.exists() or target.is_symlink():
            raise RuntimeError(f"incomplete CodeQL cache at {target}; remove that directory and retry")
        origin = 'a verified local bundle' if local_archive is not None else 'GitHub'
        sys.stderr.write(f"Installing CodeQL {VERSION} for this user from {origin} ({size // 1_000_000} MB).\n"
                         f"Use is subject to GitHub's CodeQL terms: {TERMS_URL}\n")
        with tempfile.TemporaryDirectory(prefix=".install-", dir=cache) as temporary:
            stage = Path(temporary)
            archive = stage / asset
            if local_archive is None:
                _download(archive, asset, digest, size)
            else:
                _copy_verified_archive(local_archive, archive, digest, size)
            extracted = _extract(archive, stage / "unpacked")
            cli = extracted / "codeql"
            if not cli.is_file() or cli.is_symlink() or not os.access(cli, os.X_OK):
                raise RuntimeError("CodeQL archive has no executable launcher")
            version = subprocess.run([str(cli), "version", "--format=terse"],
                                     capture_output=True, text=True, timeout=60, check=True)
            if version.stdout.strip() != VERSION:
                raise RuntimeError("downloaded CodeQL CLI reports an unexpected version")
            (extracted / ".raptor-install.json").write_text(
                json.dumps({"version": VERSION, "sha256": digest}), encoding="utf-8")
            target.parent.mkdir(parents=True, exist_ok=True)
            os.replace(extracted, target)
        sys.stderr.write(f"CodeQL {VERSION} installed at {target}.\n")
        return target / "codeql"


def main(argv: list[str]) -> int:
    try:
        if argv[:1] == ['--raptor-install-from']:
            if len(argv) != 2:
                raise RuntimeError('usage: codeql --raptor-install-from <archive.tar.gz>')
            print(ensure_installed(force=True, local_archive=Path(argv[1])))
            return 0
        if (os.environ.get('RAPTOR_CODEQL_OFFLINE', '').lower() in ('1', 'true', 'yes')
                and (tuple(argv[:2]) in {('pack', command) for command in
                     ('install', 'download', 'add', 'upgrade', 'ci', 'publish')}
                     or '--download' in argv or any(arg.startswith('--download=') and
                         arg.split('=', 1)[1].lower() not in ('false', '0', 'no') for arg in argv))):
            raise RuntimeError('offline mode: registry commands and --download are disabled; import prepared assets instead')
        if argv == ["--raptor-status"]:
            asset, digest, _ = _asset()
            path = _installed_path(_cache_root() / VERSION / asset.removesuffix(".tar.gz") / "codeql", digest)
            print(json.dumps({"version": VERSION, "installed": path is not None,
                              "path": str(path) if path else None}))
            return 0
        # Diagnostic version probes must never acquire a tool or hit the
        # network, including callers outside RAPTOR's CodeQL package.
        probe = bool(argv) and argv[0] in ('version', '--version', '--raptor-resolve-existing')
        cli = ensure_installed(force=argv == ["--raptor-install"], install=not probe)
        if argv in (["--raptor-install"], ["--raptor-resolve"], ["--raptor-resolve-existing"]):
            print(cli)
            return 0
        os.execv(str(cli), [str(cli), *argv])
    except (OSError, ValueError, RuntimeError, EOFError, subprocess.SubprocessError, tarfile.TarError) as exc:
        sys.stderr.write(f"CodeQL installation/execution failed: {exc}\n"
                         "Retry with codeql --raptor-install, or set CODEQL_CLI to an existing installation.\n")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

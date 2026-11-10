"""Auto-detect library source trees that a C/C++ target depends on.

Harvests ``#include <…>`` directives from the target, resolves them to
source packages via the system package manager, and extracts any
installed source tarballs into a RAPTOR-writable cache directory.

Package-manager dispatch uses ``packages.describe.package_manager``
(apt / dnf / yum / pacman / apk / zypper / brew). Install hints are
OS-appropriate via the same module's ``format_install_hint``.

Returns ``(path, identifier)`` pairs ready for ``_run_library_studies``.
"""

from __future__ import annotations

import abc
import glob as _glob_mod
import logging
import os
import re
import subprocess
import stat
import tarfile
import uuid
from pathlib import Path

from core.atomic_fs import rmtree_hardened
from core.atomic_fs.fs_lock import artifact_lock
from core.json import loads, save_json
from core.run.scratch import scratch_dir
from core.source import open_regular_gated, read_bytes_gated
from core.source.streams import preserving_stream_error
from core.tar.extract import _TAR_CORRUPTION_ERRORS

_glob_escape = _glob_mod.escape

logger = logging.getLogger(__name__)

# System include pattern — <header> only, not "header".
_INCLUDE_RE = re.compile(
    r'^[^\S\n]*#\s*include\s+<([^>]+)>', re.MULTILINE,
)

# Extensions to scan for includes.
_SOURCE_EXTS = frozenset({
    ".c", ".h", ".cc", ".cpp", ".cxx", ".hh", ".hpp", ".hxx",
})

# ── Header → subtree mapping ────────────────────────────────────
#
# For libraries whose source tree has multiple distinct subsystems
# (glibc being the canonical case), we map well-known headers to
# the subtree that implements them.
#
# The value is (subtree_dir, identifier) relative to the extracted
# source root.

_GLIBC_HEADER_MAP: dict[str, tuple[str, str]] = {
    # DNS / resolver
    "resolv.h": ("resolv", "glibc_resolver"),
    "arpa/nameser.h": ("resolv", "glibc_resolver"),
    "arpa/nameser_compat.h": ("resolv", "glibc_resolver"),
    # NSS
    "nss.h": ("nss", "glibc_nss"),
    "netdb.h": ("nss", "glibc_nss"),
    "grp.h": ("nss", "glibc_nss"),
    "pwd.h": ("nss", "glibc_nss"),
    "shadow.h": ("nss", "glibc_nss"),
    "gshadow.h": ("nss", "glibc_nss"),
    "aliases.h": ("nss", "glibc_nss"),
    # Heap allocator
    "malloc.h": ("malloc", "glibc_malloc"),
    "mcheck.h": ("malloc", "glibc_malloc"),
    "obstack.h": ("malloc", "glibc_malloc"),
    # Dynamic loader
    "dlfcn.h": ("dlfcn", "glibc_dlfcn"),
    "link.h": ("elf", "glibc_elf"),
    # Threading
    "pthread.h": ("nptl", "glibc_nptl"),
    "semaphore.h": ("nptl", "glibc_nptl"),
    # Signals
    "signal.h": ("signal", "glibc_signal"),
    # Sockets / networking
    "sys/socket.h": ("socket", "glibc_socket"),
    "sys/un.h": ("socket", "glibc_socket"),
    "netinet/in.h": ("inet", "glibc_inet"),
    "arpa/inet.h": ("inet", "glibc_inet"),
    # I/O
    "stdio.h": ("libio", "glibc_stdio"),
    # String / memory
    "string.h": ("string", "glibc_string"),
    "strings.h": ("string", "glibc_string"),
    # stdlib
    "stdlib.h": ("stdlib", "glibc_stdlib"),
    # IPC
    "sys/ipc.h": ("sysvipc", "glibc_sysvipc"),
    "sys/shm.h": ("sysvipc", "glibc_sysvipc"),
    "sys/sem.h": ("sysvipc", "glibc_sysvipc"),
    "sys/msg.h": ("sysvipc", "glibc_sysvipc"),
    # setjmp / longjmp
    "setjmp.h": ("setjmp", "glibc_setjmp"),
    # Login / utmp
    "utmp.h": ("login", "glibc_login"),
    "utmpx.h": ("login", "glibc_login"),
}

# Known tarball glob patterns per source package name.
_KNOWN_TARBALL_GLOBS: dict[str, str] = {
    "glibc": "glibc-*.tar.*",
}


_MAX_SOURCE_READ_BYTES = 2 * 1024 * 1024  # 2 MiB — includes live in the first few KiB


def harvest_system_includes(target_path: Path) -> set[str]:
    """Collect ``#include <…>`` headers from all source files under
    *target_path*.
    """
    headers: set[str] = set()
    try:
        for root, _dirs, files in os.walk(target_path):
            for fname in files:
                if Path(fname).suffix not in _SOURCE_EXTS:
                    continue
                fpath = Path(root) / fname
                try:
                    with open(fpath, errors="replace") as fh:
                        text = fh.read(_MAX_SOURCE_READ_BYTES)
                except OSError:
                    continue
                headers.update(_INCLUDE_RE.findall(text))
    except OSError:
        logger.debug(
            "library_detect: failed to walk %s", target_path,
            exc_info=True,
        )
    return headers


# ── Package resolver abstraction ─────────────────────────────────

def _run_quiet(
    cmd: list[str], *, timeout: int = 10,
) -> subprocess.CompletedProcess[str] | None:
    try:
        return subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
        )
    except (subprocess.TimeoutExpired, OSError, FileNotFoundError):
        return None


class _PackageResolver(abc.ABC):
    """Resolve system headers to source packages."""

    @abc.abstractmethod
    def header_to_source_package(self, header: str) -> str | None: ...

    @abc.abstractmethod
    def find_source_tarball(self, source_pkg: str) -> Path | None: ...

    @abc.abstractmethod
    def source_install_hint(self, source_pkg: str) -> str | None:
        """OS-appropriate hint for obtaining the source."""

    @property
    @abc.abstractmethod
    def name(self) -> str: ...


def _probe_src_dir(source_pkg: str) -> Path | None:
    """Check common ``/usr/src/<pkg>/`` layouts for a tarball."""
    for base in [
        Path(f"/usr/src/{source_pkg}"),
        Path("/usr/src/redhat/SOURCES"),
    ]:
        if not base.is_dir():
            continue
        glob_pat = _KNOWN_TARBALL_GLOBS.get(
            source_pkg, f"{source_pkg}-*.tar.*",
        )
        tarballs = sorted(base.glob(glob_pat))
        if tarballs:
            return tarballs[-1]
    return None


# ── Debian / Ubuntu ──────────────────────────────────────────────

class _AptResolver(_PackageResolver):
    name = "apt"

    def header_to_source_package(self, header: str) -> str | None:
        include_path = f"/usr/include/{header}"
        out = _run_quiet(["dpkg", "-S", include_path])
        if out is None or out.returncode != 0:
            return None
        binary_pkg = out.stdout.strip().split(":")[0]
        if not binary_pkg:
            return None
        out2 = _run_quiet(
            ["dpkg-query", "-W", "-f=${source:Package}", binary_pkg],
        )
        if out2 is None or out2.returncode != 0:
            return None
        return out2.stdout.strip() or None

    def find_source_tarball(self, source_pkg: str) -> Path | None:
        deb_pkg = f"{source_pkg}-source"
        out = _run_quiet(["dpkg", "-s", deb_pkg])
        if out is None or out.returncode != 0:
            return None
        if "Status: install ok installed" not in out.stdout:
            return None
        return _probe_src_dir(source_pkg)

    def source_install_hint(self, source_pkg: str) -> str | None:
        from packages.describe.package_manager import format_install_hint
        deb_pkg = f"{source_pkg}-source"
        out = _run_quiet(["apt-cache", "show", deb_pkg])
        if out and out.returncode == 0 and "Package:" in out.stdout:
            return format_install_hint([deb_pkg])
        return None


# ── Fedora / RHEL / CentOS ──────────────────────────────────────

class _DnfResolver(_PackageResolver):
    name = "dnf"

    def header_to_source_package(self, header: str) -> str | None:
        include_path = f"/usr/include/{header}"
        out = _run_quiet(["rpm", "-qf", include_path])
        if out is None or out.returncode != 0:
            return None
        binary_pkg = out.stdout.strip()
        if not binary_pkg:
            return None
        out2 = _run_quiet(
            ["rpm", "-q", "--qf", "%{SOURCERPM}", binary_pkg],
        )
        if out2 is None or out2.returncode != 0:
            return None
        srpm = out2.stdout.strip()
        if not srpm or srpm == "(none)":
            return None
        # "glibc-2.38-16.fc40.src.rpm" → "glibc"
        parts = srpm.rsplit("-", 2)
        return parts[0] if len(parts) >= 3 else srpm.split("-")[0]

    def find_source_tarball(self, source_pkg: str) -> Path | None:
        return _probe_src_dir(source_pkg)

    def source_install_hint(self, source_pkg: str) -> str | None:
        from packages.describe.package_manager import (
            detect_package_manager,
        )
        pm = detect_package_manager()
        cmd = pm if pm in ("dnf", "yum") else "dnf"
        return f"{cmd} download --source {source_pkg}"


# ── Arch Linux ───────────────────────────────────────────────────

class _PacmanResolver(_PackageResolver):
    name = "pacman"

    def header_to_source_package(self, header: str) -> str | None:
        include_path = f"/usr/include/{header}"
        out = _run_quiet(["pacman", "-Qo", include_path])
        if out is None or out.returncode != 0:
            return None
        # "/usr/include/resolv.h is owned by glibc 2.39-1"
        parts = out.stdout.strip().rsplit(" is owned by ", 1)
        if len(parts) < 2:
            return None
        return parts[1].strip().rsplit(" ", 1)[0]

    def find_source_tarball(self, source_pkg: str) -> Path | None:
        return _probe_src_dir(source_pkg)

    def source_install_hint(self, source_pkg: str) -> str | None:
        return f"asp export {source_pkg}"


# ── Alpine ───────────────────────────────────────────────────────

class _ApkResolver(_PackageResolver):
    name = "apk"

    def header_to_source_package(self, header: str) -> str | None:
        include_path = f"/usr/include/{header}"
        out = _run_quiet(["apk", "info", "--who-owns", include_path])
        if out is None or out.returncode != 0:
            return None
        parts = out.stdout.strip().rsplit(" is owned by ", 1)
        if len(parts) < 2:
            return None
        pkg_and_ver = parts[1].strip()
        name = pkg_and_ver
        for suffix in ("-dev", "-devel", "-headers"):
            idx = name.find(suffix + "-")
            if idx > 0:
                name = name[:idx]
                break
        parts2 = name.rsplit("-", 1)
        if len(parts2) == 2 and parts2[1] and parts2[1][0].isdigit():
            name = parts2[0]
        return name

    def find_source_tarball(self, source_pkg: str) -> Path | None:
        return _probe_src_dir(source_pkg)

    def source_install_hint(self, source_pkg: str) -> str | None:
        return (
            f"See https://git.alpinelinux.org for {source_pkg} source"
        )


# ── zypper (openSUSE / SLES) ────────────────────────────────────

class _ZypperResolver(_PackageResolver):
    name = "zypper"

    def header_to_source_package(self, header: str) -> str | None:
        # zypper uses rpm underneath
        include_path = f"/usr/include/{header}"
        out = _run_quiet(["rpm", "-qf", include_path])
        if out is None or out.returncode != 0:
            return None
        binary_pkg = out.stdout.strip()
        if not binary_pkg:
            return None
        out2 = _run_quiet(
            ["rpm", "-q", "--qf", "%{SOURCERPM}", binary_pkg],
        )
        if out2 is None or out2.returncode != 0:
            return None
        srpm = out2.stdout.strip()
        if not srpm or srpm == "(none)":
            return None
        parts = srpm.rsplit("-", 2)
        return parts[0] if len(parts) >= 3 else srpm.split("-")[0]

    def find_source_tarball(self, source_pkg: str) -> Path | None:
        return _probe_src_dir(source_pkg)

    def source_install_hint(self, source_pkg: str) -> str | None:
        from packages.describe.package_manager import format_install_hint
        return format_install_hint([f"{source_pkg}-source"])


# ── Resolver selection ───────────────────────────────────────────

def _detect_resolver() -> _PackageResolver | None:
    """Pick the resolver matching the detected package manager.

    Uses ``detect_package_manager`` from the describe module so
    the detection order and caching are shared.
    """
    from packages.describe.package_manager import detect_package_manager
    pm = detect_package_manager()
    if pm == "apt":
        return _AptResolver()
    if pm in ("dnf", "yum"):
        return _DnfResolver()
    if pm == "pacman":
        return _PacmanResolver()
    if pm == "apk":
        return _ApkResolver()
    if pm == "zypper":
        return _ZypperResolver()
    return None


# ── Tarball extraction ───────────────────────────────────────────
#
# Uses RAPTOR's hardened tar safety predicate (core.tar.safe_member)
# for path traversal, absolute paths, special files, oversized
# members, and NFKC-normalised traversal.  Symlinks staying within
# the extraction root are permitted (glibc source uses internal
# symlinks); escaping symlinks abort the whole extraction.

# Per-member size cap for library source extraction (256 MiB).
_EXTRACT_MAX_MEMBER_BYTES = 256 * 1024 * 1024
# Aggregate limits bound disk/inodes across many individually small members.
# Raising them admits larger source packages at higher resource cost;
# lowering them can refuse legitimate large library distributions.
_EXTRACT_MAX_TOTAL_BYTES = 8 * 1024**3
_EXTRACT_MAX_ENTRIES = 500_000
_EXTRACT_STAMP = ".raptor-extract-state.json"
_EXTRACT_ERRORS = _TAR_CORRUPTION_ERRORS + (ValueError, RuntimeError)


def _is_safe_for_extraction(
    member: tarfile.TarInfo,
    cache_resolved: str,
) -> str | None:
    """Return None if safe, or a reason string if the member should
    be rejected.  Delegates to ``core.tar.safe_member`` for the
    checks it covers, then adds a symlink-within-root check for
    the link types that ``safe_member`` blanket-rejects."""
    from core.tar.safe_member import UnsafeMemberReason, safe_member_reason

    reason = safe_member_reason(
        member,
        max_size=_EXTRACT_MAX_MEMBER_BYTES,
        allow_absolute_paths=False,
    )
    if reason == UnsafeMemberReason.SAFE:
        return None

    # safe_member rejects all symlinks and hard links.  For library
    # source extraction we allow symlinks whose target stays within
    # the cache root — glibc source uses internal symlinks.
    if reason in (
        UnsafeMemberReason.SYMLINK_UNSAFE,
        UnsafeMemberReason.HARD_LINK,
    ) and (member.issym() or member.islnk()):
        link_target = (
            Path(cache_resolved)
            / os.path.dirname(member.name)
            / (member.linkname or "")
        ).resolve()
        if str(link_target).startswith(cache_resolved + os.sep):
            return None
        return f"link escapes root: {reason.value}"

    return reason.value


def _archive_identity(info: os.stat_result) -> dict[str, int]:
    return {"device": info.st_dev, "inode": info.st_ino,
            "size": info.st_size, "mtime_ns": info.st_mtime_ns,
            "ctime_ns": info.st_ctime_ns}


def _cache_directory_id(path: Path) -> tuple[int, int] | None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    if not stat.S_ISDIR(info.st_mode):
        raise ValueError("library cache root must be a real directory")
    return info.st_dev, info.st_ino


def _same_archive(stream, tarball: Path, identity: dict[str, int]) -> bool:
    return (_archive_identity(os.fstat(stream.fileno())) == identity
            and _archive_identity(tarball.stat()) == identity)


def _extract_tarball(tarball: Path, cache_dir: Path) -> Path | None:
    """Publish a complete, bounded library extraction or keep the old cache.

    A completion manifest binds the cache to the opened archive identity;
    legacy/unmarked directories are rebuilt. Writers share a required lock.
    Temporary extraction stays private and on the cache's filesystem.
    """
    try:
        cache_dir.mkdir(parents=True, exist_ok=True)
        with preserving_stream_error(open_regular_gated(tarball)) as stream:
            identity = _archive_identity(os.fstat(stream.fileno()))
            with preserving_stream_error(tarfile.open(fileobj=stream, mode="r:*")) as tf:
                iterator = iter(tf)
                first = next(iterator, None)
                if first is None:
                    return None
                while first.name.startswith("./"):
                    first.name = first.name[2:]
                top = first.name.split("/", 1)[0]
                if not top or top in (".", "..") or "\\" in top:
                    return None
                if _is_safe_for_extraction(first, str(cache_dir.resolve())) is not None:
                    return None
                dest = cache_dir / top
                # Never retire a tree containing the source archive itself.
                if tarball.resolve().is_relative_to(dest.resolve()):
                    return None
                expected = {"version": 1, "source": identity, "root": top}
                with artifact_lock(cache_dir / ".library-cache", required=True,
                                   subject="library source extraction"):
                    original = _cache_directory_id(dest)
                    if original is not None:
                        try:
                            stamp = loads(read_bytes_gated(
                                dest / _EXTRACT_STAMP, 4096, follow_symlinks=False))
                        except (OSError, ValueError, RecursionError):
                            stamp = None
                        if (isinstance(stamp, dict) and type(stamp.get("version")) is int
                                and stamp == expected and _same_archive(stream, tarball, identity)
                                and _cache_directory_id(dest) == original):
                            logger.info("library_detect: using cached extraction at %r", dest)
                            return dest
                    with scratch_dir(".library-extract-", dir=cache_dir) as scratch:
                        members: list[tarfile.TarInfo] = []
                        total = 0
                        regular_files = 0
                        member: tarfile.TarInfo | None = first
                        while member is not None:
                            while member.name.startswith("./"):
                                member.name = member.name[2:]
                            total += max(0, member.size)
                            if len(members) >= _EXTRACT_MAX_ENTRIES or total > _EXTRACT_MAX_TOTAL_BYTES:
                                logger.warning(
                                    "library_detect: archive exceeds extraction quotas "
                                    "(%d bytes, %d entries)",
                                    _EXTRACT_MAX_TOTAL_BYTES, _EXTRACT_MAX_ENTRIES,
                                )
                                return None
                            if member.name != top and not member.name.startswith(top + "/"):
                                logger.warning("library_detect: archive has multiple source roots")
                                return None
                            reject = _is_safe_for_extraction(member, str(scratch.resolve()))
                            if reject is not None:
                                logger.warning("library_detect: rejecting member %r (%s)",
                                               member.name[:256], reject)
                                return None
                            members.append(member)
                            regular_files += int(member.isfile())
                            member = next(iterator, None)
                        if not regular_files:
                            return None
                        tf.extractall(scratch, members=members, filter="data")
                        tree = scratch / top
                        if (tree.is_symlink() or not tree.is_dir()
                                or not _verify_no_escaping_symlinks(tree, tree)):
                            return None
                        if not _same_archive(stream, tarball, identity):
                            logger.warning("library_detect: archive changed during extraction")
                            return None
                        save_json(tree / _EXTRACT_STAMP, expected)
                        if _cache_directory_id(dest) != original:
                            logger.warning("library_detect: cache slot changed during extraction")
                            return None
                        backup = None
                        try:
                            if original is not None:
                                backup = cache_dir / (".library-stale-" + uuid.uuid4().hex)
                                os.rename(dest, backup)
                            os.rename(tree, dest)
                        except BaseException:
                            if backup is not None and os.path.lexists(backup):
                                try:
                                    if not os.path.lexists(dest):
                                        os.rename(backup, dest)
                                    else:
                                        logger.warning("previous library source retained at %r", backup)
                                except OSError:
                                    logger.warning("cannot restore library source; retained at %r",
                                                   backup, exc_info=True)
                            raise
                        if backup is not None and not rmtree_hardened(backup):
                            logger.warning("library_detect: retired source cleanup incomplete: %r", backup)
                        return dest
    except _EXTRACT_ERRORS:
        logger.warning("library_detect: extraction refused or failed for %r", tarball,
                       exc_info=True)
        return None


def _verify_no_escaping_symlinks(root: Path, boundary: Path) -> bool:
    """Walk *root* and verify every symlink resolves within *boundary*.

    Pre-extraction checks validate individual link targets, but a
    chain of intra-root symlinks can compose into an escape.  This
    post-extraction pass resolves the full chain.

    ``os.walk`` does not follow symlinked directories, so directory
    symlinks are checked as entries in their parent's dir listing.
    """
    boundary_root = str(boundary.resolve())
    boundary_resolved = boundary_root + os.sep
    try:
        for dirpath, dirs, files in os.walk(root):
            for name in (*files, *dirs):
                fpath = Path(dirpath) / name
                if fpath.is_symlink():
                    target = str(fpath.resolve())
                    if target != boundary_root and not target.startswith(boundary_resolved):
                        logger.warning(
                            "library_detect: symlink chain escape: "
                            "%s → %s (outside %s)",
                            fpath, target, boundary,
                        )
                        return False
    except (OSError, RuntimeError):
        logger.warning(
            "library_detect: symlink verification failed for %s",
            root, exc_info=True,
        )
        return False
    return True


# ── Header → subtree mapping ────────────────────────────────────

def _map_headers_to_subtrees(
    headers: set[str],
    source_pkg: str,
    source_root: Path,
) -> list[tuple[str, str]]:
    """Map included headers to source subtrees.

    Returns deduplicated ``(subtree_path, identifier)`` pairs.
    """
    header_map = _GLIBC_HEADER_MAP if source_pkg == "glibc" else {}
    seen: dict[str, str] = {}

    for header in sorted(headers):
        if header in header_map:
            subtree, ident = header_map[header]
            subtree_path = source_root / subtree
            if subtree_path.is_dir() and ident not in seen:
                seen[ident] = str(subtree_path)
            continue

        escaped = _glob_escape(header)
        matches = list(source_root.glob(f"*/{escaped}"))
        if not matches:
            matches = list(source_root.glob(f"**/{escaped}"))
        if matches:
            rel = matches[0].relative_to(source_root)
            subtree = rel.parts[0] if len(rel.parts) > 1 else ""
            if subtree:
                subtree_path = source_root / subtree
                ident = f"{source_pkg}_{subtree}"
                if subtree_path.is_dir() and ident not in seen:
                    seen[ident] = str(subtree_path)

    return [(path, ident) for ident, path in seen.items()]


# ── Public API ───────────────────────────────────────────────────

class LibraryCandidate:
    """A detected library dependency with its resolution status."""

    __slots__ = (
        "source_pkg", "subtrees", "installed", "tarball",
        "extracted_root", "install_hint",
    )

    def __init__(
        self,
        source_pkg: str,
        *,
        installed: bool = False,
        tarball: Path | None = None,
        extracted_root: Path | None = None,
        install_hint: str | None = None,
    ) -> None:
        self.source_pkg = source_pkg
        self.subtrees: list[tuple[str, str]] = []
        self.installed = installed
        self.tarball = tarball
        self.extracted_root = extracted_root
        self.install_hint = install_hint


def detect_library_candidates(
    target_path: Path,
    cache_dir: Path,
    *,
    exclude_identifiers: frozenset[str] = frozenset(),
) -> tuple[list[tuple[str, str]], list[LibraryCandidate]]:
    """Detect library dependencies and prepare source for study.

    Returns ``(ready, missing)`` where *ready* is a list of
    ``(subtree_path, identifier)`` pairs for libraries whose source is
    available and extracted, and *missing* is a list of
    :class:`LibraryCandidate` objects for libraries whose source could
    not be found (with OS-appropriate install hints where possible).

    *exclude_identifiers* suppresses auto-detected subtrees that the
    operator already declared via ``--study-lib`` (manual wins).
    """
    headers = harvest_system_includes(target_path)
    if not headers:
        return [], []

    resolver = _detect_resolver()
    if resolver is None:
        logger.info(
            "library_detect: no supported package manager found — "
            "skipping auto-detection",
        )
        return [], []
    logger.debug("library_detect: using %s resolver", resolver.name)

    # Group headers by source package.
    pkg_headers: dict[str, set[str]] = {}
    _cache: dict[str, str | None] = {}

    for header in headers:
        if header not in _cache:
            _cache[header] = resolver.header_to_source_package(header)
        pkg = _cache[header]
        if pkg:
            pkg_headers.setdefault(pkg, set()).add(header)

    ready: list[tuple[str, str]] = []
    missing: list[LibraryCandidate] = []

    for pkg, pkg_hdrs in sorted(pkg_headers.items()):
        tarball = resolver.find_source_tarball(pkg)
        if tarball is None:
            hint = resolver.source_install_hint(pkg)
            missing.append(LibraryCandidate(
                pkg, installed=False, install_hint=hint,
            ))
            continue

        extracted = _extract_tarball(tarball, cache_dir)
        if extracted is None:
            missing.append(LibraryCandidate(
                pkg, installed=True, tarball=tarball,
            ))
            continue

        subtrees = _map_headers_to_subtrees(pkg_hdrs, pkg, extracted)
        subtrees = [
            (path, ident) for path, ident in subtrees
            if ident not in exclude_identifiers
        ]
        if subtrees:
            ready.extend(subtrees)
        else:
            missing.append(LibraryCandidate(
                pkg, installed=True, tarball=tarball,
                extracted_root=extracted,
            ))

    return ready, missing

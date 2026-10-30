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
import tarfile
from pathlib import Path

_glob_escape = _glob_mod.escape

logger = logging.getLogger(__name__)

# System include pattern — <header> only, not "header".
_INCLUDE_RE = re.compile(
    r'^\s*#\s*include\s+<([^>]+)>', re.MULTILINE,
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


def _extract_tarball(
    tarball: Path,
    cache_dir: Path,
) -> Path | None:
    """Extract *tarball* into *cache_dir*, returning the extracted root.

    Extracts only once — if the destination already exists and is
    non-empty, returns it directly.  Uses RAPTOR's hardened tar
    safety predicate for all member checks.
    """
    cache_dir.mkdir(parents=True, exist_ok=True)

    try:
        with tarfile.open(tarball, "r:*") as tf:
            first = tf.getmembers()[0]
            top_dir = first.name.split("/")[0]
    except (tarfile.TarError, IndexError, OSError):
        logger.warning(
            "library_detect: failed to read tarball %s", tarball,
            exc_info=True,
        )
        return None

    dest = cache_dir / top_dir
    if dest.is_dir() and any(dest.iterdir()):
        stamp = dest / ".raptor-extract-mtime"
        try:
            tarball_mtime = tarball.stat().st_mtime
        except OSError:
            tarball_mtime = 0.0
        if stamp.is_file():
            try:
                cached_mtime = float(stamp.read_text().strip())
            except (ValueError, OSError):
                cached_mtime = -1.0
            if cached_mtime == tarball_mtime:
                logger.info(
                    "library_detect: using cached extraction at %s", dest,
                )
                return dest
            logger.info(
                "library_detect: tarball mtime changed — re-extracting %s",
                tarball.name,
            )
            import shutil
            shutil.rmtree(dest, ignore_errors=True)
        else:
            logger.info(
                "library_detect: using cached extraction at %s (no stamp)",
                dest,
            )
            return dest

    logger.info(
        "library_detect: extracting %s → %s", tarball.name, cache_dir,
    )
    try:
        with tarfile.open(tarball, "r:*") as tf:
            cache_resolved = str(cache_dir.resolve())
            safe_members = []
            for member in tf.getmembers():
                reject = _is_safe_for_extraction(member, cache_resolved)
                if reject is not None:
                    logger.warning(
                        "library_detect: rejecting tarball member %r "
                        "(%s) — aborting extraction",
                        member.name, reject,
                    )
                    return None
                safe_members.append(member)
            tf.extractall(cache_dir, members=safe_members, filter="data")
    except (tarfile.TarError, OSError):
        logger.warning(
            "library_detect: extraction failed for %s",
            tarball, exc_info=True,
        )
        return None

    if dest.is_dir() and not _verify_no_escaping_symlinks(dest, cache_dir):
        import shutil
        shutil.rmtree(dest, ignore_errors=True)
        return None

    if dest.is_dir():
        try:
            tarball_mtime = tarball.stat().st_mtime
            (dest / ".raptor-extract-mtime").write_text(str(tarball_mtime))
        except OSError:
            pass
        return dest
    return None


def _verify_no_escaping_symlinks(root: Path, boundary: Path) -> bool:
    """Walk *root* and verify every symlink resolves within *boundary*.

    Pre-extraction checks validate individual link targets, but a
    chain of intra-root symlinks can compose into an escape.  This
    post-extraction pass resolves the full chain.

    ``os.walk`` does not follow symlinked directories, so directory
    symlinks are checked as entries in their parent's dir listing.
    """
    boundary_resolved = str(boundary.resolve()) + os.sep
    try:
        for dirpath, dirs, files in os.walk(root):
            for name in (*files, *dirs):
                fpath = Path(dirpath) / name
                if fpath.is_symlink():
                    target = str(fpath.resolve())
                    if not target.startswith(boundary_resolved):
                        logger.warning(
                            "library_detect: symlink chain escape: "
                            "%s → %s (outside %s)",
                            fpath, target, boundary,
                        )
                        return False
    except OSError:
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

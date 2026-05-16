"""Tar member safety predicate.

Wraps :func:`tarfile.data_filter` (PEP 706 / Python 3.12+) into a
boolean predicate consumers use as a skip-or-continue check.
Returns False for any disqualifying member; the caller decides
whether to skip-and-continue or abort the whole extraction.

The hardening rules (per PEP 706's ``data`` filter):

  * **Path traversal** — member name resolved against the
    extraction destination must not escape it. Catches
    ``../../../etc/passwd``, ``/etc/shadow``, and Windows-shaped
    drive letters that POSIX tar still accepts.
  * **Absolute paths** — leading ``/`` rejected; a tarball
    extracting to ``/usr/local`` shouldn't be writing to ``/etc``.
  * **Symlinks outside dest** — ``ln -s /etc/shadow shadow.lnk``
    in the tar would, on extract, write a symlink that the next
    open follows out of the sandbox. Refused.
  * **Hard links** — same shape as symlinks for the purposes of
    sandbox escape; refused.
  * **Special files** — block devices, character devices, FIFOs,
    sockets. None should ever appear in a "data" tarball.
  * **uid/gid bits** — setuid / setgid / sticky bits stripped.
    A tarball can't usefully grant SUID 0 to its own files; the
    presence is suspicious.

In addition to the PEP 706 rules, this helper enforces a per-member
size cap. PEP 706 doesn't address compression bombs (the size cap
is the consumer's responsibility); we fold it in here so consumers
get one predicate to call.

Usage:

    for member in tf:
        if not is_safe_member(member):
            continue
        # extract member safely
"""

from __future__ import annotations

import logging
import sys
import tarfile
from dataclasses import dataclass
from enum import Enum
from typing import Optional

logger = logging.getLogger(__name__)


# Sane upper bound — most files in real archives are KB to a few
# MB. 64 MB is generous for real data; anything bigger is either
# a misuse of tar (use a different format) or a malicious bomb.
DEFAULT_MAX_MEMBER_BYTES = 64 * 1024 * 1024

# We need a fictional "destination" path for tarfile.data_filter to
# resolve relative paths against. The path doesn't need to exist
# (data_filter does string-based resolution); we use a fixed
# sentinel that's clearly not a real filesystem location.
_RESOLUTION_DEST = "/tmp/__raptor_tar_safety_check__"


class UnsafeMemberReason(str, Enum):
    """Reason a tar member was rejected. Surfaced via
    :func:`safe_member_reason` so callers can log specific causes
    or aggregate by class."""
    SAFE = "safe"
    PATH_TRAVERSAL = "path_traversal"
    ABSOLUTE_PATH = "absolute_path"
    SPECIAL_FILE = "special_file"           # block/char dev, fifo, socket
    SYMLINK_UNSAFE = "symlink_unsafe"
    HARD_LINK = "hard_link"
    OVERSIZED = "oversized"
    UNRECOGNISED_TYPE = "unrecognised_type"


def is_safe_member(
    member: tarfile.TarInfo,
    *,
    max_size: int = DEFAULT_MAX_MEMBER_BYTES,
    allow_absolute_paths: bool = False,
) -> bool:
    """True if extracting ``member`` is safe under the hardening
    rules. Boolean wrapper over :func:`safe_member_reason` for
    callers that don't need the diagnostic detail."""
    return safe_member_reason(
        member, max_size=max_size,
        allow_absolute_paths=allow_absolute_paths,
    ) == UnsafeMemberReason.SAFE


def safe_member_reason(
    member: tarfile.TarInfo,
    *,
    max_size: int = DEFAULT_MAX_MEMBER_BYTES,
    allow_absolute_paths: bool = False,
) -> UnsafeMemberReason:
    """Return the specific reason ``member`` is unsafe, or
    :data:`UnsafeMemberReason.SAFE`.

    ``allow_absolute_paths`` is for read-into-memory consumers
    (e.g. :mod:`core.oci.blob` matching against a wanted-paths
    set without touching disk). Layer tarballs from container
    images legitimately have absolute member names (``/var/lib/...``),
    and the path-escape risk doesn't exist when nothing is written
    to disk. Default False — conservative for consumers that DO
    extract to a destination directory.

    Useful for diagnostic logging or aggregating "we rejected N
    members for path-traversal, M for symlinks" counts at the
    consumer's report layer.
    """
    # Size check first — cheap, and a 1 GB malicious entry should
    # be rejected before doing anything else with it.
    if member.size > max_size:
        return UnsafeMemberReason.OVERSIZED

    # Type check — only regular files, directories (skipped at
    # extract time but valid as members), and harmless symlinks
    # within dest. Block / char devices, FIFOs, sockets shouldn't
    # be in data tarballs.
    if member.isblk() or member.ischr() \
            or member.isfifo() or member.isdev():
        return UnsafeMemberReason.SPECIAL_FILE

    # Hard links can point inside or outside dest; PEP 706's filter
    # checks but we additionally treat any hard link as rejected
    # because none of our consumers need them (we extract individual
    # files, not full trees with internal cross-references).
    if member.islnk():
        return UnsafeMemberReason.HARD_LINK

    # Absolute-path check before delegating to data_filter. PEP 706's
    # data_filter SILENTLY STRIPS a leading ``/`` rather than
    # rejecting — that's the right behaviour for plain extraction
    # (the result lands inside dest), but our consumers' contract
    # is "no absolute paths". Surface explicitly so the operator-
    # facing reason matches what they read. Skipped when
    # ``allow_absolute_paths=True`` (read-into-memory consumers
    # don't have an escape risk).
    if not allow_absolute_paths:
        if member.name.startswith("/"):
            return UnsafeMemberReason.ABSOLUTE_PATH
        if member.issym() and member.linkname.startswith("/"):
            return UnsafeMemberReason.SYMLINK_UNSAFE

    # Use Python 3.12+ tarfile.data_filter for the canonical
    # path-traversal / symlink-target / abspath checks. Wrapped in
    # try/except because data_filter raises (rather than returns)
    # on rejection.
    if sys.version_info >= (3, 12):
        try:
            tarfile.data_filter(member, _RESOLUTION_DEST)
        except tarfile.AbsolutePathError:
            return UnsafeMemberReason.ABSOLUTE_PATH
        except tarfile.OutsideDestinationError:
            return UnsafeMemberReason.PATH_TRAVERSAL
        except tarfile.SpecialFileError:
            # data_filter also raises this for special files — we
            # already handled above, but defensive.
            return UnsafeMemberReason.SPECIAL_FILE
        except tarfile.AbsoluteLinkError:
            return UnsafeMemberReason.SYMLINK_UNSAFE
        except tarfile.LinkOutsideDestinationError:
            return UnsafeMemberReason.SYMLINK_UNSAFE
        except tarfile.FilterError:
            # Catch-all for any other filter rejection. Surface as
            # "unrecognised type" so operators investigating know
            # the member was rejected by an unrelated rule.
            return UnsafeMemberReason.UNRECOGNISED_TYPE
        except Exception:                           # noqa: BLE001
            # Unexpected error from data_filter — refuse the member
            # (fail-closed) and surface in debug logs. Better to
            # skip a borderline member than silently extract it.
            logger.debug(
                "core.tar: data_filter raised unexpected error for "
                "%r — refusing", member.name, exc_info=True,
            )
            return UnsafeMemberReason.UNRECOGNISED_TYPE
    else:
        # Pre-3.12 fallback: hand-roll the most important checks.
        # Stricter than data_filter to be safe — we'd rather over-
        # reject on legacy Python than ship a known gap.
        if member.name.startswith("/"):
            return UnsafeMemberReason.ABSOLUTE_PATH
        if "../" in member.name or member.name.startswith("../"):
            return UnsafeMemberReason.PATH_TRAVERSAL
        if member.issym():
            target = member.linkname
            if target.startswith("/") or "../" in target:
                return UnsafeMemberReason.SYMLINK_UNSAFE

    return UnsafeMemberReason.SAFE


__all__ = [
    "DEFAULT_MAX_MEMBER_BYTES",
    "UnsafeMemberReason",
    "is_safe_member",
    "safe_member_reason",
]

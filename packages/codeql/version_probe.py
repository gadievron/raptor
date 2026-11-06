"""One CodeQL version reader for compatibility checks and database metadata."""

import os
import re
import shutil
import subprocess

from core.logging import get_logger

from core.analysis.rule_versions import version_tuple
from core.run.toolprobe import probe
from .temp_env import temporary_command

logger = get_logger()

_BANNER = "CodeQL command-line toolchain release "
_BARE_RELEASE = re.compile(r"v?[0-9]{1,6}\.[0-9]{1,6}(?:\.[0-9]{1,6})?")
_MAX_VERSION_TEXT_CHARS = 64 * 1024


def parse_version_output(stdout: str, stderr: str) -> str | None:
    """Prefer named CodeQL banners; support unambiguous bare-version wrappers."""
    banners: set[tuple[int, int, int]] = set()
    bare: set[tuple[int, int, int]] = set()
    for stream in (stdout, stderr):
        if not isinstance(stream, str) or len(stream) >= _MAX_VERSION_TEXT_CHARS:
            return None
        for line in stream.splitlines():
            line = line.strip()
            if line.startswith(_BANNER):
                release = version_tuple(line.removeprefix(_BANNER).removesuffix("."))
                if release is None:
                    return None
                banners.add(release)
        text = stream.strip()
        if _BARE_RELEASE.fullmatch(text):
            release = version_tuple(text)
            if release is not None:
                bare.add(release)
    versions = banners if banners else bare
    return ".".join(map(str, next(iter(versions)))) if len(versions) == 1 else None


def read_codeql_version(executable: str) -> str | None:
    """Fresh bounded-output probe using CodeQL's existing temporary setup."""
    try:
        resolved = shutil.which(executable)
        if resolved is None:
            return None
        command = temporary_command([os.path.abspath(resolved), "version"])
        # The existing probe interface accepts a program plus argv. When a
        # temporary-directory wrapper is needed, probe that trusted wrapper
        # with the pinned CodeQL executable retained in its argument list.
        info = probe(command[0], args=tuple(command[1:]))
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        logger.warning("CodeQL version probe unavailable: %s", type(exc).__name__)
        return None
    if info is None or info.returncode != 0:
        return None
    return parse_version_output(info.stdout, info.stderr)

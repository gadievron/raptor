"""Legacy: shell-script-based mount-namespace setup.

SUPERSEDED by `core.sandbox._spawn.run_sandboxed` + `core.sandbox.mount_ns`,
which do the same work via ctypes syscalls inside a forked child, in the
right order for kernel 6.17 / Landlock ABI 7 (mount ops BEFORE
landlock_restrict_self). The shell-script path is no longer reachable
from `sandbox().run()` — `context.py` either dispatches to `_spawn` or
falls back to a Landlock-only subprocess chain.

This module is kept for two reasons:

  1. Back-compat tests (test_sandbox.py::test_build_mount_script_*) cover
     argv-injection defences (`--` separator, shlex.quote, etc.) that
     predate `_spawn`. The tests still assert the same invariants we
     want from `mount_ns.setup_mount_ns` — removing them would drop the
     negative-path coverage.

  2. It documents the old mkdir-at-`/` failure mode: on permissive
     sysctl configurations, `mkdir /target` at the root filesystem fails
     because `/` is owned by real uid 0 and our user-ns uid 0 maps to
     the caller uid for ACL checks. `_spawn`'s pivot_root-onto-tmpfs
     design closes that class of bug.

Absolute paths (`mount`, `mkdir`) are still used to defeat PATH
hijacking, consistent with every other spawn point in the sandbox.
"""

import os
import shlex
import tempfile
from typing import Optional

from .probes import _resolve_sandbox_binary


def _build_mount_script(target: Optional[str], output: Optional[str]) -> Optional[str]:
    """Build a shell script that sets up the mount namespace.

    Returns the path to the script, or None if no mount isolation requested.
    """
    if not target and not output:
        return None

    # Resolve mount and mkdir to absolute paths in the parent, before
    # the child exec's with potentially-poisoned PATH. Resolution uses
    # the hardcoded safe-bin-dir list (see probes._resolve_sandbox_binary).
    mount_bin = _resolve_sandbox_binary("mount")
    mkdir_bin = _resolve_sandbox_binary("mkdir")

    lines = [
        "#!/bin/sh",
        "set -e",
        f"{shlex.quote(mount_bin)} --make-rprivate /",
        # Create mount points while root filesystem is still writable
    ]
    if target:
        lines.append(f"{shlex.quote(mkdir_bin)} -p /target 2>/dev/null || true")
    if output:
        lines.append(f"{shlex.quote(mkdir_bin)} -p /output 2>/dev/null || true")
    lines.append("# Now make root read-only.")
    lines.append("# `remount,bind,ro` (not plain `remount,ro`) — on Ubuntu 24.04")
    lines.append("# a non-bind remount of `/` from an unprivileged user-ns fails")
    lines.append("# with EACCES because it needs CAP_SYS_ADMIN in the namespace")
    lines.append("# the mount was originally created in (the init ns). Adding")
    lines.append("# `bind` makes it a self-bind remount which only needs")
    lines.append("# CAP_SYS_ADMIN on the current ns — we have that from unshare")
    lines.append("# --user --mount --map-root-user. The filesystem becomes")
    lines.append("# read-only either way.")
    lines.append(f"{shlex.quote(mount_bin)} -o remount,bind,ro /")
    # `--` separator stops mount option parsing. Without it, a path like
    # `--help` is interpreted as a flag — mount prints help, bind never
    # happens, and `set -e` aborts before `exec "$@"`, leaving the caller
    # with an unhelpful error. Even though these paths originate from
    # RAPTOR-owned tempdirs today, defence-in-depth.
    if target:
        lines.append(f'{shlex.quote(mount_bin)} --bind -o ro -- '
                     f'{shlex.quote(target)} /target')
    if output:
        lines.append(f'{shlex.quote(mount_bin)} --bind -- '
                     f'{shlex.quote(output)} /output')
    lines.append(f"{shlex.quote(mount_bin)} -t tmpfs tmpfs /tmp")
    lines.append('exec "$@"')

    fd, path = tempfile.mkstemp(prefix=".raptor_sandbox_", suffix=".sh")
    # Unlink on any failure between mkstemp and return so a failed write
    # or chmod doesn't leak the tempfile. Caller cleans up the path on
    # normal shutdown via the context manager's finally block.
    try:
        try:
            os.write(fd, ("\n".join(lines) + "\n").encode())
        finally:
            os.close(fd)
        os.chmod(path, 0o700)
    except OSError:
        try:
            os.unlink(path)
        except OSError:
            pass
        raise
    return path

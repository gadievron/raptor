r"""Run ``packages.frida.cli`` inside a sandbox.

Invoked by ``libexec/raptor-frida`` when ``--unsafe-attach`` is NOT
set.  Wraps the CLI subprocess in ``core.sandbox.run()`` with the
``frida`` profile (ptrace allowed) and ``skip_pid_ns=True`` (/proc
readable for frida's process enumeration).

Network policy depends on target mode:
  * **spawn** (``--target ./binary``): ``block_network=True`` — we
    control the process, no reason to let it reach out.
  * **attach** (``--target <pid|name>``): network untouched — the
    process is already running with whatever connectivity it needs.

Usage (from libexec/raptor-frida)::

    python3 -m packages.frida.sandboxed --spawn --out /tmp/run -- \
        python3 -m packages.frida.cli --target ./victim ...
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

_KNOWN_PYTHON_PREFIXES = ("/usr/", "/opt/", "/home/", "/nix/")


def _find_frida_site() -> str | None:
    """Locate frida's site-packages directory.

    Probes sys.executable first, then follows the ``frida`` CLI
    shebang (covers pipx / venv installs). Returns the site-packages
    directory, or None if frida is not installed.
    """
    import shutil

    def _probe(python: str) -> str | None:
        if not python or not os.path.isfile(python):
            return None
        try:
            # Sanitised env (the codeql version-probe idiom): a bare
            # python probe would import through the shell's
            # PYTHONPATH / PYTHONSTARTUP.
            from core.security.env_sanitisation import (
                safe_subprocess_env,
            )
            r = subprocess.run(
                [python, "-c",
                 "import frida; print(frida.__file__)"],
                capture_output=True, text=True, timeout=5,
                env=safe_subprocess_env(strip_target_markers=True),
            )
            if r.returncode == 0 and r.stdout.strip():
                site = Path(r.stdout.strip()).parent.parent
                if site.is_dir():
                    return str(site)
        except (OSError, subprocess.SubprocessError):
            pass
        return None

    result = _probe(sys.executable)
    if result:
        return result

    frida_bin = shutil.which("frida")
    if not frida_bin:
        return None
    try:
        with open(frida_bin, encoding="utf-8") as f:
            shebang = f.readline(256).strip()
        if shebang.startswith("#!"):
            parts = shebang[2:].strip().split()
            if not parts:
                return None
            python = parts[0]
            if not any(python.startswith(p) for p in _KNOWN_PYTHON_PREFIXES):
                return None
            return _probe(python)
    except OSError:
        pass
    return None


def _flag_value(cmd: list[str], flag: str) -> str | None:
    """Last value of *flag* in argv, accepting both ``--flag value``
    and ``--flag=value`` (argparse takes the last occurrence)."""
    value: str | None = None
    for i, token in enumerate(cmd):
        if token == flag and i + 1 < len(cmd):
            value = cmd[i + 1]
        elif token.startswith(flag + "="):
            value = token.split("=", 1)[1]
    return value


def main() -> int:
    argv = sys.argv[1:]

    spawn_mode = False
    out_dir = None
    cmd_start = None

    i = 0
    while i < len(argv):
        if argv[i] == "--spawn":
            spawn_mode = True
            i += 1
        elif argv[i] == "--out" and i + 1 < len(argv):
            out_dir = argv[i + 1]
            i += 2
        elif argv[i] == "--":
            cmd_start = i + 1
            break
        else:
            i += 1

    if cmd_start is None or cmd_start >= len(argv):
        print("usage: python3 -m packages.frida.sandboxed "
              "[--spawn] --out DIR -- CMD...", file=sys.stderr)
        return 2

    cmd = argv[cmd_start:]

    try:
        from core.sandbox import run as sandbox_run
    except ImportError as exc:
        print(f"Fatal: core.sandbox not importable: {exc}", file=sys.stderr)
        print("Refusing to run frida unsandboxed. Fix the installation "
              "or use --unsafe-attach explicitly.", file=sys.stderr)
        return 1

    raptor_dir = os.environ.get("RAPTOR_DIR", "")
    tool_paths = []
    pypath_parts = []
    if raptor_dir:
        pypath_parts.append(raptor_dir)
        tool_paths.append(raptor_dir)

    frida_site = _find_frida_site()
    if frida_site:
        pypath_parts.append(frida_site)
        tool_paths.append(frida_site)

    from core.sandbox.python_paths import python_runtime_tool_paths
    for p in python_runtime_tool_paths():
        if p not in tool_paths:
            tool_paths.append(p)

    # Operator-supplied inputs live at arbitrary paths outside the
    # default readable set; under restrict_reads the CLI would fail
    # before any hook loads: hook sources (--script JS, --sink-watch
    # sinks/attack-paths JSON) and --stdin PoC input with an
    # "unreadable file" error, and a spawn-target binary
    # (--target /path/to/bin) with frida's PermissionDeniedError.
    # Grant each file's parent directory — the target may also
    # dlopen sibling libraries.
    for flag in ("--script", "--sink-watch", "--stdin", "--target"):
        value = _flag_value(cmd, flag)
        if not value:
            continue
        value_path = Path(value)
        if flag == "--target" and not value_path.is_file():
            continue  # PID / process name / bundle id, not a path
        parent = str(value_path.resolve().parent)
        if parent not in tool_paths:
            tool_paths.append(parent)

    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": os.environ.get("HOME", "/tmp"),
        "LANG": os.environ.get("LANG", "C.UTF-8"),
        "TERM": "dumb",
        "RAPTOR_DIR": raptor_dir,
    }
    if pypath_parts:
        env["PYTHONPATH"] = ":".join(pypath_parts)

    if out_dir and not os.path.isdir(out_dir):
        os.makedirs(out_dir, exist_ok=True)

    # restrict_reads carries the fileless-exec seccomp deny; the frida
    # profile carves memfd_create back out of it (agent injection
    # writes frida-agent.so into a memfd and the target dlopen-maps it
    # from /proc/self/fd — the wholesale deny aborts every spawn/attach
    # at injection). Consented-instrumentation rationale and the
    # execveat arm that stays: core/sandbox/seccomp.py,
    # _make_seccomp_preexec docstring.
    result = sandbox_run(
        cmd,
        profile="frida",
        skip_pid_ns=True,
        skip_mount_ns=True,
        fake_home=True,
        block_network=spawn_mode,
        output=out_dir,
        restrict_reads=True,
        caller_label="frida",
        env=env,
        tool_paths=tool_paths or None,
    )
    return result.returncode


if __name__ == "__main__":
    sys.exit(main())

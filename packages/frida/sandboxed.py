"""Run ``packages.frida.cli`` inside a sandbox.

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

    python3 -m packages.frida.sandboxed --spawn --out /tmp/run -- \\
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
            r = subprocess.run(
                [python, "-c",
                 "import frida; print(frida.__file__)"],
                capture_output=True, text=True, timeout=5,
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
        with open(frida_bin, "r", encoding="utf-8") as f:
            shebang = f.readline(256).strip()
        if shebang.startswith("#!"):
            python = shebang[2:].strip().split()[0]
            if not any(python.startswith(p) for p in _KNOWN_PYTHON_PREFIXES):
                return None
            return _probe(python)
    except OSError:
        pass
    return None


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
        print(f"FATAL: core.sandbox not importable: {exc}", file=sys.stderr)
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

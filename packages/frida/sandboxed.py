"""Run ``packages.frida.cli`` inside a sandbox.

Invoked by ``libexec/raptor-frida`` when ``--unsafe-attach`` is NOT
set.  Wraps the CLI subprocess in ``core.sandbox.run()`` with the
``debug`` profile (ptrace allowed) and ``skip_pid_ns=True`` (/proc
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


def _find_frida_site() -> str | None:
    """Locate frida's site-packages directory.

    Probes sys.executable first, then follows the ``frida`` CLI
    shebang (covers pipx / venv installs). Returns the site-packages
    directory, or None if frida is not installed.
    """
    import shutil
    from pathlib import Path

    def _probe(python: str) -> str | None:
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
            shebang = f.readline().strip()
        if shebang.startswith("#!"):
            python = shebang[2:].strip().split()[0]
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
    except ImportError:
        import subprocess
        print("warning: core.sandbox not available, running unsandboxed",
              file=sys.stderr)
        return subprocess.call(cmd)

    raptor_dir = os.environ.get("RAPTOR_DIR", "")
    env = dict(os.environ)
    tool_paths = []
    pypath_parts = []
    if raptor_dir:
        pypath_parts.append(raptor_dir)
        tool_paths.append(raptor_dir)

    frida_site = _find_frida_site()
    if frida_site:
        pypath_parts.append(frida_site)
        tool_paths.append(frida_site)

    if pypath_parts:
        env["PYTHONPATH"] = ":".join(pypath_parts)

    result = sandbox_run(
        cmd,
        profile="frida",
        skip_pid_ns=True,
        skip_mount_ns=True,
        block_network=spawn_mode,
        output=out_dir,
        caller_label="frida",
        env=env,
        tool_paths=tool_paths or None,
    )
    return result.returncode


if __name__ == "__main__":
    sys.exit(main())

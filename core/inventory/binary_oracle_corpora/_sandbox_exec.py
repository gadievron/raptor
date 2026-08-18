"""Sandboxed execution helpers for corpus drivers.

The corpus drivers clone pinned upstream refs and then execute the
FETCHED build systems (autogen.sh / configure / make / cmake / ctest /
cargo) plus the binaries they produce. The refs are pinned, but a
supply-chain compromise of an upstream tag would otherwise run
attacker build scripts on the operator machine with the operator's
full environment — exactly the class ``core.sandbox`` exists for.

Two helpers, one policy each:

* :func:`run_build_step` — fetched build systems, built test binaries,
  and test runners (ctest). Full sandbox via ``core.sandbox.run``:
  Landlock read scope + write scope on the build tree, network blocked
  unless the step is a declared package-manager fetch (cargo),
  environment reduced to ``RaptorConfig.get_safe_env()`` plus the
  explicit flags the step needs (CFLAGS/RUSTFLAGS/...).
* :func:`run_tool` — RAPTOR-chosen host tools (gcov, nm,
  llvm-profdata, llvm-cov) over artifacts of those builds. Delegates
  to ``core.sandbox.run_trusted`` (safe env + rlimits); the command is
  trusted, only its input is build-derived.

Both raise :class:`subprocess.CalledProcessError` on non-zero exit
when ``check=True`` (the sandbox layer itself never raises on exit
status), so driver control flow keeps its existing ``check=True``
semantics.
"""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)

_LABEL = "binary-oracle-corpus"


def _raise_if_failed(proc, cmd, check: bool):
    if check and proc.returncode != 0:
        tail = (proc.stderr or "")[-2000:] if isinstance(
            proc.stderr, str) else ""
        if tail:
            logger.error("%s: build step failed (rc=%s): %s",
                         _LABEL, proc.returncode, tail)
        raise subprocess.CalledProcessError(
            proc.returncode, cmd, output=proc.stdout, stderr=proc.stderr)
    return proc


def run_build_step(
    cmd: list,
    *,
    cwd: Path,
    timeout: int,
    extra_env: dict | None = None,
    network: bool = False,
    writable_paths: list | None = None,
    check: bool = True,
    scope: Path | None = None,
):
    """Run a fetched build-system step (or a binary it produced) sandboxed.

    ``cwd`` doubles as the Landlock read target and write scope unless
    ``scope`` names a wider root. ``scope`` exists for out-of-tree
    builds: under mount-namespace isolation only target/output survive
    into the child's view, so a cmake/configure step running in
    ``<scratch>/build`` cannot even SEE its sibling ``<scratch>/src``
    (reads elsewhere aren't merely denied — the paths don't exist).
    Drivers with a src/build split pass the per-corpus scratch dir
    (which contains both) as ``scope``; everything in it is
    RAPTOR-created corpus scratch, so the untrusted build system stays
    confined to its own working area either way.

    ``extra_env`` entries (CFLAGS, RUSTFLAGS, LLVM_PROFILE_FILE, ...)
    are layered on top of the sanitised base env. ``network=True`` is
    ONLY for declared package-manager fetch steps (cargo pulling
    crates); everything else builds with the network namespace removed.
    Fetch steps keep the operator's proxy vars (same opt-in contract
    as ``get_safe_git_env(preserve_proxy=True)``): they dial a remote
    outside the sandbox egress proxy, and on mandatory-egress-proxy
    hosts the fetch has no route without them.
    """
    from core.config import RaptorConfig
    from core.sandbox import run as sandbox_run

    env = RaptorConfig.get_safe_env(preserve_proxy=network)
    if extra_env:
        env.update({k: str(v) for k, v in extra_env.items()})

    scope_dir = str(scope) if scope is not None else str(cwd)
    kwargs: dict = {
        "block_network": not network,
        "target": scope_dir,
        "output": scope_dir,
        "cwd": str(cwd),
        "env": env,
        "env_caller_filtered": True,
        "caller_label": _LABEL,
        "capture_output": True,
        "text": True,
        "timeout": timeout,
    }
    if writable_paths:
        kwargs["writable_paths"] = [str(p) for p in writable_paths]

    proc = sandbox_run([str(c) for c in cmd], **kwargs)
    return _raise_if_failed(proc, cmd, check)


def run_tool(
    cmd: list,
    *,
    cwd: Path | None = None,
    timeout: int,
    check: bool = True,
    input_text: str | None = None,
):
    """Run a RAPTOR-chosen host tool (gcov/nm/llvm-*) with safe env.

    ``run_trusted`` applies ``get_safe_env()`` + rlimits; output is
    always captured as text (every corpus caller parses stdout).
    """
    from core.sandbox import run_trusted

    kwargs: dict = {
        "capture_output": True,
        "text": True,
        "timeout": timeout,
    }
    if cwd is not None:
        kwargs["cwd"] = str(cwd)
    if input_text is not None:
        kwargs["input"] = input_text
    proc = run_trusted([str(c) for c in cmd], **kwargs)
    return _raise_if_failed(proc, cmd, check)

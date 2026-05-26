#!/usr/bin/env python3
"""Subprocess-compatible SCA entry point + cross-tool launch helpers.

When invoked as a script::

    python3 packages/sca/agent.py --repo /path/to/target --out /path/to/out

Runs the full SCA analyse pipeline and writes findings.json + SARIF +
report.md into ``--out``, then prints a one-line JSON summary to stdout
so the caller can parse it.

When imported as a module, exposes two helpers used by
``raptor_agentic.py`` and other RAPTOR-side callers that want to launch
SCA as a sandboxed subprocess rather than in-process:

  - :func:`_find_sca_agent` — discover the SCA agent entry point.
    Returns the resolved path to this file (or to an external override
    set via ``RAPTOR_SCA_AGENT`` env). Pre-merge, this used to bridge
    to a separate ``raptor-sca`` repo; post-merge SCA lives in-tree.
  - :func:`run_sca_subprocess` — launch the agent under
    ``core.sandbox.run`` with egress restricted to
    :data:`packages.sca.SCA_ALLOWED_HOSTS`.

When ``--sandbox`` is passed to the script form, the analysis runs
inside a sandbox context with egress proxy enabled — the
``EgressClient`` default in ``packages.sca.__init__`` already routes
HTTP through the proxy, and the resolver subprocesses already sandbox
themselves, so the outer context adds Landlock FS confinement for the
manifest-parsing phase.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import subprocess
import sys
from pathlib import Path
from typing import Optional, Sequence

_REPO = Path(__file__).resolve().parents[2]  # raptor-sca repo root
sys.path.insert(0, str(_REPO))

from packages.sca.api import analyse  # noqa: E402

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Cross-tool launch helpers
# ---------------------------------------------------------------------------

def _find_sca_agent() -> Optional[Path]:
    """Discover the SCA agent entry point.

    Post-merge, SCA lives in-tree — this file IS the agent. So the
    default answer is ``Path(__file__).resolve()``. The
    ``RAPTOR_SCA_AGENT`` env var still allows pointing at an external
    agent (e.g. a vendored or pinned version) for CI / custom layouts.
    Returns ``None`` only when the override path is set but invalid.
    """
    env_path = os.environ.get("RAPTOR_SCA_AGENT")
    if env_path:
        p = Path(env_path).resolve()
        if not p.is_file():
            logger.warning("RAPTOR_SCA_AGENT=%s does not exist — ignoring",
                           env_path)
            return None
        # Content discriminator: a file CAN exist at the override path
        # without being a real SCA agent — operator typos, stale
        # symlinks, sibling-project ``agent.py`` files, placeholder
        # scripts. Pre-content-check, those silently launched the
        # wrong subprocess and surfaced as opaque "no SCA findings"
        # or downstream crashes blamed on raptor-sca itself. The
        # `from packages.sca import SCA_ALLOWED_HOSTS` import is the
        # discriminator — every real agent imports it; nothing else
        # has reason to.
        # Cap the marker-check read at 256 KB. Pre-fix
        # ``read_text()`` loaded the WHOLE candidate file before
        # the marker check — if RAPTOR_SCA_AGENT picked up a giant
        # file by mistake (a vendored binary mislabeled as
        # ``agent.py``, an inadvertent log paste), we'd buffer the
        # whole thing into memory just to confirm "no, this isn't
        # the right file." The marker we're looking for
        # (``from packages.sca import SCA_ALLOWED_HOSTS``) is at
        # the top of any legitimate agent — 256 KB is two orders
        # of magnitude beyond any realistic Python module's
        # first-block imports.
        _MAX_MARKER_BYTES = 256 * 1024
        try:
            with open(p, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read(_MAX_MARKER_BYTES)
        except OSError:
            logger.warning(
                "RAPTOR_SCA_AGENT=%s could not be read — ignoring",
                env_path,
            )
            return None
        if "from packages.sca import SCA_ALLOWED_HOSTS" not in text:
            logger.warning(
                "RAPTOR_SCA_AGENT=%s does not look like a raptor-sca "
                "agent (missing SCA_ALLOWED_HOSTS import) — ignoring",
                env_path,
            )
            return None
        return p
    return Path(__file__).resolve()


def run_sca_subprocess(
    agent_path: Path,
    target: Path,
    output_dir: Path,
    *,
    sandbox_args: Sequence[str] = (),
    env: Optional[dict] = None,
    timeout: int = 600,
) -> tuple:
    """Run the SCA agent as a sandboxed subprocess.

    Uses :func:`core.sandbox.run` with ``use_egress_proxy=True`` so the
    child's outbound HTTPS is funnelled through the in-process proxy
    with :data:`packages.sca.SCA_ALLOWED_HOSTS` as the hostname
    allowlist. Landlock confines writes to ``output_dir``.

    Returns ``(returncode, stdout, stderr)``.
    """
    from core.config import RaptorConfig
    from core.sandbox import run as sandbox_run

    cmd: list = [
        sys.executable, str(agent_path),
        "--repo", str(target),
        "--out", str(output_dir),
        *sandbox_args,
    ]

    # Wrap sandbox_run in a TimeoutExpired catch. The function's
    # return-type contract is ``(returncode, stdout, stderr)`` —
    # pre-fix a TimeoutExpired exception escaped past the call
    # site and surfaced to callers as an unhandled traceback when
    # the docstring promised a tuple. Convert to a synthetic-
    # failure tuple so callers' ``if rc != 0`` paths fire
    # predictably.
    try:
        result = sandbox_run(
            cmd,
            use_egress_proxy=True,
            proxy_hosts=_compose_proxy_hosts(target),
            caller_label="sca-agent",
            target=str(target),
            output=str(output_dir),
            # ``env if env is not None`` — pre-fix ``env or`` truthy-tested,
            # so an EXPLICIT ``env={}`` (caller's "spawn with empty env"
            # signal) got replaced with the default safe env because
            # ``{}`` is falsy. The empty-env intent was silently
            # overridden — sandbox children inherited the caller-default
            # RAPTOR env when caller had specifically asked for nothing.
            env=env if env is not None else RaptorConfig.get_safe_env(),
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        # Surface as a non-zero exit code with a structured stderr
        # message. Stdout from the partial run (if any) is
        # preserved so the caller's parsing layer can salvage what
        # landed.
        partial_stdout = (
            exc.stdout.decode("utf-8", errors="replace")
            if isinstance(exc.stdout, (bytes, bytearray))
            else (exc.stdout or "")
        )
        return (
            -1,
            partial_stdout,
            f"sca-agent timed out after {timeout}s",
        )
    return result.returncode, result.stdout, result.stderr


def _compose_proxy_hosts(target: Path) -> list:
    """Re-export of :func:`packages.sca.compose_proxy_hosts` for the
    sandbox-subprocess code path.

    Kept as a thin module-level alias so existing test stubs that
    monkeypatch ``packages.sca.agent._compose_proxy_hosts`` continue
    to work. New callers should use the package-level
    ``packages.sca.compose_proxy_hosts`` directly — same impl, also
    used by the in-process ``default_client(target)`` seam so both
    code paths share one allowlist composition.
    """
    from packages.sca import compose_proxy_hosts as _impl
    return _impl(target)


# ---------------------------------------------------------------------------
# Subprocess entry point — when invoked as `python3 packages/sca/agent.py …`
# ---------------------------------------------------------------------------

def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="RAPTOR SCA agent")
    ap.add_argument("--repo", required=True, help="Target project root")
    ap.add_argument("--out", required=True, help="Output directory")
    ap.add_argument("--offline", action="store_true")
    ap.add_argument("--no-cache", action="store_true")
    ap.add_argument("--sarif-dirs", nargs="*",
                    help="Sibling SARIF directories for cross-tool linking")
    ap.add_argument("--sandbox", choices=["full", "network-only", "none"],
                    default=None,
                    help="Sandbox profile (default: use egress proxy only)")
    ap.add_argument("--no-sandbox", action="store_true",
                    help="Disable all sandbox isolation")
    ap.add_argument("--audit", action="store_true")
    ap.add_argument("--audit-verbose", action="store_true")
    # ``parse_known_args`` rather than ``parse_args``: SCA is invoked
    # by raptor.py / ``/agentic --sca`` / future wrappers that pass
    # the standard RAPTOR run-lifecycle flag set (``--max-cost``,
    # ``--no-exploits``, ``--no-patches``, etc.). Pre-fix any unknown
    # flag triggered a SystemExit, breaking the wrapper invocation
    # path. Wrappers' own argparse already consumes their flags
    # before forwarding; SCA only needs to silently ignore any that
    # leak through.
    args, _unknown = ap.parse_known_args(argv)

    sarif_dirs = [Path(p) for p in args.sarif_dirs] if args.sarif_dirs else None
    target = Path(args.repo).resolve()
    output_dir = Path(args.out).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    use_sandbox = args.sandbox is not None and not args.no_sandbox

    if use_sandbox:
        result = _run_sandboxed(
            target=target,
            output_dir=output_dir,
            offline=args.offline,
            no_cache=args.no_cache,
            sarif_dirs=sarif_dirs,
            profile=args.sandbox,
            audit=args.audit,
            audit_verbose=args.audit_verbose,
        )
    else:
        result = analyse(
            target=target,
            output_dir=output_dir,
            offline=args.offline,
            no_cache=args.no_cache,
            sarif_dirs=sarif_dirs,
        )

    print(json.dumps(result))
    return 0 if result.get("status") == "ok" else 1


def _run_sandboxed(
    *, target, output_dir, offline, no_cache, sarif_dirs, profile,
    audit: bool = False, audit_verbose: bool = False,
):
    """Run analyse() inside a sandbox context.

    ``audit`` / ``audit_verbose`` pair with
    :func:`core.sandbox.context.sandbox`'s audit knob: when set,
    Landlock filesystem denials and proxy host-allowlist
    refusals get appended to ``<output_dir>/sandbox-audit.jsonl``
    so operators can verify the sandbox engaged (and spot any
    accidentally-blocked read that's degrading the run). Without
    these wired through, the agent.py CLI exposes ``--audit`` but
    the flag is silently inert — surfaced by the Tier-7 dev E2E
    sweep.
    """
    try:
        from core.sandbox.context import sandbox
    except ImportError:
        logger.warning("sca.agent: sandbox not available, running unsandboxed")
        return analyse(
            target=target, output_dir=output_dir,
            offline=offline, no_cache=no_cache, sarif_dirs=sarif_dirs,
        )

    with sandbox(
        target=str(target),
        output=str(output_dir),
        profile=profile,
        use_egress_proxy=True,
        proxy_hosts=_compose_proxy_hosts(target),
        caller_label="sca-agent",
        audit=audit,
        audit_verbose=audit_verbose,
        audit_run_dir=str(output_dir) if audit else None,
    ):
        return analyse(
            target=target, output_dir=output_dir,
            offline=offline, no_cache=no_cache, sarif_dirs=sarif_dirs,
        )


if __name__ == "__main__":
    sys.exit(main())

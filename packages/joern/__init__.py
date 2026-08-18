"""Joern CPG integration — inter-procedural dataflow analysis.

Public API:
    from packages.joern import build_cpg, run_query, run_taint_query
    from packages.joern import JoernCPG, TaintFlow, FlowStep, JoernResult

    cpg = build_cpg(Path("/src"))
    flows = run_taint_query(cpg, "parse_header", "memcpy")
    cleanup_cpg(cpg)

Cross-tool session:
    from packages.joern import joern_session

    with joern_session(target_path, cache_dir=project_dir) as srv:
        # srv is a JoernServer with CPG loaded, or None if unavailable
        ...
"""

import contextlib
import logging
from pathlib import Path
from typing import Iterator, Optional

from .models import FlowStep, JoernCPG, JoernMethodSummary, JoernResult, TaintFlow
from .prereqs import check_prereqs, is_available, version
from .runner import build_cpg, build_cpg_cached, cleanup_cpg, run_query, run_taint_query
from .server import JoernServer
from .tunables import JoernTunables

_logger = logging.getLogger(__name__)

__all__ = [
    "build_cpg",
    "cleanup_cpg",
    "run_query",
    "run_taint_query",
    "check_prereqs",
    "is_available",
    "version",
    "FlowStep",
    "JoernCPG",
    "JoernMethodSummary",
    "JoernResult",
    "TaintFlow",
    "JoernServer",
    "joern_session",
]


@contextlib.contextmanager
def joern_session(
    target_path: Path,
    *,
    cache_dir: Optional[Path] = None,
    tunables: Optional[JoernTunables] = None,
    register_reach_audit: bool = True,
) -> Iterator[Optional[JoernServer]]:
    """Context manager for a cross-tool Joern session.

    Boots a Joern server, builds/loads the CPG, imports it into
    the server, and optionally registers the server with
    ``core.analysis.reach_audit`` so ``classify_reachability``
    can resolve indirect callers.

    Yields the server (or None if Joern is unavailable). Always
    cleans up on exit.

    Usage::

        with joern_session(target, cache_dir=project_dir) as srv:
            if srv:
                result = srv.query("cpg.method.l")
    """
    if not is_available():
        yield None
        return

    if tunables is None:
        tunables = JoernTunables.from_tuning()

    srv = JoernServer.from_tunables(tunables)
    try:
        srv.start()
    except Exception:
        _logger.debug("Joern server failed to start", exc_info=True)
        yield None
        return

    cpg = None
    try:
        # Pin the joern-parse frontend from the curated per-language
        # profiles rather than trusting parse-side auto-detection.
        from .lang_config import parse_languages_for
        parse_langs = parse_languages_for(str(target_path))
        if cache_dir is not None:
            cpg = build_cpg_cached(
                target_path, cache_dir,
                languages=parse_langs,
                timeout=tunables.cpg_timeout_s,
            )
        else:
            cpg = build_cpg(
                target_path,
                languages=parse_langs,
                timeout=tunables.cpg_timeout_s,
            )
        if cpg.exists():
            srv.import_cpg(cpg.path, timeout=tunables.import_timeout_s)

        if register_reach_audit:
            try:
                from core.analysis.reach_audit import set_joern_server
                set_joern_server(srv)
            except ImportError:
                pass

        yield srv
    finally:
        if register_reach_audit:
            try:
                from core.analysis.reach_audit import set_joern_server
                set_joern_server(None)
            except ImportError:
                pass
        srv.stop()
        if cache_dir is None and cpg is not None and cpg.exists():
            cleanup_cpg(cpg)

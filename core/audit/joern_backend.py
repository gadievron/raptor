"""Joern CPG integration backend for /audit.

Server lifecycle, evidence building, taint flow resolution, and
target-detection helpers.  Separated from orchestrator.py — called
by the orchestrator but doesn't reference its mutable state.
"""

from __future__ import annotations

import hashlib
import logging
import threading
import time
from collections import deque
from concurrent.futures import Future, ThreadPoolExecutor
from pathlib import Path
from typing import Any, TYPE_CHECKING

from core.json import load_json

if TYPE_CHECKING:
    from collections.abc import Callable

logger = logging.getLogger(__name__)

_C_EXTENSIONS = frozenset({".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh"})
_JOERN_STALL_FLOOR_S = 30

# Byte budget for .raptor-run.json / pre-sweep status metadata reads.
_MAX_RUN_META_BYTES = 1024 * 1024

# Byte budget for a sibling run's joern-flows.json. The file is a
# RAPTOR-written artifact but its size tracks the analysed target —
# large-artifact class budget (matches the 256 MiB coverage/journal
# precedent); real flow files run well under this.
_MAX_JOERN_FLOWS_BYTES = 256 * 1024 * 1024

# Recognised source languages Joern has NO curated profile for.
# lang_config.detect_language() would classify such a target as its
# DEFAULT (Python) and pin the pythonsrc frontend — an empty or
# wrong-language CPG — so the gate refuses them with a logged reason
# instead of booting Joern.
# .rb and .php stay here deliberately: joern ships rubysrc2cpg and
# php2cpg frontends, but rubysrc's embedded ast-gen fails loading its
# parser gem (empty CPG, exit 0) and php2cpg needs a php interpreter
# on PATH — both probed and rejected; see lang_config's profile note.
_UNPROFILED_EXTENSIONS = frozenset({".rb", ".php", ".scala"})


def _joern_extensions() -> frozenset[str]:
    """Non-C extensions with a curated Joern language profile.

    Derived from lang_config's extension map so the gate can never
    admit a language the frontend pinning would mis-route.
    """
    try:
        from packages.joern.lang_config import supported_source_extensions
    except ImportError:
        return frozenset()
    return supported_source_extensions() - _C_EXTENSIONS


def target_has_c_sources(target_path: Path | None) -> bool:
    """Check if target directory contains C/C++ source files."""
    if not target_path or not target_path.is_dir():
        return False
    for p in target_path.rglob("*"):
        if p.is_file() and p.suffix.lower() in _C_EXTENSIONS:
            return True
    return False


def target_has_joern_sources(target_path: Path | None) -> bool:
    """Check if target has non-C sources Joern has a curated profile for.

    Targets whose only recognised sources are unprofiled languages
    (Ruby, PHP, Scala, Kotlin) gate to False with a logged reason —
    the audit then runs on the tree-sitter + LLM fallback.
    """
    if not target_path or not target_path.is_dir():
        return False
    supported = _joern_extensions()
    unprofiled_seen: set[str] = set()
    for p in target_path.rglob("*"):
        if not p.is_file():
            continue
        ext = p.suffix.lower()
        if ext in supported:
            return True
        if ext in _UNPROFILED_EXTENSIONS:
            unprofiled_seen.add(ext)
    if unprofiled_seen:
        logger.warning(
            "Joern disabled for %s: only %s sources found — no curated "
            "joern-parse profile for these languages; audit falls back "
            "to tree-sitter + LLM",
            target_path, ", ".join(sorted(unprofiled_seen)),
        )
    return False


def scope_complement_exclude_dirs(
    joern_root: Path,
    scope: str | list[str] | None,
    target_path: Path,
) -> tuple[str, ...]:
    """Directories under *joern_root* deliberately OUTSIDE the audit
    scope — the ``--scope`` complement the CPG build excludes.

    Walks the scope entries as a prefix tree: at each level, sibling
    directories on no scope path are excluded; a level fully covered
    by a scope entry excludes nothing below it. Coverage is therefore
    always a SUPERSET of the scope (file-leaf scope entries keep
    their whole parent directory's files).

    Every anomaly degrades to ``()`` — the full-tree build the audit
    always did — never to an over-exclusion: an absolute scope
    outside the target, a ``..`` segment, a whole-tree entry, or a
    scope inconsistent with the narrowed *joern_root* all mean the
    complement cannot be derived safely. Scope entries are
    target-relative (``./`` spellings tolerated, absolute paths
    rebased under the target, root-alias entries dropped — the same
    normalisation the gap selector applies), so the graph always
    covers at least what the gap selector reviews.
    """
    if not scope:
        return ()
    scopes_raw = [scope] if isinstance(scope, str) else list(scope)
    if not scopes_raw:
        return ()
    try:
        root = Path(joern_root).resolve()
        target = Path(target_path).resolve()
    except OSError:
        return ()
    if not root.is_dir():
        return ()
    try:
        root_rel_parts = root.relative_to(target).parts
    except ValueError:
        return ()

    norm: list[tuple[str, ...]] = []
    target_str = str(target).rstrip("/")
    for raw in scopes_raw:
        entry = str(raw)
        while entry.startswith("./"):
            entry = entry[2:]
        if entry.startswith("/"):
            stripped = entry.rstrip("/")
            if stripped == target_str:
                entry = ""
            elif stripped.startswith(target_str + "/"):
                entry = stripped[len(target_str) + 1:]
            else:
                return ()
        entry = entry.strip("/")
        if entry in ("", "."):
            # Whole-tree scope: there is no complement.
            return ()
        if target_str == entry or target_str.endswith("/" + entry):
            # Root-alias entry ("webapp" for a target at .../webapp):
            # the gap selector DROPS these — its gaps then span the
            # whole tree — so the complement must not read the alias
            # as a subdirectory name and exclude every sibling.
            # Dropping only the alias keeps parity on mixed lists.
            continue
        parts = Path(entry).parts
        if ".." in parts:
            return ()
        if root_rel_parts:
            # joern_root was narrowed to the scopes' common prefix —
            # re-anchor the entry below it.
            if parts[: len(root_rel_parts)] != root_rel_parts:
                return ()
            parts = parts[len(root_rel_parts):]
            if not parts:
                # The scope IS the narrowed root: full subtree.
                return ()
        norm.append(parts)

    if not norm:
        # Every entry was a root alias — the gap selector reviews
        # the whole tree, so the graph must cover it too.
        return ()

    tree: dict[str, dict] = {}
    for parts in norm:
        node = tree
        for seg in parts:
            node = node.setdefault(seg, {})

    excludes: list[str] = []

    def _walk(dir_path: Path, node: dict[str, dict]) -> None:
        if not node:
            # A scope entry ends here — everything below is in scope.
            return
        try:
            children = list(dir_path.iterdir())
        except OSError:
            return
        for child in children:
            try:
                if not child.is_dir() or child.is_symlink():
                    continue
            except OSError:
                continue
            # Dot-dirs are already excluded by the shared
            # directory-name rule on both the key and the build; the
            # complement stays self-contained without them.
            if child.name.startswith("."):
                continue
            if child.name in node:
                _walk(child, node[child.name])
            else:
                excludes.append(str(child))

    _walk(root, tree)
    return tuple(sorted(excludes))


def joern_available(overrides: dict[str, Any] | None = None) -> bool:
    """Check if Joern is installed, importable, and enabled in tuning."""
    if overrides and overrides.get("enabled") is False:
        return False
    try:
        from core.tuning import get_tuning
        if not get_tuning().joern_enabled:
            return False
    except Exception:
        logger.debug("joern tuning probe failed", exc_info=True)
    try:
        from packages.joern.prereqs import is_available
        return is_available()
    except ImportError:
        return False


def joern_tunables(overrides: dict[str, Any] | None = None):
    """Load JoernTunables from the central tuning config."""
    try:
        from packages.joern.tunables import JoernTunables
        return JoernTunables.from_tuning(overrides=overrides)
    except Exception:
        logger.debug("joern tunables from_tuning failed", exc_info=True)
        try:
            from packages.joern.tunables import JoernTunables
            return JoernTunables()
        except Exception:
            logger.debug("joern tunables unavailable", exc_info=True)
            return None


def start_joern_server(target_path, joern_overrides=None, tunables=None,
                       out_dir=None, exclude_dirs: tuple[str, ...] = (),
                       scope_exclude_dirs: tuple[str, ...] = (),
                       timings_out: dict[str, float] | None = None):
    """Start or reuse a persistent Joern server if Joern is available.

    Returns the server instance or None.  When reusing a lifecycle-managed
    server, builds/imports the CPG for *target_path* so queries run
    against the correct codebase.

    ``timings_out``: optional dict receiving ``cpg_build_s`` — the
    wall time of the CPG build/import step (near-zero on a warm cache
    or an already-loaded server, the dominant startup cost when cold),
    so run diagnostics can tell cold from warm starts.

    After the CPG loads, tool-corroborated project sanitisers from the
    IRIS store are installed as flow-semantics kill rows so taint
    sweeps stop propagating through validators the refinement loop has
    confirmed. ``out_dir`` (a run output dir) pins the store lookup;
    without it the store resolves via the active project. Callers that
    pass their own server through config own its semantics.

    ``exclude_dirs``: caller-declared exclusion roots (the run's output
    dir when it lives inside the target — see
    :func:`packages.joern.runner.run_output_exclude_dirs`) forwarded to
    the CPG build so run artifacts stay out of both the content key and
    the graph. Kept separate from ``out_dir`` on purpose: ``out_dir``
    also pins the IRIS store lookup, and the exclusion channel must not
    change store-resolution semantics for callers that only want the
    key stabilised.

    ``scope_exclude_dirs``: the run's ``--scope`` complement
    (:func:`scope_complement_exclude_dirs`) — semantic coverage
    exclusions that also key the CPG cache slot, unlike the
    freshness-neutral ``exclude_dirs``.
    """
    if not joern_available(overrides=joern_overrides):
        return None

    if not (target_has_c_sources(target_path)
            or target_has_joern_sources(target_path)):
        return None

    srv = None
    try:
        from packages.joern.lifecycle import joern_acquire
        srv = joern_acquire(tunables)
    except Exception:
        logger.debug("joern lifecycle acquire failed; trying direct start",
                     exc_info=True)

    if srv is None:
        try:
            from packages.joern.server import JoernServer
        except ImportError:
            return None
        try:
            srv = JoernServer.from_tunables(tunables)
            srv.start()
        except Exception:
            logger.debug("Joern server failed to start; using subprocess fallback",
                         exc_info=True)
            return None

    _cpg_start = time.monotonic()
    _cpg_ok = _ensure_cpg_loaded(srv, target_path, tunables,
                                 exclude_dirs=exclude_dirs,
                                 scope_exclude_dirs=scope_exclude_dirs,
                                 out_dir=out_dir)
    if timings_out is not None:
        timings_out["cpg_build_s"] = time.monotonic() - _cpg_start
    if not _cpg_ok:
        logger.warning("Joern CPG failed to load for %s — disabling Joern", target_path)
        try:
            srv.stop()
        except Exception:
            logger.debug("joern server stop failed", exc_info=True)
        return None
    try:
        # Fresh coverage memo for the graph just loaded — entries from
        # a previously loaded CPG describe a different graph. Stamped
        # with the server's load epoch so a mid-run restart's CPG
        # re-import (which never passes through here) also invalidates
        # it — see joern_function_in_cpg.
        setattr(srv, _FN_COVERAGE_CACHE_ATTR, {})
        setattr(srv, _FN_COVERAGE_EPOCH_ATTR,
                getattr(srv, "cpg_load_epoch", None))
    except AttributeError:
        logger.debug("joern server rejects coverage cache attribute")
    install_flow_semantics(srv, target_path, out_dir=out_dir)
    return srv


def install_flow_semantics(srv, target_path, out_dir=None) -> int:
    """Install learned sanitiser kill rows on a booted Joern server.

    Rows come from the IRIS store's suppression-direction reader
    (``get_project_sanitisers`` — tool-corroborated / operator-promoted
    specs only, the same XREF_BACKED floor guard-adequacy uses). Kill
    rows remove flows, so the suppression-direction gate is
    load-bearing: a heuristic-tier sanitiser must not silence a sweep.

    Returns the number of rows installed. No learned sanitisers, a
    server without semantics support, or any store/install failure
    degrade to 0 rows with the server untouched — vocabulary quality
    must never cost a sweep.
    """
    if srv is None or not hasattr(srv, "set_flow_semantics"):
        return 0
    try:
        from core.iris.api import get_project_sanitisers
    except ImportError:
        return 0
    try:
        names = get_project_sanitisers(
            out_dir=Path(out_dir) if out_dir else None,
            target_path=Path(target_path) if target_path else None,
        )
    except Exception:
        logger.debug("IRIS sanitiser recall failed", exc_info=True)
        return 0
    if not names:
        return 0
    try:
        installed = srv.set_flow_semantics(sorted(names))
    except Exception:
        logger.debug("flow-semantics install failed", exc_info=True)
        return 0
    logger.info(
        "joern flow semantics: %d of %d learned sanitiser kill row(s) "
        "installed", installed, len(names),
    )
    return installed


# Scope-size threshold (estimated SLOC) arming the retry-at-derived-
# max path. Below it a failed CPG build is rarely resource-shaped
# (parse errors, missing frontend helpers) and a retry only doubles
# the wall spent on a hopeless build; above it, resource kills
# (heap / timeout) are the observed failure mode and ONE bounded
# retry at the derivation's maxima rescues the channel for the run.
_CPG_RETRY_MIN_SLOC = 500_000

#: Run-dir artifact recording the audit CPG build outcome when it
#: failed (channel lost) or was rescued by the derived-max retry.
#: Read by the report summary so the channel loss is named in the
#: run REPORT, not just a mid-run log line.
JOERN_CPG_STATUS_FILENAME = "joern-cpg-status.json"


def _write_cpg_build_status(out_dir, status: dict) -> None:
    """Persist the CPG build outcome record. Best-effort."""
    if not out_dir:
        return
    try:
        from datetime import datetime, timezone

        from core.json import save_json
        record = dict(status)
        record["ts"] = datetime.now(timezone.utc).isoformat()
        save_json(Path(out_dir) / JOERN_CPG_STATUS_FILENAME, record)
    except Exception:  # noqa: BLE001 — bookkeeping must not cost the run
        logger.debug("CPG build status write failed", exc_info=True)


def load_cpg_build_status(out_dir) -> dict | None:
    """Read the CPG build outcome record, or None when absent."""
    if not out_dir:
        return None
    path = Path(out_dir) / JOERN_CPG_STATUS_FILENAME
    if not path.is_file():
        return None
    data = load_json(path, max_bytes=_MAX_RUN_META_BYTES)
    return data if isinstance(data, dict) else None


def _derived_max_retry_limits(
    target_path,
    exclude_dirs: tuple[str, ...],
    first_heap_mb: int | None,
    first_heap_is_derived: bool,
    first_timeout_s: int,
) -> tuple[int | None, int, int] | None:
    """(heap_mb, timeout_s, estimated_sloc) for a derived-max retry.

    None when the retry is not armed: scope below the size threshold,
    the estimate unavailable, or the first attempt already ran at the
    derivation's maxima (retrying with identical limits is pure wall
    loss). The retry heap honors the same ceiling every derivation
    does (:func:`core.tuning.derived_max_joern_heap_mb`) — and it
    honors explicitness BOTH directions: only a DERIVED (or absent)
    first heap is raised; an explicit operator heap is an assertion
    and keeps its value exactly (the retry may then only extend the
    timeout).
    """
    try:
        from core.tuning import (
            derive_joern_cpg_timeout_s,
            derived_max_joern_heap_mb,
        )
        from packages.joern.runner import estimate_in_scope_sloc
        sloc = estimate_in_scope_sloc(
            Path(target_path), exclude_dirs=exclude_dirs,
        )
    except Exception:  # noqa: BLE001 — retry arming must not cost the run
        logger.debug("derived-max retry arming failed", exc_info=True)
        return None
    if sloc < _CPG_RETRY_MIN_SLOC:
        return None
    if first_heap_mb is None or first_heap_is_derived:
        heap: int | None = max(first_heap_mb or 0,
                               derived_max_joern_heap_mb())
    else:
        heap = first_heap_mb
    timeout = max(first_timeout_s, derive_joern_cpg_timeout_s(sloc))
    if heap == first_heap_mb and timeout <= first_timeout_s:
        return None
    return heap, timeout, sloc


def _ensure_cpg_loaded(srv, target_path, tunables=None,
                       exclude_dirs: tuple[str, ...] = (),
                       scope_exclude_dirs: tuple[str, ...] = (),
                       out_dir=None) -> bool | None:
    """Build and import the CPG for *target_path* into *srv*.

    Returns True if the CPG was loaded (or already was), False on failure.
    ``exclude_dirs`` joins the CPG build's content key and ``--exclude``
    set (key/analysis parity). ``scope_exclude_dirs`` (the scope
    complement) additionally keys the cache slot — see
    :func:`packages.joern.runner.build_cpg_cached`.

    Proportionate failure: a failed build on a scope above
    :data:`_CPG_RETRY_MIN_SLOC` is retried ONCE at derived-max limits
    (heap at the tuning ceiling, timeout from the SLOC curve). The
    outcome — channel lost, or rescued by the retry — is persisted to
    :data:`JOERN_CPG_STATUS_FILENAME` for the run report.
    """
    if getattr(srv, "_cpg_loaded", False):
        return True
    try:
        from packages.joern.runner import build_cpg_cached
    except ImportError:
        logger.debug("joern runner not importable; skipping CPG import")
        return False

    # Fallbacks defer to the canonical tunables defaults — a local
    # literal here silently drifts from the policy import_cpg and
    # from_tuning own (a 120s local import fallback once killed the
    # whole Joern tier for runs without resolved tunables).
    # resolve_cpg_timeout_s refines a derived ("auto") timeout from
    # the scope's source-size estimate; non-auto tunables pass
    # through unchanged.
    from packages.joern.tunables import resolve_cpg_timeout_s
    combined_excludes = tuple(exclude_dirs) + tuple(scope_exclude_dirs)
    cpg_timeout = resolve_cpg_timeout_s(
        tunables, target_path, exclude_dirs=combined_excludes,
    )
    import_timeout = (
        getattr(tunables, "import_timeout_s", None) if tunables else None
    )
    # The parse frontend heap follows the tunables like the query
    # server's: a retry at derived-max heap is meaningless if the
    # first attempt never carried a heap at all.
    heap_mb = getattr(tunables, "heap_mb", None) if tunables else None
    heap_is_derived = bool(
        getattr(tunables, "heap_is_derived", False)) if tunables else False

    cache_dir = Path.home() / ".cache" / "raptor" / "joern-cpg"
    cache_dir.mkdir(parents=True, exist_ok=True)

    retried = False
    retry_heap: int | None = None
    retry_timeout: int | None = None
    est_sloc: int | None = None

    def _status(*, failed: bool, phase: str) -> dict:
        return {
            "target": str(target_path),
            "failed": failed,
            "phase": phase,
            "retried": retried,
            "first_heap_mb": heap_mb,
            "first_timeout_s": cpg_timeout,
            "retry_heap_mb": retry_heap,
            "retry_timeout_s": retry_timeout,
            "estimated_sloc": est_sloc,
            "scope_excluded_dirs": len(scope_exclude_dirs),
        }

    try:
        cpg = build_cpg_cached(Path(target_path), cache_dir,
                               timeout=cpg_timeout,
                               heap_mb=heap_mb,
                               exclude_dirs=exclude_dirs,
                               scope_exclude_dirs=scope_exclude_dirs)
        if not cpg.exists() or getattr(cpg, "build_failed", False):
            retry = _derived_max_retry_limits(
                target_path, combined_excludes,
                heap_mb, heap_is_derived, cpg_timeout,
            )
            if retry is not None:
                retry_heap, retry_timeout, est_sloc = retry
                logger.warning(
                    "Joern CPG build for %s failed (heap=%s MB, "
                    "timeout=%ds) — retrying once at derived-max "
                    "limits: heap=%s MB, timeout=%ds (worst-case "
                    "wall across both attempts %ds)",
                    target_path, heap_mb if heap_mb else "default",
                    cpg_timeout, retry_heap, retry_timeout,
                    cpg_timeout + retry_timeout,
                )
                retried = True
                cpg = build_cpg_cached(
                    Path(target_path), cache_dir,
                    timeout=retry_timeout,
                    heap_mb=retry_heap,
                    exclude_dirs=exclude_dirs,
                    scope_exclude_dirs=scope_exclude_dirs,
                )
        ok = cpg.exists() and not getattr(cpg, "build_failed", False)
    except Exception:
        logger.debug("CPG build failed for %s", target_path, exc_info=True)
        # An exception is a channel loss like any failed build — it
        # must reach the run report, not just this debug line.
        _write_cpg_build_status(out_dir, _status(
            failed=True, phase="build"))
        return False
    if not ok:
        _write_cpg_build_status(out_dir, _status(
            failed=True, phase="build"))
        return False
    try:
        srv.import_cpg(cpg.path, timeout=import_timeout)
    except Exception:
        logger.debug("CPG import failed for %s", target_path, exc_info=True)
        # A built-but-unimported graph is still a lost channel: the
        # record must never claim a rescue the server can't serve.
        _write_cpg_build_status(out_dir, _status(
            failed=True, phase="import"))
        return False
    if retried:
        # Success record only AFTER the import: a rescue claim for a
        # graph that failed to import would report a channel the run
        # never had.
        _write_cpg_build_status(out_dir, _status(
            failed=False, phase="complete"))
    return True


def stop_joern_server(server) -> None:
    """Stop the Joern server if it was started."""
    if server is None:
        return

    def _do_stop() -> None:
        try:
            server.stop()
        except Exception:
            logger.debug("Joern server shutdown error", exc_info=True)

    t = threading.Thread(target=_do_stop, daemon=True)
    t.start()
    t.join(timeout=30)
    if t.is_alive():
        logger.warning("Joern server stop timed out after 30s — abandoning")


def _flow_sort_key(flow: Any) -> tuple:
    """Deterministic ordering for taint flows: Joern's traversal order
    is not stable across server sessions, and flows feed reviewer
    prompts and evidence records — unordered results made LLM input
    vary run to run for identical code."""
    steps = getattr(flow, "steps", None) or []
    first = steps[0] if steps else None
    return (
        str(getattr(flow, "source_method", "") or ""),
        str(getattr(flow, "sink_call", "") or ""),
        getattr(flow, "sink_arg_idx", -1) or -1,
        str(getattr(first, "file", "") or ""),
        getattr(first, "line", 0) or 0,
        len(steps),
    )


#: Attribute holding the per-server function-coverage memo. The
#: entries describe the graph that was live when they were computed,
#: so the memo is invalidated on EVERY load path: lane start
#: (:func:`start_joern_server` installs a fresh dict) AND the mid-run
#: ``restart()`` re-import, which never passes through lane start —
#: :func:`joern_function_in_cpg` compares the epoch stamp below
#: against the server's ``cpg_load_epoch`` and discards a stale memo.
#: Pre-fix the restart path kept the memo: every probe answered during
#: a restart window memoised None ("did not look") and the joern
#: refutation lane stayed silently removed for those functions for the
#: rest of the run.
_FN_COVERAGE_CACHE_ATTR = "_raptor_fn_in_cpg_cache"
#: CPG-load epoch the memo was stamped against (see above).
_FN_COVERAGE_EPOCH_ATTR = "_raptor_fn_in_cpg_cache_epoch"


def joern_name_queryable(function_name: str) -> bool:
    """Whether *function_name* can be interpolated into a query at all.

    Names outside the substitution allowlist — C++ qualified names and
    operators, ``$``-prefixed dynamic-language names — are unqueryable
    by construction: the live query returns empty without dialing the
    server and the coverage probe cannot answer. That is a
    definitional skip for the caller, never a channel-health error
    (no transport round trip ever happened, so booking one as an
    error farms the health breaker on ordinary C++ inventories).
    """
    try:
        from packages.joern.runner import _validate_substitution_value
    except ImportError:
        return False
    return bool(_validate_substitution_value(function_name))


def joern_function_in_cpg(
    server: Any,
    function_name: str,
    timeout: int = 10,
    *,
    file_path: str | None = None,
    errors_out: list | None = None,
) -> bool | None:
    """Whether the loaded CPG actually MODELS *function_name*.

    Verdict-bearing callers treat query silence as "looked and found
    nothing". That is only true when the CPG actually models the
    function: on a target whose dominant language has no Joern
    frontend, the graph holds a sliver of the tree, every query is
    vacuously silent, and silence-as-refutation steers verdicts toward
    clean at scale. Returns None when the probe itself cannot answer
    (no query API, transport error, unparseable output) — callers must
    treat None as "did not look", never as absence.

    ``file_path`` (checklist-relative) binds coverage to the item's
    OWN file: a same-named definition elsewhere in the tree is not
    coverage of this item (the same-named-definitions mechanism), so
    it answers False → the caller skips instead of refuting. CPG
    filenames are compared exact-or-suffix (``== path`` or
    ``endsWith("/" + path)``) so relative- and absolute-rooted
    imports both bind; a layout that matches neither degrades to
    False — the fail-safe direction (skip, never a refutation).

    ``errors_out``: optional list receiving the probe's transport
    failure detail when the answer is None — a None is otherwise
    AMBIGUOUS between "REPL busy, probe timed out" (contention — the
    caller must not book channel sickness) and "transport broken /
    echo unparseable" (a genuine channel error).
    """
    try:
        from packages.joern.runner import (
            _escape_scala_string,
            _validate_substitution_value,
        )
    except ImportError:
        return None
    if not _validate_substitution_value(function_name):
        return None
    query_fn = getattr(server, "query", None)
    if query_fn is None:
        return None

    cache = getattr(server, _FN_COVERAGE_CACHE_ATTR, None)
    if cache is not None:
        epoch = getattr(server, "cpg_load_epoch", None)
        if (epoch is not None
                and getattr(server, _FN_COVERAGE_EPOCH_ATTR, None) != epoch):
            # A CPG (re)load happened since the memo was stamped —
            # every entry (a restart window's poisoned Nones included)
            # describes a graph that no longer exists. Concurrent
            # sweep threads may race this swap; both install an empty
            # dict stamped with the same epoch, so the worst case is a
            # re-probe, never a stale answer.
            cache = {}
            try:
                setattr(server, _FN_COVERAGE_CACHE_ATTR, cache)
                setattr(server, _FN_COVERAGE_EPOCH_ATTR, epoch)
            except AttributeError:
                logger.debug("joern server rejects coverage cache attribute")
    cache_key = (function_name, file_path)
    if cache is not None and cache_key in cache:
        return cache[cache_key]

    nonce = hashlib.sha256(
        f"fncov:{function_name}:{time.monotonic_ns()}".encode(),
    ).hexdigest()[:12]
    # The sentinel must ride the FINAL EXPRESSION's string echo:
    # println output does not come back through the server's
    # query-sync transport (see packages/joern/server.py — flows ride
    # the final expression for the same reason). A println-shaped
    # probe answers None on every real server, which silently demotes
    # every silent live query to skipped — abolishing the refutation
    # lane instead of gating it.
    # Coverage = a non-external method WITH A BODY in the item's own
    # file, live-verified filters (each closes a confirmed
    # false-coverage shape):
    # * .filterNot(_.isExternal) — Joern mints external METHOD STUBS
    #   for called-but-undefined names, so a bare nameExact probe
    #   answers true off a mere CALL SITE anywhere in the parsed
    #   tree — exactly this gate's target cases (parse-failed file,
    #   exclude_dirs drop, mixed-tree language sliver).
    # * .filter(_.block.astChildren.nonEmpty) — a DECLARED prototype
    #   is isExternal=false with an empty body; it models nothing.
    #   Cost: a legitimately empty-bodied function also demotes to
    #   skipped (its silence-refutation is vacuous anyway).
    # * filename binding (when a file anchor is given) — a same-named
    #   definition in a DIFFERENT file is not coverage of this item.
    cov_expr = (
        f'cpg.method.nameExact("{function_name}")'
        '.filterNot(_.isExternal)'
        '.filter(_.block.astChildren.nonEmpty).l'
    )
    if file_path is not None:
        fp = _escape_scala_string(file_path)
        query = (
            'import io.shiftleft.semanticcpg.language._\n'
            f'val raptorCov = {cov_expr}\n'
            f'"{nonce}:" + (if (raptorCov.isEmpty) "false" '
            f'else if (raptorCov.exists(m => m.filename == "{fp}" || '
            f'm.filename.endsWith("/{fp}"))) "true" else "otherfile")\n'
        )
    else:
        query = (
            'import io.shiftleft.semanticcpg.language._\n'
            f'val raptorCov = {cov_expr}\n'
            f'"{nonce}:" + raptorCov.nonEmpty\n'
        )
    try:
        try:
            # no_restart: the probe is a cheap side-channel query and
            # must not wield query()'s timeout-triggered restart — a
            # probe queued behind a sibling's minutes-long taint query
            # times out on a HEALTHY server, and the restart would
            # SIGKILL the shared multi-GB JVM mid-run and destroy the
            # sibling's in-flight evidence.
            result = query_fn(query, timeout=timeout, check_length=False,
                              no_restart=True)
        except TypeError:
            # Duck-typed server without the no_restart seam. The probe
            # is a read-only query, so the plain re-post is idempotent;
            # a real JoernServer never lands here.
            result = query_fn(query, timeout=timeout, check_length=False)
    except Exception as exc:  # noqa: BLE001 — degrade to "unanswered", never crash
        logger.debug("joern coverage probe failed for %s",
                     function_name, exc_info=True)
        if errors_out is not None:
            errors_out.append(f"{type(exc).__name__}: {exc}")
        probe_timed_out = "timed out" in str(exc).lower()
        answer: bool | None = None
    else:
        raw = str(getattr(result, "raw_output", "") or "")
        probe_timed_out = False
        if f"{nonce}:true" in raw:
            answer = True
        elif f"{nonce}:false" in raw or f"{nonce}:otherfile" in raw:
            # otherfile = a same-named definition exists but not in
            # the item's file — not coverage of THIS item.
            answer = False
        else:
            answer = None
            result_errors = list(getattr(result, "errors", None) or [])
            probe_timed_out = any(
                "timed out" in str(e).lower() for e in result_errors
            )
            if errors_out is not None:
                if result_errors:
                    errors_out.extend(str(e) for e in result_errors)
                else:
                    errors_out.append("unparseable probe echo")
    if cache is not None and not probe_timed_out:
        # None is memoised too: an unanswerable transport does not
        # heal within one CPG load, and re-probing pays a full REPL
        # round trip per silent hypothesis on the shared
        # single-threaded server. The memo dies with the CPG (re)load.
        # EXCEPT timeout-classified Nones: with the no_restart seam a
        # probe timeout no longer bumps the load epoch via a restart,
        # so memoising it would let ONE contention timeout silence
        # this function's refutation lane until a reload that may
        # never come. Contention clears on its own — re-ask next
        # time. (No restart-thrash risk either way: the probe never
        # restarts, and re-asking is one bounded round trip per
        # hypothesis, the pre-memo cost.)
        cache[cache_key] = answer
    return answer


def joern_live_query(
    server,
    function_name: str,
    sinks: list[str],
    timeout: int = 30,
    *,
    label: str | None = None,
    max_call_depth: int | None = None,
    errors_out: list | None = None,
) -> list[Any]:
    """Fire a targeted taint query via the live Joern server.

    ``errors_out``: optional list receiving one entry per sink query
    that DEGRADED (server restarting, timeout, transport error).  An
    empty return with a non-empty ``errors_out`` means "unanswered",
    not "no flow" — verdict-bearing callers must account the two
    differently (degradation is never a verdict).
    """
    from packages.joern.runner import _validate_substitution_value

    if not _validate_substitution_value(function_name):
        return []

    depth_kwargs: dict[str, int] = {}
    if max_call_depth is not None:
        depth_kwargs["max_call_depth"] = max_call_depth

    sink_names: list[str] = []
    for sink in sinks:
        sink_name = sink.split(".")[-1] if "." in sink else sink
        if not _validate_substitution_value(sink_name):
            continue
        # Duplicate names would only re-run identical dataflow work in
        # the same submission; first occurrence keeps the caller order.
        if sink_name not in sink_names:
            sink_names.append(sink_name)
    if not sink_names:
        return []

    batch_fn = getattr(server, "run_taint_queries_batch", None)
    if batch_fn is None:
        # Duck-typed servers without the batch API (test doubles,
        # minimal stand-ins) keep the historical per-sink behaviour.
        return _joern_live_query_per_sink(
            server, function_name, sink_names, timeout,
            depth_kwargs, errors_out,
        )

    batch_error = False
    try:
        query_errors: list = []
        # One REPL submission for every sink of this hypothesis, under
        # a SUBLINEAR budget — base × ceil(sqrt(N)) — rather than the
        # loop's N× or a flat 1×. Linear re-inherits the single-
        # hypothesis monopoly of the shared single-threaded REPL the
        # batch exists to avoid, and a batch timeout is dearer than a
        # per-sink one (it costs a server restart + CPG reload for
        # every pair at once); flat starves wide menus (11-sink
        # dispatch entries exist) whose per-pair engine work is real
        # even with compilation paid once.
        flows = batch_fn(
            [(function_name, s) for s in sink_names],
            timeout=timeout * _sqrt_ceil(len(sink_names)),
            errors_out=query_errors,
            **depth_kwargs,
        )
        if flows:
            if query_errors and errors_out is not None:
                # Partial degradation (flows AND errors in one batch):
                # the flows are the answer, but the error tier must
                # still see that part of the batch went unanswered.
                errors_out.append(
                    f"{function_name}->[{','.join(sink_names)}]: "
                    + "; ".join(str(e) for e in query_errors[:3])
                )
            logger.info(
                "joern live query: %s → [%s] = %d flow(s)",
                function_name, ",".join(sink_names), len(flows),
            )
            # All sinks' flows, not just the first sink with a hit —
            # strictly more evidence than the historical
            # first-hit-wins loop; consumers gate on truthiness.
            return sorted(flows, key=_flow_sort_key)
        batch_error = bool(query_errors)
    except Exception:
        logger.debug(
            "joern live batch query failed: %s → [%s]",
            function_name, ",".join(sink_names), exc_info=True,
        )
        batch_error = True

    if batch_error:
        # One-shot per-sink recovery pass: a degraded batch (timeout /
        # restart / transport) must not cost every joern:live
        # confirmation of the hypothesis at once — the loop can still
        # answer sink-by-sink against the restarted server. Error
        # accounting is delegated wholly to the loop: its verdicts
        # (flows / clean / degraded) supersede the batch's failure,
        # which would otherwise mislabel a loop-proven clean result
        # as "unanswered".
        logger.info(
            "joern live batch degraded for %s — falling back to the "
            "per-sink loop", function_name,
        )
        return _joern_live_query_per_sink(
            server, function_name, sink_names, timeout,
            depth_kwargs, errors_out,
        )

    return []


def _sqrt_ceil(n: int) -> int:
    """ceil(sqrt(n)) for n >= 1 — the batch-budget scale factor."""
    import math

    return math.isqrt(max(n, 1) - 1) + 1


def _joern_live_query_per_sink(
    server,
    function_name: str,
    sink_names: list[str],
    timeout: int,
    depth_kwargs: dict[str, int],
    errors_out: list | None,
) -> list[Any]:
    """Historical per-sink loop: first sink with flows wins."""
    for sink_name in sink_names:
        try:
            query_errors: list = []
            flows = server.run_taint_query(
                function_name, sink_name, timeout=timeout,
                errors_out=query_errors,
                **depth_kwargs,
            )
            if query_errors and errors_out is not None:
                errors_out.append(
                    f"{function_name}->{sink_name}: "
                    + "; ".join(str(e) for e in query_errors[:3])
                )
            if flows:
                logger.info(
                    "joern live query: %s → %s = %d flow(s)",
                    function_name, sink_name, len(flows),
                )
                return sorted(flows, key=_flow_sort_key)
        except Exception as exc:
            logger.debug(
                "joern live query failed: %s → %s",
                function_name, sink_name, exc_info=True,
            )
            if errors_out is not None:
                errors_out.append(
                    f"{function_name}->{sink_name}: "
                    f"{type(exc).__name__}: {exc}"
                )

    return []


def enrich_joern_evidence(
    evidence_index: dict[str, Any] | None,
    key: str,
    function_name: str,
    sinks: list[str],
    joern_server,
) -> None:
    """Add unguarded-sink details and tainted arg indices to evidence."""
    if not evidence_index:
        return
    rec = evidence_index.get(key)
    if not rec:
        return

    from core.analysis.reachability_gates import (
        query_sink_arg_indices,
        query_unguarded_sinks,
    )

    if not rec.joern_unguarded_sinks:
        unguarded = query_unguarded_sinks(function_name, joern_server)
        if unguarded:
            rec.joern_unguarded_sinks = unguarded

    if not rec.joern_sink_args:
        from packages.joern.runner import _validate_substitution_value
        sink_names: list[str] = []
        for sink in sinks:
            sink_name = sink.split(".")[-1] if "." in sink else sink
            if not _validate_substitution_value(sink_name):
                continue
            if sink_name not in sink_names:
                sink_names.append(sink_name)
        if sink_names:
            # One batched submission for the whole sink list (records
            # come back ordered by the caller's sink order, matching
            # the per-sink loop this replaces).
            args = query_sink_arg_indices(
                function_name, sink_names, joern_server,
            )
            if args:
                rec.joern_sink_args.extend(args)
        if rec.joern_sink_args:
            seen = set()
            deduped = []
            for a in rec.joern_sink_args:
                k = (a.get("sink"), a.get("arg_index"), a.get("source_param"))
                if k not in seen:
                    seen.add(k)
                    deduped.append(a)
            rec.joern_sink_args = deduped


#: Run-dir artifact recording a degraded pre-sweep — interrupted/
#: re-queued by a server restart, or errored (``interrupted`` count
#: distinguishes the two for consumers). Written by
#: :func:`build_joern_evidence`; read by the report summary and the
#: critique pass so an incomplete taint window is surfaced instead of
#: living only in a log WARNING.
PRESWEEP_STATUS_FILENAME = "joern-presweep-status.json"


def _write_presweep_status(out_dir, status: dict) -> None:
    """Persist the pre-sweep interruption record. Best-effort."""
    if not out_dir:
        return
    try:
        from datetime import datetime, timezone

        from core.json import save_json
        record = dict(status)
        record["ts"] = datetime.now(timezone.utc).isoformat()
        save_json(Path(out_dir) / PRESWEEP_STATUS_FILENAME, record)
    except Exception:  # noqa: BLE001 — bookkeeping must not cost the sweep
        logger.debug("pre-sweep status write failed", exc_info=True)


def load_presweep_status(out_dir) -> dict | None:
    """Read the pre-sweep interruption record, or None when absent."""
    if not out_dir:
        return None
    path = Path(out_dir) / PRESWEEP_STATUS_FILENAME
    if not path.is_file():
        return None
    data = load_json(path, max_bytes=_MAX_RUN_META_BYTES)
    return data if isinstance(data, dict) else None


#: Pre-sweep flow cache, relative to the run dir. The standard-sinks
#: taint sweep is a pure function of the CPG (content-hash cached) and
#: the rendered sink list, so its result is persisted across resumed
#: segments — the live query against the shared single-threaded server
#: (timeout windows, re-queue waits, restarts) is the flakiest and one
#: of the slowest prep components, and re-running it on an unchanged
#: tree buys nothing.
PRESWEEP_FLOWS_CACHE_RELPATH = str(Path("prep-cache") / "joern-presweep-flows.json")

_PRESWEEP_FLOWS_CACHE_VERSION = 1

#: Byte cap for the cache read (house bounded-JSON policy): the cache
#: is self-written but lives in a run dir — treat it with the same
#: trust class as any sibling-run JSON import.
_PRESWEEP_FLOWS_CACHE_MAX_BYTES = 256 * 1024 * 1024


def _presweep_flows_identity(
    target_path, scope_exclude_dirs: tuple[str, ...] = (),
) -> tuple[str, str] | None:
    """(cpg_hash, sink_hash) identity of a pre-sweep result, or None.

    ``cpg_hash`` covers every axis the CPG build cache invalidates on
    (see :func:`packages.joern.runner.load_cached_cpg`): the content
    key (:func:`packages.joern.runner._target_content_hash` — source
    file set + content, mtime-invariant), the frontend-args
    fingerprint recovered from compile_commands.json (a regenerated
    build database with different -D/-I flags changes the
    preprocessed code, and thus the flows, without touching the
    source hash), the exclusion rule, and the run's scope-complement
    exclusions (a scope change carves different coverage — flows
    swept under one scope must not serve a differently-scoped or
    unscoped segment as the complete sweep). ``sink_hash`` covers the
    query side: the standard_sinks.sc script body plus the rendered
    sink list substituted into it — a query-logic change across a
    framework upgrade must not serve flows computed by the old query.
    """
    try:
        from packages.joern.lang_config import (
            STANDARD_SWEEP_SINKS,
            scala_string_list,
        )
        from packages.joern.runner import (
            CPG_EXCLUDE_REGEX,
            _normalised_scope_excludes,
            _target_content_hash,
            discover_frontend_args,
        )

        target = Path(target_path)
        if not target.is_dir():
            return None
        scope_norm = _normalised_scope_excludes(scope_exclude_dirs)
        cpg_hash = hashlib.sha256("\n".join((
            _target_content_hash(
                target, exclude_dirs=tuple(scope_norm)),
            discover_frontend_args(target).fingerprint(),
            CPG_EXCLUDE_REGEX,
            *scope_norm,
        )).encode("utf-8")).hexdigest()

        import packages.joern as _joern_pkg
        script = (
            Path(_joern_pkg.__file__).parent / "queries" / "standard_sinks.sc"
        )
        rendered = scala_string_list(STANDARD_SWEEP_SINKS)
        sink_hash = hashlib.sha256(
            script.read_bytes() + b"\x00" + rendered.encode("utf-8"),  # raw-open: shipped Joern script (RAPTOR-owned)
        ).hexdigest()
    except Exception:  # noqa: BLE001 — cache identity must not cost the sweep
        logger.debug("pre-sweep flow-cache identity failed", exc_info=True)
        return None
    return (cpg_hash, sink_hash)


def load_presweep_flows_cache(
    out_dir, identity: tuple[str, str],
) -> dict[str, list] | None:
    """Reload cached pre-sweep flows for a matching identity.

    Returns the reconstructed ``flows_by_key`` mapping (values are
    :class:`packages.joern.models.TaintFlow`) on an identity match, or
    None when the cache is absent, stale, marked partial, or corrupt —
    every non-hit path falls back to the live query.
    """
    if not out_dir:
        return None
    path = Path(out_dir) / PRESWEEP_FLOWS_CACHE_RELPATH
    if not path.is_file():
        return None
    try:
        # Bounded read (house JSON policy): the cache is self-written
        # but lives in a run dir — same trust class as the sibling
        # joern-flows import above, so the same stat-gated cap.
        from core.json import load_json
        data = load_json(
            path, max_bytes=_PRESWEEP_FLOWS_CACHE_MAX_BYTES,
        )
    except Exception:  # noqa: BLE001 — any unreadable cache re-queries
        logger.warning(
            "joern pre-sweep flow cache unreadable at %s — re-running "
            "the live sweep", path,
        )
        return None
    if data is None:
        logger.warning(
            "joern pre-sweep flow cache unreadable/oversized at %s — "
            "re-running the live sweep", path,
        )
        return None
    if (
        not isinstance(data, dict)
        or data.get("version") != _PRESWEEP_FLOWS_CACHE_VERSION
        or data.get("partial")
        or not isinstance(data.get("flows_by_key"), dict)
    ):
        logger.warning(
            "joern pre-sweep flow cache at %s malformed or marked "
            "partial — re-running the live sweep", path,
        )
        return None
    if (data.get("cpg_hash"), data.get("sink_hash")) != identity:
        logger.info(
            "joern pre-sweep flow cache stale (CPG or sink-list hash "
            "changed) — re-running the live sweep",
        )
        return None
    try:
        from packages.joern.models import TaintFlow

        flows_by_key: dict[str, list] = {}
        for key, entries in data["flows_by_key"].items():
            flows_by_key[str(key)] = [
                TaintFlow.from_dict(entry) for entry in entries
            ]
    except Exception:  # noqa: BLE001 — corrupt entries mean requery, not crash
        logger.warning(
            "joern pre-sweep flow cache at %s failed to deserialise — "
            "re-running the live sweep", path, exc_info=True,
        )
        return None
    logger.info(
        "joern pre-sweep flows reloaded from prep cache (CPG hash "
        "match) — %d flow groups", len(flows_by_key),
    )
    return flows_by_key


def save_presweep_flows_cache(
    out_dir, identity: tuple[str, str],
    flows: dict[str, list] | None, status: dict,
) -> None:
    """Persist a COMPLETE pre-sweep result for later segments.

    Refuses to write anything from an interrupted or errored sweep:
    a lost query window returns whatever flows arrived before the
    restart, and caching that would let an incomplete flow set
    silently masquerade as the full sweep on every later segment.
    Skip-case results (joern unavailable — ``completed`` never set)
    are equally uncacheable. Best-effort: failures log and move on.
    """
    if not out_dir:
        return
    if (
        not status.get("completed")
        or status.get("errors")
        or (status.get("interrupted") and not status.get("recovered"))
    ):
        logger.debug(
            "pre-sweep flow cache not written (incomplete sweep): %s",
            {k: status.get(k) for k in
             ("completed", "interrupted", "recovered", "errors")},
        )
        return
    try:
        serialised: dict[str, list] = {}
        for key, group in (flows or {}).items():
            entries = []
            for flow in group:
                to_dict = getattr(flow, "to_dict", None)
                if to_dict is None:
                    logger.debug(
                        "pre-sweep flow cache not written: flow object "
                        "under %r has no to_dict", key,
                    )
                    return
                entries.append(to_dict())
            serialised[key] = entries

        from datetime import datetime, timezone

        from core.json import save_json
        save_json(Path(out_dir) / PRESWEEP_FLOWS_CACHE_RELPATH, {
            "version": _PRESWEEP_FLOWS_CACHE_VERSION,
            "cpg_hash": identity[0],
            "sink_hash": identity[1],
            "partial": False,
            "ts": datetime.now(timezone.utc).isoformat(),
            "flow_groups": len(serialised),
            "flows_by_key": serialised,
        })
    except Exception:  # noqa: BLE001 — bookkeeping must not cost the sweep
        logger.debug("pre-sweep flow cache write failed", exc_info=True)


def build_joern_evidence(
    target_path, out_dir, joern_overrides=None,
    on_progress: Callable | None = None,
    joern_server=None,
    abort_check: Callable[[], bool] | None = None,
    deadline_monotonic: float | None = None,
    scope_exclude_dirs: tuple[str, ...] = (),
) -> dict[str, list] | None:
    """Run Joern pre-sweep (standard_sinks.sc) if available.

    When the pre-sweep ended degraded — window interrupted by a server
    restart (re-queued and recovered, or lost) OR the taint query
    errored on either execution path — the outcome is persisted to
    ``joern-presweep-status.json`` in the run dir for the summary and
    critique — an incomplete taint window must not be a log-only event.

    Completed sweeps are persisted to the run dir's prep cache keyed
    by (CPG content hash, sink-list hash); a resumed segment on an
    unchanged tree reloads instead of re-running the live query.

    ``abort_check`` is polled at step boundaries here and inside
    :func:`core.audit.sweep.run_joern_pre_sweep`: True returns None
    without building/querying (and without writing cache or status) —
    the consumer has discarded the result.
    """
    try:
        from .sweep import run_joern_pre_sweep
    except ImportError:
        return None

    def _aborted() -> bool:
        if abort_check is not None and abort_check():
            logger.debug("joern pre-sweep build aborted by consumer")
            return True
        return False

    if _aborted():
        return None

    tunables = joern_tunables(overrides=joern_overrides)
    if tunables is None:
        return None

    identity = _presweep_flows_identity(
        target_path, scope_exclude_dirs=scope_exclude_dirs)
    if identity is not None:
        cached = load_presweep_flows_cache(out_dir, identity)
        if cached is not None:
            return cached or None

    if _aborted():
        return None

    cache_dir = resolve_cpg_cache_dir(out_dir)
    status: dict = {}
    # An in-target run output dir must not feed the CPG content
    # key: its artifacts change every segment, flapping the key
    # and re-buying a full rebuild per resume.
    presweep_excludes = run_exclude_dirs(out_dir, target_path)
    from packages.joern.tunables import resolve_cpg_timeout_s
    flows = run_joern_pre_sweep(
        target_path, {},
        cache_dir=cache_dir,
        on_progress=on_progress,
        # A derived ("auto") CPG timeout resolves against this
        # sweep's own target/exclusion set (non-auto passes through).
        stall_timeout=resolve_cpg_timeout_s(
            tunables, target_path,
            exclude_dirs=presweep_excludes + tuple(scope_exclude_dirs),
        ),
        query_timeout=tunables.query_timeout_s,
        heap_mb=tunables.heap_mb,
        server=joern_server,
        status_out=status,
        deadline_monotonic=deadline_monotonic,
        exclude_dirs=presweep_excludes,
        scope_exclude_dirs=scope_exclude_dirs,
        abort_check=abort_check,
    )
    if abort_check is not None and abort_check():
        # Aborted mid-sweep: a partial result must not be cached or
        # write interruption status for a run that discarded it.
        return None
    # Persist the status artifact for EVERY degraded end, not just the
    # server-restart interruption: an errored query (server or file
    # path) leaves the same incomplete flow set, and without the
    # artifact the report and the critique cadence read its missing
    # flows as "no flows" instead of "not swept". Consumers key their
    # wording on the ``interrupted`` count.
    if status.get("interrupted"):
        status["flows_recovered"] = sum(
            len(v) for v in (flows or {}).values()
        )
        _write_presweep_status(out_dir, status)
    elif status.get("errors"):
        status["flows_partial"] = sum(
            len(v) for v in (flows or {}).values()
        )
        _write_presweep_status(out_dir, status)
    if identity is not None:
        save_presweep_flows_cache(out_dir, identity, flows, status)
    return flows or None


def enrich_summaries_from_joern(
    joern_server,
    joern_flows: dict[str, list],
    taint_summary_results: dict[str, Any],
) -> None:
    """Run Joern summary batch for flow-involved methods and merge results."""
    try:
        from core.analysis.summaries import (
            EvidenceTier,
            FunctionSummary,
            Precondition,
            ReturnCondition,
            TaintRule,
        )
        from packages.joern.models import TaintFlow
    except ImportError:
        return

    methods: set[str] = set()
    file_for_method: dict[str, str] = {}
    for file_key, flow_list in joern_flows.items():
        for flow_dict in flow_list:
            try:
                flow = TaintFlow.from_dict(flow_dict) if isinstance(flow_dict, dict) else flow_dict
            except Exception:
                logger.debug("unparseable joern flow skipped", exc_info=True)
                continue
            if flow.source_method:
                methods.add(flow.source_method)
                file_for_method.setdefault(flow.source_method, file_key)
            for step in getattr(flow, "steps", []):
                fn = getattr(step, "function", "")
                if fn:
                    methods.add(fn)
                    file_for_method.setdefault(fn, getattr(step, "file", file_key))

    if not methods:
        return

    try:
        # sorted(): set iteration order varies with PYTHONHASHSEED, so
        # the batch query (and the merge order of its results) differed
        # run to run — deterministic input is a precondition for
        # reproducible reviewer context.
        summaries = joern_server.run_summary_batch(
            sorted(methods), timeout=60,
        )
    except Exception:
        logger.debug("joern summary batch failed", exc_info=True)
        return

    if not summaries:
        return

    merged = 0
    for method_name, js in summaries.items():
        file_path = file_for_method.get(method_name, "")
        key = f"{file_path}:{method_name}" if file_path else method_name

        fs = FunctionSummary(
            function=method_name,
            file=file_path,
            taint_rules=[
                TaintRule(
                    source_param=t, source_index=0,
                    sink_call="", sink_arg_index=0,
                    evidence_tier=EvidenceTier.XREF_BACKED,
                )
                for t in js.taint_rules
            ],
            preconditions=[
                Precondition(
                    param="", param_index=0,
                    conditions=[p],
                    evidence_tier=EvidenceTier.XREF_BACKED,
                )
                for p in js.preconditions
            ],
            returns=[
                ReturnCondition(
                    code=r,
                    evidence_tier=EvidenceTier.XREF_BACKED,
                )
                for r in js.returns
            ],
            evidence_tier=EvidenceTier.XREF_BACKED,
            source="joern_cpg",
            confidence="high",
        )

        existing = taint_summary_results.get(key)
        if existing is None or getattr(existing, "source", "") != "joern_cpg":
            taint_summary_results[key] = fs
            merged += 1

    if merged:
        logger.info("joern_summary_batch: merged %d CPG-backed summaries", merged)


def resolve_joern_evidence(
    target_path, joern_overrides=None,
    on_joern_progress: Callable[[str], None] | None = None,
    joern_server=None,
    out_dir=None,
    abort_event=None,
    deadline_monotonic: float | None = None,
    scope_exclude_dirs: tuple[str, ...] = (),
) -> tuple:
    """Resolve Joern evidence.

    Returns (joern_flows, joern_future).

    ``abort_event`` (threading.Event): set by a consumer that has
    discarded the future — the background build stops at its next
    step boundary instead of running to completion unread.
    """
    if not joern_available(overrides=joern_overrides):
        return (None, None)

    if not (target_has_c_sources(target_path)
            or target_has_joern_sources(target_path)):
        return (None, None)

    def _progress(msg: str) -> None:
        # ONE channel per message: the progress callback renders on
        # the operator console (stdout); emitting the same text
        # through the logger too printed every Joern progress line
        # twice (stderr + stdout). The logger is the fallback when no
        # callback exists.
        if on_joern_progress:
            on_joern_progress(msg)
        else:
            logger.info(msg)

    if joern_server is not None and joern_server.is_alive():
        _progress("Joern pre-sweep (server mode, background)...")

    executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="joern-cpg")
    future = executor.submit(
        build_joern_evidence, target_path, out_dir, joern_overrides,
        _progress, joern_server,
        abort_check=abort_event.is_set if abort_event is not None else None,
        deadline_monotonic=deadline_monotonic,
        scope_exclude_dirs=scope_exclude_dirs,
    )
    executor.shutdown(wait=False)
    return (None, future)


def merge_joern_flows(
    joern_flows: dict[str, list],
    evidence_index: dict[str, Any],
    checklist: dict[str, Any],
    sarif_cache,
) -> dict[str, Any]:
    """Merge Joern taint flows into the evidence index."""
    from core.evidence import build_evidence_index
    merged = build_evidence_index(
        checklist=checklist,
        joern_flows=joern_flows,
        sarif_cache=sarif_cache,
    )
    from .safe_env import truncate_output
    for key, rec in merged.items():
        if key in evidence_index:
            existing = evidence_index[key]
            if rec.joern_flows and not existing.joern_flows:
                truncated, _note = truncate_output(
                    rec.joern_flows, "joern_query",
                )
                existing.joern_flows = truncated
        else:
            if rec.joern_flows:
                rec.joern_flows, _note = truncate_output(
                    rec.joern_flows, "joern_query",
                )
            evidence_index[key] = rec

    enriched = sum(1 for r in merged.values() if r.joern_flows)
    logger.info(
        "Joern evidence merged: %d functions enriched",
        enriched,
    )
    return evidence_index


def drain_joern_future(
    future: Future,
    evidence_index: dict[str, Any],
    checklist: dict[str, Any],
    sarif_cache,
) -> dict[str, Any]:
    """Drain a completed Joern future and merge flows into evidence_index."""
    try:
        joern_flows = future.result(timeout=0)
    except Exception:
        logger.warning("Joern background build failed", exc_info=True)
        return evidence_index

    if not joern_flows:
        return evidence_index

    return merge_joern_flows(joern_flows, evidence_index, checklist, sarif_cache)


def resolve_cpg_cache_dir(out_dir) -> Path | None:
    """Resolve the CPG cache directory for project-level reuse."""
    if not out_dir:
        return None
    project_dir = Path(out_dir).parent
    if project_dir and project_dir != Path(out_dir):
        return project_dir
    return None


def run_exclude_dirs(out_dir, target_path) -> tuple[str, ...]:
    """Import-guarded :func:`packages.joern.runner.run_output_exclude_dirs`."""
    try:
        from packages.joern.runner import run_output_exclude_dirs
    except ImportError:
        return ()
    return run_output_exclude_dirs(out_dir, target_path)


def _current_content_hash(out_dir, target_path) -> str | None:
    """The current run's target content hash, or None when unavailable.

    Prefers the current run's own .raptor-run.json manifest; falls back
    to deriving it from the target tree the same way the CPG cache does.
    """
    manifest_path = Path(out_dir) / ".raptor-run.json"
    if manifest_path.exists():
        own = load_json(manifest_path, max_bytes=_MAX_RUN_META_BYTES)
        if isinstance(own, dict):
            own_hash = own.get("content_hash", "")
            if own_hash:
                return own_hash
    if target_path is None or not Path(target_path).is_dir():
        return None
    try:
        from packages.joern.runner import _target_content_hash
        return _target_content_hash(Path(target_path))
    except Exception:
        logger.debug("content hash derivation failed", exc_info=True)
        return None


def import_sibling_joern_flows(
    out_dir,
    target_path=None,
) -> dict[str, list] | None:
    """Step 0i: import Joern taint flows from sibling project runs."""
    siblings = sibling_run_dirs(out_dir, target_path=target_path)
    if not siblings:
        return None
    imported: dict[str, list] = {}
    skipped_stale = 0
    current_hash: str | None = None
    current_hash_resolved = False
    for sibling_dir in siblings:
        flows_path = sibling_dir / "joern-flows.json"
        if not flows_path.exists():
            continue
        # Staleness gate: a sibling run at a different commit carries
        # taint flows for code that no longer exists (line drift makes
        # them actively misleading). The gate is only meaningful when
        # BOTH hashes are known and equal — an absent/unreadable
        # sibling hash (or an unknown current hash) means freshness
        # cannot be established, and unverifiable flows must read as
        # stale, not fresh (the old both-known-only rule let any
        # sibling without a content_hash bypass the gate entirely).
        sibling_hash = ""
        manifest_path = sibling_dir / ".raptor-run.json"
        if manifest_path.exists():
            manifest = load_json(manifest_path, max_bytes=_MAX_RUN_META_BYTES)
            sibling_hash = (
                manifest.get("content_hash", "")
                if isinstance(manifest, dict) else ""
            )
        if not current_hash_resolved:
            current_hash = _current_content_hash(
                out_dir, target_path,
            )
            current_hash_resolved = True
        if not sibling_hash or not current_hash \
                or sibling_hash != current_hash:
            skipped_stale += 1
            logger.info(
                "sibling %s joern-flows unverifiable or stale "
                "(sibling hash %s, current %s) — skipped",
                sibling_dir.name,
                sibling_hash[:8] if sibling_hash else "absent",
                current_hash[:8] if current_hash else "unknown",
            )
            continue
        # Bounded load: joern-flows.json is derived from an untrusted
        # target, so a hostile or runaway run can inflate it — the
        # previous raw json.load buffered the whole file before any
        # size check. load_json stat-gates BEFORE the read and
        # warn-and-Nones on oversize/malformed, which the isinstance
        # check below turns into the existing skip-this-sibling path.
        flows_data = load_json(flows_path, max_bytes=_MAX_JOERN_FLOWS_BYTES)
        if not isinstance(flows_data, dict):
            logger.debug(
                "malformed, oversize, or unreadable joern-flows in %s "
                "— skipped", sibling_dir.name,
            )
            continue
        for key, flows in flows_data.items():
            imported.setdefault(key, []).extend(flows)
    if skipped_stale:
        logger.info(
            "sibling joern-flow import: %d stale run(s) skipped",
            skipped_stale,
        )
    return imported or None


def sibling_run_dirs(
    out_dir,
    *,
    target_path=None,
) -> list[Path]:
    """List sibling run directories under the same project."""
    out_dir = Path(out_dir)
    project_dir = out_dir.parent
    if not project_dir or project_dir == out_dir:
        return []
    dirs = []
    for child in sorted(project_dir.iterdir()):
        if not child.is_dir() or child == out_dir:
            continue
        if target_path is not None:
            manifest = child / ".raptor-run.json"
            if manifest.exists():
                m = load_json(manifest, max_bytes=_MAX_RUN_META_BYTES)
                # Malformed metadata (valid JSON, wrong shape) is
                # as disqualifying as unparseable JSON.
                if not isinstance(m, dict):
                    continue
                try:
                    sibling_target = m.get("target_path") or m.get("target", "")
                    if sibling_target and Path(sibling_target).resolve() != Path(target_path).resolve():
                        continue
                except (OSError, TypeError, ValueError):
                    # A wrong-TYPED field (number/list/bool) in an
                    # otherwise dict-shaped manifest raises TypeError
                    # from Path() — as disqualifying as a wrong-shaped
                    # manifest, never a discovery abort (the
                    # import_sibling_joern_flows caller is unwrapped).
                    continue
            else:
                continue
        dirs.append(child)
    return dirs


def adaptive_max_depth(
    inventory: dict[str, Any] | None,
    entry_points: set,
    operator_override: int | None = None,
) -> int:
    """Compute propagation depth from call graph density."""
    from .propagation import DEFAULT_MAX_DEPTH

    if operator_override is not None:
        return operator_override

    if not inventory:
        return DEFAULT_MAX_DEPTH

    depths = _sample_entry_point_depths(inventory, entry_points)

    if not depths:
        return DEFAULT_MAX_DEPTH

    p90 = sorted(depths)[int(len(depths) * 0.9)]

    return max(5, min(p90 + 2, 15))


def _sample_entry_point_depths(
    inventory: dict[str, Any],
    entry_points: set,
) -> list[int]:
    """BFS from each entry point, recording reachable function depths."""
    edges: dict[str, list[str]] = {}
    for edge in inventory.get("call_edges", inventory.get("edges", [])):
        caller = edge.get("caller", "")
        callee = edge.get("callee", "")
        if caller and callee:
            edges.setdefault(caller, []).append(callee)

    if not edges:
        return []

    depths: list[int] = []
    # sorted(): sampling a SET here made the adaptive propagation
    # depth hash-seed-dependent whenever >50 entry points exist.
    for ep in sorted(entry_points)[:50]:
        name = ep.split(":")[-1] if ":" in ep else ep
        visited: set = set()
        queue = deque([(name, 0)])
        while queue:
            func, depth = queue.popleft()
            if func in visited:
                continue
            visited.add(func)
            depths.append(depth)
            for callee in edges.get(func, []):
                if callee not in visited and depth < 20:
                    queue.append((callee, depth + 1))

    return depths

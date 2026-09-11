"""Source inventory builder.

Enumerates source files, extracts functions, computes checksums.
Used by /validate (Stage 0), /understand (MAP-0), SCA's
function-level reachability tier, and any other consumer that
needs a cached call-graph view of the project.
"""

import ast
import fnmatch
import logging
import os
from concurrent.futures import (
    FIRST_COMPLETED,
    ProcessPoolExecutor,
    ThreadPoolExecutor,
    wait,
)
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core.build.macro_config import extract_build_tus, extract_macro_config
from core.build.rust_modules import extract_rust_crate_modules
from core.config import RaptorConfig
from core.hash import sha256_bytes, sha256_string
from core.json import load_json, save_json

from .build_membership import (
    crate_module_excluded,
    detect_build_excluded,
    tu_membership_excluded,
)
from .call_graph import (
    extract_call_graph_c,
    extract_call_graph_cpp,
    extract_call_graph_csharp,
    extract_call_graph_go,
    extract_call_graph_java,
    extract_call_graph_javascript,
    extract_call_graph_kotlin,
    extract_call_graph_lua,
    extract_call_graph_php,
    extract_call_graph_python,
    extract_call_graph_ruby,
    extract_call_graph_rust,
    extract_call_graph_scala,
    extract_call_graph_swift,
)
from .dead_scope import detect_dead_scopes
from .diff import compare_inventories
from .exclusions import (
    DEFAULT_EXCLUDES,
    PKG_EXEMPTIBLE_BUILD_DIRS,
    ROOT_ANCHORED_EXCLUDE_DIRS,
    generated_marker_corroborated,
    is_binary_file,
    is_first_party_package_dir,
    is_generated_file,
    match_exclusion_reason,
)
from .extractors import compute_interstitial_items, count_sloc, extract_items
from .languages import (
    LANGUAGE_MAP,
    RECORD_ONLY_EXTENSIONS,
    detect_language,
    detect_language_from_shebang,
    refine_language,
)
from .module_load_abort import detect_module_load_abort
from .translation_view import detect_macro_call_targets, preprocess_view

logger = logging.getLogger(__name__)

def _extract_python_dunder_all(content: str) -> list[str] | None:
    """Return the list of names declared in module-level ``__all__``, or
    ``None`` if not declared (or the file isn't valid Python).

    ``__all__`` is Python's explicit export contract: a name not in
    ``__all__`` is the module author saying "this isn't part of the
    public API." The reachability heuristic uses this as an authoritative
    signal that complements the weaker leading-underscore convention —
    so a public-named function that's been omitted from ``__all__`` still
    qualifies as a dead-island candidate.

    Module-level only. COMPUTED ``__all__`` (comprehensions,
    ``list(REGISTRY)``, function results) returns ``None`` — the export
    set is unknowable statically, and returning ``[]`` would read as an
    authoritative "nothing exported", turning every public function in
    the module into a confident dead-island candidate. ``__all__ +=
    [...]`` / ``__all__.append(...)`` / ``.extend(...)`` with literal
    values are harvested; non-literal extensions also degrade to
    ``None`` (more uncertainty, never less confidence).
    """
    try:
        tree = ast.parse(content)
    except (SyntaxError, ValueError):
        return None

    def _literal_names(value: ast.expr) -> list[str] | None:
        """Names from a literal list/tuple/set, or None when computed."""
        if isinstance(value, (ast.List, ast.Tuple, ast.Set)):
            return [
                el.value for el in value.elts
                if isinstance(el, ast.Constant) and isinstance(el.value, str)
            ]
        return None

    names: list[str] = []
    saw_declaration = False
    for node in tree.body:
        value: ast.expr | None = None
        is_extension = False
        if isinstance(node, ast.Assign):
            if not any(isinstance(t, ast.Name) and t.id == "__all__"
                       for t in node.targets):
                continue
            value = node.value
        elif isinstance(node, ast.AnnAssign):
            if not (isinstance(node.target, ast.Name)
                    and node.target.id == "__all__"):
                continue
            value = node.value
        elif isinstance(node, ast.AugAssign):
            if not (isinstance(node.target, ast.Name)
                    and node.target.id == "__all__"):
                continue
            value = node.value
            is_extension = True
        elif isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
            call = node.value
            if not (isinstance(call.func, ast.Attribute)
                    and isinstance(call.func.value, ast.Name)
                    and call.func.value.id == "__all__"
                    and call.func.attr in ("append", "extend")):
                continue
            saw_declaration = True
            if call.func.attr == "append":
                if (len(call.args) == 1
                        and isinstance(call.args[0], ast.Constant)
                        and isinstance(call.args[0].value, str)):
                    names.append(call.args[0].value)
                    continue
                return None  # non-literal append — set unknowable
            if len(call.args) == 1:
                harvested = _literal_names(call.args[0])
                if harvested is not None:
                    names.extend(harvested)
                    continue
            return None  # non-literal extend — set unknowable
        if value is None:
            continue
        saw_declaration = True
        harvested = _literal_names(value)
        if harvested is None:
            return None  # computed value — export set unknowable
        if is_extension:
            names.extend(harvested)
        else:
            names = list(harvested)  # re-assignment replaces
    if not saw_declaration:
        return None
    return names


# Worker cap for the per-file extractor pool. Tree-sitter Tree
# objects can briefly hold tens of MB per file (large TS / JS
# sources in particular). On a high-core box ``os.cpu_count()``
# returns 16+, and the resulting transient peak — workers × tree
# size — dominated inventory peak RSS on Grafana-scale repos
# (observed 5.7 GB across the reach stage). Sourced from
# ``tuning.json`` (``max_inventory_workers``) so operators tune it
# alongside the other RAPTOR pool sizes; default "auto" resolves to
# half the available CPU count, capped at 8.
def _resolved_max_workers() -> int:
    try:
        from core.tuning import load_tuning
        return max(1, load_tuning().max_inventory_workers)
    except Exception:  # noqa: BLE001
        return min(8, os.cpu_count() or 4)


MAX_WORKERS = _resolved_max_workers()


def _forkserver_main_importable() -> bool:
    """True when spawn/forkserver children can re-import ``__main__``.

    multiprocessing's spawn preparation records ``__main__.__file__``
    as ``main_path`` and forkserver children re-import it. A driver
    running from stdin (``python - <<'PY'`` heredocs — the stress
    sweep's own shape) has ``__file__ == "<stdin>"``: the child dies
    in ``runpy`` with FileNotFoundError. The probe below would catch
    that lazily, but the CHILD's raw traceback still lands on
    inherited stderr, reading like a crash before the one-line
    fall-through. Detect the doomed shape up front and skip the
    candidate without ever spawning.
    """
    import sys as _sys
    main_mod = _sys.modules.get("__main__")
    main_file = getattr(main_mod, "__file__", None)
    if not main_file:
        # No __file__ (embedded interpreters, some REPLs): spawn
        # preparation records no main_path; children import nothing.
        return True
    return os.path.exists(main_file)


def _pool_mp_context():
    """Preferred multiprocessing context for the extractor pool:
    forkserver when the platform offers it (Linux/macOS) AND the
    driver's ``__main__`` is re-importable, else the platform
    default.

    Callers embed inventory builds in multi-threaded processes, and
    fork from a threaded parent hands every worker a copy of any
    lock a sibling thread held at that instant — permanently frozen
    in the child. forkserver/spawn children start clean.
    """
    import multiprocessing
    if not _forkserver_main_importable():
        # spawn-shaped contexts (forkserver AND spawn) all re-import
        # __main__ in the child and die identically under this
        # driver shape — fork is the one start method that never
        # does. Its fork-frozen-lock hazard is mitigated separately
        # (cached grammar imports removed the per-file lock
        # acquisitions; the stall watchdog retries in a fresh pool).
        logger.info(
            "inventory: driver has no re-importable __main__ "
            "(stdin/embedded); using the fork pool context — "
            "spawn-shaped contexts cannot re-import this main",
        )
        try:
            return multiprocessing.get_context("fork")
        except ValueError:
            return None
    try:
        return multiprocessing.get_context("forkserver")
    except ValueError:
        return None


def _pool_probe() -> bool:
    """No-op worker round-trip used to prove a pool context actually
    works before files are submitted to it."""
    return True


def _shutdown_pool_nowait(
    pool: "ProcessPoolExecutor | ThreadPoolExecutor",
    *,
    kill_grace_s: float = 5.0,
) -> None:
    """Tear down an extractor pool without blocking on its workers,
    and make sure process-pool workers actually die.

    Order matters: ``ProcessPoolExecutor.shutdown()`` drops the
    executor's reference to its worker map (``self._processes =
    None``) before returning, so the worker snapshot MUST be taken
    first — a post-shutdown read sees ``None`` and terminates
    nothing. A leaked wedged worker is not just leaked RAM: the
    executor's manager thread joins its workers, interpreter exit
    joins the manager thread, and the worker still holds the
    process's inherited stdout/stderr — one surviving worker turns a
    finished-and-summarised run into a process that never exits and
    an output pipe that never closes (a CI runner waits on that pipe
    even after the step's shell would have finished).

    ``terminate()`` alone is not enough either: a worker forked from
    a threaded parent inherits the parent's Python signal handlers,
    and a handler that touches a fork-frozen lock never returns — the
    worker survives SIGTERM indefinitely. Wait on the process
    sentinels (death is visible there no matter which thread reaps)
    and escalate to SIGKILL after ``kill_grace_s``. Grace trade-off
    both ways: longer lets a slow-but-responsive worker exit on
    SIGTERM cleanly; shorter recovers the build faster when the
    worker is truly wedged. 5s is orders of magnitude above a healthy
    worker's SIGTERM latency and well below the stall window that
    triggers this teardown.

    ThreadPoolExecutor has no ``_processes``: the snapshot is empty
    and this degrades to the plain non-blocking shutdown — hung
    threads cannot be killed, only abandoned.
    """
    procs = list((getattr(pool, "_processes", None) or {}).values())
    pool.shutdown(wait=False, cancel_futures=True)
    for proc in procs:
        try:
            proc.terminate()
        except Exception:  # noqa: BLE001 — teardown must never raise
            pass
    for proc in _await_worker_exit(procs, kill_grace_s):
        # kill() no-ops on an already-reaped process (returncode set),
        # so racing the manager thread's own join here is safe.
        try:
            proc.kill()
        except Exception:  # noqa: BLE001 — teardown must never raise
            pass


def _await_worker_exit(procs: list, grace_s: float) -> list:
    """Wait up to ``grace_s`` for the given worker processes to exit;
    return the survivors (empty on a full clean exit).

    Waits on the process SENTINELS, not ``join()``: death is visible
    on the sentinel no matter which thread reaps the process, so this
    never races the executor manager thread's own join. Event-driven
    — returns as soon as the last worker exits, so a prompt exit
    costs milliseconds regardless of the grace value.
    """
    import time as _time
    from multiprocessing import connection as _mp_connection

    if not procs:
        return []
    deadline = _time.monotonic() + grace_s
    pending = {proc.sentinel: proc for proc in procs}
    while pending:
        remaining = deadline - _time.monotonic()
        if remaining <= 0:
            break
        try:
            ready = _mp_connection.wait(list(pending), timeout=remaining)
        except OSError:
            break
        for sentinel in ready:
            pending.pop(sentinel, None)
    return list(pending.values())


def _shutdown_pool_clean(
    pool: "ProcessPoolExecutor | ThreadPoolExecutor",
    *,
    grace_s: float = 10.0,
) -> None:
    """Shut down a pool whose futures have ALL resolved, without an
    unbounded join on its workers.

    The clean-completion counterpart of :func:`_shutdown_pool_nowait`.
    ``shutdown(wait=True)`` here joins workers that have already
    delivered every result — but a fork-context worker can wedge on a
    fork-frozen lock ON ITS EXIT PATH, after its last result, and the
    blocking join then hangs the whole build before any summary
    prints. Results integrity is unaffected by construction: callers
    invoke this only after the drain loop consumed every future, so
    no result can be lost to an escalated kill — the workers hold
    nothing the build still needs.

    Same snapshot-before-shutdown order as the wedged-path helper
    (``shutdown()`` nulls ``_processes`` before returning). Workers
    get ``grace_s`` to exit NORMALLY off the shutdown sentinel first
    — the wait is sentinel-event-driven, so the healthy path costs
    milliseconds, not the grace value. Grace trade-off both ways:
    longer tolerates a slow-but-healthy worker teardown on a loaded
    host (exit is normally instant — the worker loop just returns);
    shorter bounds how long a wedged exit path can delay the build's
    completion. 10s is generous for "instant" and small next to the
    60s stall window the in-flight path uses. Escalation past the
    grace is terminate → ``kill_grace_s`` → SIGKILL, identical to the
    wedged path, with a WARNING naming the wedged pids — a clean
    drain that needed signals is a real anomaly worth a log line,
    but it never fails the build.

    Thread pools (the extractor fallback) take the plain blocking
    shutdown: threads share the parent's locks normally — the
    fork-frozen-lock wedge class cannot occur — and cannot be killed
    anyway.
    """
    procs = list((getattr(pool, "_processes", None) or {}).values())
    if not procs:
        pool.shutdown(wait=True)
        return
    pool.shutdown(wait=False)
    survivors = _await_worker_exit(procs, grace_s)
    if not survivors:
        return
    logger.warning(
        "inventory: %d extractor worker(s) still alive %.1fs after a "
        "clean drain (pids: %s) — escalating terminate→kill; all "
        "results were already collected, the build is unaffected",
        len(survivors), grace_s,
        ", ".join(str(p.pid) for p in survivors),
    )
    for proc in survivors:
        try:
            proc.terminate()
        except Exception:  # noqa: BLE001 — teardown must never raise
            pass
    for proc in _await_worker_exit(survivors, 5.0):
        # Same reap-race safety note as _shutdown_pool_nowait.
        try:
            proc.kill()
        except Exception:  # noqa: BLE001 — teardown must never raise
            pass


def _make_extractor_pool(initargs, *, max_workers=None, contexts=None):
    """Create the extractor process pool, PROBING each candidate
    context with a real worker round-trip before committing to it.

    forkserver preloads ``__main__``, and drivers without a
    file-backed main (``python - <<'PY'`` heredocs — the stress
    sweep's own shape — or embedders reading code from stdin) kill
    the forkserver at its first spawn. That failure is LAZY: the
    ``ProcessPoolExecutor`` constructor succeeds and the first
    ``submit`` blows up, so a constructor-level fallback never sees
    it — and every file would be lost. The probe forces the spawn
    now, and a context that cannot produce a working worker falls
    through to the next candidate (the platform default), then to
    ``None`` for the caller's thread-pool fallback.
    """
    if contexts is None:
        contexts = (_pool_mp_context(), None)
    tried = set()
    for ctx in contexts:
        method = ctx.get_start_method() if ctx is not None else "default"
        if method in tried:
            continue
        tried.add(method)
        try:
            pool = ProcessPoolExecutor(
                max_workers=max_workers or MAX_WORKERS,
                initializer=_init_inventory_worker,
                initargs=initargs,
                mp_context=ctx,
            )
        except (OSError, RuntimeError, ValueError):
            continue
        try:
            if pool.submit(_pool_probe).result(timeout=120) is True:
                return pool
        except Exception:  # noqa: BLE001 — any spawn failure disqualifies
            logger.info(
                "inventory: %s pool context failed its worker probe; "
                "trying the next candidate", method,
            )
        _shutdown_pool_nowait(pool)
    return None

# Stall watchdog for the extractor pool. The previous loop used
# ``as_completed()`` + ``future.result(timeout=300)`` — but
# ``as_completed`` only yields futures that have ALREADY completed, so
# that result() timeout could never fire, and one hung worker stalled
# the whole inventory build — and every pipeline waiting on it —
# indefinitely. The timeout belongs on the WAIT: a full window with
# zero completions declares the remaining futures stalled; they are
# retried once in a fresh pool, and the wedged pool is torn down
# without blocking on its workers.
#
# 60s, not 300: per-file extraction is millisecond-scale, so a full
# minute with ZERO completions across the whole pool is already
# decisive — and the window is pure serialized wallclock cost when a
# worker wedges (a 300s window added five minutes to one project's
# scan). The known wedge class is not pathological input at all: a
# worker forked from a multi-threaded parent inherits any lock a
# sibling thread held at fork time permanently frozen, and froze at
# its next logging/import acquisition (hence mp_context below).
INVENTORY_STALL_TIMEOUT_S = 60


def _retry_stalled_files(files, initargs, *, _on_retry_done, futures_map):
    """One-shot retry of a wedged pool's in-flight files in a FRESH
    pool. Returns the files that failed again (empty when everything
    recovered — the common case, since a zero-completion stall means
    the WORKERS wedged, not that the files are pathological).

    PER-FILE stall windows, submitted one at a time: the retry pool is
    serial (one worker), so a single shared zero-completion window let
    one genuinely-slow file mark every queued sibling as failed
    without ever executing it. Each file now gets its own full window;
    a file that exhausts it is recorded failed, its wedged pool torn
    down, and the remaining files continue in a fresh pool. No
    ``with`` block: the context manager exit would block on wedged
    workers, which is exactly what the teardown here must never do.
    """
    def _kill(p: ProcessPoolExecutor) -> None:
        _shutdown_pool_nowait(p)

    still_failed = []
    pool = None
    files = list(files)
    consecutive_stalls = 0
    try:
        for idx, fp in enumerate(files):
            if pool is None:
                pool = _make_extractor_pool(initargs, max_workers=1)
                if pool is None:
                    # No working pool context at all — don't re-probe
                    # (with its own timeout) once per remaining file.
                    still_failed.extend(files[idx:])
                    break
            fut = pool.submit(_process_file_in_worker, fp)
            # The caller's completion callback resolves file paths
            # through its own futures map — register the retry futures
            # there so results land through the same accounting.
            futures_map[fut] = fp
            done, _pending = wait({fut}, timeout=INVENTORY_STALL_TIMEOUT_S)
            if done:
                _on_retry_done(fut)
                consecutive_stalls = 0
                continue
            fut.cancel()
            _kill(pool)
            pool = None
            still_failed.append(fp)
            consecutive_stalls += 1
            # Two INDEPENDENT fresh pools stalling in a row points at
            # a systemic wedge (the known class is environmental —
            # fork-frozen locks — not per-file), so stop burning a
            # full window per remaining file; one stall alone could
            # still be a single pathological file, and its siblings
            # deserve their own attempt.
            if consecutive_stalls >= 2:
                still_failed.extend(files[idx + 1:])
                break
    finally:
        if pool is not None:
            # Bounded, not shutdown(wait=True): the last retry future
            # has resolved by here, but the retry worker can still
            # wedge on its EXIT path — see _shutdown_pool_clean.
            _shutdown_pool_clean(pool)
    return still_failed


def _drain_futures(futures, timeout_s, on_done):
    """Consume ``futures`` as they complete, calling ``on_done`` for
    each. Returns the set of futures still pending after a full
    ``timeout_s`` window passed with ZERO completions (the stalled
    set) — empty on a clean drain. Progress resets the window, so a
    slow-but-moving pool is never cut off."""
    pending = set(futures)
    while pending:
        done, pending = wait(
            pending, timeout=timeout_s, return_when=FIRST_COMPLETED,
        )
        if not done:
            return pending
        for future in done:
            on_done(future)
    return set()

# Per-file read cap. Bigger than any realistic source file (the
# largest in CPython is ~30K LOC ≈ 1 MB) but small enough that a
# pathological input — vendored binary blob, malformed
# symlink-to-/dev/zero, hostile sample in a test fixture — can't
# OOM the inventory builder. Pre-fix `read_bytes()` loaded the whole
# file into memory before any size check, so a single 10 GB file
# anywhere in the target tree killed the run.
MAX_FILE_BYTES = 8 * 1024 * 1024  # 8 MiB

# Default cache root for inventory checklists when callers don't
# supply an explicit ``output_dir``. Lives under ``~/.raptor/cache/
# inventory/<target-hash>/`` — the SHA-256-prefix-of-target-path
# keys distinct projects so two scans of unrelated trees don't
# share state. Operator-purge: ``rm -rf ~/.raptor/cache/inventory/``
# or ``raptor-sca clean-cache``.
_DEFAULT_INVENTORY_CACHE_ROOT = (
    Path.home() / ".raptor" / "cache" / "inventory"
)


def default_cache_dir(
    target_path: str, *, allow_unreachable: bool = False,
    config_fingerprint: str = "",
) -> Path:
    """Return the persistent cache directory for ``target_path``'s
    inventory checklist.

    Keyed on a SHA-256 prefix of the resolved absolute target path so
    distinct projects get distinct cache dirs. Auto-creates the
    parent directory; the cache dir itself is created lazily by
    ``build_inventory`` when needed.

    Used as the default ``output_dir`` for ``build_inventory`` when
    callers don't pass one explicitly. Useful for any consumer that
    wants checklist persistence (incremental SHA-256-keyed re-parse)
    without picking a project-specific path themselves.
    """
    target_abs = str(Path(target_path).resolve())
    # Fold the parse mode into the key: allow_unreachable changes the
    # C/C++ view (#if 0 kept vs blanked), so the two modes must not share
    # a cached checklist. Default mode keeps the original hash input, so
    # existing cache dirs are unchanged.
    key = target_abs if not allow_unreachable else target_abs + "\0allow_unreachable"
    # Fold the macro config too: config-aware blanking (#ifdef resolved via
    # -D/-U/.config) changes which arms are dead, so a config change must
    # invalidate the cache even when file contents are identical (else a
    # newly-live arm would stay blanked from cache → a false negative). Empty
    # fingerprint (no config / non-C target) leaves the key unchanged.
    if config_fingerprint:
        key += "\0cfg=" + config_fingerprint
    # core.hash.sha256_string, not a hand-rolled utf-8 encode: target
    # paths come from the filesystem and can carry surrogate escapes
    # (non-UTF-8 filenames), which a strict encode crashes on.
    target_hash = sha256_string(key)[:16]
    return _DEFAULT_INVENTORY_CACHE_ROOT / target_hash


def build_inventory(
    target_path: str,
    output_dir: str | None = None,
    exclude_patterns: list[str] | None = None,
    extensions: set[str] | None = None,
    skip_generated: bool = True,
    parallel: bool = True,
    allow_unreachable: bool = False,
    treat_exports_as_entries: bool | str = "auto",
    scope: list[str] | None = None,
) -> dict[str, Any]:
    """Build a source inventory of all files and functions in the target path.

    Enumerates source files, detects languages, extracts functions via
    AST/regex, computes SHA-256 per file, and records exclusions.

    Always rehashes files on disk.  Unchanged files (SHA-256 match with
    a previous checklist) reuse their old parsed entries, including
    coverage marks.  Changed files are re-parsed and their coverage
    marks cleared.

    Args:
        target_path: Directory or file to analyze.
        output_dir: Directory to save checklist.json. When ``None``
            (default), uses :func:`default_cache_dir` to derive a
            stable per-target cache dir under
            ``~/.raptor/cache/inventory/<target-hash>/``. Persistence
            across runs is the point — re-scans of an unchanged tree
            collapse the inventory build to a hash-check pass
            (sub-second on most projects, ~1s on large Go codebases
            like istio's ~770 files). Callers wanting ephemeral
            output (tests, one-shot tools) pass an explicit tempdir.
        exclude_patterns: Patterns to exclude (defaults to DEFAULT_EXCLUDES).
        extensions: File extensions to include (defaults to LANGUAGE_MAP keys).
        skip_generated: Skip auto-generated files.
        parallel: Use parallel processing for large codebases.
        allow_unreachable: Isolation mode for C/C++: parse the raw
            source with no dead-preprocessor-arm blanking (``#if 0``
            code stays visible for review) and skip config-aware macro
            resolution. Also folded into the default cache-dir key so
            the two modes never share a cached checklist.
        treat_exports_as_entries: target classification driving library mode
            (reachability treats exported/public symbols as entry points).
            ``True``/``"library"``/``"hybrid"``/``"on"`` enable it, ``False``/
            ``"application"``/``"off"`` disable it, and ``"auto"`` (default)
            classifies the target via
            :func:`core.inventory.library_detection.detect_target_kind`
            (library/hybrid → enabled). The classification is recorded in
            ``inventory['target_kind']`` (+ ``_reason``/``_source``);
            ``RAPTOR_TARGET_KIND`` is the operator env override.
        scope: Optional list of target-relative path prefixes; when
            set, collected files outside every prefix are dropped from
            the inventory (match is path-separator-aware, so
            ``src/a`` does not match ``src/abc``).

    Returns:
        Inventory dict (also saved to ``<output_dir>/checklist.json``).
    """
    # Build macro config once (compile_commands.json / .config). Drives
    # config-aware #ifdef resolution in each file's TranslationView. Empty
    # (and inert) when no build artifacts are present or in isolation mode.
    macro_config = extract_macro_config(target_path)
    if allow_unreachable:
        macro_config = None
    # Translation-unit set (compile_commands membership), built once for the
    # C/C++ build-membership witness. A witness record (not a view transform),
    # so — like the Go //go:build detector — it is NOT disabled under
    # allow_unreachable; the surface-only consumers ignore it in that mode.
    build_tus = extract_build_tus(target_path)
    # Rust crate-module set (mod-tree membership), same role for .rs sources.
    crate_modules = extract_rust_crate_modules(target_path)
    cfg_fp = macro_config.fingerprint() if macro_config else ""
    # Fold the membership sets into the cache key: a compile_commands / mod-tree
    # change (a file added to / removed from the build) must invalidate cached
    # build_excluded marks even when file contents are unchanged.
    # sha256_string (surrogateescape) — TU/module entries are
    # filesystem paths and may not be valid UTF-8.
    if build_tus:
        cfg_fp += "|tu=" + sha256_string("\0".join(sorted(build_tus)))[:16]
    if crate_modules:
        cfg_fp += "|rs=" + sha256_string(
            "\0".join(sorted(crate_modules)))[:16]

    if output_dir is None:
        output_dir = str(default_cache_dir(
            target_path, allow_unreachable=allow_unreachable,
            config_fingerprint=cfg_fp,
        ))
    if exclude_patterns is None:
        exclude_patterns = DEFAULT_EXCLUDES

    if extensions is None:
        extensions = set(LANGUAGE_MAP.keys())

    target = Path(target_path)

    if not target.exists():
        msg = f"Target path does not exist: {target_path}"
        raise FileNotFoundError(msg)

    if (target.is_file() and detect_language(str(target)) is None
            and (target.suffix
                 or detect_language_from_shebang(str(target)) is None)):
        # Directory mode admits extensionless shebang scripts; the
        # single-file gate must accept the same files (the shebang
        # probe only runs when there is no extension, mirroring the
        # walk).
        msg = f"Target file has no recognized source extension: {target_path}"
        raise ValueError(msg)

    # Collect files in single pass
    file_list, pruned_dirs = _collect_source_files(
        target, extensions, exclude_patterns,
    )
    if scope:
        target_resolved = target.resolve()
        resolved_prefixes: list[str] = []
        for s in scope:
            entry = Path(s)
            cand = (entry if entry.is_absolute()
                    else target_resolved / entry).resolve()
            # A scope entry must stay under the target. pathlib joins
            # DISCARD the left side for absolute entries and ``..``
            # segments escape it — either silently empties the
            # inventory (a run over zero functions reads as clean
            # downstream) or scopes to unrelated trees, so both are
            # hard errors. Absolute paths under the target are
            # accepted (relativized by resolution).
            if cand != target_resolved and target_resolved not in cand.parents:
                msg = (
                    f"scope entry escapes the target tree: {s!r} "
                    f"(resolved to {cand}; target is {target_resolved})"
                )
                raise ValueError(msg)
            resolved_prefixes.append(str(cand))
        scope_prefixes = tuple(resolved_prefixes)
        before = len(file_list)
        # separator-aware: scope "src/a" must not match "src/abc".
        def _in_scope(f: Path):
            fp = str(f.resolve())
            return any(
                fp == pre.rstrip("/") or fp.startswith(pre.rstrip("/") + "/")
                for pre in scope_prefixes
            )
        file_list = [f for f in file_list if _in_scope(f)]
        logger.info(
            "scope filter: %d → %d files (%d excluded)",
            before, len(file_list), before - len(file_list),
        )
    logger.info("Found %d source files to process", len(file_list))

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    checklist_file = output_path / 'checklist.json'
    old_inventory = load_json(checklist_file)

    # Parse-affecting configuration fingerprint. The default cache dir
    # folds this into its KEY, but an explicit ``output_dir`` (project
    # mode) reuses one directory across runs — without an in-artifact
    # stamp, the per-file stat/sha fast path would keep returning
    # entries parsed under a STALE macro config / TU set (stale
    # ``build_excluded`` marks, stale #ifdef blanking) after
    # compile_commands.json changes.
    parse_fingerprint = cfg_fp + ("|unreachable" if allow_unreachable else "")
    old_parse_fp = (
        old_inventory.get('parse_fingerprint', '')
        if isinstance(old_inventory, dict) else ''
    )

    old_files_by_path = {}
    if isinstance(old_inventory, dict) and old_parse_fp == parse_fingerprint:
        for f in old_inventory.get('files', []):
            if f.get('path') and f.get('sha256'):
                # Legacy checklists keyed per-file units under
                # 'functions'; normalize so every downstream 'items'
                # access works when the entry is reused verbatim.
                if 'items' not in f and 'functions' in f:
                    f = dict(f)
                    f['items'] = f.get('functions') or []
                old_files_by_path[f['path']] = f
    elif isinstance(old_inventory, dict):
        logger.info(
            "inventory: build configuration changed since the cached "
            "checklist was written — re-parsing all files (coverage "
            "marks are still carried forward)",
        )

    files_info = []
    # Seed `excluded_files` with the directories pruned at walk time so
    # operators still see what was skipped even though we never
    # enumerated each file inside.
    excluded_files = list(pruned_dirs)
    total_items = 0
    total_sloc = 0
    skipped = 0

    def _collect_result(result) -> None:
        nonlocal total_items, total_sloc, skipped
        if result is None:
            skipped += 1
        elif result.get("_excluded"):
            excluded_files.append({
                "path": result["path"],
                "reason": result["_reason"],
                "pattern_matched": result.get("_pattern"),
            })
            skipped += 1
        else:
            files_info.append(result)
            total_items += len(result['items'])
            total_sloc += result.get('sloc', 0)

    if parallel and len(file_list) > 10:
        initargs = (
            target, exclude_patterns, skip_generated,
            old_files_by_path, allow_unreachable,
            macro_config, build_tus, crate_modules,
        )
        # Prefer forkserver, NEVER unprobed fork: builds run inside
        # multi-threaded parents (the SCA stress sweep scans projects
        # on threads; logging holds handler locks), and a fork child
        # inherits any lock a sibling thread held at fork time
        # permanently frozen — workers then deadlocked at their next
        # logging/import acquisition and the watchdog blamed whatever
        # file they had claimed. forkserver was validated
        # deadlock-free under the same adversarial thread load that
        # wedged fork deterministically. The factory PROBES each
        # context with a real worker round-trip because forkserver's
        # failure mode under file-less ``__main__`` (stdin-heredoc
        # drivers — the sweep's own shape) is lazy: the constructor
        # succeeds and the first submit dies.
        pool = _make_extractor_pool(initargs)
        # Process-pool workers run with stdio detached (see
        # _init_inventory_worker), so their own per-file WARNING (with
        # traceback) never reaches the console and the future SUCCEEDS
        # with an _excluded record — the parent must re-voice the
        # failure or it is visible only in the artifact. Thread-pool
        # fallback workers log in-process; re-voicing there would
        # print every failure twice.
        worker_stdio_detached = pool is not None
        if pool is None:
            pool = ThreadPoolExecutor(max_workers=MAX_WORKERS)

            def submit_fn(fp, pool=pool):
                return pool.submit(
                    _process_single_file, fp, target, exclude_patterns,
                    skip_generated, old_files_by_path, allow_unreachable,
                    macro_config, build_tus, crate_modules,
                )
        else:
            def submit_fn(fp, pool=pool):
                return pool.submit(_process_file_in_worker, fp)
        def _rel_of(fp: Path):
            try:
                return str(fp.relative_to(target)
                           if target.is_dir() else fp.name)
            except ValueError:
                return str(fp)

        futures = {submit_fn(fp): fp for fp in file_list}

        def _on_done(future) -> None:
            nonlocal skipped
            fp = futures[future]
            try:
                result = future.result()
                if (worker_stdio_detached and isinstance(result, dict)
                        and result.get("_reason") == "processing_error"):
                    logger.warning(
                        "inventory: per-file extractor failed on %s "
                        "(%s) — recorded as processing_error",
                        fp, result.get("_pattern"),
                    )
                _collect_result(result)
            except Exception as exc:  # noqa: BLE001 — one bad file must not sink the pool
                logger.warning(
                    "inventory: per-file extractor raised on "
                    "%s — skipping (%s: %s)",
                    fp, exc.__class__.__name__, exc,
                )
                # Record it — a skipped file must never be silently
                # invisible in the artifact.
                excluded_files.append({
                    "path": _rel_of(fp),
                    "reason": "processing_error",
                    "pattern_matched": exc.__class__.__name__,
                })
                skipped += 1

        stalled = set()
        try:
            stalled = _drain_futures(
                futures, INVENTORY_STALL_TIMEOUT_S, _on_done,
            )
            if stalled:
                # A zero-completion window means WORKERS wedged (the
                # known class: fork-frozen locks), not that these
                # files are pathological — they are simply the wedged
                # workers' in-flight/queued items. Retry them once in
                # a fresh pool; only files that fail the retry too
                # are recorded as excluded.
                retry_files = [futures[f] for f in stalled]
                for future in stalled:
                    future.cancel()
                logger.warning(
                    "inventory: no extractor completion within %ds — "
                    "worker pool wedged; retrying the %d in-flight "
                    "file(s) in a fresh pool: %s",
                    INVENTORY_STALL_TIMEOUT_S, len(retry_files),
                    ", ".join(str(fp) for fp in retry_files[:5])
                    + ("…" if len(retry_files) > 5 else ""),
                )
                still_failed = _retry_stalled_files(
                    retry_files, initargs, _on_retry_done=_on_done,
                    futures_map=futures,
                )
                for fp in still_failed:
                    # Same visibility rule as processing_error: a
                    # dropped file must be recorded in the artifact.
                    excluded_files.append({
                        "path": _rel_of(fp),
                        "reason": "worker_stalled",
                        "pattern_matched":
                            f"no completion in {INVENTORY_STALL_TIMEOUT_S}s"
                            " + retry failed",
                    })
                    skipped += 1
        finally:
            if stalled:
                # Never block on hung workers: drop the queue, then
                # kill process-pool workers so neither this shutdown
                # nor interpreter exit waits on them. (Thread-pool
                # fallback threads can't be killed — the build still
                # proceeds; the hung thread is abandoned.)
                _shutdown_pool_nowait(pool)
            else:
                # Clean drain: every future resolved (the loop above
                # exhausted them), so the workers hold nothing the
                # build still needs — but their EXIT paths can wedge
                # on fork-frozen locks just like their task paths,
                # and shutdown(wait=True) would then hang the build
                # before any summary prints. Bounded shutdown with
                # escalation instead; see _shutdown_pool_clean.
                _shutdown_pool_clean(pool)
    else:
        for filepath in file_list:
            _collect_result(
                _process_single_file(filepath, target, exclude_patterns,
                                     skip_generated, old_files_by_path,
                                     allow_unreachable, macro_config, build_tus,
                                     crate_modules)
            )

    # Sort for consistent output
    files_info.sort(key=lambda x: x['path'])
    excluded_files.sort(key=lambda x: x['path'])

    # Count functions specifically for backwards-compatible field
    total_functions = sum(
        1 for f in files_info for item in f.get('items', [])
        if item.get('kind', 'function') == 'function'
    )

    # Record limitations when extraction is incomplete
    limitations = []
    from .extractors import _TS_AVAILABLE
    if not _TS_AVAILABLE:
        limitations.append("globals not extracted (tree-sitter was not available)")
        limitations.append("SLOC counts used regex fallback (less accurate)")

    inventory = {
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'target_path': str(target_path),
        'parse_fingerprint': parse_fingerprint,
        'total_files': len(files_info),
        'total_items': total_items,
        'total_functions': total_functions,
        'total_sloc': total_sloc,
        'skipped_files': skipped,
        'excluded_patterns': exclude_patterns,
        'excluded_files': excluded_files,
        'files': files_info,
    }
    # Target classification (library | hybrid | application | unknown) — a
    # first-class, neutral signal for downstream consumers (reachability,
    # attack-surface mapping, taint sources, SCA pinning posture). Setting is
    # auto|library|hybrid|application (auto = sniff package manifests;
    # RAPTOR_TARGET_KIND env is the operator override). ``treat_exports_as_
    # entries`` is the derived bool read by reachability._entry_functions:
    # library mode is on for library/hybrid kinds (public API consumed
    # externally).
    from .library_detection import resolve_library_mode
    _lib = resolve_library_mode(treat_exports_as_entries, target_path, files_info)
    inventory['treat_exports_as_entries'] = _lib['enabled']
    inventory['target_kind'] = _lib['kind']
    inventory['target_kind_reason'] = _lib['reason']
    inventory['target_kind_source'] = _lib['source']
    if limitations:
        inventory['limitations'] = limitations

    has_c_cpp = any(
        f.get("language") in ("c", "cpp")
        for f in files_info
    )
    if has_c_cpp:
        from .header_api import scan_public_api
        header_names = scan_public_api(str(target))
        if header_names:
            inventory['header_api'] = sorted(header_names)

    # Binary-oracle enrichment (Inc 4 + Phase 4 multi-binary) — opt-in
    # via the process-wide ``RaptorConfig.BINARY_ORACLE_PATHS`` (set by
    # ``raptor_agentic`` / ``raptor_codeql``'s repeatable ``--binary``
    # flag). Empty tuple = no-op. Populates ``inventory['binary_oracle']``
    # + per-item metadata; the reach_witness/demoter consumers (Phase 2)
    # then pick up the resulting BINARY_ORACLE_ABSENT verdicts via
    # ``classify_reachability``. For ``--target-kind=hybrid`` (library +
    # application), the operator passes multiple ``--binary`` flags and
    # the enrichment combines per-binary verdicts with alive-in-any
    # wins — so a function is only ``absent`` when EVERY declared binary
    # lacks it. Best-effort — missing tools / non-ELF / stripped binary
    # logs a skip and leaves the inventory unchanged.
    bin_paths = RaptorConfig.BINARY_ORACLE_PATHS
    if bin_paths:
        try:
            from core.analysis.binary_oracle import enrich_inventory_with_binary_oracle
            enrich_inventory_with_binary_oracle(
                inventory, bin_paths,
                no_suppression_paths=RaptorConfig.BINARY_ORACLE_NO_SUPPRESS,
            )
            # Persist per-binary verdicts into the build-ID-keyed cache
            # so later runs (and external consumers of the shared cache
            # dir) can reuse them without re-analysing the binary.
            # Best-effort — cache trouble never blocks the inventory.
            try:
                from core.audit.build_id_cache import (
                    load_build_id_cache,
                    store_oracle_verdicts,
                )
                store_oracle_verdicts(
                    load_build_id_cache(), inventory,
                    source_command="inventory-builder",
                )
            except Exception:
                logger.debug("build-id cache population failed",
                             exc_info=True)
        except Exception as exc:                          # noqa: BLE001
            logger.warning("binary_oracle enrichment failed for %r: %s",
                           bin_paths, exc)
        # Inc 2b Tier 1: opt-in direct-call-edge extraction. Adds
        # binary-found callers as positive reachability evidence
        # (``binary_call_edge`` verdict). Slow (~10-30s per binary
        # via r2 ``aaa``) so gated behind RaptorConfig.BINARY_ORACLE_EDGES.
        if RaptorConfig.BINARY_ORACLE_EDGES:
            try:
                from core.analysis.binary_oracle_edges import (
                    annotate_inventory_with_edges,
                    extract_direct_call_edges,
                )
                indices = [extract_direct_call_edges(Path(p))
                           for p in bin_paths]
                annotate_inventory_with_edges(inventory, indices)
            except Exception as exc:                      # noqa: BLE001
                logger.warning("binary_oracle_edges extraction failed: %s",
                               exc)

    # Perlasm generated-asm enrichment (asm option b): structurally
    # detect perlasm generators, run them under the strict sandbox
    # (fail-closed), and inventory the emitted assembly as
    # ``asm-generated`` records so shipped generated kernels become
    # enumerable, reviewable units. Detected-but-unanalysed generators
    # append loud notes to ``inventory['limitations']`` — never a
    # silent miss. Best-effort like the binary-oracle enrichment.
    try:
        from core.inventory.perlasm import enrich_inventory_with_perlasm
        enrich_inventory_with_perlasm(inventory, target_path)
    except Exception as exc:                              # noqa: BLE001
        logger.warning("perlasm enrichment failed for %s: %s",
                       target_path, exc)

    # Cumulative coverage: carry forward checked_by from previous inventory
    if old_inventory is not None:
        try:
            diff = compare_inventories(old_inventory, inventory)
            if diff is None:
                logger.info("Source material unchanged (SHA256 match)")
                inventory['source_unchanged'] = True
                # Carry forward all checked_by data from old inventory
                _carry_forward_coverage(old_inventory, inventory)
                _write_inventory_diff(output_path, None)
            else:
                logger.info(
                    "Source material changed: %d added, %d removed, %d modified",
                    len(diff['added']), len(diff['removed']), len(diff['modified']),
                )
                inventory['changes_since_last'] = diff
                # Carry forward checked_by only for unchanged files
                _carry_forward_coverage(old_inventory, inventory, modified=set(diff['modified']))
                _write_inventory_diff(output_path, diff, old_inventory, inventory)
        except (KeyError, TypeError):
            logger.debug("incompatible old inventory, skipping diff", exc_info=True)

    from core.inventory import save_checklist
    save_checklist(str(output_path), inventory)

    logger.info("Built inventory: %d files, %d items "
                "(%d functions, %d SLOC, %d skipped, %d excluded)",
                len(files_info), total_items, total_functions,
                total_sloc, skipped, len(excluded_files))
    logger.debug("Saved to: %s", checklist_file)

    return inventory


def _write_inventory_diff(
    output_path: Path,
    diff: dict[str, Any] | None,
    old_inventory: dict[str, Any] | None = None,
    new_inventory: dict[str, Any] | None = None,
) -> None:
    """Persist ``inventory-diff.json`` next to the checklist.

    Consumed by ``core.audit.priority.load_new_functions`` to boost
    new/changed functions in gap scoring. ``diff=None`` (source
    unchanged) writes an empty diff so a stale file from an earlier
    build cannot keep boosting functions that are no longer new.
    Best-effort — a write failure never blocks the inventory.
    """
    payload: dict[str, Any] = {
        'added': [], 'removed': [], 'modified': [],
        'functions_added': [], 'functions_changed': [],
    }
    if diff is not None:
        for k in ('added', 'removed', 'modified'):
            payload[k] = list(diff.get(k) or [])
        if old_inventory is not None and new_inventory is not None:
            try:
                from .diff import function_level_diff
                payload.update(
                    function_level_diff(old_inventory, new_inventory))
            except Exception:
                logger.debug("function-level diff failed", exc_info=True)
    try:
        save_json(output_path / 'inventory-diff.json', payload)
    except OSError:
        logger.debug("could not write inventory-diff.json", exc_info=True)


def _carry_forward_coverage(
    old: dict[str, Any],
    new: dict[str, Any],
    modified: set | None = None,
) -> None:
    """Carry forward checked_by from old inventory to new for unchanged files.

    Marks are MERGED (union, existing order preserved), never
    overwritten: the multi-run project promotion calls this repeatedly
    with older checklists against the newest one, and an overwrite
    would regress fresh coverage marks to the stalest run's list.

    Keys carry an occurrence ordinal alongside (path, name, kind):
    same-named items in one file (overloads, methods of different
    classes) are distinct review units, and a name-only key smeared one
    twin's checked_by onto the other — silently overstating coverage.

    Args:
        old: Previous inventory dict.
        new: Current inventory dict (mutated in place).
        modified: Set of file paths that changed (checked_by cleared for these).
    """
    if modified is None:
        modified = set()

    def _get_items(fi):
        return fi.get("items", fi.get("functions", [])) or []

    def _keyed_items(file_info):
        """(path, name, kind, occurrence-ordinal) per item, ordinal
        counted in file order among same-(name, kind) items — stable
        across runs for unchanged files, unlike line numbers under
        unrelated edits."""
        path = file_info.get('path')
        counts: dict[tuple, int] = {}
        for item in _get_items(file_info):
            base = (item.get('name'), item.get('kind', 'function'))
            ordinal = counts.get(base, 0)
            counts[base] = ordinal + 1
            yield (path, *base, ordinal), item

    # Build lookup: keyed item -> checked_by from old inventory
    old_coverage = {}
    for file_info in old.get('files', []):
        if file_info.get('path') in modified:
            continue  # Don't carry forward stale coverage
        for key, item in _keyed_items(file_info):
            checked_by = item.get('checked_by', [])
            if checked_by:
                old_coverage[key] = checked_by

    # Apply to new inventory
    for file_info in new.get('files', []):
        for key, item in _keyed_items(file_info):
            if key in old_coverage:
                existing = item.get('checked_by') or []
                item['checked_by'] = existing + [
                    run for run in old_coverage[key] if run not in existing
                ]


def _count_source_files(dirpath: Path, extensions: set[str], cap: int = 1000) -> int:
    """Count files under ``dirpath`` whose extension is a recognised source
    extension, bounded at ``cap`` (we only need "holds source? roughly how
    many" for an operator warning — not an exact census of a huge tree).
    """
    _skip = {"node_modules", "vendor", ".git", "__pycache__", ".tox", ".venv"}
    n = 0
    for _root, dirs, files in os.walk(dirpath):
        dirs[:] = [d for d in dirs if d not in _skip]
        for f in files:
            if Path(f).suffix.lower() in extensions:
                n += 1
                if n >= cap:
                    return n
    return n


def _collect_source_files(
    target: Path, extensions: set[str],
    exclude_patterns: list[str] | None = None,
) -> tuple[list[Path], list[dict[str, Any]]]:
    """Collect all source files in a single pass.

    Returns ``(file_list, pruned_dirs)`` where ``pruned_dirs`` lists
    directory-shaped exclusions skipped at walk time so the caller
    can record them in ``excluded_files`` for operator visibility.

    Prunes the descent at walk time on directory-shaped patterns from
    ``exclude_patterns`` (the caller's list — defaults to
    `DEFAULT_EXCLUDES`; a hardcoded module constant here meant a
    caller-supplied replacement list could never RE-include a default
    directory, while the artifact's ``excluded_patterns`` field claimed
    it applied). E.g. `node_modules/`, `vendor/`, `__pycache__/`,
    `.git/`. Pre-fix `os.walk` descended into them all, then
    `_process_single_file` later marked each enumerated file as
    excluded — but `node_modules` on a real project is hundreds of
    thousands of files. The walk-time stat() of every one of those
    files dominated inventory wallclock for any JS/TS project.
    Pruning the dir name from `dirs[:]` skips the entire subtree, so
    walk time scales with source-tree size rather than source-tree
    + dependency-tree size.
    """
    if target.is_file():
        return [target], []

    # Pre-extract directory-shaped exclusion names from DEFAULT_EXCLUDES.
    # Patterns with `/` suffix and no glob meta-chars are pure directory
    # names that prune cleanly. Patterns with `*` (e.g.
    # `cmake-build-*/`) need fnmatch — handle separately.
    if exclude_patterns is None:
        exclude_patterns = DEFAULT_EXCLUDES
    exact_dir_names = set()
    glob_dir_patterns = []
    for pat in exclude_patterns:
        if not pat.endswith('/'):
            continue
        bare = pat.rstrip('/')
        if '*' in bare or '?' in bare or '[' in bare:
            glob_dir_patterns.append(bare)
        else:
            exact_dir_names.add(bare)

    file_list: list[Path] = []
    pruned_dirs: list[dict[str, Any]] = []
    # Hidden-dir allowlist: pre-fix the blanket `d.startswith('.')`
    # check pruned EVERY dot-dir, including ones that legitimately
    # carry analysable security-relevant source. Concrete misses:
    #
    #   * `.github/workflows/` — CI definitions (YAML / JSON).
    #     Workflow injection (`pull_request_target` + untrusted
    #     event data) is one of the most common GitHub-hosted
    #     supply-chain bug classes; pruning the directory hid
    #     every workflow file from the inventory and downstream
    #     scanners couldn't find them.
    #   * `.gitlab/` / `.gitlab-ci/` — same story for GitLab CI.
    #
    # Other dot-dirs (`.git/`, `.cache/`, `.venv/`, `.tox/`,
    # `.mypy_cache/`, `.pytest_cache/`, `.ruff_cache/`, `.idea/`,
    # `.vscode/`, `.gradle/`, etc.) remain pruned — they're either
    # VCS metadata, tool caches, or editor state with no security
    # value.
    _HIDDEN_DIR_ALLOWLIST = frozenset({
        ".github",
        ".gitlab",
        ".gitlab-ci",
    })
    for root, dirs, files in os.walk(target):
        # Skip hidden directories, symlinked directories, AND any directory
        # that matches a DEFAULT_EXCLUDES dir-shaped pattern.
        kept_dirs = []
        for d in dirs:
            if d.startswith('.') and d not in _HIDDEN_DIR_ALLOWLIST:
                continue
            if (Path(root) / d).is_symlink():
                continue
            if d in exact_dir_names:
                # Root-anchored names (examples/ samples/ demo/ docs/ …) also
                # name first-party package/source segments, so pruning them by
                # basename at any depth silently drops first-party source — a
                # scanner-wide false negative. Prune them ONLY at the scan-root
                # top level; keep + analyse nested occurrences.
                if d in ROOT_ANCHORED_EXCLUDE_DIRS and Path(root) != target:
                    kept_dirs.append(d)
                    continue
                # Nested build-output names that are actually first-party
                # Python packages (direct __init__.py) are source, not
                # artifacts — keep them (mirrored in the per-file check via
                # match_exclusion_reason's target_root exemption).
                if (d in PKG_EXEMPTIBLE_BUILD_DIRS
                        and is_first_party_package_dir(Path(root) / d)):
                    kept_dirs.append(d)
                    continue
                rel = str((Path(root) / d).relative_to(target))
                # Never SILENTLY drop source: if a pruned top-level anchored dir
                # holds source files, warn with a count so the exclusion is
                # visible and the operator can scan it directly if first-party.
                if d in ROOT_ANCHORED_EXCLUDE_DIRS:
                    n = _count_source_files(Path(root) / d, extensions)
                    if n:
                        logger.warning(
                            "inventory: pruned top-level '%s/' (matches default "
                            "exclude '%s/') holding %d source file(s); scan it "
                            "directly if it is first-party code",
                            rel, d, n,
                        )
                pruned_dirs.append({
                    "path": rel + "/",
                    "reason": "excluded_directory_pruned",
                    "pattern_matched": d + "/",
                })
                continue
            matched_glob = next(
                (p for p in glob_dir_patterns if fnmatch.fnmatch(d, p)),
                None,
            )
            if matched_glob is not None:
                rel = str((Path(root) / d).relative_to(target))
                pruned_dirs.append({
                    "path": rel + "/",
                    "reason": "excluded_directory_pruned",
                    "pattern_matched": matched_glob + "/",
                })
                continue
            kept_dirs.append(d)
        dirs[:] = kept_dirs
        for filename in files:
            filepath = Path(root) / filename
            if filepath.is_symlink():
                continue  # Don't follow symlinks into files outside the repo
            ext = Path(filename).suffix.lower()
            # RECORD_ONLY_EXTENSIONS are source-like files we cannot
            # parse (parser grammars etc.) — collected so the per-file
            # pass records them in ``excluded_files`` with a reason
            # instead of leaving them silently invisible.
            if ext in extensions or ext in RECORD_ONLY_EXTENSIONS:
                file_list.append(filepath)
            elif not ext and detect_language_from_shebang(str(filepath)):
                # Extensionless interpreter scripts (launcher / dispatch
                # surfaces) carry their language in the shebang line; the
                # extension gate alone left them invisible to every
                # downstream scanner.
                file_list.append(filepath)

    return file_list, pruned_dirs


def _is_github_workflow(rel_path: str, content: str) -> bool:
    """True when a YAML file is a CI workflow with reviewable units.

    Path-based primary signal (anything under ``.github/workflows/``),
    plus a content check for jobs-shaped CI YAML found elsewhere. The
    content check must match the yaml extractor's own predicate — a
    top-level ``jobs:`` block (see ``GitHubWorkflowExtractor``) —
    exactly: requiring an additional trigger key here excluded files
    the extractor would have yielded job items for (Azure Pipelines
    style ``trigger:`` + ``jobs:``, or a YAML-roundtripped workflow
    whose unquoted ``on:`` was rewritten to ``true:``).
    """
    norm = rel_path.replace(os.sep, "/")
    if ".github/workflows/" in norm or norm.startswith(".github/workflows/"):
        return True
    from .extractors import GitHubWorkflowExtractor
    return any(GitHubWorkflowExtractor._JOBS_RE.match(line)
               for line in content.split("\n"))


_worker_ctx: dict[str, Any] = {}


def _init_inventory_worker(
    target: Path,
    exclude_patterns: list[str],
    skip_generated: bool,
    old_files: dict[str, Any],
    allow_unreachable: bool,
    macro_config,
    build_tus,
    crate_modules,
) -> None:
    # Signal hygiene first: fork-context workers inherit the parent's
    # Python-level signal handlers, and embedding drivers install
    # SIGTERM handlers whose post-mortem paths take locks that can be
    # fork-frozen in this child — SIGTERM then never kills the worker
    # (the handler blocks forever) and the pool teardown has to
    # escalate to SIGKILL. Reset to the default disposition so
    # terminate() means terminate and no parent post-mortem ever runs
    # (and prints) inside an extractor worker. Never raise: a raising
    # initializer breaks the whole pool.
    import signal as _signal
    try:
        _signal.signal(_signal.SIGTERM, _signal.SIG_DFL)
    except (ValueError, OSError):
        # ValueError: not the main thread (thread-pool fallback path
        # reuses none of this, but be safe); OSError: exotic platform.
        pass
    # The MASK is inherited separately from the disposition: a parent
    # thread that had SIGTERM blocked at fork leaves it blocked here,
    # where a pending SIGTERM then sits undelivered forever — the
    # disposition reset above looks correct but terminate() still
    # does nothing and teardown must SIGKILL. Unblock it explicitly.
    try:
        _signal.pthread_sigmask(_signal.SIG_UNBLOCK, {_signal.SIGTERM})
    except (AttributeError, ValueError, OSError):
        # pthread_sigmask absent (non-POSIX) or refused — the
        # disposition reset above still holds; never break the pool.
        pass
    # Detach the worker from the parent's stdout/stderr. Workers
    # inherit those descriptors, and when the parent's stdout is a
    # pipe (CI step streams), any worker that outlives the parent —
    # however it got there — keeps the pipe open and the pipe's
    # reader waiting; the teardown escalation makes that window
    # small, this makes the worker unable to hold it at all. Nothing
    # owned is lost: per-file failures come back as processing_error
    # records that the parent re-voices (see _on_done), and direct
    # worker writes were unowned noise interleaving into the
    # parent's stream. Never raise.
    try:
        devnull = os.open(os.devnull, os.O_WRONLY)
        try:
            os.dup2(devnull, 1)
            os.dup2(devnull, 2)
        finally:
            os.close(devnull)
    except OSError:
        pass
    _worker_ctx["target"] = target
    _worker_ctx["exclude_patterns"] = exclude_patterns
    _worker_ctx["skip_generated"] = skip_generated
    _worker_ctx["old_files"] = old_files
    _worker_ctx["allow_unreachable"] = allow_unreachable
    _worker_ctx["macro_config"] = macro_config
    _worker_ctx["build_tus"] = build_tus
    _worker_ctx["crate_modules"] = crate_modules


def _process_file_in_worker(filepath: Path) -> dict[str, Any] | None:
    return _process_single_file(
        filepath,
        _worker_ctx["target"],
        _worker_ctx["exclude_patterns"],
        _worker_ctx["skip_generated"],
        _worker_ctx["old_files"],
        _worker_ctx["allow_unreachable"],
        _worker_ctx["macro_config"],
        _worker_ctx["build_tus"],
        _worker_ctx["crate_modules"],
    )


def _process_single_file(
    filepath: Path,
    target: Path,
    exclude_patterns: list[str],
    skip_generated: bool = True,
    old_files: dict[str, Any] | None = None,
    allow_unreachable: bool = False,
    macro_config: object | None = None,
    build_tus: frozenset | None = None,
    crate_modules: frozenset | None = None,
) -> dict[str, Any] | None:
    """Process a single file for the inventory.

    If old_files contains an entry for this file with a matching SHA-256,
    the old entry is returned as-is (skipping tree-sitter parsing).

    Returns:
        File info dict, exclusion record (with _excluded flag), or None if skipped.
    """
    rel_path = str(filepath.relative_to(target) if target.is_dir() else filepath.name)

    # Check exclusions against relative path (not absolute — avoids false
    # positives when parent directories match patterns like "tests/").
    # target_root arms the first-party package exemption for nested
    # build-output dir names, matching the walk-time prune.
    excluded, reason, pattern = match_exclusion_reason(
        rel_path, exclude_patterns,
        target_root=target if target.is_dir() else None,
    )
    if excluded:
        return {"path": rel_path, "_excluded": True, "_reason": reason, "_pattern": pattern}

    # Detect language
    language = detect_language(str(filepath))
    if not language and not filepath.suffix:
        language = detect_language_from_shebang(str(filepath))
    if not language:
        # Source-like files we still don't parse (parser grammars,
        # inline-include fragments, Solidity) were previously dropped
        # with only a counter — invisible in the artifact. Record them
        # as exclusions so the recall loss is operator-visible; plain
        # non-source files (docs, data) stay silent.
        if filepath.suffix.lower() in RECORD_ONLY_EXTENSIONS:
            return {"path": rel_path, "_excluded": True,
                    "_reason": "unsupported_source_extension",
                    "_pattern": filepath.suffix.lower()}
        return None

    # Skip binary files — recorded, not silent: a source-extension file
    # with binary content is a skip the operator should see.
    if is_binary_file(filepath):
        return {"path": rel_path, "_excluded": True,
                "_reason": "binary_content", "_pattern": None}

    try:
        try:
            st = filepath.stat()
            file_stat = [st.st_mtime_ns, st.st_size]
        except OSError:
            file_stat = None

        # Fast path: if stat (mtime_ns + size) matches old entry, reuse
        # without reading the file at all — skips I/O, hash, and parsing.
        if old_files and rel_path in old_files:
            old_entry = old_files[rel_path]
            old_stat = old_entry.get('_stat')
            if file_stat and old_stat and file_stat == old_stat:
                return old_entry

        # Bounded read. `read_bytes()` loads the whole file into
        # memory before any size check — a 10 GB binary, malformed
        # symlink-to-/dev/zero, or hostile sample in a vendored
        # archive OOM-killed the inventory builder. stat-then-bound
        # caps the in-flight memory at MAX_FILE_BYTES + 1 regardless
        # of file size.
        try:
            file_size = filepath.stat().st_size
        except OSError:
            return {"path": rel_path, "_excluded": True,
                    "_reason": "stat_failed", "_pattern": None}
        if file_size > MAX_FILE_BYTES:
            return {"path": rel_path, "_excluded": True,
                    "_reason": "too_large",
                    "_pattern": f"size>{MAX_FILE_BYTES}"}
        # `O_NOFOLLOW` so a symlink that wasn't caught by the
        # walk-time `is_symlink()` filter (race: file became a
        # symlink between walk and read) doesn't transit us into
        # an unrelated tree. The walk-time check was already
        # there as a fast path; this is the authoritative guard
        # at the read site itself. ELOOP from a symlink → caught
        # under OSError below and the file is recorded excluded.
        try:
            fd = os.open(str(filepath), os.O_RDONLY | os.O_NOFOLLOW)
        except OSError:
            return {"path": rel_path, "_excluded": True,
                    "_reason": "open_failed_or_symlink",
                    "_pattern": None}
        with os.fdopen(fd, "rb") as fh:
            raw_bytes = fh.read(MAX_FILE_BYTES + 1)
        if len(raw_bytes) > MAX_FILE_BYTES:
            # File grew between stat and read — still reject.
            return {"path": rel_path, "_excluded": True,
                    "_reason": "too_large_during_read",
                    "_pattern": f"size>{MAX_FILE_BYTES}"}
        content = raw_bytes.decode('utf-8', errors='ignore')

        _uncorroborated_generated = False
        if skip_generated and is_generated_file(content):
            if generated_marker_corroborated(rel_path):
                return {"path": rel_path, "_excluded": True,
                        "_reason": "generated_file", "_pattern": None}
            # The in-file marker is target-controlled text; honouring
            # it alone let one comment line self-exclude a file from
            # every analysis tier (evasion channel). Without path
            # corroboration the file STAYS in the inventory and the
            # claim rides along as a visible flag consumers may use
            # to deprioritise — never to skip silently.
            _uncorroborated_generated = True
            logger.info(
                "inventory: %s carries a generated-file marker but no "
                "generated-shaped path/name — keeping it in the "
                "inventory (marker alone does not exclude)", rel_path,
            )

        # Content-based routing: .h headers with C++ markers parse as
        # C++ (class methods / templates otherwise silently drop);
        # .inc fragments route to php / asm / c by content.
        language = refine_language(language, str(filepath), content)

        # YAML is in the inventory for GitHub workflow files (jobs /
        # steps are the reviewable units — workflow injection surface).
        # Other YAML has no extractable units; record it as excluded
        # rather than dropping it silently.
        if language == "yaml" and not _is_github_workflow(rel_path, content):
            return {"path": rel_path, "_excluded": True,
                    "_reason": "yaml_without_reviewable_units",
                    "_pattern": None}

        line_count = content.count('\n') + 1
        sha256 = sha256_bytes(raw_bytes)

        # Fall back to SHA-256 comparison when stat changed but content didn't
        if old_files and rel_path in old_files:
            old_entry = old_files[rel_path]
            if old_entry.get('sha256') == sha256:
                old_entry['_stat'] = file_stat
                return old_entry

        # The parser reads a TranslationView (its parse_text), not raw
        # content, so future preprocessing fidelity (e.g. C/C++ #if 0
        # blanking, real cpp) slots in behind this seam without rewiring
        # consumers. Identity view today ⇒ byte-identical behavior.
        # Metrics (sloc, line_count, sha256) and text scanners
        # (detect_dead_scopes / detect_module_load_abort) keep using the
        # real `content`; only the tree-sitter / AST parse uses parse_text.
        view = preprocess_view(
            str(filepath), language, content,
            allow_unreachable=allow_unreachable,
            config=macro_config,
        )
        parse_text = view.parse_text
        tree_cache: dict[str, Any] = {}
        items = extract_items(str(filepath), language, parse_text, _tree_cache=tree_cache)
        # Safety net: every SLOC-bearing line outside an extracted item becomes
        # an interstitial item, so non-function code (top-level statements,
        # missed globals) is never invisible to coverage (coverage Decision #2).
        items = items + compute_interstitial_items(items, parse_text)
        sloc = count_sloc(content, language, _tree=tree_cache.get("tree"))

        record: dict[str, Any] = {
            'path': rel_path,
            'language': language,
            'lines': line_count,
            'sloc': sloc,
            'sha256': sha256,
            '_stat': file_stat,
            'items': [item.to_dict() for item in items],
        }
        if _uncorroborated_generated:
            record['generated_marker'] = 'uncorroborated'
        # Per-item span hashes (core.staleness format: SHA-256[:12] of
        # the raw span lines). The function-level inventory diff
        # compares these across runs to find added/changed functions
        # without needing the previous run's source. Interstitial
        # residue is skipped (synthetic, not a reviewable unit).
        # Best-effort — a hash failure just leaves the field absent.
        try:
            from core.staleness import hash_spans_text
            span_items = []
            spans = []
            for item_dict in record['items']:
                ls = item_dict.get('line_start')
                le = item_dict.get('line_end')
                if (isinstance(ls, int) and not isinstance(ls, bool)
                        and isinstance(le, int) and not isinstance(le, bool)
                        and 0 < ls <= le
                        and item_dict.get('kind') != 'interstitial'):
                    span_items.append(item_dict)
                    spans.append((ls, le))
            if spans:
                for item_dict, h in zip(span_items,
                                        hash_spans_text(content, spans)):
                    if h:
                        item_dict['span_hash'] = h
        except Exception:
            logger.debug("span-hash stamping failed for %s", rel_path,
                         exc_info=True)
        # S3: per-function lexical-dead tagging. Functions whose
        # definition lies inside an always-false guard (``if False:``,
        # ``if (false) {…}``, ``#[cfg(any())]``) never bind — the
        # guard's body never runs / compiles. The reachability prepass
        # demotes such functions regardless of in-scope call edges
        # (two dead-scope functions calling each other otherwise read
        # as mutually CALLED). Tagged here (not in each extractor) so
        # detection lives in one place per language; field is set only
        # when dead so inventory size stays flat.
        dead_ranges = detect_dead_scopes(language, content)
        if dead_ranges:
            for item_dict in record['items']:
                ls = item_dict.get('line_start') or 0
                if ls and any(lo <= ls <= hi for lo, hi in dead_ranges):
                    item_dict['lexical_dead'] = True
        # Call-graph extraction. The resolver in
        # core.analysis.reachability is language-agnostic; per-file
        # extractors emit the same FileCallGraph dataclass for
        # whichever languages have a walker.
        if language == 'python':
            record['call_graph'] = extract_call_graph_python(parse_text).to_dict()
            # Module-level ``__all__`` is the explicit export contract.
            # Stored on the file record as a sorted list (so the JSON
            # snapshot is stable) — absent when the module doesn't
            # declare it. ``entry_reachability`` reads this to
            # distinguish "module author marked internal" from "no
            # contract declared, fall back to PEP 8 underscore
            # convention as a softer hint."
            exports = _extract_python_dunder_all(parse_text)
            if exports is not None:
                record['exports'] = sorted(set(exports))
        elif language in ('javascript', 'typescript', 'tsx'):
            # Tree-sitter-driven; gracefully empty when the grammar
            # isn't installed. TS/TSX use the typescript grammar so typed
            # source (annotations, decorators, interfaces) parses.
            record['call_graph'] = extract_call_graph_javascript(
                parse_text, language=language,
            ).to_dict()
        elif language == 'go':
            record['call_graph'] = extract_call_graph_go(
                parse_text,
            ).to_dict()
        elif language == 'java':
            record['call_graph'] = extract_call_graph_java(
                parse_text,
            ).to_dict()
        elif language == 'rust':
            record['call_graph'] = extract_call_graph_rust(
                parse_text,
            ).to_dict()
        elif language == 'ruby':
            record['call_graph'] = extract_call_graph_ruby(
                parse_text,
            ).to_dict()
        elif language in ('csharp', 'c_sharp'):
            record['call_graph'] = extract_call_graph_csharp(
                parse_text,
            ).to_dict()
        elif language == 'php':
            record['call_graph'] = extract_call_graph_php(
                parse_text,
            ).to_dict()
        elif language == 'lua':
            record['call_graph'] = extract_call_graph_lua(
                parse_text,
            ).to_dict()
        elif language == 'scala':
            record['call_graph'] = extract_call_graph_scala(
                parse_text,
            ).to_dict()
        elif language == 'kotlin':
            record['call_graph'] = extract_call_graph_kotlin(
                parse_text,
            ).to_dict()
        elif language == 'swift':
            record['call_graph'] = extract_call_graph_swift(
                parse_text,
            ).to_dict()
        elif language == 'c':
            # S5: wire the existing extract_call_graph_c into the
            # dispatch. The walker has been present (and tested in
            # core/inventory/tests) for a while but was orphaned —
            # C files were getting empty call_graph records, so
            # function_called returned no useful data for any C
            # finding and the analysis prompt's Reachability: block
            # was absent for every C scan. Closes RAPTOR's largest
            # whole-language reachability blind spot.
            record['call_graph'] = extract_call_graph_c(
                parse_text,
            ).to_dict()
        elif language == 'cpp':
            # S5: same wiring story for C++. _CppCallGraph inherits
            # from _CCallGraph; adds class/namespace/qualified-id
            # handling. Covers .cpp / .cc / .cxx / .hpp (per the
            # languages.py extension map).
            record['call_graph'] = extract_call_graph_cpp(
                parse_text,
            ).to_dict()
        # U4 (macro-masking): record the function names invoked inside
        # function-like macro bodies. tree-sitter sees a macro call as a
        # call to the macro, not its expansion, so a function reachable
        # only via a macro reads NOT_CALLED. The resolver consults this to
        # downgrade such verdicts to UNCERTAIN (FN-safe). C/C++ only;
        # scanned from parse_text so macros inside blanked #if 0 don't
        # count. Stored only when non-empty to keep inventory size flat.
        if language in ('c', 'cpp') and isinstance(record.get('call_graph'), dict):
            macro_targets = detect_macro_call_targets(parse_text)
            if macro_targets:
                record['call_graph']['macro_call_targets'] = sorted(macro_targets)
        # S4: file-level module-load-abort gate. When the file's
        # top-level execution unconditionally aborts (raise
        # ImportError / throw new Error / init() panic /
        # compile_error!), no function it defines is reachable
        # through import / link regardless of in-file call edges.
        # The reachability resolver treats this as a whole-file
        # NOT_REACHED gate. Stored only when detected so the field
        # is absent (not False) on the overwhelming majority of
        # files — keeps inventory size flat.
        abort = detect_module_load_abort(language, content)
        if abort is not None:
            record['module_aborts_on_load'] = {
                'line': abort.line,
                'summary': abort.summary,
            }
        # Whole-file build exclusion (e.g. Go `//go:build ignore`): the file
        # is never compiled, so every function in it is dead regardless of
        # call edges or external linkage. Heuristic (config-dependent) — a
        # surface-only gate, never hard-suppress.
        excluded = detect_build_excluded(language, content)
        if excluded is not None:
            record['build_excluded'] = {
                'line': excluded.line,
                'summary': excluded.summary,
            }
        # C/C++ build-membership: a source TU absent from compile_commands.json
        # is not compiled → dead. Whole-file, heuristic. Only when a
        # content-based detector above didn't already fire. Headers are exempt
        # (tu_membership_excluded checks the extension). Path resolved to match
        # the resolved TU-set entries.
        if 'build_excluded' not in record and build_tus is not None:
            tu_excluded = tu_membership_excluded(
                str(filepath.resolve()), build_tus,
            )
            if tu_excluded is not None:
                record['build_excluded'] = {
                    'line': tu_excluded.line,
                    'summary': tu_excluded.summary,
                }
        # Rust crate-module membership: a .rs not reachable via the mod tree
        # from any crate root is not compiled → dead. Whole-file, heuristic.
        if 'build_excluded' not in record and crate_modules is not None:
            rs_excluded = crate_module_excluded(
                str(filepath.resolve()), crate_modules,
            )
            if rs_excluded is not None:
                record['build_excluded'] = {
                    'line': rs_excluded.line,
                    'summary': rs_excluded.summary,
                }
        return record

    except Exception as exc:
        logger.warning("Failed to process %s", filepath, exc_info=True)
        # Recorded, not silent: the file stays visible in the artifact
        # with a reason instead of vanishing behind a counter.
        return {"path": rel_path, "_excluded": True,
                "_reason": "processing_error",
                "_pattern": exc.__class__.__name__}

"""Ghidra REDatabase context injection for LLM analysis prompts.

Two-phase pattern (mirrors source_intel_inject.py):

1. :func:`prepare_ghidra_context` — called once per run to load
   REDatabases from the project's ghidra_projects list.  Prefers
   cached ``re-database.json`` from a prior ``/ghidra import``; the
   live PyGhidra import fallback applies to EXPLICITLY passed lists
   only — auto-resolved attachments are cache-only (the sandboxed
   import happens at attach time, never unprompted at run start).

2. :func:`ghidra_blocks_for_finding` — called per-finding to produce
   :class:`UntrustedBlock` entries with decompilation, type info, and
   cross-references for the finding's function.

Caching: process-global dict keyed by absolute resolved repo path.
One entry per target — multiple findings in one repo share the
loaded REDatabases.
"""

from __future__ import annotations

import logging
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from core.json.utils import RE_DATABASE_MAX_BYTES
from core.security.prompt_envelope import UntrustedBlock

from .model import REDatabase, REFunction

logger = logging.getLogger(__name__)

#: Prompt-budget clipping for injected blocks — mirrors the sibling
#: injectors' discipline (flow-context clips fields, source-intel
#: caps lines). Attacker-authored .gpr content must not be able to
#: inflate every finding's prompt.
_MAX_DECOMP_LINES = 200
_MAX_DECOMP_CHARS = 16 * 1024
_MAX_COMMENT_CHARS = 300
#: Every other cache-derived text field is clipped too — the decomp
#: cap alone left signature/name/binary_path/type-field inflation
#: routes that reached the prompt (or forced all-or-nothing block
#: shedding) unbounded.
_MAX_SIG_CHARS = 512
_MAX_NAME_CHARS = 200
_MAX_TYPE_FIELDS = 20
#: Callers/callees COLLECTION cap (display shows 15) — collection
#: itself must stay bounded on xref floods.
_MAX_XREF_SCAN = 64
#: Cache-file read ceiling — the shared RE-database bound (bound to
#: the imported name, never a value copy: writers and every reader
#: must agree or the importer writes artifacts its own consumers
#: reject; the trade-off rationale lives at the constant's
#: definition in core.json.utils).
_MAX_CACHE_BYTES = RE_DATABASE_MAX_BYTES

_GHIDRA_CACHE: Dict[str, List[REDatabase]] = {}
_GHIDRA_FUNC_INDEX: Dict[str, Dict[str, List[REFunction]]] = {}
_GHIDRA_LOCK = threading.RLock()


def _load_cached_redb(gpr_path: Path) -> Optional[REDatabase]:
    """Try to load re-database.json from a prior /ghidra import or attach."""
    from .roundtrip import redb_cache_candidates

    for candidate in redb_cache_candidates(gpr_path):
        if candidate.is_file():
            try:
                from core.json import load_json
                # Bounded: the cache is RAPTOR-written but its SIZE
                # is attacker-influenced (decompilation volume of a
                # hostile binary) and the auto path reads it at every
                # run start.
                data = load_json(candidate, max_bytes=_MAX_CACHE_BYTES)
                if data is None:
                    continue
                db = REDatabase.from_dict(data)
                logger.debug(
                    "loaded cached REDatabase from %s (%d functions)",
                    candidate, len(db.functions),
                )
                return db
            except Exception as e:  # noqa: BLE001
                logger.debug("failed to load %s: %s", candidate, e)
    return None


def _live_import(gpr_path: Path) -> Optional[REDatabase]:
    """Import a .gpr via PyGhidra (starts JVM if needed)."""
    try:
        from .bridge import GhidraBridge
    except ImportError:
        logger.debug("packages.ghidra.bridge not importable; skipping")
        return None
    import tempfile
    try:
        with tempfile.TemporaryDirectory(prefix="raptor-ghidra-ctx-") as td:
            with GhidraBridge(gpr_path) as bridge:
                db = bridge.import_project(Path(td))
            logger.info(
                "live-imported Ghidra project %s (%d functions)",
                gpr_path.name, len(db.functions),
            )
            return db
    except Exception as e:  # noqa: BLE001
        logger.warning(
            "live import of %s failed: %s; skipping", gpr_path.name, e,
        )
        return None


def _build_func_index(
    databases: List[REDatabase],
) -> Dict[str, List[REFunction]]:
    """Build a name→function lookup index across all databases."""
    index: Dict[str, List[REFunction]] = {}
    for db in databases:
        for func in db.functions:
            if func.is_auto_named or func.is_thunk or func.is_external:
                continue
            index.setdefault(func.name, []).append(func)
    return index


def _resolve_ghidra_projects(repo_path: Path) -> List[str]:
    """Auto-resolve the project-persisted .gpr list for *repo_path*.

    Reads the active project's ``ghidra_projects`` attachments —
    operator-registered .gpr paths, never harvested from the scanned
    repo. Failures resolve to an empty list: context injection is an
    enrichment, not a dependency.
    """
    del repo_path
    try:
        from .attach import get_attached_projects
        return get_attached_projects()
    except Exception:  # noqa: BLE001 — projects substrate unavailable
        logger.debug("ghidra project resolution failed", exc_info=True)
        return []

def prepare_ghidra_context(
    repo_path: Path,
    ghidra_projects: Optional[List[str]] = None,
    refresh: bool = False,
) -> None:
    """Pre-seed the Ghidra REDatabase cache for a run.

    When *ghidra_projects* is None, auto-resolves from the active
    project's ``ghidra_projects`` attachments and loads CACHED
    databases only — the auto path runs on every analysis start with
    no operator action, and a live import there would parse the
    attacker-controlled project unprompted (worse, in-process when
    analyzeHeadless is absent). ``raptor-ghidra attach`` is where the
    sandboxed import happens. Explicitly-passed lists keep the
    cache-or-live behaviour: the caller chose those projects NOW.

    Best-effort: individual project failures are logged and skipped.
    """
    # Callers pass both Path and str (the orchestrator holds
    # repo_path as str) — a str here reached `repo_path.resolve()`
    # below as AttributeError, which the callers' blanket except
    # swallowed into silently-disabled injection.
    repo_path = Path(repo_path)
    auto_resolved = ghidra_projects is None
    if auto_resolved:
        ghidra_projects = _resolve_ghidra_projects(repo_path)
    if refresh:
        # Long-lived interpreters (multi-model orchestration, API
        # consumers) otherwise carry a stale — possibly empty — cache
        # entry across logical runs: an attachment added between runs
        # would stay invisible until process restart.
        try:
            key = str(Path(repo_path).resolve())
            with _GHIDRA_LOCK:
                _GHIDRA_CACHE.pop(key, None)
                _GHIDRA_FUNC_INDEX.pop(key, None)
        except (OSError, ValueError):
            pass
    if not ghidra_projects:
        return

    try:
        key = str(repo_path.resolve())
    except (OSError, ValueError):
        logger.debug(
            "prepare_ghidra_context: unresolvable repo_path %s; skipping",
            repo_path,
        )
        return

    with _GHIDRA_LOCK:
        if key in _GHIDRA_CACHE:
            return

    databases: List[REDatabase] = []
    for gpr_str in ghidra_projects:
        gpr_path = Path(gpr_str)
        if not gpr_path.exists():
            logger.warning("ghidra project not found: %s", gpr_path)
            continue

        db = _load_cached_redb(gpr_path)
        if db is None and not auto_resolved:
            db = _live_import(gpr_path)
        elif db is None:
            logger.info(
                "attached ghidra project %s has no cached database — "
                "run 'raptor-ghidra attach' to import it; skipping "
                "for this run", gpr_path,
            )
        if db is not None:
            databases.append(db)

    if not databases:
        logger.info(
            "prepare_ghidra_context: no databases loaded from %d projects",
            len(ghidra_projects),
        )
        with _GHIDRA_LOCK:
            _GHIDRA_CACHE[key] = []
            _GHIDRA_FUNC_INDEX[key] = {}
        return

    func_index = _build_func_index(databases)
    total_funcs = sum(len(db.functions) for db in databases)
    named_funcs = sum(
        1 for db in databases
        for f in db.functions
        if not f.is_auto_named
    )

    with _GHIDRA_LOCK:
        _GHIDRA_CACHE[key] = databases
        _GHIDRA_FUNC_INDEX[key] = func_index

    logger.info(
        "prepare_ghidra_context: %d database(s), %d functions "
        "(%d named, %d indexed)",
        len(databases), total_funcs, named_funcs, len(func_index),
    )


def ghidra_blocks_for_finding(
    finding: Dict[str, Any],
) -> Tuple[UntrustedBlock, ...]:
    """Build Ghidra context UntrustedBlocks for one finding.

    Returns () when any of:
    - no repo_path on the finding
    - cache miss (prepare_ghidra_context wasn't called)
    - no function match in the REDatabase
    - matched function has no useful context to inject

    Otherwise returns a 1-tuple with decompilation, types, and xrefs.
    """
    repo_raw = finding.get("repo_path")
    # Wrong-typed finding fields must degrade to (), not raise into
    # the callers' blanket excepts (which read as silently-disabled
    # injection): findings arrive from operator-supplied SARIF too.
    if not repo_raw or not isinstance(repo_raw, (str, Path)):
        return ()
    try:
        key = str(Path(repo_raw).resolve())
    except (OSError, ValueError):
        return ()

    with _GHIDRA_LOCK:
        func_index = _GHIDRA_FUNC_INDEX.get(key)
        databases = _GHIDRA_CACHE.get(key)

    if not func_index or not databases:
        return ()

    metadata = finding.get("metadata")
    if not isinstance(metadata, dict):
        metadata = {}
    function_name = (
        metadata.get("name")
        or finding.get("function")
        or finding.get("function_name")
        or ""
    )
    if not isinstance(function_name, str) or not function_name:
        return ()

    matches = func_index.get(function_name)
    if not matches:
        return ()

    matched = matches[0]
    owning_db = _find_owning_db(databases, matched)

    parts = _render_function_context(matched, owning_db)
    if not parts:
        return ()

    # Identify WHICH binary this context came from in the body, not
    # just the envelope origin: with two attached versions defining
    # the same function, a reviewer reading v1's decompilation for a
    # v2 finding is misdirected analysis. Multiple matches get an
    # explicit ambiguity note rather than a silent first-pick.
    header = "## Ghidra context source\n\nbinary: %s" % (
        str(owning_db.binary_path or "unknown")[:_MAX_NAME_CHARS]
    )
    if len(matches) > 1:
        # Split on DATABASE IDENTITY, not binary_path equality — two
        # attachments can import the same binary (snapshots of one
        # target), and calling their duplicates "this same database"
        # is literally false while a binary_path-set difference would
        # do exactly that.
        own_bin = owning_db.binary_path or "unknown"
        other_dbs = []
        seen_ids = {id(owning_db)}
        for m in matches[1:]:
            db_m = _find_owning_db(databases, m)
            # Dedup by IDENTITY: dataclass value-equality would
            # collapse two identical snapshot attachments into one
            # (and deep-compare whole databases per finding).
            if id(db_m) not in seen_ids:
                seen_ids.add(id(db_m))
                other_dbs.append(db_m)
        n_other = len(matches) - 1
        if other_dbs:
            labels = []
            for db_m in other_dbs[:3]:
                b = db_m.binary_path or "unknown"
                # "(same binary)" only when both paths are KNOWN and
                # equal — unknown == unknown proves nothing.
                same = (bool(db_m.binary_path)
                        and bool(owning_db.binary_path)
                        and b == own_bin)
                labels.append(str(b)[:_MAX_NAME_CHARS]
                              + (" (same binary)" if same else ""))
            if len(other_dbs) > 3:
                labels.append("…")
            header += (
                "\n\nNOTE: %s has %d other definition(s), including "
                "in %d other attached database(s) (%s) — this "
                "context shows only the database named above; "
                "verify it matches the finding's target."
                % (function_name, n_other, len(other_dbs),
                   ", ".join(labels))
            )
        else:
            # All duplicates live in THIS database (e.g. two static
            # functions from different CUs) — naming the same binary
            # as "another database" would contradict the header line.
            header += (
                "\n\nNOTE: %s has %d other definition(s) in this "
                "same database — this context shows only the first "
                "match; verify the address matches the finding's "
                "target." % (function_name, n_other)
            )
    parts.insert(0, header)

    content = "\n\n".join(parts)
    origin = "ghidra:%s:%s" % (
        str(owning_db.binary_path or "unknown")[:_MAX_NAME_CHARS],
        str(matched.name)[:_MAX_NAME_CHARS],
    )

    logger.debug(
        "ghidra context injected for finding function=%s "
        "(%d context sections)",
        function_name, len(parts),
    )

    return (
        UntrustedBlock(
            content=content,
            kind="ghidra-context",
            origin=origin,
        ),
    )


def _find_owning_db(
    databases: List[REDatabase], func: REFunction,
) -> REDatabase:
    """Find which database owns a function (by identity)."""
    for db in databases:
        _starts, _ordered, _by_addr, ids = db._addr_index()
        if id(func) in ids:
            return db
    return databases[0]


def _render_function_context(
    func: REFunction,
    db: REDatabase,
) -> List[str]:
    """Render all available context for a function."""
    parts: List[str] = []

    if func.decompilation:
        decomp = func.decompilation
        # Clip like the sibling injectors (flow-context 160-char
        # fields, source-intel 12 lines): one giant function must not
        # blow the whole finding's prompt budget, and shed_blocks is
        # all-or-nothing far too late.
        lines = decomp.splitlines()
        if len(lines) > _MAX_DECOMP_LINES:
            decomp = "\n".join(lines[:_MAX_DECOMP_LINES]) + (
                "\n/* ... truncated: %d more lines ... */"
                % (len(lines) - _MAX_DECOMP_LINES)
            )
        # The char cap applies UNCONDITIONALLY after the line clip:
        # an elif here let 200 retained lines of unbounded length
        # bypass the byte budget entirely (200 x 1MB lines = 200MB
        # rendered — the exact inflation the caps exist to prevent).
        if len(decomp) > _MAX_DECOMP_CHARS:
            decomp = decomp[:_MAX_DECOMP_CHARS] + (
                "\n/* ... truncated ... */"
            )
        parts.append(
            "## Ghidra Decompilation: %s\n\n```c\n%s\n```"
            % (str(func.name)[:_MAX_NAME_CHARS], decomp)
        )

    if func.signature:
        parts.append("## Function Signature\n\n`%s`"
                     % str(func.signature)[:_MAX_SIG_CHARS])

    callers: List = []
    callees: List = []
    for x in db.xrefs:
        if x.kind != "call":
            continue
        if x.to_addr == func.address and len(callers) < _MAX_XREF_SCAN:
            callers.append(x)
        if len(callees) < _MAX_XREF_SCAN:
            owner = db.function_containing_address(x.from_addr)
            if owner is not None and owner.address == func.address:
                callees.append(x)
        if (len(callers) >= _MAX_XREF_SCAN
                and len(callees) >= _MAX_XREF_SCAN):
            break

    if callers or callees:
        xref_lines = []
        if callers:
            caller_names = [
                _resolve_name(db, x.from_addr) for x in callers[:15]
            ]
            xref_lines.append("Called by: " + ", ".join(caller_names))
        if callees:
            callee_names = [
                _resolve_name(db, x.to_addr) for x in callees[:15]
            ]
            xref_lines.append("Calls: " + ", ".join(callee_names))
        parts.append("## Cross-References\n\n" + "\n".join(xref_lines))

    related_types = _find_related_types(func, db)
    if related_types:
        type_lines = []
        for t in related_types[:5]:
            header = "%s %s" % (str(t.kind)[:_MAX_NAME_CHARS],
                                str(t.name)[:_MAX_NAME_CHARS])
            if isinstance(t.size, int):
                header += " (size: %d)" % t.size
            if t.fields:
                field_strs = []
                for fld in t.fields[:_MAX_TYPE_FIELDS]:
                    offset = fld.get("offset")
                    fname = str(fld.get("name", "?"))[:_MAX_NAME_CHARS]
                    ftype = str(fld.get("type", "?"))[:_MAX_NAME_CHARS]
                    fsize = fld.get("size")
                    if isinstance(offset, int):
                        s = "  offset 0x%x: %s %s" % (offset, ftype, fname)
                    else:
                        s = "  %s %s" % (ftype, fname)
                    if isinstance(fsize, int) and fsize:
                        s += " (%d bytes)" % fsize
                    field_strs.append(s)
                if len(t.fields) > _MAX_TYPE_FIELDS:
                    field_strs.append(
                        "  ... %d more field(s) ..."
                        % (len(t.fields) - _MAX_TYPE_FIELDS))
                header += "\n" + "\n".join(field_strs)
            type_lines.append(header)
        parts.append(
            "## Related Types\n\n```\n" + "\n\n".join(type_lines) + "\n```"
        )

    comments = [
        c for c in db.comments
        if c.function == func.name
    ]
    if comments:
        comment_lines = [
            "[%s] %s" % (c.kind, c.text[:_MAX_COMMENT_CHARS])
            for c in comments[:10]
        ]
        parts.append(
            "## Ghidra project comments (untrusted)\n\n" + "\n".join(comment_lines)
        )

    return parts


def _resolve_name(db: REDatabase, addr: int) -> str:
    """Resolve an instruction address to its containing function's name."""
    func = db.function_containing_address(addr)
    if func is not None:
        # Clipped: hostile symbol names are a no-plant inflation
        # vector (they arrive via the binary itself).
        return str(func.name)[:_MAX_NAME_CHARS]
    if not isinstance(addr, int) or isinstance(addr, bool):
        return "sub_?"
    return "sub_%x" % addr


def _find_related_types(func: REFunction, db: REDatabase) -> list:
    """Find types referenced in a function's signature or decompilation."""
    if not db.types:
        return []
    text = (func.signature or "") + " " + (func.decompilation or "")
    words = set(text.replace("*", " ").replace("(", " ").replace(")", " ")
                .replace(",", " ").replace(";", " ").split())
    return [t for t in db.types if t.name in words]


def lookup_function_context(
    repo_path: str | Path,
    function_name: str,
) -> Tuple[Optional[REFunction], Optional[REDatabase]]:
    """Look up a function's REFunction and owning REDatabase from cache.

    Returns (None, None) on cache miss, no match, or any error.
    Callers use this for mechanical enrichment (struct types, xrefs)
    without reaching into private cache internals.
    """
    try:
        key = str(Path(repo_path).resolve())
    except (OSError, ValueError):
        return None, None

    with _GHIDRA_LOCK:
        func_index = _GHIDRA_FUNC_INDEX.get(key)
        databases = _GHIDRA_CACHE.get(key)

    if not func_index or not databases:
        return None, None

    if not isinstance(function_name, str) or not function_name:
        return None, None

    matches = func_index.get(function_name)
    if not matches:
        return None, None

    matched = matches[0]
    owning_db = _find_owning_db(databases, matched)
    return matched, owning_db


def clear_ghidra_cache() -> None:
    """Drop every cached REDatabase."""
    with _GHIDRA_LOCK:
        _GHIDRA_CACHE.clear()
        _GHIDRA_FUNC_INDEX.clear()

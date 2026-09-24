"""Binary context assembler — the ``binary:`` branch of assemble_context.

Builds context dicts for binary functions from an
:class:`~packages.ghidra.model.REDatabase` (Ghidra, r2, or objdump
provenance). Returns the same dict shape :func:`assemble_context`
produces so downstream consumers (prompt formatting, strategy
selection, the review loop, the sweep) work unchanged.

Key differences: ``source`` holds decompiled C or a stub (never
source lines), ``representation`` says which, ``is_binary`` is True,
and everything derived (names, comments, decompilation) is
attacker-controlled — consumers must envelope it exactly like source
from a scanned repo.
"""

from __future__ import annotations

import logging
import threading
from pathlib import Path
from typing import Any

from core.inventory.binary_builder import BINARY_PATH_PREFIX

from .run_memo import BoundedMemo

logger = logging.getLogger(__name__)

#: Cached (path, mtime) → REDatabase so a gap loop over hundreds of
#: functions parses the JSON once. Bounded + thread-safe with
#: per-key in-flight collapse — concurrent review workers raced the
#: previous bare dict's check-then-set into duplicate parses.
_REDB_MEMO: "BoundedMemo[Any]" = BoundedMemo(32)

#: One sandboxed GhidraServer per analysed binary, booted lazily the
#: first time a checklist function has no cached decompilation and
#: reused for the rest of the run (JVM boot ~4s once vs per call).
#: The per-key boot lock keeps concurrent workers from double-booting
#: the ~4s JVM (the loser leaked until atexit); the cache lock guards
#: dict operations only.
_SERVER_CACHE: dict[str, Any] = {}
_SERVER_CACHE_LOCK = threading.Lock()
_SERVER_BOOT_LOCKS: dict[str, threading.Lock] = {}


def _lazy_decompile(
    binary_path: str, function_name: str, address,
    out_dir: Path | None = None,
) -> str | None:
    """On-demand decompilation through the persistent sandboxed
    server. Availability-gated (pyghidra + a real project source);
    any failure degrades to None and the stub text stands."""
    try:
        from packages.ghidra.detect import pyghidra_available
        if not pyghidra_available():
            return None
        from packages.ghidra.server import GhidraServer
    except ImportError:
        return None
    key = str(Path(binary_path).resolve())
    with _SERVER_CACHE_LOCK:
        srv = _SERVER_CACHE.get(key)
        boot_lock = _SERVER_BOOT_LOCKS.setdefault(key, threading.Lock())
    if srv is None:
        with boot_lock:
            with _SERVER_CACHE_LOCK:
                srv = _SERVER_CACHE.get(key)
            if srv is None:
                try:
                    gpr = _project_for_binary(Path(binary_path), out_dir)
                    if gpr is None:
                        with _SERVER_CACHE_LOCK:
                            _SERVER_CACHE[key] = False
                        return None
                    srv = GhidraServer(gpr)
                    srv.start()
                    import atexit
                    atexit.register(srv.stop)
                    srv.open()  # raw-open: not a filesystem open — Ghidra bridge server session
                    with _SERVER_CACHE_LOCK:
                        _SERVER_CACHE[key] = srv
                except Exception:  # noqa: BLE001 — boot failure poisons the cache
                    logger.debug(
                        "lazy decompile server boot failed for %s",
                        binary_path, exc_info=True,
                    )
                    with _SERVER_CACHE_LOCK:
                        _SERVER_CACHE[key] = False
                    return None
    if srv is False:
        return None  # previous BOOT failed — don't retry every call
    target = address if address is not None else function_name
    try:
        return srv.decompile(target)
    except Exception as e:  # noqa: BLE001 — a per-function miss (unrecovered
        # name, decompile timeout) must NOT poison the healthy server
        # for every later function.
        logger.debug(
            "lazy decompile failed for %s", function_name, exc_info=True,
        )
        # A dead worker (watchdog self-kill on a wedged JVM call,
        # crash) takes every LATER function with it unless replaced.
        # One restart attempt; the poisoned function is not retried.
        try:
            from packages.ghidra.server import GhidraServerDied
        except ImportError:
            return None
        if isinstance(e, GhidraServerDied):
            try:
                srv.restart()
                logger.info(
                    "lazy decompile server restarted after worker "
                    "death on %s", function_name,
                )
            except Exception:  # noqa: BLE001 — restart failure poisons
                logger.debug(
                    "lazy decompile server restart failed",
                    exc_info=True,
                )
                with _SERVER_CACHE_LOCK:
                    _SERVER_CACHE[key] = False
        return None


def _project_for_binary(
    binary_path: Path, out_dir: Path | None = None,
) -> Path | None:
    """A Ghidra project for the binary — RAPTOR-owned locations ONLY.

    The binary's own directory is attacker territory: a planted
    ``.gpr`` there would substitute attacker-authored decompilation
    into review context (and its clean verdicts would be staleness-
    anchored to the REAL binary). Same rule as :func:`find_redb`.
    """
    import os
    if binary_path.suffix == ".gpr":
        return binary_path
    candidates = []
    if out_dir:
        candidates.append(Path(out_dir) / f"{binary_path.stem}.gpr")
    raptor_dir = os.environ.get("RAPTOR_DIR")
    if raptor_dir:
        candidates.append(
            Path(raptor_dir) / "out"
            / f"ghidra-import-{binary_path.stem}"
            / f"{binary_path.stem}.gpr"
        )
    for cand in candidates:
        if cand.is_file():
            return cand
    return None


def find_redb(out_dir: Path | None, target_path: Path | None) -> Path | None:
    """Locate the run's re-database.json.

    Search order: the run output directory, its parent (shared
    pipeline dirs), then the import cache convention for the target
    binary. Only RAPTOR-owned locations — never the scanned target's
    own directory.
    """
    import os
    candidates: list[Path] = []
    if out_dir:
        candidates.append(Path(out_dir) / "re-database.json")
        candidates.append(Path(out_dir).parent / "re-database.json")
    if target_path:
        # Anchor to the RAPTOR repo's out/ — a cwd-relative path
        # would resolve inside the scanned target's own directory
        # when invoked from there, handing the target author the
        # entire derived database.
        raptor_dir = os.environ.get("RAPTOR_DIR")
        if raptor_dir:
            candidates.append(
                Path(raptor_dir) / "out"
                / f"ghidra-import-{Path(target_path).stem}"
                / "re-database.json"
            )
    for cand in candidates:
        if cand.is_file():
            return cand
    return None


#: re-database.json read ceiling. RAPTOR-written, but derived from a
#: hostile binary's decompilation/symbols — a pathological import can
#: balloon it. Bound to the ONE shared RE-database constant (never a
#: value copy): a private 64MiB cap here refused the legitimate
#: --decompile-all artifact the importer itself recommends creating,
#: erroring the build-checklist lane on it. Imported at the
#: definition site so the binding and its rationale read as one unit.
from core.json.utils import (  # noqa: E402
    RE_DATABASE_MAX_BYTES as _MAX_REDB_BYTES,
)


def load_redb(redb_path: Path):
    """Load an REDatabase from disk, cached on (path, mtime).

    Size-gated (:data:`_MAX_REDB_BYTES`): an over-budget file raises
    :class:`~core.json.utils.JsonBudgetExceededError` (a ``ValueError``,
    so existing malformed-input handlers degrade the same way).
    """
    from core.json import load_json_bounded
    from packages.ghidra.model import REDatabase

    key = (
        str(Path(redb_path).resolve()),
        Path(redb_path).stat().st_mtime_ns,
    )
    db, _cached = _REDB_MEMO.get_or_compute(
        key,
        lambda: REDatabase.from_dict(
            load_json_bounded(redb_path, max_bytes=_MAX_REDB_BYTES)
        ),
    )
    return db


def assemble_binary_context(
    *,
    target_path: Path,
    file_path: str,
    function_name: str,
    checklist: dict[str, Any] | None = None,
    context_map: dict[str, Any] | None = None,
    annotations_dir: Path | None = None,
    out_dir: Path | None = None,
    db=None,
) -> dict[str, Any]:
    """Assemble a context slice for one binary function.

    Mirrors :func:`core.audit.context.assemble_context`'s return
    shape; ``db`` may be passed directly (tests, callers holding one)
    or is located via :func:`find_redb`.
    """
    if db is None:
        redb_path = find_redb(out_dir, target_path)
        if redb_path is not None:
            try:
                db = load_redb(redb_path)
            except (OSError, ValueError, KeyError):
                logger.warning(
                    "could not load %s", redb_path, exc_info=True,
                )

    item = _find_item(checklist, file_path, function_name)
    address = (item or {}).get("address")
    if address is None:
        address = ((item or {}).get("metadata") or {}).get("address")

    lookup_name = function_name
    if address is None and "@0x" in function_name:
        # Collision-suffixed checklist names (name@0xADDR).
        base, _, addr_s = function_name.rpartition("@")
        try:
            address = int(addr_s, 16)
            lookup_name = base
        except ValueError:
            address = None

    func = None
    if db is not None:
        if address is not None:
            func = db.function_by_address(address)
        if func is None:
            func = next(
                (f for f in db.functions if f.name == lookup_name),
                None,
            )
            if func is not None:
                address = func.address

    ctx: dict[str, Any] = {
        "file": file_path,
        "function": function_name,
        "line_start": 0,
        "line_end": None,
        "address": address,
        "is_binary": True,
        "target_path": str(target_path),
    }

    source, representation = _read_binary_source(func, target_path, out_dir)
    ctx["source"] = source
    ctx["representation"] = representation

    metadata = dict((item or {}).get("metadata") or {})
    metadata.setdefault("name", function_name)
    if func is not None:
        metadata.setdefault("address", func.address)
        metadata.setdefault("size", func.size)
        if func.signature:
            metadata.setdefault("signature", func.signature)
    ctx["metadata"] = metadata

    ctx["callers"] = _binary_callers(db, func)
    ctx["callees"] = _binary_callees(db, func)
    ctx["existing_annotation"] = _load_annotation(
        annotations_dir, file_path, function_name, out_dir,
    )
    ctx["is_prior_audit_annotation"] = False
    ctx["sinks"] = _binary_sinks(context_map, function_name, address, func)
    ctx["threat_model"] = _load_threat_model(target_path)
    ctx["trust_surface"] = []
    ctx["prior_attempts"] = {}
    ctx["shared_state"] = {}
    ctx["crypto_inventory"] = {}
    ctx["ownership_model"] = {}
    ctx["role_context"] = ""
    ctx["type_definitions"] = _related_types(func, db)
    ctx["macro_definitions"] = ""
    ctx["flow_traces"] = []
    ctx["project_context"] = ""
    ctx["framework_guarantees"] = []

    strategies = None
    if item:
        try:
            from .strategy import learned_vocab, strategies_from_item
            strategies = strategies_from_item(
                item, file_path,
                reachable_sinks=ctx["sinks"],
                source=source,
                target_path=target_path,
                domain_vocab=learned_vocab(out_dir, target_path),
            )
        except Exception:
            logger.debug(
                "strategy selection failed for %s:%s",
                file_path, function_name, exc_info=True,
            )
    ctx["strategy_exemplars"] = _strategy_exemplars(strategies)
    ctx["strategy_primers"] = _strategy_primers(strategies)

    comments = _function_comments(db, func)
    parts = []
    if func is not None and func.signature:
        parts.append(f"Signature: {func.signature}")
    for c in comments[:5]:
        parts.append(f"[{c['kind']}] {c['text']}")
    if parts:
        ctx["ghidra_context"] = "\n".join(parts)

    # Same prompt defences hostile SOURCE gets (control-char strip,
    # size cap, injection scan): decompilation, database comments,
    # and callee snippets are attacker-derived text on the same
    # trust footing.
    try:
        from .prompt_defence import sanitise_for_prompt, scan_for_injection
        location = f"{file_path}:{function_name}"
        if ctx.get("source"):
            ctx["source"] = sanitise_for_prompt(
                ctx["source"], content_type="source",
                location=location,
            )
            injection_warnings = scan_for_injection(
                ctx["source"], location=location,
            )
            if injection_warnings:
                ctx["injection_warnings"] = injection_warnings
        if ctx.get("ghidra_context"):
            ctx["ghidra_context"] = sanitise_for_prompt(
                ctx["ghidra_context"], content_type="source",
                location=location,
            )
        for callee in ctx.get("callees", []):
            if callee.get("source_snippet"):
                callee["source_snippet"] = sanitise_for_prompt(
                    callee["source_snippet"], content_type="source",
                    location=location,
                )
        # Recovered type bodies are DWARF/Ghidra-derived (type and
        # field names come from the hostile binary) — same trust
        # footing as the decompilation above.
        for td in ctx.get("type_definitions", []):
            if td.get("source"):
                td["source"] = sanitise_for_prompt(
                    td["source"], content_type="source",
                    location=f"{location} (recovered type "
                             f"{td.get('name', '?')})",
                )
    except Exception:
        logger.warning("prompt defence failed", exc_info=True)

    return ctx


def _find_item(checklist, file_path, function_name):
    for file_entry in (checklist or {}).get("files", []):
        if file_entry.get("path") != file_path:
            continue
        items = file_entry.get("items", file_entry.get("functions", []))
        for item in items or []:
            if item.get("name") == function_name:
                return item
    return None


def _read_binary_source(func, target_path=None, out_dir=None):
    """Return (source_text, representation)."""
    if func is None:
        return "(function not found in the binary database)", "unknown"
    if func.decompilation:
        return func.decompilation, "decompilation"
    if target_path is not None:
        code = _lazy_decompile(
            str(target_path), func.name, func.address, out_dir,
        )
        if code:
            return code, "decompilation"
    return (
        "(no decompilation available for %s at 0x%x, size %d bytes — "
        "re-import with --decompile-all or use "
        "'raptor-ghidra decompile' on demand)"
        % (func.name, func.address, func.size),
        "stub",
    )


def _xref_call_adjacency(db) -> tuple[dict[Any, list], dict[Any, list]]:
    """Call-edge adjacency: (to_addr -> [xref], caller_addr -> [xref]).

    Both renderers below used to walk ``db.xrefs`` in full for EVERY
    reviewed function — N functions x X xrefs per gap loop.  Built
    once per database object and memoised on it (same count-based
    invalidation discipline as the model's ``_addr_index``: the
    enrich path appends xrefs).  The memo dies with the db object,
    so the (path, mtime)-keyed ``_REDB_MEMO`` carries it across the
    whole run and a changed re-database.json starts fresh.
    """
    cached = getattr(db, "_audit_xref_adjacency", None)
    if cached is not None and cached[0] == len(db.xrefs):
        return cached[1], cached[2]
    by_callee: dict[Any, list] = {}
    by_caller: dict[Any, list] = {}
    for xref in db.xrefs:
        if xref.kind != "call":
            continue
        by_callee.setdefault(xref.to_addr, []).append(xref)
        caller = db.function_containing_address(xref.from_addr)
        if caller is not None:
            by_caller.setdefault(caller.address, []).append(xref)
    db._audit_xref_adjacency = (len(db.xrefs), by_callee, by_caller)
    return by_callee, by_caller


def _binary_callers(db, func) -> list[dict[str, Any]]:
    if db is None or func is None:
        return []
    callers = []
    seen = set()
    by_callee, _ = _xref_call_adjacency(db)
    for xref in by_callee.get(func.address, []):
        caller = db.function_containing_address(xref.from_addr)
        if caller and caller.address not in seen:
            seen.add(caller.address)
            entry: dict[str, Any] = {
                "name": caller.name,
                "file": BINARY_PATH_PREFIX + Path(
                    db.binary_path or "unknown").stem,
                "line_start": 0,
                "address": caller.address,
            }
            if caller.signature:
                entry["signature"] = caller.signature
            callers.append(entry)
    return callers[:15]


def _binary_callees(db, func) -> list[dict[str, Any]]:
    if db is None or func is None:
        return []
    callees = []
    seen = set()
    _, by_caller = _xref_call_adjacency(db)
    for xref in by_caller.get(func.address, []):
        callee = db.function_by_address(xref.to_addr)
        if callee and callee.address not in seen:
            seen.add(callee.address)
            entry: dict[str, Any] = {
                "name": callee.name,
                "file": BINARY_PATH_PREFIX + Path(
                    db.binary_path or "unknown").stem,
                "line_start": 0,
                "address": callee.address,
            }
            if callee.signature:
                entry["signature"] = callee.signature
            if callee.decompilation:
                entry["source_snippet"] = "\n".join(
                    callee.decompilation.splitlines()[:20]
                )
            callees.append(entry)
    return callees[:15]


def _binary_sinks(context_map, function_name, address, func=None) -> list[str]:
    """Sinks reachable from THIS function, as prompt-ready strings.

    Matches the source path's contract (strings, per-function): map
    sink entries are kept when they name this function or fall inside
    its address range — returning the whole map would hand every
    function the input strategy and render dict reprs into the
    prompt.
    """
    if not context_map:
        return []
    lo = address if isinstance(address, int) else None
    hi = None
    if lo is not None and func is not None:
        hi = lo + max((func.size or 0) - 1, 0)
    out = []
    for sink in context_map.get(
            "sinks", context_map.get("dangerous_sinks", [])):
        s_fn = sink.get("function", sink.get("containing_function", ""))
        s_addr = sink.get("address")
        if isinstance(s_addr, str):
            try:
                s_addr = int(s_addr, 16)
            except ValueError:
                s_addr = None
        matched = bool(s_fn) and s_fn == function_name
        if not matched and lo is not None and isinstance(s_addr, int):
            matched = lo <= s_addr <= (hi if hi is not None else lo)
        if not matched:
            continue
        loc = sink.get("location", sink.get("name", ""))
        kind = sink.get("type", "")
        out.append(f"{kind} at {loc}" if kind else str(loc))
    return out[:20]


def _load_threat_model(target_path):
    try:
        from .context import _load_threat_model as _source_ltm
        return _source_ltm(Path(target_path))
    except Exception:
        logger.debug("threat model load failed", exc_info=True)
        return None


def _load_annotation(annotations_dir, file_path, function_name, out_dir):
    try:
        from .context import _load_existing_annotation
        return _load_existing_annotation(
            annotations_dir, file_path, function_name, out_dir=out_dir,
        )
    except Exception:
        logger.debug(
            "annotation load failed for %s:%s",
            file_path, function_name, exc_info=True,
        )
        return None


def _related_types(func, db) -> list[dict[str, Any]]:
    """Types referenced by the function, in the formatter's shape.

    ``format_context_for_prompt`` renders type_definitions entries as
    ``{name, file, line, source}`` dicts — file/line have no source
    meaning here, so they carry the recovered-type provenance.
    """
    if func is None or db is None or not db.types:
        return []
    text = (func.signature or "") + " " + (func.decompilation or "")
    for ch in "*(),;[]{}":
        text = text.replace(ch, " ")
    words = set(text.split())
    matched = [t for t in db.types if t.name in words]
    out = []
    for t in matched[:5]:
        body = f"{t.kind} {t.name}"
        if t.size is not None:
            body += f" /* size: {t.size} */"
        for fld in (t.fields or []):
            offset = fld.get("offset")
            line = (
                f"  /* {offset:#x} */ " if isinstance(offset, int)
                else "  "
            )
            line += f"{fld.get('type', '?')} {fld.get('name', '?')};"
            if fld.get("size"):
                line += f" /* {fld['size']} bytes */"
            body += "\n" + line
        out.append({
            "name": t.name,
            "file": "ghidra-types",
            "line": 0,
            "source": body,
        })
    return out


def _function_comments(db, func) -> list[dict[str, str]]:
    if db is None or func is None:
        return []
    return [
        {"kind": c.kind, "text": c.text}
        for c in db.comments
        if c.function == func.name
    ][:10]


def _strategy_exemplars(strategies):
    try:
        from .context import _load_strategy_exemplars
        return _load_strategy_exemplars(strategies)
    except Exception:
        return []


def _strategy_primers(strategies):
    try:
        from .context import _load_strategy_primers
        return _load_strategy_primers(strategies)
    except Exception:
        return []

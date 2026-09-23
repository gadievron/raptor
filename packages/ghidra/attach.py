"""Persistent Ghidra project bindings — the attach lifecycle.

An ATTACHED .gpr is registered on the RAPTOR project (the
``ghidra_projects`` list, persisted in the project file) so every
later run finds it without re-passing paths: review context injection
loads its cached REDatabase, and ``sync_findings_to_attached`` pushes
a run's findings (agentic results, review journal, annotations) back
into a working copy of the Ghidra project as comments and bookmarks.

The binding is operator-initiated only (``raptor-ghidra attach`` /
``/project ghidra add``) — nothing here ever harvests .gpr files from
the scanned repo. Cached databases are read exclusively from
RAPTOR-owned output locations (:func:`roundtrip.redb_cache_candidates`);
the .gpr's own directory is attacker territory.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


def _load_project(project_name: Optional[str] = None):
    """(manager, project) for *project_name* or the active project.

    Returns ``(None, None)`` when no project resolves — attach is an
    opt-in convenience layered on projects; everything degrades to
    explicit --gpr paths without one.
    """
    try:
        from core.project.project import ProjectManager
        mgr = ProjectManager()
        name = project_name or mgr.get_active()
        if not name:
            return None, None
        project = mgr.load(name)
        if project is None:
            return None, None
        return mgr, project
    except Exception:  # noqa: BLE001 — projects substrate unavailable
        logger.debug("attach: project resolution failed", exc_info=True)
        return None, None


def get_attached_projects(project_name: Optional[str] = None) -> List[str]:
    """The project-persisted .gpr list (active project by default)."""
    _mgr, project = _load_project(project_name)
    if project is None:
        return []
    return list(getattr(project, "ghidra_projects", None) or [])


def attach_dir(project, gpr_path: Path) -> Path:
    """The RAPTOR-owned cache directory for an attached .gpr.

    Keyed on stem PLUS a short hash of the resolved path: stems
    collide in exactly the layouts attach targets (v1/fw.gpr vs
    v2/fw.gpr, or a hostile bundle reusing a common name), and a
    stem-only key let one attachment's database silently overwrite —
    and then masquerade as — another's. The hash is recomputable from
    the registered path, so no side-channel persistence is needed.
    """
    import hashlib
    import os
    tag = hashlib.sha256(
        str(Path(gpr_path).resolve()).encode()).hexdigest()[:8]
    # NOT dot-prefixed: Ghidra's ProjectLocator rejects any project
    # path containing a dot-prefixed element, and the attach-time
    # headless import places its working copy inside this directory —
    # a `.ghidra` parent made every sandboxed attach import fail.
    # Run management skips it by name instead: `ghidra-attach` is in
    # Project._list_run_dirs's generated-dirs exclusion, so /project
    # clean and status never treat the cache as an adoptable run.
    # Textually absolutized (no symlink dereference — the hidden-path
    # guard reasons about the textual form): a RELATIVE registered
    # output_dir otherwise flows into JVM-facing paths that the
    # sandboxed analyzeHeadless resolves against its private scratch
    # cwd, never landing where the readers look.
    return (Path(os.path.abspath(str(project.output_dir)))
            / "ghidra-attach" / f"{gpr_path.stem}-{tag}")


def attach(
    gpr_path: Path,
    *,
    project_name: Optional[str] = None,
    import_now: bool = True,
    program_name: Optional[str] = None,
    import_fn=None,
    wait: bool = False,
) -> "Path | tuple[Path, Any]":
    """Register *gpr_path* on the project and cache its database.

    Returns the cache directory holding ``re-database.json`` — or,
    when *import_fn* is given, ``(cache_dir, import_fn's return)``
    with the callback executed INSIDE the op-locked region. Always
    :func:`attach_dir`; a caller-chosen location would be invisible to
    every later reader (sync, status, context injection), which is a
    silently-degraded attachment. With ``import_now=False`` (and no
    *import_fn*) the returned directory exists but holds no
    ``re-database.json`` yet — readers degrade until an import runs.

    Idempotent: re-attaching an already-attached project refreshes
    the cache without duplicating the registration.

    ``wait=True`` blocks on a busy project op lock instead of raising
    ``OpLockContention``.

    Raises ``ValueError`` when the path is not an existing .gpr or no
    project is active, so operator typos fail NOW rather than as a
    silent no-op weeks later. Post-registration import errors (from
    the default ``import_now`` bridge) propagate as-is — the
    registration is already persisted when they do.
    """
    raw = str(gpr_path)
    if any(ord(c) < 0x20 or c == "\x7f" or c == "\x9b"
           or "\u202a" <= c <= "\u202e" or "\u2066" <= c <= "\u2069"
           for c in raw):
        # The stored path is echoed by status/list surfaces — refuse
        # terminal-control characters at the registration boundary so
        # every later print is clean. Bidi overrides/isolates count:
        # they visually reverse the echoed path, disguising WHICH
        # .gpr is attached.
        raise ValueError("control characters in the .gpr path")
    gpr_path = Path(gpr_path).expanduser().resolve()
    if gpr_path.suffix != ".gpr" or not gpr_path.is_file():
        raise ValueError(
            f"not a Ghidra project file: {gpr_path} "
            "(expected an existing .gpr)"
        )
    mgr, project = _load_project(project_name)
    if project is None:
        raise ValueError(
            "no active RAPTOR project — create/use one first, or use "
            "'raptor-ghidra import' for a one-shot ingest"
        )

    resolved = str(gpr_path)
    from core.json import save_json
    from core.project.oplock import project_op_lock
    from core.project.project import project_file_lock
    project_file = mgr.projects_dir / f"{project.name}.json"
    # The op lock serialises against run starts and /project clean —
    # a concurrent clean could otherwise delete the cache dir
    # mid-import. The file lock inside guards the JSON RMW itself.
    # WARNING: project_op_lock is NOT reentrant in-process (separate
    # fds; flock treats them as independent lockers) — never call
    # attach()/detach() from a context already holding this project's
    # op lock, it self-deadlocks under wait=True.
    with project_op_lock(Path(project.output_dir), "ghidra attach",
                         wait=wait):
        with project_file_lock(project_file):
            fresh = mgr.load(project.name)
            if fresh is None:
                raise ValueError(f"project vanished: {project.name}")
            if resolved not in fresh.ghidra_projects:
                fresh.ghidra_projects.append(resolved)
                save_json(project_file, fresh.to_dict())
            project = fresh

        cache_dir = attach_dir(project, gpr_path)
        cache_dir.mkdir(parents=True, exist_ok=True)

        # The import runs INSIDE the op lock: a concurrent /project
        # clean or run start must not interleave with the cache
        # write. Cost acknowledged — a long analyzeHeadless import
        # holds the project's op lock for its duration; that is the
        # price of a cache that is never half-deleted. *import_fn*
        # lets the CLI thread its flag-dependent import (enrich /
        # decompile-all) through the same locked region.
        result_db = None
        if import_fn is not None:
            result_db = import_fn(cache_dir)
        elif import_now:
            from .bridge import GhidraBridge
            bridge = GhidraBridge(gpr_path, program_name=program_name)
            try:
                bridge.import_project(cache_dir)
            finally:
                bridge.close()
    if import_fn is not None:
        return cache_dir, result_db
    return cache_dir


def detach(
    gpr_path: Optional[Path] = None,
    *,
    project_name: Optional[str] = None,
    wait: bool = False,
) -> int:
    """Remove one attached project (or all, when *gpr_path* is None).

    Returns the number of registrations removed. Cached databases are
    left on disk so a re-attach starts warm; run cleanup never
    touches them (``ghidra-attach`` is excluded from run-dir
    enumeration), so reclaiming the bytes is ``/project delete
    --purge`` or deleting the slot by hand. ``wait=True`` blocks on a
    busy project op lock instead of raising.
    """
    mgr, project = _load_project(project_name)
    if project is None:
        return 0
    from core.json import save_json
    from core.project.oplock import project_op_lock
    from core.project.project import project_file_lock
    project_file = mgr.projects_dir / f"{project.name}.json"
    with project_op_lock(Path(project.output_dir), "ghidra detach",
                         wait=wait), \
            project_file_lock(project_file):
        fresh = mgr.load(project.name)
        if fresh is None:
            return 0
        before = len(fresh.ghidra_projects)
        if gpr_path is None:
            fresh.ghidra_projects = []
        else:
            wanted = str(Path(gpr_path).expanduser().resolve())
            fresh.ghidra_projects = [
                g for g in fresh.ghidra_projects
                if g != wanted and g != str(gpr_path)
            ]
        removed = before - len(fresh.ghidra_projects)
        if removed:
            save_json(project_file, fresh.to_dict())
    return removed


def _load_attached_db(gpr_path: Path, project=None):
    """Cached REDatabase for an attached .gpr, RAPTOR-owned locations
    only. None when no cache exists (sync degrades to name-keyed
    findings, resolved inside Ghidra by the import script).

    *project*, when given, contributes its attach cache dir directly —
    the fallback candidates re-resolve the ACTIVE project themselves,
    which is wrong for an explicit ``project_name`` caller.
    """
    from core.json import load_json

    from core.json.utils import RE_DATABASE_MAX_BYTES as _MAX_CACHE_BYTES

    from .model import REDatabase
    from .roundtrip import redb_cache_candidates

    candidates = []
    if project is not None:
        candidates.append(attach_dir(project, gpr_path)
                          / "re-database.json")
    candidates.extend(redb_cache_candidates(gpr_path))
    for cand in candidates:
        if cand.is_file():
            try:
                data = load_json(cand, max_bytes=_MAX_CACHE_BYTES)
                if data is None:
                    continue
                return REDatabase.from_dict(data)
            except Exception:  # noqa: BLE001 — a hostile/corrupt cache
                # (wrong-shape JSON raises AttributeError, not just
                # ValueError) must degrade to name-keyed findings,
                # never crash status or the sync loop.
                logger.debug("unreadable redb cache: %s", cand,
                             exc_info=True)
    return None


def _resolve_addresses(
    findings: List[Dict[str, Any]], db,
) -> List[Dict[str, Any]]:
    """Fill each finding's ``address`` from the database by name.

    Address-anchored enrichments place deterministically; name-keyed
    ones depend on Ghidra-side resolution. Names that don't resolve
    keep the name key (the apply step skips unmatched ones there).
    """
    if db is None:
        return findings
    by_name: Dict[str, set] = {}
    for func in db.functions:
        if func.name and not getattr(func, "is_auto_named", False):
            by_name.setdefault(func.name, set()).add(func.address)
    out = []
    for f in findings:
        addrs = by_name.get(f.get("function") or "")
        if f.get("address") is None and addrs:
            if len(addrs) == 1:
                f = {**f, "address": next(iter(addrs))}
            else:
                # Duplicate name inside one database (e.g. two static
                # functions from different CUs): anchoring to the
                # first match silently places the enrichment on the
                # wrong function. Stay name-keyed — Ghidra-side
                # resolution owns the ambiguity there.
                logger.info(
                    "ambiguous function name %r (%d definitions) — "
                    "leaving name-keyed for Ghidra-side resolution",
                    str(f.get("function"))[:100], len(addrs),
                )
        out.append(f)
    return out


class SyncResult(int):
    """Total submissions, with per-attachment failure detail.

    Subclasses int so existing callers counting submissions keep
    working; honest reporters read ``failed`` / ``attachments``.

    NEVER truth-test this value: ``SyncResult(0, ["/gone.gpr"], 1)``
    is falsy even though the sync FAILED — check ``.failed``.
    Arithmetic and json.dumps decay to plain int (dropping the
    detail); pickle/copy round-trip via ``__getnewargs__``.
    """

    failed: List[str]
    attachments: int

    def __new__(cls, total: int, failed: List[str], attachments: int):
        obj = super().__new__(cls, total)
        obj.failed = failed
        obj.attachments = attachments
        return obj

    def __getnewargs__(self):
        return (int(self), self.failed, self.attachments)


def sync_findings_to_attached(
    out_dir: Path,
    *,
    target_path: Optional[Path] = None,
    analysed_results: Optional[List[Dict[str, Any]]] = None,
    project_name: Optional[str] = None,
) -> "SyncResult":
    """Export a run's findings into every attached Ghidra project.

    Gathers the three finding sources from *out_dir* (agentic
    results, review journal, annotations), resolves function names to
    addresses through each attachment's cached database, and applies
    them in ONE pass per .gpr (multiple passes would each re-copy the
    project and clobber the previous pass's enrichments).

    Returns a :class:`SyncResult` — the int value is total
    SUBMISSIONS across attachments (three findings into two
    attachments count six); ``failed`` names attachments whose apply
    raised or whose .gpr is missing. Zero with no failures is a
    normal answer (nothing attached, or nothing to export).
    """
    del target_path  # reserved: per-target attachment filtering
    out_dir = Path(out_dir)
    attached = get_attached_projects(project_name)
    if not attached:
        return SyncResult(0, [], 0)

    from .roundtrip import (
        _apply_findings,
        collect_agentic_findings,
        collect_annotation_findings,
        collect_journal_findings,
    )

    _mgr, project = _load_project(project_name)
    if analysed_results is None:
        analysed_results = _read_analysed_results(out_dir)
    agentic = collect_agentic_findings(analysed_results or [])
    journal = collect_journal_findings(out_dir)
    if not journal and (out_dir / "autonomous").is_dir():
        # Sequential runs journal under autonomous/.
        journal = collect_journal_findings(out_dir / "autonomous")
    # Orchestrated runs ALSO journal their own results — exporting
    # both submits every exploitable finding twice with differing
    # summaries the operator cannot dedup in Ghidra. The agentic
    # record is the richer one; drop journal rows for functions it
    # already covers.
    if agentic:
        agentic_fns = {f.get("function") for f in agentic
                       if f.get("function")}
        journal = [j for j in journal
                   if j.get("function") not in agentic_fns]
    annotations = collect_annotation_findings(out_dir)
    if not annotations and project is not None:
        # /annotate's base is the PROJECT output dir, not the run dir.
        annotations = collect_annotation_findings(
            Path(project.output_dir))
    findings = agentic + journal + annotations
    if not findings:
        return SyncResult(0, [], len(attached))
    total = 0
    failed: List[str] = []
    for gpr_str in attached:
        gpr_path = Path(gpr_str)
        if not gpr_path.is_file():
            logger.warning("attached ghidra project missing: %s",
                           str(gpr_path)[:200])
            failed.append(gpr_str)
            continue
        try:
            # Load inside the per-attachment guard: one hostile or
            # corrupt cache must degrade THIS attachment, not abort
            # the loop before healthy ones are synced.
            db = _load_attached_db(gpr_path, project)
            resolved = _resolve_addresses(findings, db)
            # Slot name derived from the gpr path directly — not from
            # the project object (which can resolve to None in the
            # narrow race between resolution reads, silently reviving
            # the same-stem working-copy clobber).
            import hashlib
            tag = hashlib.sha256(
                str(gpr_path.resolve()).encode()).hexdigest()[:8]
            total += _apply_findings(
                gpr_path, out_dir, resolved,
                export_subdir=f"{gpr_path.stem}-{tag}",
            )
        except Exception:  # noqa: BLE001 — one attachment must not kill the rest
            logger.warning("ghidra sync failed for %s",
                           str(gpr_path)[:200], exc_info=True)
            failed.append(gpr_str)
    return SyncResult(total, failed, len(attached))


def _read_analysed_results(out_dir: Path) -> List[Dict[str, Any]]:
    """The run's agentic analysis records, when present.

    Accepted shapes: ``analysed_results.json`` (a bare record list —
    an explicit-input convention, not written by any pipeline) and
    the run-written reports — ``orchestrated_report.json`` or the
    sequential ``autonomous/autonomous_analysis_report.json`` (dicts
    whose ``results`` key holds the records).
    """
    from core.json import load_json

    from core.json.utils import RE_DATABASE_MAX_BYTES
    cap = RE_DATABASE_MAX_BYTES
    path = out_dir / "analysed_results.json"
    if path.is_file():
        data = load_json(path, max_bytes=cap)
        if isinstance(data, list):
            return data
    for report in (
        out_dir / "orchestrated_report.json",
        # sequential runs write under autonomous/
        out_dir / "autonomous" / "autonomous_analysis_report.json",
    ):
        if report.is_file():
            data = load_json(report, max_bytes=cap)
            if isinstance(data, dict) and isinstance(
                    data.get("results"), list):
                return data["results"]
    return []

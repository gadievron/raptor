"""PHP include-graph derivation — Layer 1 of the include model.

Folds the per-file structured include edges the PHP call-graph walker
records (:class:`core.inventory.call_graph.IncludeEdge`) into one
derived artifact, ``include-graph.json``, written beside
``checklist.json`` under the checklist's lock discipline:

* **Reverse includer index** — ``included_by[file] → [(includer,
  edge)]``: the "full includer set of X" fact, derived once,
  mechanically, instead of re-derived per finding by the LLM.
* **Two-component census** — every includer-set consumer must quote
  BOTH components or the completeness claim is dishonest:
  ``unresolved_edges[]`` (dynamic/ambiguous include sites) and
  ``unwalked_targets[]`` (include targets the walker could not parse
  — foreign extensions outside the language map, parse failures,
  excluded files). A hostile tree hides an includer inside an
  unwalked target; the second component keeps the qualifier honest.
* **File roles** — derived ONLY from the includer index plus the
  walker's direct-access-guard evidence: ``library`` iff ≥1 includer,
  ``designed_entry`` iff zero. "dual" (included AND directly
  requestable without a guard) is a QUERY over those two
  evidence-carrying fields (:func:`directly_requestable_library`),
  never a stored label. No directory conventions.
* **Resolution profile** — per-shape counts and per-derivation
  outcomes, so consumers can see whether the graph is load-bearing or
  vestigial for this target.

Authority: the whole artifact is **hint-tier** (stamped on the
artifact itself, with producer provenance). It may steer hypotheses,
prompts, priorities, and severity context; NOTHING derived from it
may refute a hypothesis, demote a finding, or suppress a review slot.
No verdict path reads this graph.

Resolution discipline (phase 1a — per-file only, no environment
walk): pure-literal edges anchor relative to the including file;
``const_prefix`` edges join the includer index only when their
literal tail matches exactly ONE tree path (component-aligned —
zero or multiple matches refuse into the census, never a guess).
Tail matching is a reachability-direction device: acceptable for
includer-set facts because a wrong edge only widens review
attention; it is NEVER guarantee material. The phase-1b per-entry
constant-environment walk supersedes it for anything
guarantee-shaped. ``dynamic`` edges never resolve; their literal
stem/tail material only enumerates census candidates.
"""

from __future__ import annotations

import logging
import os
import posixpath
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

PRODUCER_MODULE = "core.inventory.include_graph"
PRODUCER_VERSION = 1
ARTIFACT_NAME = "include-graph.json"

#: Classic-PHP honesty note, carried on the artifact itself.
ARTIFACT_NOTE = (
    "Hint-tier syntactic derivation from hostile content. 'library' "
    "does not mean unreachable: any webroot file is directly "
    "requestable, and a planted includer can at most flip "
    "designed_entry to library, which only widens review attention. "
    "Includer-set facts are complete only modulo the two-component "
    "census (unresolved_edges + unwalked_targets)."
)

# Bounds — the graph derives from hostile content; every list a
# planted tree can grow is capped, with full counts kept beside the
# truncated lists.
MAX_TREE_FILES = 200_000
MAX_CANDIDATES_PER_EDGE = 32
MAX_TREE_SCAN_EDGES_PER_RUN = 256
MAX_MATCH_PROBES_PER_RUN = 2_000_000
MAX_INCLUDED_BY_RENDERED = 200
MAX_UNRESOLVED_LISTED = 2000
MAX_UNWALKED_LISTED = 2000
MAX_VIA_SITES = 5
MAX_GRAPH_BYTES = 64 * 1024 * 1024
_MAX_SOURCE_BYTES = 8 * 1024 * 1024  # mirrors builder MAX_FILE_BYTES

_WALK_SKIP_DIRS = frozenset({
    ".git", ".svn", ".hg", "node_modules", "vendor", "__pycache__",
})


def anchor_literal_include_targets(
    call_graph: dict[str, Any] | None, rel_path: str,
) -> None:
    """Populate ``target`` on pure-literal include edges.

    Layer-0 rule: ``target`` is set only for pure literals anchorable
    relative to the including file — pure path arithmetic, tree-
    relative, no filesystem access (existence is the derivation's
    job). Absolute paths and joins that escape the tree stay
    unanchored (they land in the census instead of guessing).
    Mutates the serialized call-graph dict in place.
    """
    if not isinstance(call_graph, dict):
        return
    edges = call_graph.get("includes")
    if not isinstance(edges, list):
        return
    base = posixpath.dirname(rel_path.replace("\\", "/"))
    for e in edges:
        if not isinstance(e, dict) or e.get("shape") != "literal":
            continue
        if e.get("target"):
            continue
        tail = e.get("literal_tail")
        if not isinstance(tail, str) or not tail:
            continue
        t = tail.replace("\\", "/")
        if t.startswith("/") or ":" in t.split("/", 1)[0]:
            continue  # absolute / scheme-or-drive-ish — not tree-relative
        joined = posixpath.normpath(posixpath.join(base, t))
        if joined == ".." or joined.startswith("../"):
            continue  # escapes the tree — refuse, never guess
        e["target"] = joined


# ---------------------------------------------------------------------------
# Derivation
# ---------------------------------------------------------------------------


def _list_tree_files(target_root: str | Path) -> list[str] | None:
    """Repo-relative posix paths of ALL regular files under the tree.

    The candidate-matching universe must include files OUTSIDE the
    inventory's language map (foreign-extension dispatcher modules —
    the census's unwalked-target exemplar). Bounded; returns None when
    the root is unusable.
    """
    root = Path(target_root)
    if not root.is_dir():
        return None
    out: list[str] = []
    root_s = str(root)
    for dirpath, dirnames, filenames in os.walk(root_s):
        dirnames[:] = [d for d in dirnames if d not in _WALK_SKIP_DIRS]
        for fn in filenames:
            full = os.path.join(dirpath, fn)
            if os.path.islink(full):
                continue
            rel = os.path.relpath(full, root_s).replace(os.sep, "/")
            out.append(rel)
            if len(out) >= MAX_TREE_FILES:
                logger.warning(
                    "include_graph: tree listing capped at %d files",
                    MAX_TREE_FILES)
                return out
    return out


def _match_tail(
    tail: str,
    stem: str | None,
    tree_paths: list[str],
    by_basename: dict[str, list[str]],
    cap: int | None = None,
    scan_budget: list[int] | None = None,
    probe_budget: list[int] | None = None,
) -> list[str] | None:
    """Tree paths matching a literal tail (+ optional stem filter).

    Component-aligned via the basename index whenever the tail's
    final segment is a real file name: ``boot.php`` never matches
    ``reboot.php``, ``a/x.php`` and ``/a/x.php`` anchor at component
    boundaries, and the cost is one bucket, never a tree scan.

    A tail whose final segment starts with ``.`` is an EXTENSION
    FRAGMENT (the ``.mod`` dispatcher class): component alignment is
    impossible, so it matches by bare suffix over the whole tree —
    census-candidate material only. That route requires BOTH a cap
    and a run-level ``scan_budget`` (mutable one-element counter);
    without them it returns None, so no resolution lane can ever be
    steered by an unaligned match or ground through tree-sized scans
    per flooded edge.

    ``probe_budget`` bounds ITERATIONS, not matches: a never-matching
    needle against a heavily shared basename bucket (100k ``x.php``
    files vs tail ``zz/x.php``) walks the whole bucket per edge, so
    the match cap alone left a linear-in-flooders grind. Every
    candidate inspected on either route draws the run-level probe
    budget down; exhaustion returns None.

    Returns None on cap overflow / exhausted budget — the caller
    records an overflow marker rather than a flood, and never a
    partial list dressed up as complete.
    """
    if not tail:
        return []
    base = tail.rsplit("/", 1)[-1]
    if not base:
        return []  # 'dir/' tails cannot name a file
    matches: list[str] = []

    if base.startswith("."):
        # Extension-fragment tail — tree-scan route (see docstring).
        if cap is None or scan_budget is None or scan_budget[0] <= 0:
            return None
        scan_budget[0] -= 1
        source: Any = tree_paths

        def _hit(p: str) -> bool:
            return p.endswith(tail)
    else:
        source = by_basename.get(base, ())
        needle = tail.lstrip("/")

        def _hit(p: str) -> bool:
            return p == needle or p.endswith("/" + needle)

    stem_needle = ("/" + stem) if stem else None
    for p in source:
        if probe_budget is not None:
            if probe_budget[0] <= 0:
                return None
            probe_budget[0] -= 1
        if not _hit(p):
            continue
        if stem_needle and stem_needle not in ("/" + p):
            continue
        matches.append(p)
        if cap is not None and len(matches) > cap:
            return None
    return matches


def _recompute_edges(
    record: dict[str, Any], target_root: str | Path,
) -> dict[str, Any] | None:
    """Recompute-from-source exception for pre-edge checklists.

    Mirrors the script_handler stamp's documented exception: a
    checklist written before the edge layer existed carries the gap
    forward on every SHA-reused record, so a consumer WITH source
    access may recompute — exact only when the on-disk content still
    matches the record's SHA-256 (drifted files stay unextracted and
    are counted, never guessed at).
    """
    from core.hash import sha256_bytes
    from core.paths import confine

    path = record.get("path")
    if not isinstance(path, str):
        return None
    full = confine(Path(target_root), path)
    if full is None or not full.is_file():
        return None
    try:
        with open(full, "rb") as fh:
            raw = fh.read(_MAX_SOURCE_BYTES + 1)
    except OSError:
        return None
    if len(raw) > _MAX_SOURCE_BYTES:
        return None
    if record.get("sha256") and sha256_bytes(raw) != record.get("sha256"):
        return None
    from core.inventory.call_graph import extract_call_graph_php
    graph = extract_call_graph_php(raw.decode("utf-8", errors="replace"))
    if not graph.includes_extracted:
        return None
    out = graph.to_dict()
    anchor_literal_include_targets(out, path)
    return out


def build_include_graph(
    inventory: dict[str, Any],
    *,
    target_root: str | Path | None = None,
    recompute_missing: bool = True,
) -> dict[str, Any]:
    """Derive the include graph from an inventory dict.

    Mechanical only — no LLM anywhere (the LLM never enumerates the
    graph). ``target_root`` widens the candidate-matching universe to
    the whole tree (needed for foreign-extension unwalked targets)
    and arms the recompute-from-source exception for pre-edge
    checklists.
    """
    files = [
        f for f in (inventory.get("files") or [])
        if isinstance(f, dict) and not f.get("_excluded")
    ]
    php_records = {
        f["path"]: f for f in files
        if f.get("language") == "php" and isinstance(f.get("path"), str)
    }
    excluded_paths = {
        e.get("path") for e in (inventory.get("excluded_files") or [])
        if isinstance(e, dict) and isinstance(e.get("path"), str)
    }
    # Pruned directories are recorded as one ``dir/`` entry; a target
    # under one is excluded, not language-unknown.
    excluded_dir_prefixes = tuple(
        p for p in excluded_paths if p.endswith("/"))
    inventory_paths = {
        f["path"] for f in files if isinstance(f.get("path"), str)
    }

    tree_paths: list[str] | None = None
    if target_root is not None:
        tree_paths = _list_tree_files(target_root)
    if tree_paths is None:
        # Inventory-only universe: honest but narrower — foreign-
        # extension files never entered the inventory, so the
        # unwalked census can only cover excluded/parse-fail cases.
        tree_paths = sorted(inventory_paths | excluded_paths)
    tree_set = set(tree_paths)
    by_basename: dict[str, list[str]] = {}
    for p in tree_paths:
        by_basename.setdefault(p.rsplit("/", 1)[-1], []).append(p)

    # Per-file edge lists (+ recompute exception).
    edges_by_file: dict[str, list[dict[str, Any]]] = {}
    guards: dict[str, dict[str, Any]] = {}
    edges_unavailable: list[str] = []
    truncated_files: list[dict[str, Any]] = []
    recomputed = 0
    for path, rec in php_records.items():
        cg = rec.get("call_graph")
        if not (isinstance(cg, dict) and "includes" in cg):
            if recompute_missing and target_root is not None:
                fresh = _recompute_edges(rec, target_root)
                if fresh is not None:
                    cg = fresh
                    recomputed += 1
        if isinstance(cg, dict) and isinstance(cg.get("includes"), list):
            edges_by_file[path] = [
                e for e in cg["includes"] if isinstance(e, dict)
            ]
            # Edge-capped extraction is a census fact, not a detail:
            # every edge past the walker cap is INVISIBLE here, so
            # this file's outgoing includer contributions may be
            # missing entirely — an includer-set completeness claim
            # that ignored it would be dishonest.
            if cg.get("includes_truncated"):
                truncated_files.append({
                    "path": path,
                    "recorded_edges": len(edges_by_file[path]),
                })
            dag = cg.get("direct_access_guard")
            if isinstance(dag, dict):
                guards[path] = dag
        else:
            edges_unavailable.append(path)

    # Edge resolution (phase-1a per-file rules; see module docstring).
    included_by: dict[str, list[dict[str, Any]]] = {}
    unresolved: list[dict[str, Any]] = []
    unwalked: dict[str, dict[str, Any]] = {}
    shape_counts: dict[str, dict[str, int]] = {
        "file_scope": {}, "function_body": {},
    }
    outcomes: dict[str, int] = {}

    # Run-level match budgets. ``scan_budget`` bounds how many edges
    # may take the O(tree) extension-fragment route; ``probe_budget``
    # bounds total candidate ITERATIONS across both routes (a
    # never-matching needle against a shared-basename bucket costs
    # the whole bucket per edge). Files derive in sorted-path order,
    # so an early-sorting hostile file ("aaa.php") can starve later
    # files of both budgets — accepted: exhaustion is an HONEST
    # refusal (overflow markers, censused), never a wrong edge, and
    # per-file budgets would instead hand a flooder N× the total
    # work. Real trees spend a tiny fraction of either budget.
    scan_budget = [MAX_TREE_SCAN_EDGES_PER_RUN]
    probe_budget = [MAX_MATCH_PROBES_PER_RUN]

    def _bump(d: dict[str, int], k: str) -> None:
        d[k] = d.get(k, 0) + 1

    def _edge_ref(includer: str, e: dict[str, Any]) -> dict[str, Any]:
        return {
            "includer": includer,
            "line": e.get("line") if isinstance(e.get("line"), int) else 0,
            "keyword": str(e.get("keyword") or "include"),
            "conditional": bool(e.get("conditional", False)),
            "position": str(e.get("position") or "file_scope"),
        }

    def _note_unwalked(target: str, reason: str,
                       includer: str, e: dict[str, Any]) -> None:
        entry = unwalked.setdefault(
            target, {"path": target, "reason": reason, "via": []})
        if len(entry["via"]) < MAX_VIA_SITES:
            entry["via"].append({
                "file": includer,
                "line": e.get("line")
                if isinstance(e.get("line"), int) else 0,
            })

    def _walkability_reason(target: str) -> str | None:
        """None when walkable; else why the target's own includes
        are invisible (the census's second component)."""
        if target in php_records:
            if target in edges_unavailable:
                return "php_unparsed"
            return None
        if (target in excluded_paths
                or target.startswith(excluded_dir_prefixes)):
            return "excluded"
        if target in inventory_paths:
            return "not_php"
        return "not_in_language_map"

    def _resolve_to(target: str, basis: str,
                    includer: str, e: dict[str, Any]) -> None:
        ref = _edge_ref(includer, e)
        ref["basis"] = basis
        included_by.setdefault(target, []).append(ref)
        reason = _walkability_reason(target)
        if reason is not None:
            _note_unwalked(target, reason, includer, e)

    for path in sorted(edges_by_file):
        for e in edges_by_file[path]:
            shape = str(e.get("shape") or "dynamic")
            pos = ("function_body"
                   if e.get("position") == "function_body"
                   else "file_scope")
            _bump(shape_counts[pos], shape)
            _bump(shape_counts[pos], "total")

            if shape == "literal":
                target = e.get("target")
                if isinstance(target, str) and target in tree_set:
                    _bump(outcomes, "resolved_relative_literal")
                    _resolve_to(target, "relative_literal", path, e)
                    continue
                _bump(outcomes, "unresolved_target_missing")
                unresolved.append({
                    **_edge_ref(path, e), "file": path, "shape": shape,
                    "raw": str(e.get("raw") or ""),
                    "reason": "target_missing",
                })
                continue

            if shape == "const_prefix":
                tail = e.get("literal_tail")
                base = (tail.rsplit("/", 1)[-1]
                        if isinstance(tail, str) else "")
                if not base or base.startswith("."):
                    # Extension-fragment tail: component alignment is
                    # impossible, so a "unique" bare-suffix match can
                    # be the WRONG file — refuse into the census (the
                    # dark direction), never resolve.
                    _bump(outcomes, "unresolved_tail_unaligned")
                    unresolved.append({
                        **_edge_ref(path, e), "file": path,
                        "shape": shape,
                        "raw": str(e.get("raw") or ""),
                        "reason": "tail_unaligned",
                    })
                    continue
                # Uniqueness needs to see at most two matches; a
                # capless collect-then-sort let one flooded file grind
                # the whole build against a large tree.
                matches = _match_tail(
                    tail, None, tree_paths, by_basename, cap=2,
                    probe_budget=probe_budget,
                )
                if matches and len(matches) == 1:
                    _bump(outcomes, "resolved_tail_unique")
                    _resolve_to(matches[0], "tail_unique", path, e)
                    continue
                reason = ("tail_unmatched"
                          if matches == [] else "tail_ambiguous")
                _bump(outcomes, "unresolved_" + reason)
                rec = {
                    **_edge_ref(path, e), "file": path, "shape": shape,
                    "raw": str(e.get("raw") or ""), "reason": reason,
                }
                if matches:
                    rec["candidates"] = sorted(matches)
                elif matches is None:
                    rec["candidates_overflow"] = True
                unresolved.append(rec)
                continue

            # dynamic / config_bounded / unknown shapes: never
            # resolved. Literal stem/tail material enumerates census
            # candidates only (over-approximation is acceptable in
            # the census direction; a cap overflow records nothing).
            # Extension-fragment tails are the only tree-scan route
            # and draw down the run-level scan budget.
            _bump(outcomes, "unresolved_dynamic")
            tail = e.get("literal_tail")
            stem = e.get("literal_stem")
            cands = _match_tail(
                tail, stem if isinstance(stem, str) else None,
                tree_paths, by_basename, cap=MAX_CANDIDATES_PER_EDGE,
                scan_budget=scan_budget, probe_budget=probe_budget,
            ) if isinstance(tail, str) else []
            rec: dict[str, Any] = {
                **_edge_ref(path, e), "file": path, "shape": shape,
                "raw": str(e.get("raw") or ""), "reason": "dynamic",
            }
            if cands is None:
                rec["candidates_overflow"] = True
            elif cands:
                rec["candidates"] = sorted(cands)
                for c in cands:
                    why = _walkability_reason(c)
                    if why is not None:
                        _note_unwalked(c, why, path, e)
            unresolved.append(rec)

    # File roles — includer index + guard evidence ONLY.
    files_out: dict[str, dict[str, Any]] = {}
    for path in sorted(php_records):
        incs = included_by.get(path, [])
        entry: dict[str, Any] = {
            "role": "library" if incs else "designed_entry",
            "includer_count": len(incs),
            "included_by": incs[:MAX_INCLUDED_BY_RENDERED],
            "direct_access_guard": path in guards,
        }
        if len(incs) > MAX_INCLUDED_BY_RENDERED:
            entry["included_by_truncated"] = True
        g = guards.get(path)
        if g is not None:
            if isinstance(g.get("line"), int):
                entry["direct_access_guard_line"] = g["line"]
            if isinstance(g.get("constant"), str):
                entry["direct_access_guard_constant"] = g["constant"]
        if path in edges_unavailable:
            entry["edges_unavailable"] = True
        files_out[path] = entry
    # Resolved targets outside the inventory's PHP set have includer
    # facts too (they are census members, not role-bearing files).
    for target in sorted(included_by):
        if target in files_out:
            continue
        files_out[target] = {
            "role": "library",
            "includer_count": len(included_by[target]),
            "included_by": included_by[target][:MAX_INCLUDED_BY_RENDERED],
            "direct_access_guard": False,
            "unwalked": True,
        }

    unresolved.sort(key=lambda r: (r.get("file", ""), r.get("line", 0)))
    unwalked_list = [unwalked[k] for k in sorted(unwalked)]

    graph: dict[str, Any] = {
        "tier": "hint",
        "producer": {
            "module": PRODUCER_MODULE,
            "version": PRODUCER_VERSION,
            "parse_fingerprint": str(
                inventory.get("parse_fingerprint") or ""),
            "generated_at": datetime.now(timezone.utc).isoformat(),
        },
        "note": ARTIFACT_NOTE,
        "target_path": str(inventory.get("target_path") or ""),
        "resolution_profile": {
            "file_scope": shape_counts["file_scope"],
            "function_body": shape_counts["function_body"],
            "outcomes": outcomes,
        },
        "census": {
            "unresolved_edge_count": len(unresolved),
            "unwalked_target_count": len(unwalked_list),
        },
        "files": files_out,
        "unresolved_edges": unresolved[:MAX_UNRESOLVED_LISTED],
        "unwalked_targets": unwalked_list[:MAX_UNWALKED_LISTED],
    }
    if truncated_files:
        # Third census component: files whose edge extraction hit the
        # walker cap — every edge past it is invisible, so those
        # files' includer contributions may be missing entirely and
        # the completeness qualifier must say so.
        graph["census"]["truncated_file_count"] = len(truncated_files)
        graph["truncated_files"] = truncated_files[:MAX_UNWALKED_LISTED]
    if len(unresolved) > MAX_UNRESOLVED_LISTED:
        graph["unresolved_edges_truncated"] = True
    if len(unwalked_list) > MAX_UNWALKED_LISTED:
        graph["unwalked_targets_truncated"] = True
    if edges_unavailable:
        graph["php_files_without_edges"] = len(edges_unavailable)
    if recomputed:
        graph["recomputed_files"] = recomputed
    return graph


# ---------------------------------------------------------------------------
# Artifact I/O — checklist lock discipline, project-symlink aware
# ---------------------------------------------------------------------------


def save_include_graph(output_dir: str | Path,
                       graph: dict[str, Any]) -> None:
    """Write ``include-graph.json`` beside the (resolved) checklist,
    under the checklist's flock — one writer, atomic replace."""
    from core.inventory import _checklist_lock, _resolve_checklist_path
    from core.json import save_json

    checklist_path = _resolve_checklist_path(output_dir)
    with _checklist_lock(checklist_path):
        save_json(checklist_path.parent / ARTIFACT_NAME, graph)


def resolve_artifact_path(output_dir: str | Path) -> Path | None:
    """The existing ``include-graph.json`` for a run dir, or None.

    Follows the project-mode checklist symlink the way the artifact
    was written (beside the resolved checklist).
    """
    base = Path(output_dir)
    cand = base / ARTIFACT_NAME
    if not cand.exists():
        cl = base / "checklist.json"
        if cl.is_symlink():
            try:
                cand = cl.resolve().parent / ARTIFACT_NAME
            except OSError:
                return None
    return cand if cand.is_file() else None


def load_include_graph(output_dir: str | Path) -> dict[str, Any] | None:
    """Read ``include-graph.json`` from a run dir.

    Returns None when missing or malformed — consumers degrade to
    today's behavior.
    """
    from core.json import load_json

    cand = resolve_artifact_path(output_dir)
    if cand is None:
        return None
    try:
        data = load_json(cand, max_bytes=MAX_GRAPH_BYTES)
    except Exception:  # noqa: BLE001 — a bad artifact never blocks a consumer
        logger.debug("include_graph: unreadable artifact at %s",
                     cand, exc_info=True)
        return None
    return data if isinstance(data, dict) else None


# ---------------------------------------------------------------------------
# Consumer queries — hint-tier, census-qualified
# ---------------------------------------------------------------------------


def _census_counts(
    graph: dict[str, Any],
) -> tuple[int, int, int] | None:
    """Validated census counts (unresolved, unwalked, truncated
    files), or None when the census object is missing or carries
    non-count values. None means UNKNOWN — a failed census must
    never coerce to zeros, because "modulo 0 and 0" is a positive
    completeness claim the artifact no longer supports."""
    c = graph.get("census")
    if not isinstance(c, dict):
        return None

    def _count(v: Any) -> int | None:
        return (v if isinstance(v, int) and not isinstance(v, bool)
                and v >= 0 else None)

    ue = _count(c.get("unresolved_edge_count"))
    ut = _count(c.get("unwalked_target_count"))
    tf = _count(c.get("truncated_file_count", 0))
    if ue is None or ut is None or tf is None:
        return None
    return ue, ut, tf


#: Qualifier rendered when the census cannot be validated — an
#: explicit refusal, never an implied "complete modulo 0 and 0".
CENSUS_UNKNOWN_QUALIFIER = (
    "Include-graph census is missing or invalid — includer-set "
    "completeness is unknown. Treat every includer set as "
    "potentially incomplete and verify against source; never treat "
    "these facts as a verdict input."
)


def census_qualifier(graph: dict[str, Any]) -> str:
    """The mandatory completeness qualifier every includer-set
    consumer must render beside the facts."""
    counts = _census_counts(graph)
    if counts is None:
        return CENSUS_UNKNOWN_QUALIFIER
    ue, ut, tf = counts
    trunc = ""
    if tf:
        trunc = (f", and edge extraction was truncated in {tf} "
                 f"file(s) whose includer contributions may be "
                 f"missing entirely")
    return (
        f"Hint-tier includer-set facts, complete only modulo "
        f"{ue} unresolved include site(s) and {ut} unwalked include "
        f"target(s) in this tree{trunc}. Steering context — verify "
        f"against source; never treat as a verdict input."
    )


def directly_requestable_library(entry: dict[str, Any]) -> bool:
    """The "dual" QUERY (never a stored label): included by others
    AND carrying no file-scope direct-access guard."""
    return (entry.get("role") == "library"
            and not entry.get("direct_access_guard"))


def include_facts_for_file(
    graph: dict[str, Any],
    file_path: str,
    *,
    max_includers: int = 25,
    max_sample_sites: int = 5,
) -> dict[str, Any] | None:
    """Consumer-facing includer-set facts for one file.

    Returns None when the graph has no entry for the file. The census
    and qualifier are ALWAYS part of the result — an includer-set
    fact without its completeness qualifier is exactly the dishonest
    shape the design forbids. The artifact lives in a run directory
    (attacker-adjacent shapes), so every field is coerced.
    """
    files = graph.get("files")
    if not isinstance(files, dict):
        return None
    p = file_path.replace("\\", "/").removeprefix("./") if file_path else ""
    entry = files.get(file_path) or files.get(p)
    if not isinstance(entry, dict):
        return None

    # Enum and bound re-validation happens HERE, the one query every
    # consumer (audit prompt block, validate stage C) goes through:
    # the artifact is run-dir JSON, so a tampered keyword/position/
    # basis string must never flow verbatim into a prompt or a
    # findings file, and a planted multi-megabyte "includer" path
    # must not ride into every finding.
    includers: list[dict[str, Any]] = []
    for ref in (entry.get("included_by") or [])[:max_includers]:
        if not isinstance(ref, dict):
            continue
        line = ref.get("line")
        keyword = ref.get("keyword")
        position = ref.get("position")
        basis = ref.get("basis")
        includers.append({
            "file": str(ref.get("includer") or "")[:512],
            "line": line if isinstance(line, int)
            and not isinstance(line, bool) and line >= 0 else 0,
            "keyword": keyword if keyword in (
                "include", "include_once", "require", "require_once",
            ) else "include",
            "conditional": bool(ref.get("conditional", False)),
            "position": position if position in (
                "file_scope", "function_body") else "file_scope",
            "basis": basis if basis in (
                "tail_unique", "relative_literal") else "",
        })
    count = entry.get("includer_count")
    count = (count if isinstance(count, int)
             and not isinstance(count, bool) else len(includers))
    role = entry.get("role")
    role = role if role in ("library", "designed_entry") else "unknown"

    def _sample(records: Any, fmt) -> list[str]:
        out: list[str] = []
        for r in (records or []):
            if isinstance(r, dict):
                out.append(fmt(r)[:200])
            if len(out) >= max_sample_sites:
                break
        return out

    counts = _census_counts(graph)
    census: dict[str, Any]
    if counts is None:
        # A failed census renders as UNKNOWN, never as zeros — zeros
        # are a positive completeness claim.
        census = {"valid": False}
    else:
        ue, ut, tf = counts
        census = {
            "valid": True,
            "unresolved_edges": ue,
            "unwalked_targets": ut,
            "sample_unresolved_sites": _sample(
                graph.get("unresolved_edges"),
                lambda r: (f"{r.get('file', '?')}:{r.get('line', '?')} "
                           f"({r.get('shape', '?')})"),
            ),
            "sample_unwalked_targets": _sample(
                graph.get("unwalked_targets"),
                lambda r: str(r.get("path", "?")),
            ),
        }
        if tf:
            census["truncated_files"] = tf
    return {
        "tier": "hint",
        "role": role,
        "direct_access_guard": bool(entry.get("direct_access_guard")),
        "includer_total": count,
        "includers": includers,
        "census": census,
        "qualifier": census_qualifier(graph),
    }

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

#: Every ``basis`` value the build writes on an includer ref: phase
#: 1a's per-file resolutions (``relative_literal``, ``tail_unique``)
#: plus phase 1b's environment-grounded ``env_resolved`` (written on
#: walk resolutions and by the supersede that upgrades 1a bases).
#: :func:`include_facts_for_file` — the one query every consumer goes
#: through — re-validates artifact refs against exactly this
#: vocabulary; a basis missing here renders ``""``, indistinguishable
#: from an unknown/forged value. When adding a write site, extend
#: this tuple — the vocabulary test pins the module's write sites
#: against it.
REF_BASIS_VALUES: tuple[str, ...] = (
    "relative_literal", "tail_unique", "env_resolved")

# Bounds — the graph derives from hostile content; every list a
# planted tree can grow is capped, with full counts kept beside the
# truncated lists.
MAX_TREE_FILES = 200_000
MAX_CANDIDATES_PER_EDGE = 32
MAX_TREE_SCAN_EDGES_PER_RUN = 256
MAX_MATCH_PROBES_PER_RUN = 2_000_000
MAX_PREFIX_MEMBERS_RENDERED = 64
MAX_WALK_UNRESOLVED_RENDERED = 25
MAX_CLASS_ENTRIES_RENDERED = 25
MAX_VIA_RENDERED = 8
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
    defines_by_file: dict[str, list[dict[str, Any]]] = {}
    walk_meta: dict[str, dict[str, Any]] = {}
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
            defines_by_file[path] = [
                d for d in (cg.get("defines") or [])
                if isinstance(d, dict)
            ]
            walk_meta[path] = {
                "parse_errors": bool(cg.get("parse_errors")),
                "boundaries": [
                    b for b in (cg.get("boundaries") or [])
                    if isinstance(b, dict)
                ],
            }
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

    resolved_1a: dict[tuple[str, int], tuple[str, dict[str, Any]]] = {}

    def _resolve_to(target: str, basis: str,
                    includer: str, e: dict[str, Any]) -> None:
        ref = _edge_ref(includer, e)
        ref["basis"] = basis
        included_by.setdefault(target, []).append(ref)
        resolved_1a[(includer, ref["line"])] = (target, ref)
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

    # ---- Phase 1b: per-entry constant-environment walk -----------
    # Entry candidates come from the pass-1 includer index (zero
    # includers); the walk's environment-grounded resolutions then
    # SUPERSEDE the 1a per-file bases (the basis field was recorded
    # for exactly this), and roles are derived afterwards from the
    # merged index.
    walk_data: dict[str, Any] | None = None
    if edges_by_file:
        from core.inventory.include_walk import walk_entries
        pass1_entries = sorted(
            p for p in edges_by_file if not included_by.get(p))
        walk_data = walk_entries(
            pass1_entries,
            edges_by_file=edges_by_file,
            defines_by_file=defines_by_file,
            meta_by_file=walk_meta,
            tree_set=tree_set,
        )
        for (includer, line), rec in sorted(
                walk_data["env_resolutions"].items()):
            targets = sorted(rec["targets"])
            if len(targets) > 1:
                _bump(outcomes, "env_multi_target")
            old = resolved_1a.get((includer, line))
            for target in targets:
                if old is not None and old[0] == target:
                    old[1]["basis"] = "env_resolved"
                    _bump(outcomes, "env_confirmed_tail_basis")
                    continue
                ref = {
                    "includer": includer, "line": line,
                    "keyword": rec["keyword"],
                    "conditional": rec["conditional"],
                    "position": rec["position"],
                    "basis": "env_resolved",
                }
                included_by.setdefault(target, []).append(ref)
                why = _walkability_reason(target)
                if why is not None:
                    _note_unwalked(target, why, includer,
                                   {"line": line})
                if old is None:
                    _bump(outcomes, "env_resolved_from_census")
                else:
                    _bump(outcomes, "env_superseded_tail_mismatch")
            if old is not None and old[0] not in targets:
                if "\\" in old[0] or any("\\" in t for t in targets):
                    # Backslash-bearing paths are literal file names
                    # on POSIX runtimes — a separator-interpretation
                    # disagreement between the lanes must never evict
                    # the 1a base (it may be the file that actually
                    # runs). Keep both, census the disagreement.
                    _bump(outcomes, "env_tail_disagreement_kept")
                else:
                    # The suffix guess disagreed with the grounded
                    # resolution — the guessed ref comes out.
                    refs = included_by.get(old[0], [])
                    if old[1] in refs:
                        refs.remove(old[1])
                        if not refs:
                            included_by.pop(old[0], None)
            if old is None:
                # The edge left the 1a census (env grounded it).
                before = len(unresolved)
                unresolved[:] = [
                    u for u in unresolved
                    if not (u.get("file") == includer
                            and u.get("line") == line)
                ]
                if len(unresolved) != before:
                    _bump(outcomes, "env_census_discharged")

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

    if walk_data is not None:
        graph["walk"] = _render_walk(walk_data, files_out)
    return graph


def _render_walk(walk_data: dict[str, Any],
                 files_out: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """Fold the walk output into artifact shape: capped per-entry
    prefixes, the entry-class partition, and the query-ready
    ``file_facts`` reverse index (file → classes reaching it, with a
    guaranteed flag and one example receipt). Entries whose role
    flipped to library after the basis supersede drop out of the
    entry-class partition (their walks remain as prefix data)."""
    prefixes_out: dict[str, dict[str, Any]] = {}
    file_facts: dict[str, dict[str, Any]] = {}
    still_entries = {
        p for p, e in files_out.items()
        if e.get("role") == "designed_entry"
    }
    class_index: dict[str, dict[str, Any]] = {
        c["class"]: c for c in walk_data["entry_classes"]
    }

    for entry, p in sorted(walk_data["prefixes"].items()):
        members = p["members"]
        rendered = []
        for m in members[:MAX_PREFIX_MEMBERS_RENDERED]:
            r: dict[str, Any] = {
                "file": m["file"],
                "guaranteed": bool(m["guaranteed"]),
                "via": list(m["via"][-MAX_VIA_RENDERED:]),
            }
            if len(m["via"]) > MAX_VIA_RENDERED:
                r["via_total"] = len(m["via"])  # elision is explicit
            for k in ("boundary_line", "unwalked", "parse_errors",
                      "root"):
                if m.get(k) is not None and m.get(k) is not False:
                    r[k] = m[k]
            rendered.append(r)
        entry_out: dict[str, Any] = {
            "class": p["class"] if entry in still_entries else None,
            "members": rendered,
            "member_total": len(members),
            "unresolved": p["unresolved"][:MAX_WALK_UNRESOLVED_RENDERED],
            "unresolved_total": len(p["unresolved"]),
        }
        if p["closure_truncated"]:
            entry_out["closure_truncated"] = True
        if p.get("unresolved_overflow"):
            entry_out["unresolved_truncated"] = True
        if len(members) > MAX_PREFIX_MEMBERS_RENDERED:
            entry_out["members_render_truncated"] = True
        prefixes_out[entry] = entry_out

        if p["class"] is None or entry not in still_entries:
            continue
        cls = class_index.get(p["class"])
        guaranteed_set = set(
            cls["guaranteed_prefix"]) if cls else set()
        # Order-aware: "executed BEFORE this file" means members that
        # PRECEDE it in this entry's execution order — a file
        # included after the target must never render as having run
        # first. The per-slot set intersects across the class's
        # entries (different entries may reach the file at different
        # points).
        preceding_guaranteed: list[str] = []
        for m in members:
            if m.get("root"):
                continue
            ff = file_facts.setdefault(m["file"], {"classes": {}})
            slot = ff["classes"].get(p["class"])
            if slot is None:
                slot = {
                    "guaranteed": m["file"] in guaranteed_set,
                    "entries_reaching": 0,
                    "receipt": " -> ".join(
                        [entry] + list(m["via"][-MAX_VIA_RENDERED:])),
                    "preceding": sorted(preceding_guaranteed),
                }
                ff["classes"][p["class"]] = slot
            else:
                slot["preceding"] = sorted(
                    set(slot.get("preceding") or [])
                    & set(preceding_guaranteed))
            slot["entries_reaching"] += 1
            if m["guaranteed"]:
                preceding_guaranteed.append(m["file"])

    entry_classes = []
    for c in walk_data["entry_classes"]:
        live = [e for e in c["entries"] if e in still_entries]
        if not live:
            continue
        entry_classes.append({
            "class": c["class"],
            "entry_count": len(live),
            "entries": live[:MAX_CLASS_ENTRIES_RENDERED],
            "guaranteed_prefix": c["guaranteed_prefix"],
        })

    return {
        "entries_walked": walk_data["entries_walked"],
        "entries_truncated": walk_data["entries_truncated"],
        # Census fact, not a detail: bootstrap_context_for_file reads
        # the RENDERED walk section, so a dropped flag here would
        # silently erase "(global walk budget exhausted)" from every
        # consumer's qualifier.
        "budget_exhausted": bool(walk_data.get("budget_exhausted")),
        "outcomes": walk_data["outcomes"],
        "entry_classes": entry_classes,
        "prefixes": prefixes_out,
        "file_facts": {
            f: {"classes": [
                {"class": cid, **slot}
                for cid, slot in sorted(ff["classes"].items())
            ]}
            for f, ff in sorted(file_facts.items())
        },
    }


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


def _norm_key(file_path: str) -> str:
    return (file_path.replace("\\", "/").removeprefix("./")
            if file_path else "")


def executed_before(
    graph: dict[str, Any], entry: str, file_path: str,
    line: int | None = None,
) -> bool | None:
    """Whether ``file_path``'s file-scope code (above ``line`` when
    given) is GUARANTEED to have executed once ``entry`` reaches its
    own code — the §1a bootstrap-gate query. Returns None (unknown)
    when there is no walk data, the entry was not walked, or the
    prefix rendering was truncated before the file; never guesses."""
    walk = graph.get("walk")
    if not isinstance(walk, dict):
        return None
    prefix = (walk.get("prefixes") or {}).get(_norm_key(entry))
    if not isinstance(prefix, dict):
        return None
    target = _norm_key(file_path)
    for m in prefix.get("members") or []:
        if not isinstance(m, dict) or m.get("file") != target:
            continue
        if m.get("parse_errors"):
            # The member's own tree is ERROR-bearing: its recorded
            # boundary and line structure are not trustworthy enough
            # for a yes/no at line granularity — unknown, never a
            # guess.
            return None
        if not m.get("guaranteed"):
            return False
        b = m.get("boundary_line")
        if (line is not None and isinstance(b, int)
                and not isinstance(b, bool) and line >= b):
            return False  # below the member's straight-line boundary
        return True
    if prefix.get("members_render_truncated") or prefix.get(
            "closure_truncated"):
        return None  # honest unknown — the prefix list is partial
    return False


def bootstrap_context_for_file(
    graph: dict[str, Any], file_path: str,
    *, max_classes: int = 5, max_prefix: int = 15,
) -> dict[str, Any] | None:
    """The §5 ``bootstrap_context`` object for one file: the entry
    classes that reach it, the guaranteed-prefix files shared by
    EVERY guaranteed-reaching class (the facts that hold on every
    stock path), and the MANDATORY census. Returns None when there is
    no walk data, the file is unknown to the walk, or the graph
    census fails validation — a bootstrap_context without a valid
    census must never exist (hint tier, like everything here)."""
    walk = graph.get("walk")
    if not isinstance(walk, dict):
        return None
    counts = _census_counts(graph)
    if counts is None:
        return None  # never an unqualified gate fact
    ue, ut, tf = counts
    path = _norm_key(file_path)
    file_facts = walk.get("file_facts") or {}
    prefixes = walk.get("prefixes") or {}
    class_rows = {c.get("class"): c
                  for c in walk.get("entry_classes") or []
                  if isinstance(c, dict)}

    # ALL reaching classes participate in the shared-prefix
    # intersection below; only the rendered list is capped — an
    # intersection over a capped subset would overclaim "on every
    # stock path".
    classes: list[dict[str, Any]] = []
    note: str | None = None
    ff = file_facts.get(path)
    if isinstance(ff, dict):
        for row in (ff.get("classes") or []):
            if not isinstance(row, dict):
                continue
            cid = row.get("class")
            cls = class_rows.get(cid) or {}
            classes.append({
                "class": str(cid or ""),
                "guaranteed": bool(row.get("guaranteed")),
                "entry_count": cls.get("entry_count", 0),
                "entries": list(cls.get("entries") or [])[:5],
                "receipt": str(row.get("receipt") or "")[:400],
                "_preceding": [x for x in (row.get("preceding") or [])
                               if isinstance(x, str)],
            })
    own = prefixes.get(path)
    if isinstance(own, dict) and own.get("class"):
        cls = class_rows.get(own["class"]) or {}
        classes.insert(0, {
            "class": str(own["class"]),
            "guaranteed": True,
            "entry_count": cls.get("entry_count", 0),
            "entries": list(cls.get("entries") or [])[:5],
            "receipt": path + " (is itself an entry of this class)",
            "_preceding": [],  # nothing precedes the entry itself
        })
        note = ("this file is a designed entry: its class prefix is "
                "complete at end-of-bootstrap — for code inside the "
                "entry itself, verify include order above the "
                "finding line")
    if not classes:
        return None
    # Rendering order: guaranteed classes first, biggest first (the
    # cap below must not hide the guaranteed ones behind
    # reachability-only rows).
    classes.sort(key=lambda c: (not c["guaranteed"],
                                -c["entry_count"], c["class"]))

    # Guaranteed-PRECEDING prefix shared by EVERY guaranteed-reaching
    # class — files whose file-scope code ran BEFORE this file on
    # every stock path. Order-aware by construction: the per-slot
    # preceding sets were collected in execution order, so a file
    # included AFTER the target never renders as having run first.
    guaranteed_classes = [c for c in classes if c["guaranteed"]]
    shared: list[str] = []
    if guaranteed_classes:
        sets = [set(c.get("_preceding") or [])
                for c in guaranteed_classes]
        shared = (sorted(set.intersection(*sets) - {path})
                  if sets else [])
    if shared:
        # Render order must not hide the load-bearing row: an
        # alphabetical slice of a shared set larger than the cap can
        # cut off exactly the file that gates the whole surface.
        # Execution pre-order from a witness entry (first entry of
        # the largest guaranteed class) fixes that mechanically: the
        # walk's member lists are pre-order (an includer renders
        # before its children), and the include-the-gate-first idiom
        # puts the gate at the top of every gated entry — so the
        # outermost first includes fill the cap, page-local helpers
        # trail. Files absent from the witness's (render-capped)
        # member list keep a deterministic name-sorted tail; the
        # true total + an explicit marker are carried below whenever
        # the cap bites.
        order: dict[str, int] = {}
        witness_entries = guaranteed_classes[0].get("entries") or []
        if witness_entries:
            wp = prefixes.get(str(witness_entries[0]))
            if isinstance(wp, dict):
                for i, m in enumerate(wp.get("members") or []):
                    if isinstance(m, dict) and isinstance(
                            m.get("file"), str):
                        order.setdefault(m["file"], i)
        unseen = len(order)
        shared.sort(key=lambda f: (order.get(f, unseen), f))
    guaranteed_prefix = []
    for f in shared[:max_prefix]:
        row: dict[str, Any] = {"file": f, "guaranteed": True}
        f_ff = file_facts.get(f)
        if isinstance(f_ff, dict):
            for cr in f_ff.get("classes") or []:
                if (isinstance(cr, dict)
                        and cr.get("class") == guaranteed_classes[0]["class"]):
                    row["via"] = str(cr.get("receipt") or "")[:400]
                    break
        guaranteed_prefix.append(row)

    walk_outcomes = walk.get("outcomes") or {}
    rendered_classes = []
    for c in classes[:max_classes]:
        rc = dict(c)
        rc.pop("_preceding", None)  # internal to the intersection
        rendered_classes.append(rc)
    ctx: dict[str, Any] = {
        "tier": "hint",
        "entry_class_total": len(classes),
        "entry_classes": rendered_classes,
        "guaranteed_prefix": guaranteed_prefix,
        "guaranteed_prefix_total": len(shared),
        "unresolved_census": {
            "unresolved_edges": ue,
            "unwalked_targets": ut,
            "walk_unresolved": sum(
                v for k, v in walk_outcomes.items()
                if isinstance(v, int) and k.startswith("edge_env_")
                and k != "edge_env_resolved"),
            "sites": [
                f"{r.get('file', '?')}:{r.get('line', '?')}"
                for r in (graph.get("unresolved_edges") or [])[:5]
                if isinstance(r, dict)
            ],
        },
        "qualifier": census_qualifier(graph),
        "invariants": [],
    }
    if len(shared) > max_prefix:
        ctx["guaranteed_prefix_truncated"] = True  # elision explicit
    if tf:
        ctx["unresolved_census"]["truncated_files"] = tf
    # Walk-truncation joins the census: unclassed/uncapped/budgeted
    # entries shrink the class partition, and an includer-set or
    # gate fact quoted without that qualifier would overstate "every
    # stock path".
    walk_truncated = (
        int(walk_outcomes.get("entries_unclassed_truncated") or 0)
        + int(walk_outcomes.get("entries_truncated") or 0))
    if walk.get("budget_exhausted"):
        ctx["unresolved_census"]["walk_budget_exhausted"] = True
    if walk_truncated:
        ctx["unresolved_census"]["walk_truncated_entries"] = walk_truncated
    if walk_truncated or walk.get("budget_exhausted"):
        ctx["qualifier"] = (
            ctx["qualifier"].rstrip()
            + f" The environment walk was TRUNCATED for "
              f"{walk_truncated} entr"
            + ("y" if walk_truncated == 1 else "ies")
            + (" (global walk budget exhausted)"
               if walk.get("budget_exhausted") else "")
            + " — their entry classes are absent from these facts.")
    if note:
        ctx["note"] = note
    return ctx


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
            "basis": basis if basis in REF_BASIS_VALUES else "",
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

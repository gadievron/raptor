"""Supplied dependency paths and ownership deltas; missing data is not an empty graph."""
from __future__ import annotations

from collections import defaultdict, deque

from .model import selected


def dependency_changes(pairs):
    aliases = {(a.scope, a.id): b.id for a, b in pairs}
    changes, unavailable = [], []
    compared = 0
    for a, b in pairs:
        if not a.graph_supplied or not b.graph_supplied:
            unavailable.append({"before": a.id, "after": b.id})
            continue
        compared += 1
        old_targets = {aliases.get((a.scope, ref), "before:" + ref): ref for ref in a.children}
        new_targets = set(b.children)
        for key in sorted(old_targets.keys() - new_targets):
            changes.append({"kind": "dependency_removed", "before_source": a.id, "after_source": b.id,
                            "target": old_targets[key]})
        for key in sorted(new_targets - old_targets.keys()):
            changes.append({"kind": "dependency_added", "before_source": a.id, "after_source": b.id, "target": key})
    return {"compared_records": compared, "unavailable": unavailable, "changes": changes}


def _ownership(coverage):
    if not coverage or (coverage.get("metrics") or {}).get("scanner_unidentified_executables") is None:
        return None
    by_path = defaultdict(list)
    for field, basis in (("inventory_ownership", "package_checksum"), ("native_identity_matches", "native_identity"),
                         ("native_declaration_matches", "build_declaration"), ("inventory_candidates", "unexplained")):
        rows = coverage.get(field, [])
        if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
            raise ValueError("invalid recorded ownership inventory")
        for row in rows:
            path = row.get("path")
            if not isinstance(path, str):
                raise ValueError("invalid recorded ownership path")
            identity = row.get("identity") or row
            if not isinstance(identity, dict):
                raise ValueError("invalid recorded owner identity")
            by_path[path].append({"path": path, "layer_id": row.get("layer_id"), "sha256": row.get("sha256"),
                                  "owner": identity.get("name"), "version": identity.get("version"),
                                  "basis": row.get("evidence_kind", basis)})
    return by_path


def ownership_changes(before, after):
    a, b = _ownership(before.coverage), _ownership(after.coverage)
    if a is None or b is None:
        return {"status": "not_compared", "reason": "ownership inventory unavailable on one or both sides", "changes": [], "ambiguous": []}
    changes, ambiguous = [], []
    def add(kind, old, new, attention=False):
        changes.append({"kind": kind, "before": old, "after": new, "attention": attention})
    for path in sorted(a.keys() | b.keys()):
        old, new = a.get(path, []), b.get(path, [])
        if len(old) > 1 or len(new) > 1:
            ambiguous.append({"path": path, "before": old, "after": new})
            continue
        if not old:
            add("ownership_check_added", None, new[0], new[0]["basis"] == "unexplained")
        elif not new:
            add("ownership_check_removed", old[0], None)
        else:
            old, new = old[0], new[0]
            if old["basis"] != "unexplained" and new["basis"] == "unexplained":
                add("new_unexplained_executable", old, new, True)
            elif old["basis"] == "unexplained" and new["basis"] != "unexplained":
                add("resolved_executable_ownership", old, new)
            for key, kind in (("owner", "executable_owner_changed"), ("version", "owner_version_changed"),
                              ("basis", "ownership_evidence_changed"), ("sha256", "executable_content_changed")):
                if old[key] != new[key]:
                    add(kind, old, new)
    return {"status": "compared", "changes": changes, "ambiguous": ambiguous,
            "scope": "scanner-unidentified executable ownership checks; absence is not proof a file was removed"}


def explain(inventory, package, *, root=None, max_paths=20, max_depth=32):
    if not 1 <= max_paths <= 1000 or not 1 <= max_depth <= 128:
        raise ValueError("path/depth budgets are outside supported ranges")
    matches = selected(inventory, package=package)
    if not matches:
        raise ValueError("package not found in inventory")
    nodes = {}
    for row in inventory.records:
        if row.id in nodes:
            raise ValueError("ambiguous dependency graph identifier")
        nodes[row.id] = row
    roots = {p.id for p in selected(inventory, package=root)} if root else set()
    if root and not roots:
        raise ValueError("requested root not found")
    results, total_visited, total_queued, total_edges = [], 0, 0, 0
    for target in matches:
        if total_queued >= 10_000 or total_visited + total_edges >= 10_000:
            break
        queue = deque([(target.id,)])
        total_queued += 1
        paths, truncated = [], False
        while queue and len(paths) < max_paths and total_visited + total_edges < 10_000:
            path = queue.popleft()
            current = nodes[path[-1]]
            total_visited += 1
            cycle, exhausted = False, False
            parents, seen = [], set()
            if current.id not in roots and len(path) < max_depth:
                ancestors = set(path)
                for ref in current.parents:
                    if total_visited + total_edges >= 10_000:
                        exhausted = True
                        break
                    total_edges += 1
                    if ref in ancestors:
                        cycle = True
                    elif ref in nodes and ref not in seen:
                        parents.append(ref)
                        seen.add(ref)
            if exhausted:
                truncated = True
                break
            if current.id in roots or not parents or len(path) >= max_depth:
                truncated |= bool(current.parents and current.id not in roots and len(path) >= max_depth)
                paths.append({"nodes": [{"id": nodes[ref].id, "name": nodes[ref].name, "version": nodes[ref].version,
                                          "scope": nodes[ref].scope} for ref in reversed(path)],
                              "requested_root_reached": current.id in roots, "cycle_boundary": cycle})
            else:
                remaining = max(0, 10_000 - total_queued)
                truncated |= len(parents) > remaining
                queue.extend(path + (parent,) for parent in parents[:remaining])
                total_queued += min(len(parents), remaining)
        truncated |= bool(queue)
        results.append({"id": target.id, "paths": paths, "truncated": truncated,
                        "outgoing_data_supplied": target.graph_supplied})
    return {"format": "raptor-sbom-dependency-paths", "schema_version": 1, "source": inventory.source_sha256,
            "query": package, "requested_roots": sorted(roots), "results": results,
            "work_budget": {"visited": total_visited, "processed_edges": total_edges, "used": total_visited + total_edges,
                            "maximum": 10_000, "unit": "node visits and parent references",
                            "unexamined_occurrences": len(matches) - len(results)},
            "limitations": ["Paths use supplied relationships only; a boundary without parents does not prove a direct dependency."]}

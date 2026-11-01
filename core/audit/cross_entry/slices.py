"""Consumer-centered candidate selection, with bounded exploration and receipts."""
from __future__ import annotations

from collections import defaultdict, deque
import time
from typing import Iterable

from .model import AccessIndex, Limits, StudySlice, digest


def entry_paths(index: AccessIndex, target: str, depth: int, parents=None) -> list[list[str]]:
    if parents is None:
        parents = defaultdict(set)
        for r in index.relations:
            if r.kind == "call":
                parents[r.target].add(r.source)
    queue = deque([[target]])
    paths = []
    while queue and len(paths) < 16:
        trail = queue.popleft()
        if trail[0] in index.entries:
            paths.append(trail)
        if len(trail) <= depth:
            for parent in sorted(parents[trail[0]]):
                if parent not in trail:
                    queue.append([parent]+trail)
        # Bound both depth and breadth even in dense cyclic call graphs.
        if len(queue) > 256:
            queue = deque(list(queue)[:256])
    return paths


def build_slices(index: AccessIndex, report_functions: Iterable[str] | None = None,
                 *, limits: Limits | None = None, focus_functions: Iterable[str] = (),
                 skip_consumers: Iterable[str] = ()) -> tuple[list[StudySlice], list[dict]]:
    limits = limits or Limits()
    requested = set(report_functions) if report_functions is not None else None
    focus = set(focus_functions)
    skipped = set(skip_consumers)
    per_function = defaultdict(list)
    by_type = defaultdict(set)
    by_path = defaultdict(set)
    signatures = defaultdict(set)
    mutations = defaultdict(set)
    children = defaultdict(set)
    parents = defaultdict(set)
    callbacks = defaultdict(list)
    for row in index.callbacks:
        callbacks[row["owner_type"],row["slot"],row["target"]].append(row)
    for a in index.accesses:
        per_function[a.function].append(a)
        if a.resolution != "unresolved":
            by_type[a.type_id].add(a.function)
            key = (a.type_id,a.member_path)
            signatures[a.function].add(key)
            by_path[key].add(a.function)
            if a.operation != "read":
                mutations[a.function].add(key)
    for r in index.relations:
        if r.kind == "call":
            children[r.source].add(r.target)
            parents[r.target].add(r.source)
    candidates = []
    unassembled = []
    started = time.monotonic()
    role_cache = {}
    def roles(f):
        if f not in role_cache:
            role_cache[f] = {reg.get("field","") for p in entry_paths(index,f,limits.graph_depth,parents)
                             for reg in index.entries.get(p[0],[]) if reg.get("field")}
        return role_cache[f]
    for fid, fn in sorted(index.functions.items()):
        if fid in skipped:
            continue
        if requested is not None and fid not in requested and f"{fn.file}:{fn.name}" not in requested:
            continue
        if time.monotonic()-started > limits.graph_seconds:
            unassembled.append({"consumer":fid,"reason":"graph_budget"})
            continue
        accesses = per_function[fid]
        # Wrappers inherit their concrete callee's accesses, with the actual
        # helper retained in the slice. No field or entry-count threshold.
        neighborhood = {fid}
        frontier = {fid}
        graph_truncated = False
        for _ in range(limits.graph_depth):
            frontier = {t for f in frontier for t in children[f]} - neighborhood
            neighborhood |= frontier
            if len(neighborhood) > limits.functions_per_slice * 4:
                graph_truncated = True
                break
        if any(children[f]-neighborhood for f in frontier):
            graph_truncated = True
        seed_accesses = accesses + [a for f in sorted(neighborhood - {fid}) for a in per_function[f]]
        if not seed_accesses:
            continue
        types = {a.type_id for a in seed_accesses if a.resolution != "unresolved"}
        resources = {a.type_id+":"+a.member_path for a in seed_accesses}
        # Follow syntax-backed cross-type resource transfers in either direction.
        linked = set()
        for r in index.relations:
            if r.kind == "resource_assignment" and (r.source in resources or r.target in resources):
                linked.update((r.source, r.target))
        peers = {f for t in types for f in by_type[t]}
        peers |= {a.function for a in index.accesses if a.type_id+":"+a.member_path in linked}
        # Compare typed paths, once per function, not raw field spelling or
        # touch counts. Large setup drivers must not win simply by repeating
        # generic scatterlist/request fields. Prefer direct consumer state
        # over state observed only in its transitive callees.
        core_paths = signatures[fid] or {key for f in neighborhood for key in signatures[f]}
        related_paths = {key for f in neighborhood for key in signatures[f]}
        consumer_roles = roles(fid)
        def weight(paths: set) -> int:
            return sum(10_000//max(1,len(by_path[p])) for p in paths)
        def rank(f: str) -> tuple:
            direct = signatures[f] & core_paths
            related = signatures[f] & related_paths
            cross_role = bool(direct and consumer_roles and roles(f)-consumer_roles)
            return (-int(cross_role),-weight(direct),-weight(direct & mutations[f]),
                    -weight(related),-weight(related & mutations[f]),f)
        peer_order = sorted(peers-neighborhood,key=rank)
        # Reserve early space for sibling producers and their dispatch
        # wrappers. Deep consumer callees must not crowd them out.
        anchors = [fid]+peer_order[:3]
        anchor_paths = [p for f in anchors for p in entry_paths(index,f,limits.graph_depth,parents)]
        # These are conditional edges, kept separate from the resolved call
        # graph and its entry-point reachability. Retain every indexed target
        # row even when only some source excerpts fit in this study slice.
        dispatch_rows = []
        dispatch_callers = set()
        for call in index.calls:
            if call.caller not in neighborhood or not call.dispatch_candidates:
                continue
            dispatch_callers.add(call.caller)
            if call.dispatch_bindings:
                dispatch_rows.extend(call.dispatch_bindings)
                continue
            for target in call.dispatch_candidates:
                for row in callbacks[call.dispatch_type,call.dispatch_slot,target]:
                    dispatch_rows.append({**row,"caller":call.caller,"call_line":call.line,
                                          "arguments":call.arguments})
        dispatch_deferred = []
        if dispatch_rows:
            from .dispatch import expand_dispatch_paths
            dispatch_rows,dispatch_deferred = expand_dispatch_paths(index,dispatch_rows,limits)
        ordered = list(dict.fromkeys([fid]+peer_order[:1]
                       +sorted(focus & set(index.functions)-{fid})
                       +sorted(dispatch_callers)
                       +peer_order[1:3]
                       +[f for p in anchor_paths for f in p]
                       +sorted(neighborhood-{fid},key=rank)+peer_order[3:]))
        reasons = ["consumer_and_repeated_entry"]
        if peers - neighborhood:
            reasons.append("shared_type_candidates")
            reasons.append("unique_typed_path_affinity")
        if linked:
            reasons.append("cross_type_resource_assignment")
        if dispatch_rows:
            reasons.append("conditional_callback_dispatch")
        effects = {a.operation for a in seed_accesses}
        if effects & {"address_escape","helper_argument","unresolved_effect"}:
            reasons.append("unknown_helper_effects")
        if effects & {"direct_write","read_modify_write","indirect_write"}:
            reasons.append("state_transition")
        keep = ordered[:limits.functions_per_slice]
        truncated = []
        truncated.extend(f"{d['reason']}:{d['target']}" for d in dispatch_deferred)
        if graph_truncated:
            truncated.append("graph_expansion")
        if len(ordered) > len(keep):
            truncated.append(f"functions:{len(ordered)-len(keep)}")
        # Include causal wrapper paths to producers as well as consumers.
        paths = [p for f in keep for p in entry_paths(index,f,limits.graph_depth,parents)]
        for f in [f for p in paths for f in p]:
            if f not in keep and len(keep) < limits.functions_per_slice:
                keep.append(f)
            elif f not in keep:
                truncated.append("entry_path_body")
        if len(paths) > 32:
            truncated.append(f"entry_paths:{len(paths)-32}")
            paths = paths[:32]
        chunks = []
        dispatch_budget = limits.source_chars//3 if dispatch_rows else 0
        remaining = limits.source_chars-dispatch_budget
        for f in keep:
            body = index.functions[f].source
            label = f"\nFUNCTION {f} ({index.functions[f].file}:{index.functions[f].start})\n"
            segment = label + body
            if len(segment) > remaining:
                truncated.append(f"source:{f}")
            chunks.append(segment[:remaining])
            remaining = max(0, remaining-len(segment))
        if dispatch_rows:
            from .dispatch import dispatch_catalogue
            fragments,omitted = dispatch_catalogue(index,dispatch_rows,dispatch_budget+remaining)
            chunks.extend(rendered for _,rendered in fragments)
            if omitted:
                truncated.append(f"dispatch_fragments:{omitted}")
        relevant = [a for f in keep for a in per_function[f]]
        unresolved = [f"{c.caller}:{c.line}:{c.name}" for c in index.calls if c.caller in keep and len(c.targets) != 1]
        if any(a.resolution != "resolved" for a in relevant):
            unresolved.append("partial_or_unresolved_type_identity")
        unresolved.append("same_object_and_call_order_require_verification")
        if dispatch_rows:
            unresolved.append("callback_selection_and_installation_guards_unverified")
        if not index.coverage["complete"]:
            unresolved.append("context_incomplete")
        if len(unresolved) > 64:
            truncated.append(f"unresolved_edges:{len(unresolved)-64}")
            unresolved = unresolved[:64]
        score = 4*len(reasons) + min(8,len(peers-neighborhood))
        fingerprint = digest({"selection_version":4,"index":index.fingerprint,"consumer":fid,"functions":keep,
                              "dispatch":dispatch_rows,"focus":sorted(focus),"limits":limits.content_settings()})
        inventory = list(dict.fromkeys(ordered+[r["target"] for r in dispatch_rows]))
        unit_id = digest([fid,sorted(focus)])[:20] if focus else digest(fid)[:20]
        candidates.append(StudySlice(unit_id,fid,keep,[a.id for a in relevant],paths,reasons,
                                     sorted(set(unresolved)),sorted(set(truncated)),score,"\n".join(chunks),fingerprint,dispatch_rows,inventory,sorted(focus)))
    ranked = sorted(candidates,key=lambda s:(-s.score,s.consumer))
    # Reserve one fifth for deterministic exploration instead of always
    # dropping the weak tail. Partition the remaining ranked candidates evenly.
    explore = min(len(ranked), max(1, limits.max_slices//5)) if limits.max_slices else 0
    head = max(0,limits.max_slices-explore)
    chosen = ranked[:head]
    tail = sorted(ranked[head:],key=lambda s:s.consumer)
    if tail and explore:
        slots = min(explore,len(tail))
        chosen += [tail[i*len(tail)//slots] for i in range(slots)]
    selected = {s.id for s in chosen}
    deferred = [{"id":s.id,"consumer":s.consumer,"score":s.score,"reason":"slice_budget"}
                for s in ranked if s.id not in selected]
    return chosen, deferred+unassembled

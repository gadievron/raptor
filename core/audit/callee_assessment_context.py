"""Canonical ready callee assessments shared by caller review stages.

Relations and model assessments are advisory inputs, not verification facts.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from hashlib import sha256
import json
import re
from typing import Any

MAX_CALLEE_ASSESSMENTS = 16
MAX_CALLEE_ASSUMPTIONS = 4
_READY_STATUSES = frozenset(("clean", "finding", "suspicious"))
_POSITIVE_STATUSES = frozenset(("finding", "suspicious"))
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


@dataclass(frozen=True)
class CalleeAssessmentBundle:
    payload: dict[str, Any]
    contributors: tuple[Any, ...]


def _occurrence(outcome):
    file = getattr(outcome, "file", None)
    function = getattr(outcome, "function", None)
    line = getattr(outcome, "line", 0)
    if not isinstance(file, str) or not file or not isinstance(function, str) or not function:
        return None
    return file, function, line if type(line) is int else 0


def assessment_occurrence_anchor(occurrence):
    return sha256(json.dumps(occurrence, ensure_ascii=True, separators=(",", ":")).encode("ascii")).hexdigest()


def _bounded_text(value, limit):
    return value[:limit] if isinstance(value, str) else ""


def _scope_note(outcome):
    scope = getattr(outcome, "review_input_scope", None)
    identity = getattr(getattr(scope, "origin", None), "source_identity", None)
    digest = getattr(identity, "sha256", None)
    if not isinstance(digest, str) or _SHA256.fullmatch(digest) is None:
        return "Original callee source binding unavailable; advisory assessment only."
    record = getattr(scope, "record_digest", None)
    record_note = f"; input record {record}" if isinstance(record, str) and _SHA256.fullmatch(record) else ""
    return f"sha256 {digest}{record_note}; original captured inputs, not verification evidence."


def build_callee_assessment_bundle(caller, outcomes, *, inventory=None, context_map=None,
                                   include_graph=True, target_root=None):
    """Build the same currently-ready union regardless of the triggering stage.

    Namespace ambiguity is resolved against all canonical outcomes before
    freshness or readiness filtering. A stale declaration therefore cannot
    make a different same-name declaration appear uniquely resolved.
    """
    grouped = defaultdict(list)
    aliases = defaultdict(set)
    for outcome in outcomes:
        occurrence = _occurrence(outcome)
        if occurrence is None:
            continue
        grouped[occurrence].append(outcome)
        file, function, line = occurrence
        for alias in (function, f"{file}:{function}", f"{file}:{function}:{line}"):
            aliases[alias].add(occurrence)

    limits = Counter()
    related = set()
    assumptions = defaultdict(set)

    def resolve(name, *, file=None, line=None, source):
        if not isinstance(name, str) or not name:
            limits[f"unresolved_{source}"] += 1
            return None
        if file is not None and (not isinstance(file, str) or not file):
            limits[f"unresolved_{source}"] += 1
            return None
        if line is not None and (type(line) is not int or line <= 0):
            limits[f"unresolved_{source}"] += 1
            return None
        matches = aliases.get(name, set())
        if file is not None:
            matches = {key for key in matches if key[0] == file}
        if line is not None:
            matches = {key for key in matches if key[2] == line}
        if len(matches) != 1 or any(len(grouped[key]) != 1 for key in matches):
            limits[f"ambiguous_{source}" if matches else f"unresolved_{source}"] += 1
            return None
        return next(iter(matches))

    review = getattr(caller, "review_result", None)
    dependencies = review.get("relies_on", ()) if isinstance(review, dict) else ()
    if not isinstance(dependencies, (list, tuple)):
        dependencies = ()
        limits["unresolved_explicit"] += 1
    # Duplicate declarations of the same explicit relation are one input.
    seen_dependencies = set()
    for dependency in dependencies:
        if not isinstance(dependency, dict):
            limits["unresolved_explicit"] += 1
            continue
        name = dependency.get("callee")
        file = dependency.get("file")
        line = dependency.get("line_start", dependency.get("line"))
        assumption = dependency.get("assumption", "")
        if not isinstance(assumption, str):
            limits["unresolved_explicit"] += 1
            continue
        signature = (name, file, line, assumption)
        if all(isinstance(item, (str, int, type(None))) for item in signature):
            if signature in seen_dependencies:
                continue
            seen_dependencies.add(signature)
        key = resolve(name, file=file, line=line, source="explicit")
        if key is not None:
            related.add(key)
            if assumption:
                assumptions[key].add(_bounded_text(assumption, 300))

    caller_occurrence = _occurrence(caller)
    use_context_map = False
    if include_graph and caller_occurrence is not None:
        if inventory and caller_occurrence[2] > 0:
            from core.analysis.reachability import InternalFunction, callees_of

            try:
                graph = callees_of(inventory, InternalFunction(*caller_occurrence))
                limits["uncertain_graph"] += len(graph.uncertain) + int(graph.has_method_dispatch)
                for callee in graph.definitive:
                    if isinstance(callee, InternalFunction):
                        key = (callee.file_path, callee.name, callee.line)
                        if key in grouped and len(grouped[key]) == 1:
                            related.add(key)
                        else:
                            limits["ambiguous_graph" if key in grouped else "unavailable_graph"] += 1
                    else:
                        limits["external_graph"] += 1
                use_context_map = not graph.definitive and not graph.uncertain and not graph.has_method_dispatch
            except (AttributeError, KeyError, TypeError, ValueError, RuntimeError):
                limits["graph_unavailable"] += 1
                use_context_map = True
        else:
            use_context_map = True

    if include_graph and use_context_map and isinstance(context_map, dict) and caller_occurrence is not None:
        caller_names = {key for key in grouped if key[:2] == caller_occurrence[:2]}
        edges = context_map.get("call_edges", ())
        if not isinstance(edges, (list, tuple)):
            edges = ()
            limits["graph_unavailable"] += 1
        seen_edges = set()
        for edge in edges:
            if not isinstance(edge, dict) or (edge.get("caller_file"), edge.get("caller")) != caller_occurrence[:2]:
                continue
            caller_line = edge.get("caller_line_start", edge.get("caller_line", 0))
            if type(caller_line) is not int or caller_line < 0:
                limits["ambiguous_graph"] += 1
                continue
            if caller_line:
                if caller_line != caller_occurrence[2]:
                    continue
            elif len(caller_names) != 1 or len(grouped.get(caller_occurrence, ())) != 1:
                limits["ambiguous_graph"] += 1
                continue
            name = edge.get("callee")
            file = edge.get("callee_file")
            line = edge.get("callee_line_start", edge.get("callee_line"))
            signature = (name, file, line)
            if all(isinstance(item, (str, int, type(None))) for item in signature):
                if signature in seen_edges:
                    continue
                seen_edges.add(signature)
            key = resolve(name, file=file, line=line, source="graph")
            if key is not None:
                related.add(key)

    ready = []
    for key in sorted(related):
        outcome = grouped[key][0]
        if key == caller_occurrence:
            continue
        if key[2] <= 0 or getattr(outcome, "status", None) not in _READY_STATUSES:
            limits["assessment_unavailable"] += 1
            continue
        scope = getattr(outcome, "review_input_scope", None)
        if scope is not None:
            origin = getattr(scope, "origin", None)
            if (getattr(origin, "file", None), getattr(origin, "function", None),
                    getattr(origin, "line_start", None)) != key:
                limits["invalid_original_scope"] += 1
                continue
        if target_root is not None and scope is not None:
            try:
                current = scope.current(target_root)
            except (AttributeError, OSError, TypeError, ValueError, RuntimeError):
                current = False
            if not current:
                limits["stale_assessment"] += 1
                continue
        ready.append((key, outcome))
    if not any(outcome.status in _POSITIVE_STATUSES for _, outcome in ready):
        return None
    # Keep a triggering concern in a bounded bundle; report every omitted row.
    selected = sorted(ready, key=lambda item: (item[1].status not in _POSITIVE_STATUSES, item[0]))[:MAX_CALLEE_ASSESSMENTS]
    limits["overflow_assessment"] += len(ready) - len(selected)
    selected.sort(key=lambda item: item[0])
    limits["overflow_assumption"] += sum(max(0, len(assumptions[key]) - MAX_CALLEE_ASSUMPTIONS)
                                         for key, _ in selected)
    rows = [{"file": key[0], "function": key[1], "line_start": key[2],
             "occurrence_anchor": assessment_occurrence_anchor(key),
             "status": outcome.status, "hypothesis": _bounded_text(getattr(outcome, "hypothesis", ""), 400),
             "body": _bounded_text(getattr(outcome, "body", ""), 500),
             "assumptions": tuple(sorted(assumptions[key])[:MAX_CALLEE_ASSUMPTIONS]), "scope_note": _scope_note(outcome)}
            for key, outcome in selected]
    limitations = tuple(f"{name}: {count}" for name, count in sorted(limits.items()) if count)
    return CalleeAssessmentBundle({"assessments": rows, "limitations": limitations},
                                  tuple(outcome for _, outcome in selected))

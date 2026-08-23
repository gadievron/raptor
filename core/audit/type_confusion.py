"""Type-confusion detector via deserialization → virtual dispatch analysis.

Finds cases where a deserialized object reaches a virtual dispatch site
and a subtype overrides the dispatched method — the type contract between
deserialiser and consumer may be violated.

Operates on tree-sitter-extracted ``ClassDef`` and ``CallSite`` data
from ``FileCallGraph``.  When a Joern server is available, CPG queries
upgrade confidence from medium to high.  Degrades gracefully to
tree-sitter-only when Joern is absent.

Safety contract: boost-only.  This detector adds findings; it never
suppresses, demotes, or removes existing findings from review.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

_DESER_APIS: frozenset[str] = frozenset({
    "pickle.loads", "pickle.load",
    "yaml.load", "yaml.unsafe_load", "yaml.full_load",
    "marshal.loads",
    "jsonpickle.decode", "shelve.open",
    "ObjectInputStream.readObject", "XMLDecoder.readObject",
    "XStream.fromXML",
    "unserialize",
    "YAML.load", "Marshal.load",
    "BinaryFormatter.Deserialize", "JsonConvert.DeserializeObject",
    "JSON.parse",
})

_ROOT_CLASSES: frozenset[str] = frozenset({
    "object", "Object", "BaseException", "Exception",
})


def _transitive_subtypes(
    parent_to_children: dict[str, set[str]],
    class_name: str,
) -> set[str]:
    """BFS over parent→children to find all transitive subtypes."""
    from collections import deque
    visited: set[str] = set()
    queue = deque(parent_to_children.get(class_name, set()))
    visited.update(queue)
    while queue:
        current = queue.popleft()
        for child in parent_to_children.get(current, set()):
            if child not in visited:
                visited.add(child)
                queue.append(child)
    return visited


@dataclass
class _TypeIndex:
    parent_to_children: dict[str, set[str]] = field(
        default_factory=lambda: defaultdict(set),
    )
    class_methods: dict[str, set[str]] = field(
        default_factory=lambda: defaultdict(set),
    )
    class_to_file: dict[str, str] = field(default_factory=dict)
    method_to_classes: dict[str, set[str]] = field(
        default_factory=lambda: defaultdict(set),
    )


@dataclass
class TypeConfusionFinding:
    file: str
    function: str
    line: int
    deser_source: str
    deser_function: str
    base_type: str
    overriding_subtypes: list[str]
    overridden_method: str
    confidence: str = "medium"

    def describe(self) -> str:
        """Operator/LLM-facing one-liner for the mechanical finding.

        Names the deserialisation origin explicitly: in the transitive
        case the virtual-dispatch site (``function``) is a different
        function from the deserialising one (``deser_function``), so
        without it the taint origin cannot be located from the record.
        """
        subtypes_str = ", ".join(self.overriding_subtypes[:3])
        return (
            f"object deserialised in {self.deser_function}() via "
            f"{self.deser_source} reaches virtual dispatch of "
            f"{self.overridden_method}() — subtypes [{subtypes_str}] "
            f"override this method"
        )


def _build_type_index(
    call_graphs: dict[str, Any],
) -> _TypeIndex:
    """Build a type hierarchy index from ClassDef data across all files."""
    idx = _TypeIndex()

    for filepath, graph in call_graphs.items():
        classes = getattr(graph, "classes", None)
        if classes is None and isinstance(graph, dict):
            classes = graph.get("classes", [])
        if not classes:
            continue

        for cls in classes:
            name = cls.name if hasattr(cls, "name") else cls.get("name", "")
            if not name:
                continue

            raw_methods = cls.methods if hasattr(cls, "methods") else cls.get("methods", [])
            methods: set[str] = set()
            for m in raw_methods:
                if isinstance(m, (list, tuple)) and len(m) >= 1:
                    methods.add(m[0])
                elif isinstance(m, str):
                    methods.add(m)

            idx.class_methods[name] |= methods
            for m in methods:
                idx.method_to_classes[m].add(name)
            if name not in idx.class_to_file:
                idx.class_to_file[name] = filepath

            bases = cls.bases if hasattr(cls, "bases") else cls.get("bases", [])
            for base in bases:
                base_simple = base.rsplit(".", 1)[-1] if isinstance(base, str) else ""
                if base_simple and base_simple not in _ROOT_CLASSES:
                    idx.parent_to_children[base_simple].add(name)

    return idx


def _find_deser_sources(
    call_graphs: dict[str, Any],
) -> list[tuple[str, str, str, int]]:
    """Find deserialization call sites across all files.

    Returns ``(file, caller_function, deser_api, line)`` tuples.
    """
    results: list[tuple[str, str, str, int]] = []

    for filepath, graph in call_graphs.items():
        calls = getattr(graph, "calls", None)
        if calls is None and isinstance(graph, dict):
            calls = graph.get("calls", [])
        if not calls:
            continue

        for call in calls:
            chain = call.chain if hasattr(call, "chain") else call.get("chain", [])
            if not chain:
                continue

            dotted = ".".join(chain)
            if dotted in _DESER_APIS:
                caller = (call.caller if hasattr(call, "caller")
                          else call.get("caller")) or "<module>"
                line = call.line if hasattr(call, "line") else call.get("line", 0)
                results.append((filepath, caller, dotted, line))
                continue

            if len(chain) >= 2:
                qualified_tail = f"{chain[-2]}.{chain[-1]}"
                if qualified_tail in _DESER_APIS:
                    caller = (call.caller if hasattr(call, "caller")
                              else call.get("caller")) or "<module>"
                    line = call.line if hasattr(call, "line") else call.get("line", 0)
                    results.append((filepath, caller, qualified_tail, line))

    return results


def _find_virtual_dispatch_sites(
    call_graphs: dict[str, Any],
    type_index: _TypeIndex,
) -> list[tuple[str, str, int, str, str, list[str]]]:
    """Find call sites where virtual dispatch may reach overridden methods.

    Returns ``(file, function, line, base_type, method_name,
    overriding_subtypes)`` tuples.

    Two resolution paths:
    1. Tier 2: ``receiver_type`` set on the CallSite (Java/C#/TS).
    2. Fallback: ``self.method()`` / ``this.method()`` chains where the
       enclosing class has subtypes overriding the method.
    """
    results: list[tuple[str, str, int, str, str, list[str]]] = []
    seen: set[tuple[str, str, int]] = set()

    for filepath, graph in call_graphs.items():
        calls = getattr(graph, "calls", None)
        if calls is None and isinstance(graph, dict):
            calls = graph.get("calls", [])
        if not calls:
            continue

        classes = getattr(graph, "classes", None)
        if classes is None and isinstance(graph, dict):
            classes = graph.get("classes", [])

        method_to_enclosing: dict[str, list[str]] = defaultdict(list)
        if classes:
            for cls in classes:
                cls_name = cls.name if hasattr(cls, "name") else cls.get("name", "")
                raw_methods = cls.methods if hasattr(cls, "methods") else cls.get("methods", [])
                for m in raw_methods:
                    mname = m[0] if isinstance(m, (list, tuple)) and m else (m if isinstance(m, str) else "")
                    if mname and cls_name not in method_to_enclosing[mname]:
                        method_to_enclosing[mname].append(cls_name)

        for call in calls:
            chain = call.chain if hasattr(call, "chain") else call.get("chain", [])
            if not chain:
                continue

            caller = (call.caller if hasattr(call, "caller")
                      else call.get("caller")) or "<module>"
            line = call.line if hasattr(call, "line") else call.get("line", 0)
            recv_type = (call.receiver_type if hasattr(call, "receiver_type")
                         else call.get("receiver_type"))

            if recv_type and len(chain) >= 1:
                method_name = chain[-1]
                all_subtypes = _transitive_subtypes(
                    type_index.parent_to_children, recv_type,
                )
                overriders = sorted(
                    st for st in all_subtypes
                    if method_name in type_index.class_methods.get(st, set())
                )
                if overriders:
                    # Keyed per receiver type: two calls on one line
                    # with different receivers are distinct findings.
                    key = (filepath, caller, line, recv_type)
                    if key not in seen:
                        seen.add(key)
                        results.append((
                            filepath, caller, line,
                            recv_type, method_name, overriders,
                        ))
                continue

            if (len(chain) == 2
                    and chain[0] in ("self", "this")
                    and caller in method_to_enclosing):
                method_name = chain[1]
                for enclosing in method_to_enclosing[caller]:
                    all_subtypes = _transitive_subtypes(
                        type_index.parent_to_children, enclosing,
                    )
                    overriders = sorted(
                        st for st in all_subtypes
                        if method_name in type_index.class_methods.get(st, set())
                    )
                    if overriders:
                        # Keyed per enclosing class: two same-named
                        # methods in one file are distinct dispatch
                        # findings at the same call site.
                        key = (filepath, caller, line, enclosing)
                        if key not in seen:
                            seen.add(key)
                            results.append((
                                filepath, caller, line,
                                enclosing, method_name, overriders,
                            ))

    return results


def _build_forward_reach(
    call_graphs: dict[str, Any],
    max_hops: int = 2,
) -> dict[str, set[str]]:
    """Build a function-name → reachable-function-names map (forward edges).

    Uses simple name matching (no file qualification) — intentional
    over-approximation for boost-only analysis.
    """
    forward: dict[str, set[str]] = defaultdict(set)

    for graph in call_graphs.values():
        calls = getattr(graph, "calls", None)
        if calls is None and isinstance(graph, dict):
            calls = graph.get("calls", [])
        if not calls:
            continue

        for call in calls:
            chain = call.chain if hasattr(call, "chain") else call.get("chain", [])
            caller = (call.caller if hasattr(call, "caller")
                      else call.get("caller")) or "<module>"
            if chain:
                callee = chain[-1]
                forward[caller].add(callee)

    if max_hops <= 1:
        return dict(forward)

    extended: dict[str, set[str]] = {}
    for func, direct in forward.items():
        reachable = set(direct)
        frontier = set(direct)
        for _ in range(max_hops - 1):
            next_frontier: set[str] = set()
            for f in frontier:
                for callee in forward.get(f, ()):
                    if callee not in reachable:
                        reachable.add(callee)
                        next_frontier.add(callee)
            frontier = next_frontier
            if not frontier:
                break
        extended[func] = reachable

    return extended


def _try_cpg_verify(
    finding: TypeConfusionFinding,
    joern_server: Any,
) -> str:
    """Attempt CPG verification of a type-confusion candidate.

    Returns ``"high"`` if verified, ``"medium"`` otherwise.
    """
    try:
        from packages.joern.runner import _escape_scala_string
    except ImportError:
        return "medium"

    try:
        safe_type = _escape_scala_string(finding.base_type)
        query = f'cpg.typeDecl.name("{safe_type}").derivedTypeDecl.name.l'
        resp = joern_server.query(query, timeout=15)
        if resp is None:
            return "medium"

        stdout = resp.get("stdout", "") if isinstance(resp, dict) else str(resp)
        confirmed_subtypes = set()
        import re
        cpg_names = set(re.findall(r'"([^"]+)"', stdout))
        for st in finding.overriding_subtypes:
            if st in cpg_names:
                confirmed_subtypes.add(st)

        if not confirmed_subtypes:
            return "medium"

        if hasattr(joern_server, "run_taint_exists_query"):
            taint_ok = joern_server.run_taint_exists_query(
                finding.deser_source.split(".")[-1],
                finding.overridden_method,
            )
            if taint_ok:
                return "high"

        return "medium"
    except Exception:
        logger.debug("CPG verification failed for type confusion", exc_info=True)
        return "medium"


def detect_type_confusion(
    _source_texts: dict[str, str],
    call_graphs: dict[str, Any] | None,
    joern_server: Any | None = None,
) -> list[TypeConfusionFinding]:
    """Detect type-confusion vulnerabilities via deser → virtual dispatch.

    Returns findings where deserialized data reaches a virtual dispatch
    site whose method is overridden by subtypes — a potential type
    contract violation.
    """
    from core.audit.safety_contract import assert_boost_only
    assert_boost_only("type_confusion")

    if not call_graphs:
        return []

    type_index = _build_type_index(call_graphs)
    if not type_index.parent_to_children:
        return []

    deser_sources = _find_deser_sources(call_graphs)
    if not deser_sources:
        return []

    dispatch_sites = _find_virtual_dispatch_sites(call_graphs, type_index)
    if not dispatch_sites:
        return []

    forward_reach = _build_forward_reach(call_graphs, max_hops=2)

    deser_funcs: dict[str, list[tuple[str, str, int]]] = defaultdict(list)
    for dfile, dfunc, dapi, dline in deser_sources:
        deser_funcs[dfunc].append((dfile, dapi, dline))

    dispatch_by_func: dict[str, list[tuple[str, int, str, str, list[str]]]] = defaultdict(list)
    for vfile, vfunc, vline, vbase, vmethod, voverrides in dispatch_sites:
        dispatch_by_func[vfunc].append((vfile, vline, vbase, vmethod, voverrides))

    findings: list[TypeConfusionFinding] = []
    seen: set[tuple[str, str, int, str]] = set()

    for dfunc, dlocations in deser_funcs.items():
        if dfunc in dispatch_by_func:
            for dfile, dapi, _dline in dlocations:
                for vfile, vline, vbase, vmethod, voverrides in dispatch_by_func[dfunc]:
                    key = (vfile, dfunc, vline, vbase)
                    if key in seen:
                        continue
                    seen.add(key)
                    findings.append(TypeConfusionFinding(
                        file=vfile,
                        function=dfunc,
                        line=vline,
                        deser_source=dapi,
                        deser_function=dfunc,
                        base_type=vbase,
                        overriding_subtypes=voverrides,
                        overridden_method=vmethod,
                    ))

        reachable = forward_reach.get(dfunc, set())
        for reached_func in reachable:
            if reached_func in dispatch_by_func:
                for dfile, dapi, _dline in dlocations:
                    for vfile, vline, vbase, vmethod, voverrides in dispatch_by_func[reached_func]:
                        key = (vfile, reached_func, vline, vbase)
                        if key in seen:
                            continue
                        seen.add(key)
                        findings.append(TypeConfusionFinding(
                            file=vfile,
                            function=reached_func,
                            line=vline,
                            deser_source=dapi,
                            deser_function=dfunc,
                            base_type=vbase,
                            overriding_subtypes=voverrides,
                            overridden_method=vmethod,
                        ))

    if joern_server and findings:
        for f in findings:
            f.confidence = _try_cpg_verify(f, joern_server)

    return findings

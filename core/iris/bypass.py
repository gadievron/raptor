"""Compositional bypass detection using call-graph set operations.

Given a :class:`SafetyAssumption` ("function *target* is safe IF
*enforcer* was called on the path"), this module finds callers of
*target* that do NOT call *enforcer* — a compositional bypass.

The engine operates entirely on RAPTOR's existing per-file call graphs
(:class:`core.inventory.call_graph.FileCallGraph`).  No external tools
(Joern, CodeQL) are needed for bypass detection itself.  Sub-millisecond
on call graphs up to ~10k functions.

Three query shapes:

1. **Set-difference bypass** — ``transitive_callers(target) \
   transitive_callers(enforcer)``.  Catches missing-guard bugs.

2. **Ordering violation** — caller invokes both enforcer and target,
   but an *underminer* call sits between source and enforcer, defeating
   the enforcer's precondition.  Detected via line-number ordering
   within the same function body.

3. **Widening** — given one bypass finding, discover *sibling* callers
   through the same intermediate function.  BFS over intermediates,
   not exponential.
"""

from __future__ import annotations

import logging
from collections import defaultdict, deque

from core.inventory.call_graph import FileCallGraph

from .assumptions import BypassFinding, SafetyAssumption

logger = logging.getLogger(__name__)

FuncKey = tuple[str, str]


class CompositionalAnalyzer:
    """Bypass detection engine over a project's call graphs."""

    def __init__(self, call_graphs: dict[str, FileCallGraph]) -> None:
        self.forward: dict[FuncKey, set[FuncKey]] = defaultdict(set)
        self.reverse: dict[FuncKey, set[FuncKey]] = defaultdict(set)
        self.all_funcs: set[FuncKey] = set()
        self._call_lines: dict[tuple[FuncKey, str], list[int]] = defaultdict(list)
        self._name_to_keys: dict[str, set[FuncKey]] = defaultdict(set)

        func_defined_in: dict[str, set[str]] = defaultdict(set)
        for filepath, graph in call_graphs.items():
            for call in graph.calls:
                if call.caller and call.caller != "<module>":
                    func_defined_in[call.caller].add(filepath)

        for filepath, graph in call_graphs.items():
            for call in graph.calls:
                caller = call.caller or "<module>"
                caller_key: FuncKey = (filepath, caller)
                self.all_funcs.add(caller_key)
                self._name_to_keys[caller].add(caller_key)

                if len(call.chain) == 1:
                    callee_name = call.chain[0]
                    callee_key: FuncKey = (filepath, callee_name)
                    self.forward[caller_key].add(callee_key)
                    self.reverse[callee_key].add(caller_key)
                    self.all_funcs.add(callee_key)
                    self._name_to_keys[callee_name].add(callee_key)
                    self._call_lines[(caller_key, callee_name)].append(call.line)

                    for other_file in func_defined_in.get(callee_name, ()):
                        if other_file != filepath:
                            cross_key: FuncKey = (other_file, callee_name)
                            self.forward[caller_key].add(cross_key)
                            self.reverse[cross_key].add(caller_key)
                            self.all_funcs.add(cross_key)
                            self._name_to_keys[callee_name].add(cross_key)

                elif len(call.chain) == 2 and call.chain[0] in ("self", "this"):
                    callee_key = (filepath, call.chain[1])
                    self.forward[caller_key].add(callee_key)
                    self.reverse[callee_key].add(caller_key)
                    self.all_funcs.add(callee_key)
                    self._name_to_keys[call.chain[1]].add(callee_key)
                    self._call_lines[(caller_key, call.chain[1])].append(call.line)

        _ROOT_CLASSES = frozenset({"object", "Object", "BaseException", "Exception"})
        self._class_methods: dict[str, set[str]] = defaultdict(set)
        self._parent_to_children: dict[str, set[str]] = defaultdict(set)
        self._method_to_classes: dict[str, set[str]] = defaultdict(set)
        self._class_to_files: dict[str, set[str]] = defaultdict(set)

        for filepath, graph in call_graphs.items():
            for cls in graph.classes:
                methods = {m[0] for m in cls.methods}
                self._class_methods[cls.name] |= methods
                self._class_to_files[cls.name].add(filepath)
                for m in methods:
                    self._method_to_classes[m].add(cls.name)
                for base in cls.bases:
                    base_simple = base.rsplit(".", 1)[-1]
                    if base_simple not in _ROOT_CLASSES:
                        self._parent_to_children[base_simple].add(cls.name)

    def _keys_for(self, func_name: str) -> set[FuncKey]:
        return self._name_to_keys.get(func_name, set())

    def transitive_callers(self, func_name: str) -> set[FuncKey]:
        """BFS over reverse edges: all functions that transitively
        call any function named *func_name* in any file."""
        seeds: set[FuncKey] = set()
        for key in self._keys_for(func_name):
            seeds |= self.reverse.get(key, set())

        visited = set(seeds)
        queue = deque(seeds)
        while queue:
            current = queue.popleft()
            for caller in self.reverse.get(current, set()):
                if caller not in visited:
                    visited.add(caller)
                    queue.append(caller)
        return visited

    def transitive_callees(self, func_name: str) -> set[FuncKey]:
        """BFS over forward edges: all functions transitively called
        by any function named *func_name* in any file."""
        seeds: set[FuncKey] = set()
        for key in self._keys_for(func_name):
            seeds |= self.forward.get(key, set())

        visited = set(seeds)
        queue = deque(seeds)
        while queue:
            current = queue.popleft()
            for callee in self.forward.get(current, set()):
                if callee not in visited:
                    visited.add(callee)
                    queue.append(callee)
        return visited

    def detect_bypasses(
        self,
        assumption: SafetyAssumption,
    ) -> list[BypassFinding]:
        """Find callers of *target* that never call any *enforcer*.

        Returns one :class:`BypassFinding` per unsafe caller, annotated
        with the intermediate function (if the caller reaches the target
        transitively) for widening.
        """
        from core.audit.safety_contract import assert_boost_only
        assert_boost_only("bypass_loop")
        if not assumption.enforced_by:
            return []
        target_callers = self.transitive_callers(assumption.target)
        enforcer_callers: set[FuncKey] = set()
        for enforcer in assumption.enforced_by:
            enforcer_callers |= self.transitive_callers(enforcer)

        unsafe = target_callers - enforcer_callers

        findings: list[BypassFinding] = []
        for file, func in sorted(unsafe):
            if (file, func) == (assumption.file, assumption.target) or func == "main":
                continue

            via = self._find_intermediate(file, func, assumption.target)

            findings.append(BypassFinding(
                assumption=assumption,
                caller_file=file,
                caller_function=func,
                missing_enforcer=assumption.enforced_by[0] if assumption.enforced_by else "",
                via_intermediate=via,
                is_transitive=via is not None,
            ))
        return findings

    def detect_ordering_violations(
        self,
        assumption: SafetyAssumption,
    ) -> list[BypassFinding]:
        """Detect callers where *underminer* is invoked before *enforcer*.

        Only applies when ``assumption.underminer`` is set.  Catches the
        "3-tiers-up" bug class where the enforcer IS present but its
        precondition has already been defeated.

        With multiple enforcers (any sufficient), the violation only
        holds if the underminer precedes ALL of them.
        """
        if not assumption.underminer or not assumption.enforced_by:
            return []

        target_callers = self.transitive_callers(assumption.target)
        findings: list[BypassFinding] = []

        for file, func in sorted(target_callers):
            callees = {cn for _, cn in self.forward.get((file, func), set())}
            if assumption.underminer not in callees:
                continue

            u_lines = self._call_lines.get(
                ((file, func), assumption.underminer), [],
            )
            u_lines = [ln for ln in u_lines if ln > 0]
            if not u_lines:
                continue

            all_undermined = True
            earliest_enforcer_line = -1
            for enforcer in assumption.enforced_by:
                if enforcer not in callees:
                    continue
                e_lines = self._call_lines.get(
                    ((file, func), enforcer), [],
                )
                e_lines = [ln for ln in e_lines if ln > 0]
                if not e_lines:
                    all_undermined = False
                    break
                if min(u_lines) >= min(e_lines):
                    all_undermined = False
                    break
                if e_lines:
                    el = min(e_lines)
                    if earliest_enforcer_line < 0 or el < earliest_enforcer_line:
                        earliest_enforcer_line = el

            if all_undermined and earliest_enforcer_line > 0:
                findings.append(BypassFinding(
                    assumption=assumption,
                    caller_file=file,
                    caller_function=func,
                    ordering_violation=True,
                    line_info={
                        "underminer_line": min(u_lines),
                        "enforcer_line": earliest_enforcer_line,
                    },
                ))
        return findings

    def detect_type_hierarchy_bypasses(
        self,
        assumption: SafetyAssumption,
    ) -> list[BypassFinding]:
        """Find subtypes that override an enforcer method.

        If a safety assumption says ``validate`` (in class ``Base``) is
        the enforcer, and class ``Sub(Base)`` also defines ``validate``,
        the subtype override may weaken the enforcer — callers using
        ``Sub`` instances bypass the intended validation.

        Only considers base classes with at least one method appearing
        in the call-graph context of the assumption's target (transitive
        callers + callees).  This filters out unrelated classes that
        happen to define a method with the same name as the enforcer.

        Operates entirely on ``ClassDef`` data already extracted by
        tree-sitter.  No Joern or CodeQL required.
        """
        from core.audit.safety_contract import assert_boost_only
        assert_boost_only("bypass_loop")

        if not self._parent_to_children:
            return []

        context_files: set[str] = {assumption.file}
        for fpath, _ in self.transitive_callers(assumption.target):
            context_files.add(fpath)
        for fpath, _ in self.transitive_callees(assumption.target):
            context_files.add(fpath)
        for fpath, _ in self._keys_for(assumption.target):
            context_files.add(fpath)

        findings: list[BypassFinding] = []
        seen: set[tuple[str, str]] = set()

        for enforcer in assumption.enforced_by:
            defining_classes = self._method_to_classes.get(enforcer, set())
            for base_class in defining_classes:
                all_subtypes = self._transitive_subtypes(base_class)
                if not all_subtypes:
                    continue
                class_files = self._class_to_files.get(base_class, set())
                if class_files and not class_files & context_files:
                    continue
                for subtype in sorted(all_subtypes):
                    if enforcer in self._class_methods.get(subtype, set()):
                        key = (subtype, enforcer)
                        if key in seen:
                            continue
                        seen.add(key)
                        findings.append(BypassFinding(
                            assumption=assumption,
                            caller_file="<type_hierarchy>",
                            caller_function=f"{subtype}.{enforcer}",
                            missing_enforcer=enforcer,
                        ))
        return findings

    def _transitive_subtypes(self, class_name: str) -> set[str]:
        """BFS over parent→children to find all transitive subtypes."""
        visited: set[str] = set()
        queue = deque(self._parent_to_children.get(class_name, set()))
        visited.update(queue)
        while queue:
            current = queue.popleft()
            for child in self._parent_to_children.get(current, set()):
                if child not in visited:
                    visited.add(child)
                    queue.append(child)
        return visited

    def widen_from_finding(
        self,
        finding: BypassFinding,
    ) -> list[BypassFinding]:
        """Given a bypass finding, discover sibling callers through
        the same intermediate function."""
        if not finding.via_intermediate:
            return []

        intermediate = finding.via_intermediate
        assumption = finding.assumption

        siblings: list[BypassFinding] = []
        enforcer_names = set(assumption.enforced_by)

        for (file, func), callees in self.forward.items():
            callee_names = {cn for _, cn in callees}
            if intermediate in callee_names and (file, func) != (finding.caller_file, finding.caller_function):
                if not (callee_names & enforcer_names):
                    siblings.append(BypassFinding(
                        assumption=assumption,
                        caller_file=file,
                        caller_function=func,
                        missing_enforcer=finding.missing_enforcer,
                        via_intermediate=intermediate,
                        is_transitive=True,
                    ))
        return siblings

    def _find_intermediate(
        self,
        file: str,
        func: str,
        target: str,
    ) -> str | None:
        """Find which callee of (file, func) transitively reaches *target*."""
        callees = self.forward.get((file, func), set())
        direct_names = {cn for _, cn in callees}
        if target in direct_names:
            return None

        target_keys = self._keys_for(target)
        if not target_keys:
            return None

        for _, callee_name in callees:
            reachable = self.transitive_callees(callee_name)
            if reachable & target_keys:
                return callee_name
        return None

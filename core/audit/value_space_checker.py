"""Cross-module value-space mismatch detection.

Detects bugs where a producer emits string values that a consumer
never handles, or a consumer switches on values nobody produces.
These are real bugs — silent mismatches that cause data to be
silently dropped, branches that never execute, or enums that
diverge between modules.

Concrete examples from the RAPTOR codebase:

- Bug 361: ``version_diff_review.py`` gates on literal ``"Composer"``
  but the parser emits ``ecosystem="Packagist"`` — they never match.
- Bug 454: transitive-drop adapter hardcodes ``ecosystem=PyPI`` for
  ALL ecosystems, dropping the actual eco field.
- Bug 226: ``classify_crash_type`` matches ``"7"`` for SIGBUS but the
  GDB/LLDB parsers emit zero-padded ``"07"``.
- Bug 302: ``final_status`` enum omits ``'likely_exploitable'`` that the
  orchestrator produces.

Detection strategy (all mechanical — no LLM):

1. Extract string literals from each function, classified as
   *produced* (dict keys, assignments to known fields, return values)
   or *consumed* (equality comparisons, set/list membership tests).

2. Link producers to consumers via call-graph edges or field-name
   heuristics (same module, shared field name).

3. Flag gaps: values produced but not consumed (``unhandled``), and
   values consumed but never produced (``dead_branches``).
"""

from __future__ import annotations

import ast
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class ValueSpaceMismatch:
    """One producer-consumer pair whose value spaces don't fully overlap."""

    producer_file: str
    producer_function: str
    producer_values: List[str]
    consumer_file: str
    consumer_function: str
    consumer_values: List[str]
    unhandled: List[str]
    dead_branches: List[str]
    confidence: str  # "high", "medium", "low"
    format_mismatches: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "producer_file": self.producer_file,
            "producer_function": self.producer_function,
            "producer_values": self.producer_values,
            "consumer_file": self.consumer_file,
            "consumer_function": self.consumer_function,
            "consumer_values": self.consumer_values,
            "unhandled": self.unhandled,
            "dead_branches": self.dead_branches,
            "confidence": self.confidence,
            "format_mismatches": self.format_mismatches,
        }


# ---------------------------------------------------------------------------
# String-literal extraction
# ---------------------------------------------------------------------------

# Field names commonly carrying bounded string-value domains.
_FIELD_NAME_RE = re.compile(
    r"^(?:ecosystem|status|state|kind|category|type|mode|level|"
    r"severity|phase|stage|role|action|signal|crash_type|"
    r"final_status|result|verdict|classification|"
    r"method|event_type|protocol|encoding|operation|platform|"
    r"direction|priority|strategy|transport|scheme|backend)$",
    re.IGNORECASE,
)


@dataclass
class _FunctionLiterals:
    """String literals extracted from one function, classified by role."""

    file: str
    function: str
    produced: Set[str] = field(default_factory=set)
    consumed: Set[str] = field(default_factory=set)
    # Names of bounded-domain fields this function produces/consumes
    # values for — linking only needs the names, not the values.
    field_produced: Set[str] = field(default_factory=set)
    field_consumed: Set[str] = field(default_factory=set)


class _LiteralExtractor(ast.NodeVisitor):
    """Walk a function AST and classify string literals."""

    def __init__(
        self, file: str, func_name: str, param_names: List[str] | None = None
    ) -> None:
        self.result = _FunctionLiterals(file=file, function=func_name)
        # Parameter names that match known field names — dict keys in the
        # function body are likely the valid domain of that parameter.
        self._field_params: List[str] = [
            p for p in (param_names or []) if _FIELD_NAME_RE.match(p)
        ]

    # -- producers ----------------------------------------------------------

    def visit_Dict(self, node: ast.Dict) -> None:
        str_keys: List[str] = []
        for key in node.keys:
            if isinstance(key, ast.Constant) and isinstance(key.value, str):
                self.result.produced.add(key.value)
                str_keys.append(key.value)
        # If the function has a parameter matching a field name, the dict
        # keys plausibly define the valid domain for that parameter
        # (e.g. ``def get_label(ecosystem): labels = {"Packagist": ...}``).
        if str_keys:
            self.result.field_produced.update(self._field_params)
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        field_name = self._target_field_name(node.targets)
        if field_name and isinstance(node.value, ast.Constant) and isinstance(
            node.value.value, str
        ):
            self.result.produced.add(node.value.value)
            self.result.field_produced.add(field_name)
        self.generic_visit(node)

    def visit_Return(self, node: ast.Return) -> None:
        if isinstance(node.value, ast.Constant) and isinstance(
            node.value.value, str
        ):
            self.result.produced.add(node.value.value)
        self.generic_visit(node)

    # -- consumers ----------------------------------------------------------

    def visit_Compare(self, node: ast.Compare) -> None:
        field_name = self._name_from_node(node.left)
        for op, comparator in zip(node.ops, node.comparators):
            if isinstance(op, (ast.Eq, ast.NotEq)):
                if isinstance(comparator, ast.Constant) and isinstance(
                    comparator.value, str
                ):
                    self.result.consumed.add(comparator.value)
                    if field_name and _FIELD_NAME_RE.match(field_name):
                        self.result.field_consumed.add(field_name)
            if isinstance(op, (ast.In, ast.NotIn)):
                self._extract_membership_values(comparator, field_name)
        # Also check the symmetric case: "Composer" == ecosystem
        for op, comparator in zip(node.ops, node.comparators):
            comp_field = self._name_from_node(comparator)
            if isinstance(op, (ast.Eq, ast.NotEq)):
                if isinstance(node.left, ast.Constant) and isinstance(
                    node.left.value, str
                ):
                    self.result.consumed.add(node.left.value)
                    if comp_field and _FIELD_NAME_RE.match(comp_field):
                        self.result.field_consumed.add(comp_field)
        self.generic_visit(node)

    # -- dynamic producers (f-strings, .format(), concatenation) -----------

    def visit_JoinedStr(self, node: ast.JoinedStr) -> None:
        """Extract template patterns from f-strings."""
        parts: List[str] = []
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                parts.append(value.value)
            elif isinstance(value, ast.FormattedValue):
                fmt = ""
                if (value.format_spec
                        and isinstance(value.format_spec, ast.JoinedStr)):
                    fmt_parts = []
                    for fv in value.format_spec.values:
                        if isinstance(fv, ast.Constant):
                            fmt_parts.append(str(fv.value))
                    fmt = "".join(fmt_parts)
                parts.append(f"{{{fmt}}}" if fmt else "{}")
        template = "".join(parts)
        if template and template != "{}":
            self.result.produced.add(template)
        self.generic_visit(node)

    def visit_BinOp(self, node: ast.BinOp) -> None:
        """Extract template patterns from string concatenation."""
        if isinstance(node.op, ast.Add):
            if (isinstance(node.left, ast.Constant)
                    and isinstance(node.left.value, str)
                    and not isinstance(node.right, ast.Constant)):
                self.result.produced.add(node.left.value + "{}")
            if (isinstance(node.right, ast.Constant)
                    and isinstance(node.right.value, str)
                    and not isinstance(node.left, ast.Constant)):
                self.result.produced.add("{}" + node.right.value)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        """Extract template patterns from str.format() calls."""
        if (isinstance(node.func, ast.Attribute)
                and node.func.attr == "format"
                and isinstance(node.func.value, ast.Constant)
                and isinstance(node.func.value.value, str)):
            self.result.produced.add(node.func.value.value)
        self.generic_visit(node)

    # -- helpers ------------------------------------------------------------

    def _extract_membership_values(
        self, node: ast.expr, field_name: Optional[str]
    ) -> None:
        """Extract string values from set/list/tuple membership tests."""
        elts: Optional[list] = None
        if isinstance(node, (ast.Set, ast.List, ast.Tuple)):
            elts = node.elts
        if elts is None:
            return
        for elt in elts:
            if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                self.result.consumed.add(elt.value)
                if field_name and _FIELD_NAME_RE.match(field_name):
                    self.result.field_consumed.add(field_name)

    @staticmethod
    def _target_field_name(targets: list) -> Optional[str]:
        """Return the field name from a simple assignment target."""
        if len(targets) != 1:
            return None
        t = targets[0]
        if isinstance(t, ast.Name) and _FIELD_NAME_RE.match(t.id):
            return t.id
        if isinstance(t, ast.Attribute) and _FIELD_NAME_RE.match(t.attr):
            return t.attr
        return None

    @staticmethod
    def _name_from_node(node: ast.expr) -> Optional[str]:
        """Best-effort name extraction for a comparison operand."""
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return node.attr
        return None


def _extract_function_literals(
    source: str, file_path: str
) -> List[_FunctionLiterals]:
    """Parse *source* and return per-function literal classifications."""
    try:
        tree = ast.parse(source, filename=file_path)
    except SyntaxError:
        logger.debug("SyntaxError parsing %s — skipping", file_path)
        return []

    results: List[_FunctionLiterals] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            param_names = [a.arg for a in node.args.args]
            extractor = _LiteralExtractor(
                file_path, node.name, param_names=param_names
            )
            extractor.visit(node)
            fl = extractor.result
            # Only keep functions that actually have classifiable literals.
            if fl.produced or fl.consumed:
                results.append(fl)
    return results


def _extract_function_literals_ts(
    source: str, file_path: str
) -> List[_FunctionLiterals]:
    """Extract function literals via tree-sitter for non-Python files."""
    if file_path.endswith(".py"):
        return []
    try:
        from .ts_extract import extract_string_literals
    except ImportError:
        return []

    lits = extract_string_literals(file_path, source)
    if lits is None:
        return []

    by_func: Dict[str, _FunctionLiterals] = {}
    for lit in lits:
        if not lit.value or lit.is_template:
            continue
        fl = by_func.get(lit.function)
        if fl is None:
            fl = _FunctionLiterals(file=file_path, function=lit.function)
            by_func[lit.function] = fl
        if lit.context == "dict_key":
            fl.produced.add(lit.value)
            # field_produced: use the key as the field name so
            # _link_by_field_heuristic can match cross-function pairs
            fl.field_produced.add(lit.value)
        elif lit.context in ("return", "assignment"):
            fl.produced.add(lit.value)
        elif lit.context in ("comparison", "switch_case"):
            fl.consumed.add(lit.value)
        elif lit.context == "argument":
            fl.field_consumed.add(lit.value)

    return [fl for fl in by_func.values() if fl.produced or fl.consumed]


# ---------------------------------------------------------------------------
# Producer-consumer linking
# ---------------------------------------------------------------------------


def _link_by_call_graph(
    all_funcs: Dict[str, List[_FunctionLiterals]],
    call_graphs: dict,
) -> List[Tuple[_FunctionLiterals, _FunctionLiterals, str]]:
    """Link producer→consumer using explicit call-graph edges.

    *call_graphs* maps file paths to objects with a ``calls`` attribute.
    Each call has ``caller`` (str) and ``chain`` (List[str]) attributes.
    A producer is the callee; a consumer is any caller that switches on
    the return value.

    Returns (producer, consumer, confidence) triples.
    """
    links: List[Tuple[_FunctionLiterals, _FunctionLiterals, str]] = []

    # Build a lookup: (file, func_name) -> _FunctionLiterals
    by_name: Dict[Tuple[str, str], _FunctionLiterals] = {}
    for file_path, funcs in all_funcs.items():
        for fl in funcs:
            by_name[(file_path, fl.function)] = fl

    # Also build a name-only lookup for cross-file resolution
    by_func_name: Dict[str, List[_FunctionLiterals]] = {}
    for (_fp, fn), fl in by_name.items():
        by_func_name.setdefault(fn, []).append(fl)

    for file_path, cg in call_graphs.items():
        calls = getattr(cg, "calls", None) or cg.get("calls", [])
        for call in calls:
            caller_name = getattr(call, "caller", None) or call.get(
                "caller", ""
            )
            chain = getattr(call, "chain", None) or call.get("chain", [])
            caller_fl = by_name.get((file_path, caller_name))
            if not caller_fl or not caller_fl.consumed:
                continue
            for callee_name in chain:
                # Try same-file first (high confidence)
                callee_fl = by_name.get((file_path, callee_name))
                if callee_fl and callee_fl.produced:
                    if callee_fl is not caller_fl:
                        links.append((callee_fl, caller_fl, "high"))
                    continue
                # Cross-file: find by function name alone (medium confidence)
                for candidate in by_func_name.get(callee_name, []):
                    if candidate.produced and candidate is not caller_fl:
                        links.append((candidate, caller_fl, "medium"))
    return links


def _link_by_field_heuristic(
    all_funcs: Dict[str, List[_FunctionLiterals]],
) -> List[Tuple[_FunctionLiterals, _FunctionLiterals, str]]:
    """Link producer→consumer by shared field names within a package.

    When function A assigns ``ecosystem = "PyPI"`` and function B tests
    ``if ecosystem == "npm":``, and both are in the same package, they
    are likely a producer-consumer pair for the ``ecosystem`` field.
    """
    links: List[Tuple[_FunctionLiterals, _FunctionLiterals, str]] = []

    # Group functions by their containing package (parent directory).
    by_package: Dict[str, List[_FunctionLiterals]] = {}
    for file_path, funcs in all_funcs.items():
        # Use the directory as the package key.
        parts = file_path.replace("\\", "/").rsplit("/", 1)
        pkg = parts[0] if len(parts) > 1 else ""
        by_package.setdefault(pkg, []).extend(funcs)

    for _pkg, funcs in by_package.items():
        producers: Dict[str, List[_FunctionLiterals]] = {}
        consumers: Dict[str, List[_FunctionLiterals]] = {}

        for fl in funcs:
            for fname in fl.field_produced:
                producers.setdefault(fname, []).append(fl)
            for fname in fl.field_consumed:
                consumers.setdefault(fname, []).append(fl)

        for field_name in set(producers) & set(consumers):
            for p in producers[field_name]:
                for c in consumers[field_name]:
                    if p is c:
                        continue
                    links.append((p, c, "medium"))

    return links


def _link_intra_module(
    all_funcs: Dict[str, List[_FunctionLiterals]],
) -> List[Tuple[_FunctionLiterals, _FunctionLiterals, str]]:
    """Link producer→consumer within the same file.

    When one function in a module only produces values and another only
    consumes values, and their value sets partially overlap, they are
    likely a producer-consumer pair.
    """
    links: List[Tuple[_FunctionLiterals, _FunctionLiterals, str]] = []

    for _file_path, funcs in all_funcs.items():
        producers = [fl for fl in funcs if fl.produced and not fl.consumed]
        consumers = [fl for fl in funcs if fl.consumed and not fl.produced]

        for p in producers:
            for c in consumers:
                if p is c:
                    continue
                overlap = p.produced & c.consumed
                if overlap:
                    links.append((p, c, "low"))

    return links


# ---------------------------------------------------------------------------
# Gap detection
# ---------------------------------------------------------------------------


def _normalize_for_comparison(value: str) -> str:
    """Normalize a value for loose comparison (padding, case)."""
    stripped = value.lstrip("0") or "0"
    return stripped.casefold()


def _is_template(value: str) -> bool:
    """Check if a value is a dynamic template (contains {} placeholders)."""
    return "{" in value and "}" in value


def _template_matches(template: str, literal: str) -> bool:
    """Check if a literal could have been produced by a template."""
    import re as _re
    pattern = _re.escape(template).replace(r"\{\}", r".+")
    for fmt_spec in _re.findall(r"\\\{[^}]*\\\}", pattern):
        pattern = pattern.replace(fmt_spec, ".+")
    try:
        return bool(_re.fullmatch(pattern, literal))
    except _re.error:
        return False


def _compute_gaps(
    links: List[Tuple[_FunctionLiterals, _FunctionLiterals, str]],
) -> List[ValueSpaceMismatch]:
    """For each linked pair, compute unhandled and dead-branch sets."""
    results: List[ValueSpaceMismatch] = []
    seen: Set[Tuple[str, str, str, str]] = set()

    for producer, consumer, confidence in links:
        key = (
            producer.file,
            producer.function,
            consumer.file,
            consumer.function,
        )
        if key in seen:
            continue
        seen.add(key)

        unhandled = sorted(producer.produced - consumer.consumed)
        dead = sorted(consumer.consumed - producer.produced)

        # Remove template producers that cover consumed literals.
        producer_templates = [v for v in producer.produced if _is_template(v)]
        if producer_templates:
            dead = [
                d for d in dead
                if not any(_template_matches(t, d) for t in producer_templates)
            ]

        # Remove template values from unhandled (they aren't literal gaps).
        unhandled = [u for u in unhandled if not _is_template(u)]

        # Symmetric normalization for dead branches: remove consumer values
        # that match a producer value after case-folding / zero-stripping.
        if dead:
            producer_norms = {_normalize_for_comparison(p) for p in producer.produced}
            dead = [d for d in dead if _normalize_for_comparison(d) not in producer_norms]

        # Format normalization: flag exact-miss values that match after
        # case-folding or zero-stripping.
        format_mismatches: List[str] = []
        remaining_unhandled: List[str] = []
        for u in unhandled:
            u_norm = _normalize_for_comparison(u)
            matched = False
            for c in consumer.consumed:
                if c == u:
                    continue
                if _normalize_for_comparison(c) == u_norm:
                    format_mismatches.append(
                        f"{u!r} vs {c!r} (format mismatch)"
                    )
                    matched = True
                    break
            if not matched:
                remaining_unhandled.append(u)

        if not remaining_unhandled and not dead and not format_mismatches:
            continue

        results.append(
            ValueSpaceMismatch(
                producer_file=producer.file,
                producer_function=producer.function,
                producer_values=sorted(producer.produced),
                consumer_file=consumer.file,
                consumer_function=consumer.function,
                consumer_values=sorted(consumer.consumed),
                unhandled=remaining_unhandled,
                dead_branches=dead,
                confidence=confidence,
                format_mismatches=format_mismatches,
            )
        )

    return results


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def detect_value_space_mismatches(
    source_text: Dict[str, str],
    call_graphs: Optional[dict] = None,
) -> List[ValueSpaceMismatch]:
    """Detect cross-module value-space mismatches.

    Parameters
    ----------
    source_text
        Mapping of file path to source code text.
    call_graphs
        Optional mapping of file path to call-graph objects. Each object
        should have a ``calls`` attribute (or ``"calls"`` key) containing
        a list of call records with ``caller`` and ``chain`` fields.

    Returns
    -------
    list[ValueSpaceMismatch]
        One entry per producer-consumer pair with non-empty gaps.
    """
    # Phase 1: extract literals from all source files.
    all_funcs: Dict[str, List[_FunctionLiterals]] = {}
    for file_path, source in source_text.items():
        if file_path.endswith(".py"):
            funcs = _extract_function_literals(source, file_path)
        else:
            funcs = _extract_function_literals_ts(source, file_path)
        if funcs:
            all_funcs[file_path] = funcs

    if not all_funcs:
        return []

    # Phase 2: link producers to consumers.
    links: List[Tuple[_FunctionLiterals, _FunctionLiterals, str]] = []

    if call_graphs:
        links.extend(_link_by_call_graph(all_funcs, call_graphs))

    links.extend(_link_by_field_heuristic(all_funcs))
    links.extend(_link_intra_module(all_funcs))

    if not links:
        return []

    # Phase 3: compute gaps.
    return _compute_gaps(links)

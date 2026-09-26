"""PHP gadget-chain oracle — mechanical CWE-502 witness, both directions.

Enumerates PHP magic methods across a target tree via tree-sitter-php
and traces property flows from unserialize-reachable object state into
sinks (file ops, command execution, include, SQL, output). Both
directions of the gadget question become tool-grounded:

* **Found chain** — a witness exhibit (class, magic method, property
  path, sink line). WITNESS-GRADE, detection-role: it boosts and
  exhibits, it never confirms a finding alone (every stamp this
  channel mints is detection-grade by :func:`is_detection_rule_id` —
  the sanwit precedent). A gadget chain adjudicates gadget EXISTENCE,
  not the taint path from request data to the unserialize call.
* **Verified absence** — a refutation INPUT, not a refutation. In this
  increment absence renders as strong hint-tier evidence with a
  completeness census attached ("no gadget chains found in the N/M
  parseable PHP files; depth limits stated"). Absence-as-suppression
  follows the binary oracle's earned-suppression precedent: NO
  consumer hard-suppresses on this artifact until a measured corpus
  earns the promotion (a named follow-up — see the module constants
  ``ABSENCE_*`` and the channel's outcome mapping, which never emits
  ``refuted``).

Approximations — stated, never implied away:

* **Flow depth**: intra-method direct flows (property reads,
  straight-line local assignments, concatenation/interpolation, a
  small seed set of string-propagating builtins) plus exactly ONE
  level of same-class method-call indirection. No inheritance-resolved
  dispatch, no cross-class hops, no loop/branch sensitivity. A gadget
  needing a deeper chain is NOT found — which is why absence is
  census-qualified evidence, not proof.
* **Class availability**: PHP gadget classes must be loaded or
  autoloadable at the unserialize site. Statically knowable bases are
  recorded per chain (``same_file`` / ``autoload_registered`` /
  ``included_somewhere`` via a provided include-graph / the honest
  ``not_established``); none of them proves runtime availability.
* **Trigger conditions**: ``__destruct``/``__wakeup``/
  ``__unserialize`` fire from unserialize itself; ``__toString`` /
  ``__call`` / ``__get`` / ``__set`` chains carry an explicit
  ``trigger_requires`` describing the extra usage context they need.

The oracle is pure static analysis — no LLM calls, no execution of
target code. Grammar absence is a recorded capability gap (the
channel returns ``skipped``, the artifact stamps
``capability.tree_sitter_php: false``), NEVER a silent pass.
"""

from __future__ import annotations

import logging
import os
import re
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

PRODUCER_MODULE = "core.analysis.gadget_oracle"
PRODUCER_VERSION = 1
ARTIFACT_NAME = "gadget-chains.json"

#: Honesty note carried on the artifact itself.
ARTIFACT_NOTE = (
    "Hint-tier static derivation from hostile content. A listed chain "
    "is a witness exhibit to verify against source, never a "
    "confirmation by itself; an empty chain list is evidence of "
    "absence only modulo the census (parse failures, unscanned "
    "PHP-like files, size/count caps) and the stated flow depth. No "
    "verdict path may suppress on this artifact until absence "
    "precision is corpus-earned (named follow-up)."
)

# CWE family the channel joins via the audit fallback chain.
GADGET_ORACLE_CWES = frozenset({"CWE-502"})

# Rule-id stamps (all detection-grade — see is_detection_rule_id).
RULE_CHAIN = "gadget_oracle:chain"
RULE_CHAIN_CONDITIONAL = "gadget_oracle:chain-conditional"
RULE_ABSENCE = "gadget_oracle:no-gadgets"

# Enumerated reasons (each a distinct tested string).
REASON_GRAMMAR_UNAVAILABLE = "grammar-unavailable"
REASON_LANGUAGE_UNSUPPORTED = "language-unsupported"
REASON_TARGET_UNUSABLE = "target-unusable"
REASON_NO_GADGETS_COMPLETE = "no-gadgets-complete-census"
REASON_NO_GADGETS_DEGRADED = "no-gadgets-degraded-census"

#: suppressions.jsonl verdict string for the record-only absence rows.
ABSENCE_RECORD_VERDICT = "gadget_oracle_no_gadgets"

#: The named follow-up gate: absence stays hint-tier until a measured
#: corpus earns suppression authority (binary-oracle precedent). This
#: constant exists so the promotion, when it lands, is a one-line flip
#: with the corpus citation beside it — and so tests can pin that the
#: current increment never suppresses.
ABSENCE_EARNS_SUPPRESSION = False

# Magic methods triggered by the unserialize lifecycle itself.
TRIGGER_METHODS = ("__destruct", "__wakeup", "__unserialize")

# Sink-relevant magic methods needing an extra usage context; the
# value is the honest trigger_requires prose carried on their chains.
CONDITIONAL_TRIGGERS: dict[str, str] = {
    "__toString": (
        "the injected object must reach a string-conversion context"
    ),
    "__call": (
        "an undefined method must be invoked on the injected object"
    ),
    "__get": (
        "an undefined/inaccessible property must be read from the "
        "injected object"
    ),
    "__set": (
        "an undefined/inaccessible property must be written on the "
        "injected object"
    ),
}

#: Lowercase → canonical spelling for the conditional-trigger table.
#: PHP method names are case-insensitive, so matching goes through
#: the lowercased form; the canonical key survives for display.
_CONDITIONAL_TRIGGERS_LOWER: dict[str, str] = {
    k.lower(): k for k in CONDITIONAL_TRIGGERS
}

# ── sink vocabulary (SEED-tier: canonical exemplars only — the
#    vocab-list policy; per-target vocabulary is the study loop's job,
#    never this tuple's) ──────────────────────────────────────────────

_FILE_SINKS = frozenset({
    "unlink", "file_put_contents", "file_get_contents", "fopen",
    "fwrite", "rename", "copy", "rmdir", "chmod", "readfile", "touch",
})
_EXEC_SINKS = frozenset({
    "exec", "system", "passthru", "shell_exec", "popen", "proc_open",
    "pcntl_exec", "eval", "assert", "create_function",
})
# Callable-injection sinks: the FIRST argument is the callable.
_CALLABLE_SINKS = frozenset({"call_user_func", "call_user_func_array"})
_SQL_FUNCTIONS = frozenset({
    "mysqli_query", "mysql_query", "pg_query", "sqlite_query",
})
# Receiver-method SQL sinks ($db->query($tainted)) — receiver type is
# unknown statically; hits are detection-grade witnesses by design.
_SQL_METHODS = frozenset({"query", "exec", "multi_query", "prepare"})

# String-shape propagators: a call to one of these with a tainted
# argument stays tainted. Seed set — direct-flow modelling only.
_PROPAGATORS = frozenset({
    "sprintf", "implode", "join", "str_replace", "trim", "strval",
    "strtolower", "strtoupper", "base64_decode", "urldecode",
    "rawurldecode", "stripslashes", "substr", "str_repeat",
})

_SINK_CATEGORY_BY_NAME: dict[str, str] = {}
for _n in _FILE_SINKS:
    _SINK_CATEGORY_BY_NAME[_n] = "file"
for _n in _EXEC_SINKS:
    _SINK_CATEGORY_BY_NAME[_n] = "exec"
for _n in _SQL_FUNCTIONS:
    _SINK_CATEGORY_BY_NAME[_n] = "sql"

# ── bounds (the tree is hostile content; every list it can grow is
#    capped, with the caps recorded in the census) ────────────────────

MAX_FILES = 50_000
MAX_FILE_BYTES = 8 * 1024 * 1024  # mirrors inventory MAX_FILE_BYTES
# Chain accumulation stops at MAX_CHAINS + 1 DURING the scan (the +1
# proves truncation), never after it: one hostile file can otherwise
# mint millions of one-hop chain dicts before a final slice would
# discard them (memory, not correctness). Lower loses real chains on
# gadget-dense trees; higher only raises the hostile-tree memory
# ceiling — the census carries chains_truncated either way.
MAX_CHAINS = 200
MAX_SINKS_PER_METHOD = 16
# Same-class call records per method, mirroring MAX_SINKS_PER_METHOD:
# each recorded call can fan out into callee-sink chains, so an
# unbounded list is a memory amplifier on hostile input. Lower drops
# real one-hop chains in call-heavy magic methods (absence stays
# census-qualified either way); higher re-opens the amplifier.
MAX_CALLS_PER_METHOD = 16
MAX_SITES_LISTED = 500
MAX_CENSUS_PATHS_LISTED = 50
MAX_EXCERPT_CHARS = 200
MAX_PROPERTY_PATH_CHARS = 120
MAX_REPORT_BYTES = 32 * 1024 * 1024

#: PHP extensions parsed unconditionally. Other files are probed for
#: an opening ``<?php`` tag and, when it is present, counted as
#: ``php_like_unscanned`` — completeness-breaking, never silently
#: ignored (a gadget class in an ``.inc`` module must not vanish from
#: the absence claim).
PHP_EXTENSIONS = (".php", ".phtml", ".php3", ".php4", ".php5")

#: VCS/metadata dirs never walked. NOTE: unlike the include-graph
#: walker, ``vendor/`` IS scanned — third-party libraries are exactly
#: where classic gadget chains live.
_WALK_SKIP_DIRS = frozenset({".git", ".svn", ".hg", "__pycache__",
                             "node_modules"})

# PHP-tag probe window for non-PHP extensions. 64 KiB clears any
# plausible legitimate HTML/text preamble before an embedded open tag;
# a larger window mostly re-reads binary blobs on every walked file,
# a smaller one lets a long preamble hide a PHP-like file from the
# census. The bound is DECLARED in the census (php_probe_bytes) and in
# the qualifier prose — a file whose first open tag sits beyond it is
# invisible to the probe, so the bound must ride with the absence
# claim rather than be silently absorbed.
_PHP_PROBE_BYTES = 65536
_PHP_OPEN_TAG_RE = re.compile(rb"<\?php\b|<\?=")

# Hypothesis shapes asserting a deserialization gadget claim (either
# direction — "a gadget chain exists" and "no gadgets in tree" both
# route here). Bounded gaps (hostile-text discipline).
_GADGET_HYPOTHESIS_RE = re.compile(
    r"(?:\bgadgets?\b|pop\s+chain|object\s+injection"
    r"|magic[\s_-]+method|__destruct|__wakeup|__tostring"
    r"|unseriali[sz]e|deseriali[sz]at)",
    re.IGNORECASE,
)


# ── grammar loading (clean degradation) ──────────────────────────────


_PARSER_LOCK = threading.Lock()
_PARSER_CACHE: list[Any] = []  # [] = unprobed, [None] = absent, [p]


def _php_parser() -> Any:
    """Cached tree-sitter-php parser, or ``None`` when the grammar or
    the tree_sitter runtime is not installed (capability-absent —
    recorded by every caller, never a silent pass).

    Mirrors :func:`core.inventory.call_graph.extract_call_graph_php`'s
    language resolution (``language_php`` attr vs ``language()``) and
    wraps the parser in the shared parse budget.
    """
    with _PARSER_LOCK:
        if _PARSER_CACHE:
            return _PARSER_CACHE[0]
        parser = None
        try:
            from core.inventory._ts_cache import bounded, import_grammar
            ts_php = import_grammar("tree_sitter_php")
            if ts_php is not None:
                from tree_sitter import Language, Parser
                lang_fn = (getattr(ts_php, "language_php", None)
                           or ts_php.language())
                if callable(lang_fn):
                    lang_fn = lang_fn()
                parser = bounded(Parser(Language(lang_fn)),
                                 label="gadget_oracle")
        except Exception as e:  # noqa: BLE001 — degradation, not crash
            logger.debug("gadget_oracle: php parser unavailable (%s)", e)
            parser = None
        _PARSER_CACHE.append(parser)
        return parser


def reset_parser_cache() -> None:
    """Test seam: forget the probed parser (grammar monkeypatching)."""
    with _PARSER_LOCK:
        _PARSER_CACHE.clear()


def php_grammar_available() -> bool:
    """Whether the tree-sitter-php substrate is usable right now."""
    return _php_parser() is not None


# ── per-file AST analysis ────────────────────────────────────────────


def _node_text(node: Any, src: bytes) -> str:
    return src[node.start_byte:node.end_byte].decode(
        "utf-8", errors="replace")


def _node_line(node: Any) -> int:
    return node.start_point[0] + 1


def _child_names(node: Any, type_name: str) -> list[Any]:
    return [c for c in node.named_children if c.type == type_name]


def _is_this(node: Any, src: bytes) -> bool:
    return (node.type == "variable_name"
            and _node_text(node, src) == "$this")


def _callee_name(fn: Any, src: bytes) -> str | None:
    """Casefolded global-callee name for a call's function node, or
    None when the callee is not a statically-named global function.

    PHP resolves function and method names case-insensitively
    (``SYSTEM(...)`` calls ``system``), so EVERY name comparison in
    this module goes through a lowercased form — byte-exact matching
    is a gadget-evasion hole, not a precision feature. A
    ``qualified_name`` whose only qualifier is a leading ``\\`` is the
    same global function written explicitly (``\\system``); a
    namespace-qualified name (``App\\system``) is a DIFFERENT symbol
    and must never match the global sink/propagator vocabulary.
    """
    if fn is None:
        return None
    if fn.type == "name":
        return _node_text(fn, src).lower()
    if fn.type == "qualified_name":
        if any(c.type == "namespace_name" for c in fn.named_children):
            return None
        name = _node_text(fn, src).lstrip("\\").lower()
        return name if name and "\\" not in name else None
    return None


def _property_path(node: Any, src: bytes) -> str | None:
    """``$this->a`` → ``"a"``; ``$this->a->b`` → ``"a->b"``; None when
    the member access is not rooted at ``$this``. Depth-bounded by the
    render cap (a hostile 10k-hop chain renders truncated)."""
    parts: list[str] = []
    cur = node
    while cur is not None and cur.type == "member_access_expression":
        name = cur.child_by_field_name("name")
        parts.append(_node_text(name, src) if name is not None else "?")
        cur = cur.child_by_field_name("object")
    if cur is None or not _is_this(cur, src):
        return None
    path = "->".join(reversed(parts))
    return path[:MAX_PROPERTY_PATH_CHARS]


@dataclass
class _SinkHit:
    category: str
    callee: str
    line: int
    via: str          # property path (or param:<name> marker)
    excerpt: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "callee": self.callee,
            "line": self.line,
            "via": self.via,
            "excerpt": self.excerpt,
        }


@dataclass
class _SameClassCall:
    method: str
    line: int
    tainted_args: list[int] = field(default_factory=list)
    via: str = ""     # property path feeding the first tainted arg


@dataclass
class _MethodFlow:
    name: str
    line: int
    params: list[str] = field(default_factory=list)
    property_sinks: list[_SinkHit] = field(default_factory=list)
    param_sinks: list[_SinkHit] = field(default_factory=list)
    calls: list[_SameClassCall] = field(default_factory=list)


@dataclass
class _ClassFacts:
    name: str
    line: int
    methods: dict[str, _MethodFlow] = field(default_factory=dict)


@dataclass
class _FileFacts:
    classes: list[_ClassFacts] = field(default_factory=list)
    unserialize_sites: list[dict[str, Any]] = field(default_factory=list)
    autoload_sites: list[int] = field(default_factory=list)
    parse_errors: bool = False
    #: ``use SomeTrait;`` clauses whose trait body is NOT in this file
    #: (or is namespace-qualified). A trait can carry the magic method
    #: AND the sink, so every unresolved use breaks census
    #: completeness — the absence claim must never stay "complete"
    #: while trait-provided gadget surface went unmodelled.
    unresolved_trait_uses: int = 0


_REQUEST_SUPERGLOBALS = ("$_GET", "$_POST", "$_REQUEST", "$_COOKIE",
                         "php://input", "$_SERVER")

_INCLUDE_NODE_TYPES = frozenset({
    "include_expression", "include_once_expression",
    "require_expression", "require_once_expression",
})


class _MethodWalker:
    """Single forward pass over one method body.

    Direct flows only: property reads root the taint set; straight-
    line local assignments, ``.=``, concatenation, interpolation,
    foreach-over-property and the propagator seed extend it; anything
    else (unknown calls, array gymnastics, control-flow joins) does
    NOT — the under-approximation the module docstring states.
    """

    def __init__(self, src: bytes, taint_params: list[str]):
        self.src = src
        # var name -> property-path (or param marker) it carries
        self.tainted: dict[str, str] = {
            p: f"param:{p}" for p in taint_params
        }
        self.property_sinks: list[_SinkHit] = []
        self.param_sinks: list[_SinkHit] = []
        self.calls: list[_SameClassCall] = []

    # -- taint predicate ---------------------------------------------

    def _taint_of(self, node: Any, depth: int = 0) -> str | None:
        """Property path (or param marker) the expression carries, or
        None when untainted under the direct-flow model."""
        if node is None or depth > 24:
            return None
        t = node.type
        if t == "member_access_expression":
            return _property_path(node, self.src)
        if t == "variable_name":
            return self.tainted.get(_node_text(node, self.src))
        if (t in ("parenthesized_expression", "cast_expression",
                  "unary_op_expression", "clone_expression",
                  "argument")
                or t in _INCLUDE_NODE_TYPES):
            for c in node.named_children:
                got = self._taint_of(c, depth + 1)
                if got:
                    return got
            return None
        if t in ("binary_expression", "encapsed_string",
                 "shell_command_expression", "augmented_assignment_expression",
                 "sequence_expression", "conditional_expression",
                 "array_creation_expression", "array_element_initializer"):
            for c in node.named_children:
                got = self._taint_of(c, depth + 1)
                if got:
                    return got
            return None
        if t == "function_call_expression":
            fn = node.child_by_field_name("function")
            if _callee_name(fn, self.src) in _PROPAGATORS:
                args = node.child_by_field_name("arguments")
                if args is not None:
                    return self._taint_of(args, depth + 1)
            return None
        if t == "arguments":
            for c in node.named_children:
                got = self._taint_of(c, depth + 1)
                if got:
                    return got
            return None
        return None

    # -- sink recording ----------------------------------------------

    def _record_sink(self, category: str, callee: str, node: Any,
                     via: str) -> None:
        hit = _SinkHit(
            category=category, callee=callee, line=_node_line(node),
            via=via,
            excerpt=_node_text(node, self.src)[:MAX_EXCERPT_CHARS],
        )
        bucket = (self.param_sinks if via.startswith("param:")
                  else self.property_sinks)
        if len(bucket) < MAX_SINKS_PER_METHOD:
            bucket.append(hit)

    def _tainted_args(self, args_node: Any) -> list[tuple[int, str]]:
        out: list[tuple[int, str]] = []
        if args_node is None:
            return out
        idx = 0
        for c in args_node.named_children:
            if c.type != "argument":
                continue
            via = self._taint_of(c)
            if via:
                out.append((idx, via))
            idx += 1
        return out

    # -- statement walk ----------------------------------------------

    def walk(self, node: Any) -> None:
        t = node.type
        if t == "assignment_expression":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if left is not None and left.type == "variable_name":
                via = self._taint_of(right)
                name = _node_text(left, self.src)
                if via:
                    self.tainted[name] = via
                else:
                    self.tainted.pop(name, None)  # strong update
            if right is not None:
                self.walk(right)
            return
        if t == "augmented_assignment_expression":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if left is not None and left.type == "variable_name":
                via = self._taint_of(right)
                if via:
                    self.tainted[_node_text(left, self.src)] = via
            if right is not None:
                self.walk(right)
            return
        if t == "foreach_statement":
            # foreach ($this->items as $k => $v): value var tainted.
            coll_via: str | None = None
            value_var: Any = None
            for c in node.named_children:
                if coll_via is None:
                    coll_via = self._taint_of(c)
                if c.type == "pair":
                    kids = _child_names(c, "variable_name")
                    value_var = kids[-1] if kids else None
                elif c.type == "variable_name":
                    value_var = c
                if c.type in ("compound_statement", "colon_block"):
                    break
            if coll_via and value_var is not None:
                self.tainted[_node_text(value_var, self.src)] = coll_via
            for c in node.named_children:
                if c.type in ("compound_statement", "colon_block"):
                    self.walk(c)
            return
        if t == "function_call_expression":
            fn = node.child_by_field_name("function")
            args = node.child_by_field_name("arguments")
            name = _callee_name(fn, self.src)
            if name is not None:
                tainted = self._tainted_args(args)
                if name in _CALLABLE_SINKS:
                    first = [v for i, v in tainted if i == 0]
                    if first:
                        self._record_sink("exec", name, node, first[0])
                elif name in _SINK_CATEGORY_BY_NAME and tainted:
                    self._record_sink(
                        _SINK_CATEGORY_BY_NAME[name], name, node,
                        tainted[0][1],
                    )
        elif t in _INCLUDE_NODE_TYPES:
            via = self._taint_of(node)
            if via:
                self._record_sink(
                    "include", t.replace("_expression", ""), node, via)
            return
        elif t == "echo_statement":
            for c in node.named_children:
                via = self._taint_of(c)
                if via:
                    self._record_sink("echo", "echo", node, via)
                    break
        elif t == "print_intrinsic":
            via = self._taint_of(node.named_children[0]
                                 if node.named_children else None)
            if via:
                self._record_sink("echo", "print", node, via)
        elif t == "shell_command_expression":
            via = self._taint_of(node)
            if via:
                self._record_sink("exec", "shell_command", node, via)
        elif t == "member_call_expression":
            obj = node.child_by_field_name("object")
            name_node = node.child_by_field_name("name")
            args = node.child_by_field_name("arguments")
            mname = (_node_text(name_node, self.src)
                     if name_node is not None else "")
            tainted = self._tainted_args(args)
            if obj is not None and _is_this(obj, self.src):
                # $this->helper(...) — same-class one-hop candidate.
                # PHP method names are case-insensitive; store the
                # canonical lowercased form so chain assembly matches
                # the (also lowercased) method table.
                if len(self.calls) < MAX_CALLS_PER_METHOD:
                    self.calls.append(_SameClassCall(
                        method=mname.lower(), line=_node_line(node),
                        tainted_args=[i for i, _ in tainted],
                        via=tainted[0][1] if tainted else "",
                    ))
            elif mname.lower() in _SQL_METHODS and tainted:
                self._record_sink("sql", "->" + mname, node,
                                  tainted[0][1])
        elif t == "scoped_call_expression":
            scope = node.named_children[0] if node.named_children else None
            name_node = node.child_by_field_name("name")
            args = node.child_by_field_name("arguments")
            if (scope is not None and scope.type == "relative_scope"
                    and name_node is not None
                    and len(self.calls) < MAX_CALLS_PER_METHOD):
                tainted = self._tainted_args(args)
                self.calls.append(_SameClassCall(
                    method=_node_text(name_node, self.src).lower(),
                    line=_node_line(node),
                    tainted_args=[i for i, _ in tainted],
                    via=tainted[0][1] if tainted else "",
                ))
        # Nested definitions get their own walk; do not descend.
        if t in ("function_definition", "method_declaration",
                 "anonymous_function_creation_expression",
                 "arrow_function", "class_declaration"):
            return
        for c in node.named_children:
            self.walk(c)


def _method_params(method_node: Any, src: bytes) -> list[str]:
    params = method_node.child_by_field_name("parameters")
    out: list[str] = []
    if params is None:
        return out
    for c in params.named_children:
        for v in _child_names(c, "variable_name"):
            out.append(_node_text(v, src))
    return out


def _analyze_method(method_node: Any, src: bytes) -> _MethodFlow:
    name_node = method_node.child_by_field_name("name")
    name = _node_text(name_node, src) if name_node is not None else "?"
    flow = _MethodFlow(name=name, line=_node_line(method_node),
                       params=_method_params(method_node, src))
    body = method_node.child_by_field_name("body")
    if body is None:
        return flow
    walker = _MethodWalker(src, taint_params=flow.params)
    walker.walk(body)
    flow.property_sinks = walker.property_sinks
    flow.param_sinks = walker.param_sinks
    flow.calls = walker.calls
    return flow


def _scan_toplevel(root: Any, src: bytes, facts: _FileFacts) -> None:
    """Collect unserialize sites and autoload registrations anywhere
    in the file (including inside functions/methods)."""
    stack = [root]
    while stack:
        node = stack.pop()
        if node.type == "function_call_expression":
            fn = node.child_by_field_name("function")
            name = _callee_name(fn, src)
            if name == "unserialize":
                args = node.child_by_field_name("arguments")
                arg_text = (_node_text(args, src)[:MAX_EXCERPT_CHARS]
                            if args is not None else "")
                facts.unserialize_sites.append({
                    "line": _node_line(node),
                    "excerpt": arg_text,
                    "request_derived": any(
                        g in arg_text
                        for g in _REQUEST_SUPERGLOBALS),
                })
            elif name == "spl_autoload_register":
                facts.autoload_sites.append(_node_line(node))
        elif node.type == "function_definition":
            fn_name = node.child_by_field_name("name")
            if (fn_name is not None
                    and _node_text(fn_name, src).lower() == "__autoload"):
                facts.autoload_sites.append(_node_line(node))
        stack.extend(node.named_children)


def _trait_use_names(body: Any, src: bytes) -> tuple[list[str], int]:
    """(same-file-resolvable trait names lowercased, unresolved count)
    from a class body's ``use`` clauses. A leading ``\\`` is stripped
    (global reference); a namespace-qualified trait name cannot be
    resolved within this file and counts as unresolved."""
    resolvable: list[str] = []
    unresolved = 0
    for use in _child_names(body, "use_declaration"):
        for c in use.named_children:
            if c.type == "name":
                resolvable.append(_node_text(c, src).lower())
            elif c.type == "qualified_name":
                text = _node_text(c, src).lstrip("\\")
                if "\\" in text:
                    unresolved += 1
                elif text:
                    resolvable.append(text.lower())
    return resolvable, unresolved


def analyze_php_source(content: bytes) -> _FileFacts | None:
    """Parse one PHP source buffer; None when the grammar is absent."""
    parser = _php_parser()
    if parser is None:
        return None
    facts = _FileFacts()
    try:
        tree = parser.parse(content)
    except Exception as e:  # noqa: BLE001 — parse trouble is census data
        logger.debug("gadget_oracle: parse failed (%s)", e)
        facts.parse_errors = True
        return facts
    if tree is None:
        facts.parse_errors = True
        return facts
    root = tree.root_node
    try:
        facts.parse_errors = bool(root.has_error)
    except AttributeError:
        facts.parse_errors = True
    # One pathological file (a single machine-deep expression) must
    # degrade to a census'd parse error, never crash the tree scan:
    # the method walker recurses over expression depth.
    try:
        _scan_toplevel(root, content, facts)
        traits: dict[str, dict[str, _MethodFlow]] = {}
        pending: list[tuple[_ClassFacts, list[str]]] = []
        stack = [root]
        while stack:
            node = stack.pop()
            if node.type in ("class_declaration", "trait_declaration"):
                name_node = node.child_by_field_name("name")
                name = (_node_text(name_node, content)
                        if name_node is not None else "?")
                body = node.child_by_field_name("body")
                methods: dict[str, _MethodFlow] = {}
                used: list[str] = []
                if body is not None:
                    for m in _child_names(body, "method_declaration"):
                        flow = _analyze_method(m, content)
                        # PHP method names are case-insensitive: key
                        # the table by the lowercased form so
                        # __DESTRUCT is the same method as __destruct.
                        methods[flow.name.lower()] = flow
                    names, unresolved = _trait_use_names(body, content)
                    used = names
                    facts.unresolved_trait_uses += unresolved
                if node.type == "trait_declaration":
                    # Trait names resolve case-insensitively too.
                    traits[name.lower()] = methods
                else:
                    cls = _ClassFacts(name=name, line=_node_line(node),
                                      methods=methods)
                    pending.append((cls, used))
            stack.extend(node.named_children)
        # Merge same-file trait methods (a trait can be declared after
        # its user, so merging happens once the walk is done). The
        # class's own method wins on collision — PHP precedence.
        for cls, used in pending:
            for tname in used:
                tmethods = traits.get(tname)
                if tmethods is None:
                    facts.unresolved_trait_uses += 1
                    continue
                for mname, flow in tmethods.items():
                    cls.methods.setdefault(mname, flow)
            facts.classes.append(cls)
    except RecursionError:
        logger.debug("gadget_oracle: recursion limit hit — file "
                     "census'd as parse error")
        facts.parse_errors = True
    return facts


# ── chain assembly ───────────────────────────────────────────────────


def _chains_for_class(cls: _ClassFacts, rel_path: str,
                      budget: int) -> list[dict[str, Any]]:
    """Gadget chains rooted at this class's magic methods.

    Depth: the magic method's own property sinks, plus ONE same-class
    call hop — the callee's property-rooted sinks (reachable because
    the magic method invokes it) and its param-rooted sinks on
    parameters that received a tainted argument.

    ``budget`` is the caller's remaining chain allowance: assembly
    STOPS once it is spent, so a gadget-dense tree never materialises
    an unbounded chain list that a later slice would discard.
    """
    chains: list[dict[str, Any]] = []
    magic_names = list(TRIGGER_METHODS) + list(CONDITIONAL_TRIGGERS)
    for magic in magic_names:
        if len(chains) >= budget:
            return chains
        # The method table is keyed lowercase (PHP case-insensitivity);
        # ``magic`` keeps its canonical spelling for the exhibit.
        flow = cls.methods.get(magic.lower())
        if flow is None:
            continue
        base = {
            "class": cls.name,
            "file": rel_path,
            "magic_method": magic,
            "line": flow.line,
            "trigger": ("unserialize" if magic in TRIGGER_METHODS
                        else "conditional"),
        }
        if magic in CONDITIONAL_TRIGGERS:
            base["trigger_requires"] = CONDITIONAL_TRIGGERS[magic]
        for hit in flow.property_sinks:
            if len(chains) >= budget:
                return chains
            chains.append({
                **base, "steps": [],
                "property_path": hit.via, "sink": hit.to_dict(),
            })
        for call in flow.calls:
            callee = cls.methods.get(call.method)
            if callee is None:
                continue
            step = [{"method": call.method, "line": callee.line,
                     "call_line": call.line}]
            for hit in callee.property_sinks:
                if len(chains) >= budget:
                    return chains
                chains.append({
                    **base, "steps": step,
                    "property_path": hit.via, "sink": hit.to_dict(),
                })
            if call.tainted_args:
                passed = {callee.params[i] for i in call.tainted_args
                          if i < len(callee.params)}
                for hit in callee.param_sinks:
                    pname = hit.via.removeprefix("param:")
                    if pname in passed:
                        if len(chains) >= budget:
                            return chains
                        chains.append({
                            **base, "steps": step,
                            "property_path": call.via or hit.via,
                            "sink": hit.to_dict(),
                        })
    return chains


# ── tree scan ────────────────────────────────────────────────────────


def _iter_tree_files(root: Path) -> tuple[list[tuple[str, Path]],
                                          dict[str, Any]]:
    """(rel_posix, abs) pairs for regular files, plus walk stats.

    Only REGULAR files are opened: a FIFO/socket/device in a hostile
    tree would block ``open()`` forever (the shared inventory walker's
    ``is_file()`` guard, mirrored here). Skips are never silent —
    symlinks (files AND directories, which ``os.walk`` does not
    follow) and special files are counted so the census can state
    exactly what the walk did not look at.
    """
    out: list[tuple[str, Path]] = []
    stats: dict[str, Any] = {
        "truncated": False,
        "symlink_skipped": 0,
        "special_skipped": 0,
    }
    root_s = str(root)
    for dirpath, dirnames, filenames in os.walk(root_s):
        kept: list[str] = []
        for d in sorted(dirnames):
            if d in _WALK_SKIP_DIRS:
                continue
            if os.path.islink(os.path.join(dirpath, d)):
                stats["symlink_skipped"] += 1
                continue
            kept.append(d)
        dirnames[:] = kept
        for fn in sorted(filenames):
            full = os.path.join(dirpath, fn)
            if os.path.islink(full):
                stats["symlink_skipped"] += 1
                continue
            if not os.path.isfile(full):
                stats["special_skipped"] += 1
                continue
            rel = os.path.relpath(full, root_s).replace(os.sep, "/")
            out.append((rel, Path(full)))
            if len(out) >= MAX_FILES:
                logger.warning(
                    "gadget_oracle: tree listing capped at %d files",
                    MAX_FILES)
                stats["truncated"] = True
                return out, stats
    return out, stats


def _availability_basis(
    class_file: str,
    site_files: set[str],
    autoload_registered: bool,
    include_graph: dict[str, Any] | None,
) -> str:
    """Best statically-knowable availability basis for a gadget class
    at the tree's unserialize sites. NONE of these proves runtime
    availability; ``not_established`` is the honest floor, never a
    reachability verdict."""
    if class_file in site_files:
        return "same_file"
    if autoload_registered:
        return "autoload_registered"
    if isinstance(include_graph, dict):
        files = include_graph.get("files")
        if isinstance(files, dict):
            entry = files.get(class_file)
            if isinstance(entry, dict):
                count = entry.get("includer_count")
                if isinstance(count, int) and count >= 1:
                    return "included_somewhere"
    return "not_established"


def scan_tree(
    target_root: str | Path,
    *,
    include_graph: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Scan a tree for PHP gadget chains; returns the artifact dict.

    Mechanical only — no LLM anywhere, no target code executed. The
    census is the completeness contract: every file the scan could
    not read/parse/afford is COUNTED, so the absence direction is
    quotable only modulo those counts.
    """
    root = Path(target_root)
    generated_at = datetime.now(timezone.utc).isoformat()
    report: dict[str, Any] = {
        "tier": "hint",
        "producer": {
            "module": PRODUCER_MODULE,
            "version": PRODUCER_VERSION,
            "generated_at": generated_at,
        },
        "note": ARTIFACT_NOTE,
        "target_path": str(root),
        "capability": {"tree_sitter_php": php_grammar_available()},
        "analysis_depth": {
            "property_flow": (
                "intra-method direct flows plus one same-class "
                "method-call hop"
            ),
            "flow_insensitive": True,
            "inheritance_resolved": False,
            "trigger_methods": list(TRIGGER_METHODS),
            "conditional_triggers": sorted(CONDITIONAL_TRIGGERS),
        },
    }
    if not root.is_dir():
        report["capability"]["target_usable"] = False
        report["census"] = {"complete": False,
                            "incomplete_reasons": ["target-unusable"]}
        report["chains"] = []
        report["unserialize_sites"] = []
        return report
    report["target_path"] = str(root.resolve())
    if not report["capability"]["tree_sitter_php"]:
        report["census"] = {
            "complete": False,
            "incomplete_reasons": [REASON_GRAMMAR_UNAVAILABLE],
        }
        report["chains"] = []
        report["unserialize_sites"] = []
        return report

    files, walk_stats = _iter_tree_files(root)
    php_files = 0
    parsed_clean = 0
    parse_error_count = 0
    read_error_count = 0
    oversized_count = 0
    php_like_unscanned_count = 0
    unresolved_trait_count = 0
    parse_error_files: list[str] = []
    read_error_files: list[str] = []
    oversized_files: list[str] = []
    php_like_listed: list[str] = []
    chains: list[dict[str, Any]] = []
    sites: list[dict[str, Any]] = []
    sites_total = 0
    site_files: set[str] = set()
    autoload_sites: list[dict[str, Any]] = []
    autoload_registered = False
    magic_counts: dict[str, int] = {}
    class_count = 0
    per_class_availability: list[tuple[dict[str, Any], str]] = []

    for rel, full in files:
        suffix = os.path.splitext(rel)[1].lower()
        is_php = suffix in PHP_EXTENSIONS
        try:
            if not is_php:
                with open(full, "rb") as fh:
                    head = fh.read(_PHP_PROBE_BYTES)
                if _PHP_OPEN_TAG_RE.search(head):
                    php_like_unscanned_count += 1
                    if len(php_like_listed) < MAX_CENSUS_PATHS_LISTED:
                        php_like_listed.append(rel)
                continue
            php_files += 1
            size = full.stat().st_size
            if size > MAX_FILE_BYTES:
                oversized_count += 1
                if len(oversized_files) < MAX_CENSUS_PATHS_LISTED:
                    oversized_files.append(rel)
                continue
            with open(full, "rb") as fh:
                content = fh.read(MAX_FILE_BYTES + 1)
        except OSError:
            if is_php:
                read_error_count += 1
                if len(read_error_files) < MAX_CENSUS_PATHS_LISTED:
                    read_error_files.append(rel)
            continue
        facts = analyze_php_source(content)
        if facts is None:
            # Grammar vanished mid-scan (test seams) — capability gap.
            report["capability"]["tree_sitter_php"] = False
            break
        if facts.parse_errors:
            parse_error_count += 1
            if len(parse_error_files) < MAX_CENSUS_PATHS_LISTED:
                parse_error_files.append(rel)
        else:
            parsed_clean += 1
        unresolved_trait_count += facts.unresolved_trait_uses
        if facts.unserialize_sites:
            site_files.add(rel)
        for s in facts.unserialize_sites:
            sites_total += 1
            if len(sites) < MAX_SITES_LISTED:
                sites.append({"file": rel, **s})
        if facts.autoload_sites:
            autoload_registered = True
        for line in facts.autoload_sites:
            if len(autoload_sites) >= MAX_CENSUS_PATHS_LISTED:
                break
            autoload_sites.append({"file": rel, "line": line})
        for cls in facts.classes:
            class_count += 1
            for m in cls.methods.values():
                low = m.name.lower()
                if (low in TRIGGER_METHODS
                        or low in _CONDITIONAL_TRIGGERS_LOWER):
                    canon = _CONDITIONAL_TRIGGERS_LOWER.get(low, low)
                    magic_counts[canon] = magic_counts.get(canon, 0) + 1
            # Chain assembly stops at MAX_CHAINS + 1 (the +1 proves
            # truncation) DURING the walk; the census above continues
            # so magic/class counts stay complete after the budget is
            # spent.
            budget = MAX_CHAINS + 1 - len(per_class_availability)
            if budget > 0:
                for chain in _chains_for_class(cls, rel, budget):
                    per_class_availability.append((chain, rel))

    for chain, rel in per_class_availability:
        chain["availability"] = _availability_basis(
            rel, site_files, autoload_registered, include_graph)
        chains.append(chain)

    incomplete: list[str] = []
    if not report["capability"]["tree_sitter_php"]:
        incomplete.append(REASON_GRAMMAR_UNAVAILABLE)
    if parse_error_count:
        incomplete.append("parse-errors")
    if read_error_count:
        incomplete.append("read-errors")
    if oversized_count:
        incomplete.append("oversized-files")
    if php_like_unscanned_count:
        incomplete.append("php-like-unscanned")
    if walk_stats["symlink_skipped"]:
        # A symlink can point at a gadget class the walk never read —
        # completeness-breaking, never a silent skip.
        incomplete.append("symlinks-skipped")
    if unresolved_trait_count:
        # A trait defined elsewhere can carry the magic method AND
        # the sink — using it unresolved breaks the absence claim.
        incomplete.append("unresolved-traits")
    if walk_stats["truncated"]:
        incomplete.append("file-cap-truncated")
    # Special files (FIFO/socket/device) are COUNTED but not
    # completeness-breaking: they have no at-rest content a parse
    # could have seen, so no gadget class can hide in one. Breaking
    # on them would mark any tree with a stray socket Incomplete for
    # content that cannot exist; not counting them would hide that
    # the walk met (and refused to open) non-regular files.

    report["census"] = {
        "php_files": php_files,
        "parsed_clean": parsed_clean,
        "parse_error_count": parse_error_count,
        "read_error_count": read_error_count,
        "oversized_count": oversized_count,
        "php_like_unscanned_count": php_like_unscanned_count,
        "symlink_skipped_count": walk_stats["symlink_skipped"],
        "special_file_count": walk_stats["special_skipped"],
        "unresolved_trait_count": unresolved_trait_count,
        "php_probe_bytes": _PHP_PROBE_BYTES,
        "files_truncated": walk_stats["truncated"],
        "complete": not incomplete,
        "incomplete_reasons": incomplete,
    }
    report["census_detail"] = {
        "parse_error_files": parse_error_files,
        "read_error_files": read_error_files,
        "oversized_files": oversized_files,
        "php_like_unscanned_files": php_like_listed,
    }
    report["magic_method_census"] = {
        "classes": class_count,
        "by_method": dict(sorted(magic_counts.items())),
    }
    report["autoload"] = {
        "registered": autoload_registered,
        "sites": autoload_sites,
    }
    report["unserialize_sites"] = sites
    report["unserialize_sites_total"] = sites_total
    if sites_total > MAX_SITES_LISTED:
        report["unserialize_sites_truncated"] = True
    report["chains"] = chains[:MAX_CHAINS]
    if len(chains) > MAX_CHAINS:
        report["chains_truncated"] = True
    return report


# ── artifact I/O ─────────────────────────────────────────────────────


def save_gadget_report(output_dir: str | Path,
                       report: dict[str, Any]) -> None:
    """Write ``gadget-chains.json`` into the run directory (atomic)."""
    from core.json import save_json
    save_json(Path(output_dir) / ARTIFACT_NAME, report)


def resolve_artifact_path(output_dir: str | Path) -> Path | None:
    """The existing artifact for a run dir, or None. Follows the
    project-mode ``checklist.json`` symlink the way the include-graph
    loader does (sibling artifacts live beside the resolved
    checklist)."""
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


def load_gadget_report(output_dir: str | Path) -> dict[str, Any] | None:
    """Read the artifact from a run dir; None when missing/malformed
    (consumers degrade to pre-oracle behaviour)."""
    from core.json import load_json
    cand = resolve_artifact_path(output_dir)
    if cand is None:
        return None
    try:
        data = load_json(cand, max_bytes=MAX_REPORT_BYTES)
    except Exception:  # noqa: BLE001 — a bad artifact never blocks a consumer
        logger.debug("gadget_oracle: unreadable artifact at %s", cand,
                     exc_info=True)
        return None
    return data if isinstance(data, dict) else None


def report_matches_target(report: dict[str, Any],
                          target_root: str | Path | None) -> bool:
    """One-target rule, fail-closed: the artifact's facts apply only
    to the tree they were derived from. Unknown/unresolvable roots on
    EITHER side refuse (False), never guess."""
    recorded = report.get("target_path")
    if not isinstance(recorded, str) or not recorded or target_root is None:
        return False
    try:
        return Path(recorded).resolve() == Path(target_root).resolve()
    except OSError:
        return False


# ── consumer query (the ONE re-validating read path) ─────────────────


#: Qualifier rendered when the census cannot be validated.
CENSUS_UNKNOWN_QUALIFIER = (
    "Gadget-oracle census is missing or invalid — enumeration "
    "completeness is unknown. Treat both directions as hints and "
    "verify against source; never treat these facts as a verdict "
    "input."
)


def census_qualifier(report: dict[str, Any]) -> str:
    """Mandatory completeness qualifier every consumer must render
    beside the facts — quoting absence without it is exactly the
    dishonest shape this tool exists to replace."""
    census = report.get("census")
    if not isinstance(census, dict) or not isinstance(
            census.get("complete"), bool):
        return CENSUS_UNKNOWN_QUALIFIER
    depth = "intra-method + one same-class call hop"
    probe = census.get("php_probe_bytes")
    probe_note = (
        f"; non-PHP extensions probed only the first "
        f"{probe // 1024} KiB for open tags"
        if isinstance(probe, int) and not isinstance(probe, bool)
        and probe > 0 else ""
    )
    if census["complete"]:
        return (
            f"Hint-tier gadget facts from a COMPLETE parse census "
            f"({census.get('parsed_clean', '?')} PHP file(s), all "
            f"parsed clean; flow depth: {depth}{probe_note}). A "
            f"deeper or cross-class chain would not be found. "
            f"Steering context — verify against source; never treat "
            f"as a verdict input."
        )
    reasons = ", ".join(
        str(r) for r in (census.get("incomplete_reasons") or [])[:6]
    ) or "unknown"
    return (
        f"Hint-tier gadget facts from an INCOMPLETE census "
        f"({census.get('parsed_clean', '?')}/"
        f"{census.get('php_files', '?')} PHP file(s) parsed clean; "
        f"gaps: {reasons}; flow depth: {depth}{probe_note}). Absence "
        f"of chains here is weak evidence. Steering context — verify "
        f"against source; never treat as a verdict input."
    )


def _coerce_chain(raw: Any) -> dict[str, Any] | None:
    """Bound and type-coerce one chain row from run-dir (untrusted)
    JSON — tampered strings must never ride unbounded into prompts."""
    if not isinstance(raw, dict):
        return None
    sink = raw.get("sink") if isinstance(raw.get("sink"), dict) else {}
    line = raw.get("line")
    sink_line = sink.get("line")
    steps = []
    for s in (raw.get("steps") or [])[:4]:
        if isinstance(s, dict):
            steps.append(str(s.get("method") or "")[:128])
    return {
        "class": str(raw.get("class") or "")[:256],
        "file": str(raw.get("file") or "")[:512],
        "magic_method": str(raw.get("magic_method") or "")[:64],
        "line": line if isinstance(line, int)
        and not isinstance(line, bool) and line >= 0 else 0,
        "trigger": ("unserialize"
                    if raw.get("trigger") == "unserialize"
                    else "conditional"),
        "trigger_requires": str(raw.get("trigger_requires") or "")[:200],
        "steps": steps,
        "property_path": str(
            raw.get("property_path") or "")[:MAX_PROPERTY_PATH_CHARS],
        "sink_category": str(sink.get("category") or "")[:32],
        "sink_callee": str(sink.get("callee") or "")[:128],
        "sink_line": sink_line if isinstance(sink_line, int)
        and not isinstance(sink_line, bool) and sink_line >= 0 else 0,
        "sink_excerpt": str(sink.get("excerpt") or "")[:MAX_EXCERPT_CHARS],
        "availability": str(raw.get("availability") or "")[:64],
    }


def gadget_facts_for_file(
    report: dict[str, Any],
    file_path: str,
    *,
    max_chains: int = 8,
    max_sites: int = 5,
) -> dict[str, Any] | None:
    """Consumer-facing gadget facts for one file plus the tree-level
    summary. The census + qualifier are ALWAYS part of the result.
    Returns None when the report carries no usable census (an
    unqualified fact must never exist). The artifact lives in a run
    directory (attacker-adjacent shapes), so every field is coerced
    and bounded here — the one query every consumer goes through.
    """
    if not isinstance(report, dict):
        return None
    census = report.get("census")
    if not isinstance(census, dict):
        return None
    p = (file_path.replace("\\", "/").removeprefix("./")
         if file_path else "")
    all_chains = [c for c in (report.get("chains") or [])
                  if isinstance(c, dict)]
    file_chains = []
    for raw in all_chains:
        coerced = _coerce_chain(raw)
        if coerced and coerced["file"] == p:
            file_chains.append(coerced)
        if len(file_chains) >= max_chains:
            break
    tree_chains: list[dict[str, Any]] = []
    if not file_chains:
        for raw in all_chains[:max_chains]:
            coerced = _coerce_chain(raw)
            if coerced:
                tree_chains.append(coerced)
    file_sites = []
    for s in (report.get("unserialize_sites") or []):
        if not isinstance(s, dict) or s.get("file") != p:
            continue
        line = s.get("line")
        file_sites.append({
            "line": line if isinstance(line, int)
            and not isinstance(line, bool) and line >= 0 else 0,
            "request_derived": bool(s.get("request_derived")),
            "excerpt": str(s.get("excerpt") or "")[:MAX_EXCERPT_CHARS],
        })
        if len(file_sites) >= max_sites:
            break
    return {
        "tier": "hint",
        "chains_total": len(all_chains),
        "chains_in_file": file_chains,
        "chains_elsewhere": tree_chains,
        "unserialize_sites_in_file": file_sites,
        "census_complete": bool(census.get("complete"))
        if isinstance(census.get("complete"), bool) else False,
        "qualifier": census_qualifier(report),
    }


# ── audit-channel surface ────────────────────────────────────────────


def is_gadget_hypothesis(text: str) -> bool:
    """True when the hypothesis asserts a deserialization-gadget shape
    (either direction: a chain exists, or 'no gadgets in tree')."""
    return bool(text) and bool(_GADGET_HYPOTHESIS_RE.search(text))


def gadget_oracle_applicable(cwe: str) -> bool:
    """CWE fallback-chain gate: the deserialization family."""
    norm = (cwe or "").upper().strip()
    if norm and not norm.startswith("CWE-"):
        norm = f"CWE-{norm}"
    return norm in GADGET_ORACLE_CWES


def gadget_language_permitted(
    file_path: str, language: str | None = None,
) -> bool:
    """Chain-BUILD language gate (both orchestrator hooks call it).

    PHP is the only modeled substrate. Mirrors the sanwit gate: mapped
    ``.php`` extensions pass; unmapped extensions pass on a php
    content-probe hint; no file context fails CLOSED (the joern_langs
    precedent) — the leg's existence feeds the empty-dispatch
    synthesis routing, which must stay unchanged off-PHP.
    """
    from core.audit.hypothesis_mapping import (
        semgrep_language_for,
        semgrep_probed_language,
    )
    if semgrep_language_for(file_path or "") == "php":
        return True
    return semgrep_probed_language(file_path or "", language) == "php"


def is_detection_rule_id(rule_id: str) -> bool:
    """The WHOLE namespace is detection-grade (sanwit precedent): a
    found chain adjudicates gadget existence, not the request-to-
    unserialize taint path, so it may corroborate and exhibit but
    never promote a finding alone."""
    return rule_id.startswith("gadget_oracle:")


@dataclass
class GadgetOracleEvidence:
    """Channel verdict for one CWE-502 hypothesis."""

    outcome: str                 # confirmed | inconclusive | skipped | error
    reason: str
    rule_id: str = RULE_CHAIN
    tool: str = "gadget_oracle"
    file_path: str = ""
    function_name: str = ""
    chains: list[dict[str, Any]] = field(default_factory=list)
    census: dict[str, Any] = field(default_factory=dict)
    qualifier: str = ""
    # Plain tool stamps and structured receipts both slot in (the
    # fail_open corroboration convention).
    corroboration: list[Any] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "tool": self.tool,
            "outcome": self.outcome,
            "reason": self.reason,
            "rule_id": self.rule_id,
            "file_path": self.file_path,
            "function_name": self.function_name,
            "census": self.census,
            "qualifier": self.qualifier,
        }
        if self.chains:
            d["chains"] = self.chains
        if self.corroboration:
            d["corroboration"] = list(self.corroboration)
        return d


_SCAN_MEMO_LOCK = threading.Lock()
_SCAN_MEMO: dict[str, dict[str, Any]] = {}


def reset_scan_memo() -> None:
    """Test seam: forget per-target scan results."""
    with _SCAN_MEMO_LOCK:
        _SCAN_MEMO.clear()


def _memoized_scan(target_root: Path,
                   include_graph: dict[str, Any] | None) -> dict[str, Any]:
    """One tree scan per resolved target root per process — the audit
    dispatches this channel once per hypothesis, and the tree does
    not change mid-run."""
    try:
        key = str(target_root.resolve())
    except OSError:
        key = str(target_root)
    with _SCAN_MEMO_LOCK:
        hit = _SCAN_MEMO.get(key)
    if hit is not None:
        return hit
    report = scan_tree(target_root, include_graph=include_graph)
    with _SCAN_MEMO_LOCK:
        return _SCAN_MEMO.setdefault(key, report)


def _record_absence_row(
    output_dir: str | Path,
    file_path: str,
    function_name: str,
    report: dict[str, Any],
) -> None:
    """Record-only suppressions.jsonl row (``dropped: false``): the
    absence evidence was attached to a finding's adjudication. In this
    increment NOTHING is dropped on it — the row exists so operators
    can see exactly what the oracle saw, and so the corpus-earned
    promotion (named follow-up) has an audit trail to measure
    against."""
    try:
        from core.analysis.reach_chokepoint import record_suppression
        census = report.get("census") or {}
        record_suppression(
            Path(output_dir),
            finding={"file_path": file_path, "function": function_name},
            verdict=ABSENCE_RECORD_VERDICT,
            reason=census_qualifier(report),
            dropped=False,
            extra={
                "census": {
                    k: census.get(k)
                    for k in ("php_files", "parsed_clean", "complete",
                              "incomplete_reasons")
                },
                "earns_suppression": ABSENCE_EARNS_SUPPRESSION,
            },
        )
    except Exception:  # noqa: BLE001 — best-effort audit trail
        logger.debug("gadget_oracle: absence record write failed",
                     exc_info=True)


def run_gadget_oracle_check(
    target_path: str | Path,
    file_path: str,
    function_name: str,
    hypothesis: str,
    *,
    language: str | None = None,
    include_graph: dict[str, Any] | None = None,
    output_dir: str | Path | None = None,
) -> GadgetOracleEvidence:
    """Channel entry point (the run_*_check convention).

    Outcome mapping — the authority adjudication, in code:

    * chains found → ``confirmed`` with a detection-grade stamp
      (witness exhibits ride on the receipt; the stamp never promotes
      alone).
    * no chains → ``inconclusive`` ALWAYS (never ``refuted``): with a
      complete census the reason is the strong-absence variant, with
      a degraded census the weak one. A ``dropped: false``
      suppressions row records what the oracle saw.
    * grammar absent / non-PHP file / unusable target → ``skipped``
      (capability-absent recorded, never a silent pass and never a
      clean resolution).
    """
    ev = GadgetOracleEvidence(
        outcome="skipped", reason="", file_path=file_path,
        function_name=function_name,
    )
    if not gadget_language_permitted(file_path, language):
        ev.reason = REASON_LANGUAGE_UNSUPPORTED
        return ev
    if not php_grammar_available():
        ev.reason = REASON_GRAMMAR_UNAVAILABLE
        return ev
    root = Path(target_path)
    if not root.is_dir():
        ev.reason = REASON_TARGET_UNUSABLE
        return ev
    report = _memoized_scan(root, include_graph)
    if output_dir is not None:
        try:
            existing = load_gadget_report(output_dir)
            if existing is None or not report_matches_target(
                    existing, root):
                save_gadget_report(output_dir, report)
        except Exception:  # noqa: BLE001 — artifact write is best-effort
            logger.debug("gadget_oracle: artifact write failed",
                         exc_info=True)
    census = report.get("census") or {}
    ev.census = {
        k: census.get(k)
        for k in ("php_files", "parsed_clean", "parse_error_count",
                  "php_like_unscanned_count", "complete",
                  "incomplete_reasons")
    }
    ev.qualifier = census_qualifier(report)
    chains = [c for c in (report.get("chains") or [])
              if isinstance(c, dict)]
    if chains:
        coerced = [c for c in (_coerce_chain(raw) for raw in chains[:8])
                   if c is not None]
        ev.chains = coerced
        unconditional = [c for c in coerced
                         if c["trigger"] == "unserialize"]
        ev.outcome = "confirmed"
        ev.rule_id = (RULE_CHAIN if unconditional
                      else RULE_CHAIN_CONDITIONAL)
        top = (unconditional or coerced)[0]
        ev.reason = (
            f"{len(chains)} gadget chain(s) in tree; e.g. "
            f"{top['class']}::{top['magic_method']} -> "
            f"{top['sink_category']}:{top['sink_callee']} via "
            f"$this->{top['property_path']} "
            f"({top['file']}:{top['sink_line']}, availability: "
            f"{top['availability']}). Witness exhibit — verify "
            f"against source; the request-to-unserialize taint path "
            f"is a separate claim."
        )
        return ev
    ev.outcome = "inconclusive"
    ev.rule_id = RULE_ABSENCE
    complete = census.get("complete") is True
    ev.reason = (REASON_NO_GADGETS_COMPLETE if complete
                 else REASON_NO_GADGETS_DEGRADED)
    if output_dir is not None:
        _record_absence_row(output_dir, file_path, function_name, report)
    return ev

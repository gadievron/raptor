"""Control-flow ordering refinement for lexical TOCTOU candidates.

The lexical TOCTOU scan pairs a check call with a later use call by
line order alone, which also pairs calls in different functions, calls
on mutually exclusive branches, and uses of a reassigned variable. This
refiner re-examines each candidate pair on the real statement-level
control-flow graph and can only narrow the lexical verdict:

- ``pruned`` — the pair is provably not an ordered flow: the calls sit
  in different functions, no CFG path leads from the check to the use,
  or every such path first reassigns the checked variable.
- ``discharged`` — the ordered flow exists but the use carries an
  atomicity idiom (``O_NOFOLLOW``, ``O_CREAT|O_EXCL``, ``fopen``'s
  exclusive ``"x"`` mode) that closes the checked race's primary
  vector. Discharge is mitigation, not absence: the caller reports it
  as inconclusive, never as refuted.
- ``sustained`` — the ordered flow was verified (``verified`` set) or
  the refiner could not model the source at all, in which case the
  lexical verdict stands exactly as before (``verified`` unset).

Anything unmodeled — an unparseable file, an ambiguous call site, a
statement form the CFG builder refuses — sustains the baseline rather
than minting a conclusion in either direction.
"""

from dataclasses import dataclass
import re

from .defassign import ProofRefusal
from .lifetime_witness import CFG_EXIT, build_statement_cfg

_MAX_SOURCE_CHARS = 1 << 20
_IDENTIFIER_RE = re.compile(r"[A-Za-z_]\w*\Z")
_NOFOLLOW_RE = re.compile(r"\bO_NOFOLLOW\b")
_CREAT_RE = re.compile(r"\bO_CREAT\b")
_EXCL_RE = re.compile(r"\bO_EXCL\b")
#: Zero-based flags-argument position for the atomically-flaggable
#: openers; fopen is handled separately via its mode string.
_OPEN_FLAG_POSITIONS = {"open": 1, "openat": 2}


@dataclass(frozen=True)
class OrderVerdict:
    status: str  # "sustained" | "pruned" | "discharged"
    reason: str = ""
    #: True only when the check-to-use flow was positively verified on
    #: the CFG; False for baseline sustains the refiner could not model.
    verified: bool = False


_SUSTAIN_UNMODELED = OrderVerdict(
    status="sustained",
    reason="control-flow refinement unavailable; lexical verdict retained",
)


class ToctouRefiner:
    """Per-source refiner; parses once, builds one CFG per function."""

    def __init__(self, source: str) -> None:
        self._root = None
        self._data = b""
        self._cfgs: dict[int, object] = {}
        if not isinstance(source, str) or len(source) > _MAX_SOURCE_CHARS:
            return
        from .condition_extraction import _get_parser

        parser = _get_parser("c")
        if parser is None:
            return
        data = source.encode("utf-8")
        root = parser.parse(data).root_node
        if root.has_error:
            return
        self._root = root
        self._data = data

    def _text(self, node) -> str:
        return self._data[node.start_byte : node.end_byte].decode(
            "utf-8", "replace",
        )

    def _call_on_line(self, line: int, name: str):
        """The unique call to *name* starting on 1-based *line*, else None."""
        row = line - 1
        matches = []
        stack = [self._root]
        while stack:
            node = stack.pop()
            if node.type == "call_expression" and node.start_point[0] == row:
                callee = node.child_by_field_name("function")
                if callee is not None and self._text(callee) == name:
                    matches.append(node)
            stack.extend(child for child in node.children
                         if child.start_point[0] <= row <= child.end_point[0])
        return matches[0] if len(matches) == 1 else None

    @staticmethod
    def _enclosing_function(node):
        while node is not None and node.type != "function_definition":
            node = node.parent
        return node

    def _cfg_for(self, func):
        cached = self._cfgs.get(func.id)
        if cached is not None:
            return cached
        body = func.child_by_field_name("body")
        if body is None:
            raise ProofRefusal("function without a body")
        cfg = build_statement_cfg(body)
        self._cfgs[func.id] = cfg
        return cfg

    def _node_covering(self, cfg, call):
        """The unique CFG node whose expressions contain *call*, else None."""
        hits = []
        for nid, stmts in cfg.exprs.items():
            for stmt in stmts:
                if (stmt.start_byte <= call.start_byte
                        and call.end_byte <= stmt.end_byte):
                    hits.append(nid)
                    break
        return hits[0] if len(hits) == 1 else None

    @staticmethod
    def _reaches(cfg, start, target, blocked):
        """True when *target* is reachable from *start*'s successors
        without expanding any node in *blocked* (the blocked node itself
        may still be the target)."""
        seen = set()
        queue = [n for n in cfg.succ.get(start, ()) if n != CFG_EXIT]
        while queue:
            nid = queue.pop()
            if nid in seen:
                continue
            seen.add(nid)
            if nid == target:
                return True
            if nid in blocked:
                continue
            queue.extend(cfg.succ.get(nid, ()))
        return False

    def _kill_nodes(self, cfg, variable, exclude):
        """CFG nodes that rebind *variable* (assignment or declaration)."""
        kills = set()
        for nid, stmts in cfg.exprs.items():
            if nid in exclude:
                continue
            for stmt in stmts:
                stack = [stmt]
                while stack:
                    node = stack.pop()
                    if node.type == "assignment_expression":
                        left = node.child_by_field_name("left")
                        if (left is not None and left.type == "identifier"
                                and self._text(left) == variable):
                            kills.add(nid)
                    elif node.type in ("declaration", "init_declarator"):
                        declarator = node.child_by_field_name("declarator")
                        inner = declarator
                        while inner is not None and inner.type != "identifier":
                            inner = inner.child_by_field_name("declarator")
                        if inner is not None and self._text(inner) == variable:
                            kills.add(nid)
                    stack.extend(node.named_children)
        return kills

    def _atomic_discharge(self, use_call, use_name: str) -> str:
        """A mitigation reason when the use is an atomic idiom, else ''."""
        arguments = use_call.child_by_field_name("arguments")
        args = ([] if arguments is None else
                [c for c in arguments.named_children if c.type != "comment"])
        position = _OPEN_FLAG_POSITIONS.get(use_name)
        if position is not None and position < len(args):
            flags = self._text(args[position])
            if _NOFOLLOW_RE.search(flags):
                return "O_NOFOLLOW on the use mitigates the symlink vector"
            if _CREAT_RE.search(flags) and _EXCL_RE.search(flags):
                return "O_CREAT|O_EXCL makes the creation atomic"
        if use_name == "fopen" and len(args) >= 2:
            mode = args[1]
            if mode.type == "string_literal" and "x" in self._text(mode):
                return 'fopen exclusive "x" mode makes the creation atomic'
        return ""

    def refine(
        self,
        check_name: str,
        check_line: int,
        use_name: str,
        use_line: int,
        variable: str,
    ) -> OrderVerdict:
        """Order one lexical candidate pair on the CFG."""
        if self._root is None:
            return _SUSTAIN_UNMODELED
        check_call = self._call_on_line(check_line, check_name)
        use_call = self._call_on_line(use_line, use_name)
        if check_call is None or use_call is None:
            return _SUSTAIN_UNMODELED
        # Computed up front, applied only after the hard prunes: a pair
        # with no flow at all is pruned, not merely "mitigated".
        discharge = self._atomic_discharge(use_call, use_name)

        def fallback() -> OrderVerdict:
            if discharge:
                return OrderVerdict(status="discharged", reason=discharge)
            return _SUSTAIN_UNMODELED

        check_func = self._enclosing_function(check_call)
        use_func = self._enclosing_function(use_call)
        if check_func is None or use_func is None:
            return fallback()
        if check_func.id != use_func.id:
            return OrderVerdict(
                status="pruned",
                reason="check and use are in different functions",
            )
        try:
            cfg = self._cfg_for(check_func)
        except ProofRefusal:
            return fallback()
        check_node = self._node_covering(cfg, check_call)
        use_node = self._node_covering(cfg, use_call)
        if check_node is None or use_node is None:
            return fallback()
        if check_node == use_node:
            # Ordering within one statement is beyond the statement CFG.
            return fallback()
        if not self._reaches(cfg, check_node, use_node, blocked=frozenset()):
            return OrderVerdict(
                status="pruned",
                reason="no control-flow path from the check to the use",
            )
        if _IDENTIFIER_RE.match(variable):
            kills = self._kill_nodes(
                cfg, variable, exclude={check_node, use_node},
            )
            if kills and not self._reaches(
                cfg, check_node, use_node, blocked=kills,
            ):
                return OrderVerdict(
                    status="pruned",
                    reason=(
                        f"'{variable}' is reassigned on every control-flow "
                        "path from the check to the use"
                    ),
                )
        if discharge:
            return OrderVerdict(status="discharged", reason=discharge)
        return OrderVerdict(
            status="sustained",
            reason="control-flow path from the check to the use verified",
            verified=True,
        )

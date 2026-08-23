"""Bounded compile-time constant folding for the Java value gate.

Answers ONE question for the sanitizer-cut gate: does every reaching
definition of the sink argument assign a compile-time constant? When
it does, the value consumed at the sink cannot carry taint regardless
of any sanitizer — the OWASP-Benchmark-style dead-branch ternary
(``bar = (7 * 18) + num > 200 ? "constant" : tainted``) is the
canonical shape: the condition folds over literal-only reaching
definitions, the constant branch is selected, and the tainted branch
is provably dead.

Soundness posture (refusal-first, mirroring the Java CFG builder):

* The expression grammar is a closed allowlist — integer / string /
  boolean / char / null literals, parentheses, unary ``-`` / ``!``,
  integer ``+ - * / %`` (division and modulo refuse a zero divisor
  rather than guessing), string ``+`` concatenation, comparisons,
  ``== !=``, ``&& ||``, and the ternary (folded only when its
  condition folds to a boolean). Casts, method calls, field and
  array accesses, and every other node type refuse.
* Identifiers resolve through the caller-supplied reaching-defs
  oracle: every reaching definition of the name at that point must
  itself fold, and all of them must fold to the SAME value —
  disagreeing constants refuse (the branch taken is unknown).
* Java locals cannot be aliased (no address-of), so a local whose
  every reaching definition folds is genuinely constant at the use;
  array elements and fields CAN alias, and they refuse structurally:
  an array/field store is not a ``name = expr`` shape this module
  accepts as a definition.
* Recursion is bounded (depth cap, visited set) — cyclic definitions
  refuse.

Integer semantics are Python's, not Java's: values whose magnitude
exceeds 31-bit two's-complement range refuse rather than model
wraparound (a folded comparison near overflow would otherwise be
wrong in exactly the false-suppression direction).
"""

from __future__ import annotations

from typing import Any

from core.analysis.threat_model_java import (
    NON_SOURCE_JVM_CONSTANT_FIELDS,
    NON_SOURCE_SYSTEM_READS,
)
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from tree_sitter import Node



_MAX_DEPTH = 8
_INT_MIN = -(2 ** 31)
_INT_MAX = 2 ** 31 - 1

# Sentinel distinguishing "folds to None (null literal)" from "refuses".
_REFUSE = object()


class _TaintFree:
    """Sentinel: provably attacker-uncontrolled, runtime value unknown
    (JVM constant fields such as ``File.separator`` and JDK class
    constants — NOT environment reads: the threat-model authority
    classifies ``System.getenv``/``getProperty`` as taint sources, the
    b44 stop-ship's root cause).
    Never a usable VALUE — value consumers (switch pruning, weak-name
    matching, danger checks) must never see it, so the fold boundary
    converts it to REFUSE unless the caller opted in. Taint-freedom
    consumers (:func:`definers_all_fold`) opt in: whichever runtime
    value such an expression takes, it carries no caller taint."""

    __slots__ = ()

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "<TAINT_FREE>"


TAINT_FREE = _TaintFree()

# System reads that may fold taint-free and the JVM constant fields —
# BOTH derived from the shared threat-model authority so this table can
# never contradict the postpass source-kind locator (the b44 stop-ship:
# System.getenv was taint-free here and a taint source there, and
# enforcement suppressed six real Juliet findings). Under the current
# model the System-read set is EMPTY — getenv/getProperty are
# environment taint sources; ``_fold_tf_system_read`` is kept for any
# future authority-approved non-source read.
_TF_SYSTEM_READS = NON_SOURCE_SYSTEM_READS
_TF_FILE_FIELDS = NON_SOURCE_JVM_CONSTANT_FIELDS


class _FoldExt:
    """Bundled opt-in extensions threaded through the fold recursion:
    the taint-free tier and the cross-file resolver. ``None`` (the
    default everywhere) is byte-for-byte the pre-extension folder."""

    __slots__ = (
        "allow_taint_free",
        "ban_tf_system_reads",
        "receiver_type",
        "union_hits",
        "union_member_check",
        "xfile",
    )

    def __init__(self, allow_taint_free: bool = False, xfile=None,
                 receiver_type=None, ban_tf_system_reads: bool = False) -> None:
        self.allow_taint_free = allow_taint_free
        self.xfile = xfile
        # receiver_type(name) -> exact created class name, or None.
        # Sound only when EVERY indexed definition of the local is a
        # creation of that same class (see JavaConstIndex).
        self.receiver_type = receiver_type
        # b42: count of non-agreeing definer merges resolved by the
        # taint-free union (audit attribution; empty when the tier is
        # off or every merge agreed).
        self.union_hits: list = []
        # b42: when the postpass locator classified any of THIS
        # finding's surviving source candidates as a system-read kind
        # (environment/properties/file/console/database/socket), a
        # system read cannot be taint-free FOR THIS FINDING — the read
        # is the suspected source, and calling it attacker-free is
        # exactly the circularity the all-candidates discipline
        # forbids.  Measured live: 17 Juliet ground-truth-bad
        # environment-source findings suppressed via the TF tier.
        self.ban_tf_system_reads: bool = ban_tf_system_reads
        # b42 x b40 composition: the union merges VALUE-CARRYING
        # members too, and a compile-time constant can violate a
        # value-based finding class on its own (the finite-value-set
        # path's per-element danger discipline — a set containing a
        # danger-bearing constant never suppresses).  The union holds
        # itself to the same bar: concrete string members pass through
        # this caller-supplied predicate (str list -> bool); None (no
        # danger authority at this entry) refuses any union containing
        # a concrete string member.
        self.union_member_check = None


def _tf_or_refuse(val: Any, ext) -> Any:
    if val is TAINT_FREE and (ext is None or not ext.allow_taint_free):
        return _REFUSE
    return val


def _parser():
    from core.analysis.cfg_builder_java import _get_parser
    return _get_parser()


class JavaConstIndex:
    """Per-file index of simple definitions: (line, name) → RHS node.

    Only ``type name = expr;`` declarators and ``name = expr``
    assignments within ``line_span`` are indexed — anything else
    (array stores, field stores, compound assignments, ++/--) is
    absent, so lookups on it refuse.
    """

    def __init__(self, source_text: str,
                 line_span: tuple[int, int],
                 java_file_path: str | None = None,
                 repo_root: str | None = None) -> None:
        self._defs: dict[tuple[int, str], Any] = {}
        # (lineno, name) keys that hold MORE THAN ONE write on the
        # line (one-liner if/else arms, chained statements).  A
        # line-keyed lookup cannot tell the reaching-defs oracle's
        # per-definition nodes apart, so serving any single RHS would
        # collapse distinct definers into one — measured as a live
        # false suppression when a one-liner if/else discriminant
        # folded to its first arm and pruned the tainted switch arm
        # (b42 trap fixture).  Such keys refuse.
        self._multi_write_lines: set[tuple[int, str]] = set()
        self._compound_writers: set[str] = set()
        # name -> exact created class, poisoned to None on any
        # non-creation or differently-typed definition.
        self._creation_types: dict[str, str | None] = {}
        self.xfile = None
        if java_file_path:
            # repo_root may be absent: the resolver then serves only
            # the JDK tier (no tree lookups), which needs no root.
            try:
                from core.analysis.java_xfile_const import (
                    make_xfile_resolver,
                )
                self.xfile = make_xfile_resolver(java_file_path, repo_root)
            except Exception:  # noqa: BLE001 — optional layer
                self.xfile = None
        self.ok = False
        parser = _parser()
        if parser is None:
            return
        try:
            tree = parser.parse(source_text.encode("utf-8"))
        except Exception:  # noqa: BLE001
            return
        lo, hi = line_span
        stack = [tree.root_node]
        while stack:
            n = stack.pop()
            if n.start_point[0] + 1 > hi or n.end_point[0] + 1 < lo:
                continue
            if n.type == "variable_declarator":
                name = n.child_by_field_name("name")
                value = n.child_by_field_name("value")
                if (name is not None and name.type == "identifier"
                        and value is not None):
                    nm = name.text.decode()
                    key = (n.start_point[0] + 1, nm)
                    if key in self._defs:
                        self._multi_write_lines.add(key)
                    self._defs[key] = value
                    self._note_creation(nm, value)
            elif n.type == "assignment_expression":
                left = n.child_by_field_name("left")
                right = n.child_by_field_name("right")
                op = n.child_by_field_name("operator")
                if left is not None and left.type == "identifier":
                    lname = left.text.decode()
                    if op is not None and op.type != "=":
                        # +=, -=, ... — a writer this index doesn't
                        # model; every lookup of the name must refuse.
                        self._compound_writers.add(lname)
                    elif right is not None:
                        akey = (n.start_point[0] + 1, lname)
                        if akey in self._defs:
                            self._multi_write_lines.add(akey)
                        self._defs[akey] = right
                        self._note_creation(lname, right)
            elif n.type == "update_expression":
                for ch in n.children:
                    if ch.type == "identifier":
                        self._compound_writers.add(ch.text.decode())
            stack.extend(n.children)
        self.ok = True

    def _note_creation(self, name: str, value: Node) -> None:
        """Track exact-creation-typed locals: usable as a method-call
        receiver class only when EVERY definition creates the same
        class. Any other definition shape poisons the name."""
        if value.type == "object_creation_expression":
            ty = value.child_by_field_name("type")
            cls = (ty.text.decode("utf-8", "replace").split("<", 1)[0]
                   if ty is not None else None)
        else:
            cls = None
        if name in self._creation_types:
            if self._creation_types[name] != cls:
                self._creation_types[name] = None
        else:
            self._creation_types[name] = cls

    def receiver_type(self, name: str) -> str | None:
        if name in self._compound_writers:
            return None
        return self._creation_types.get(name)

    def rhs_at(self, lineno: int, name: str):
        if name in self._compound_writers:
            return None
        if (lineno, name) in self._multi_write_lines:
            # Two+ writes to the name on one line: a line-keyed lookup
            # cannot disambiguate the oracle's definition nodes, and
            # serving either RHS collapses distinct definers (the b42
            # one-liner if/else trap).  Refuse.
            return None
        return self._defs.get((lineno, name))


def fold_expr(node, resolve_name, array_resolver=None,
          config_resolver=None, conduit_resolver=None,
          allow_taint_free: bool = False, xfile_resolver=None) -> Any:
    """Fold a tree-sitter Java expression node to a constant.

    ``resolve_name(name, depth)`` returns the name's constant value or
    ``_REFUSE``. ``array_resolver(node, resolve_name, depth)`` — when
    supplied (see :mod:`core.analysis.value_set_java`) — resolves an
    ``array_access`` read; without it every array access refuses.
    ``allow_taint_free`` opts into the :data:`TAINT_FREE` tier (the
    result may then be TAINT_FREE instead of a value); off (default),
    taint-free subexpressions refuse and behavior is unchanged.
    ``xfile_resolver`` (see :mod:`core.analysis.java_xfile_const`)
    resolves cross-file static-final fields and returns-literal
    methods. Returns the folded value, TAINT_FREE (opt-in), or
    ``_REFUSE``.
    """
    ext = None
    if allow_taint_free or xfile_resolver is not None:
        ext = _FoldExt(allow_taint_free=allow_taint_free,
                       xfile=xfile_resolver)
    val = _fold(node, resolve_name, 0, array_resolver, config_resolver,
                conduit_resolver, ext)
    return _tf_or_refuse(val, ext)


REFUSE = _REFUSE


def _receiver_chain(node: Node) -> str | None:
    """Dotted text of an identifier/field_access chain (``Utils`` /
    ``org.owasp.benchmark.helpers.Utils``); None for anything else."""
    if node is None:
        return None
    if node.type == "identifier":
        return node.text.decode("utf-8", "replace")
    if node.type == "field_access":
        obj = _receiver_chain(node.child_by_field_name("object"))
        fld = node.child_by_field_name("field")
        if obj is not None and fld is not None \
                and fld.type == "identifier":
            return obj + "." + fld.text.decode("utf-8", "replace")
    if node.type == "scoped_identifier":
        return node.text.decode("utf-8", "replace")
    return None


def _fold_field_access(node: Node, ext) -> Any:
    """``File.separator``-class taint-free fields and cross-file
    static-final resolution. Only fires under an extension context —
    the default folder refuses every field access, unchanged."""
    if ext is None:
        return _REFUSE
    obj = node.child_by_field_name("object")
    fld = node.child_by_field_name("field")
    if obj is None or fld is None or fld.type != "identifier":
        return _REFUSE
    field = fld.text.decode("utf-8", "replace")
    chain = _receiver_chain(obj)
    if chain is None:
        return _REFUSE
    if ext.allow_taint_free and chain.rsplit(".", 1)[-1] == "File" \
            and field in _TF_FILE_FIELDS:
        return TAINT_FREE
    if ext.xfile is not None:
        return ext.xfile.resolve_field(chain, field,
                                       ext.allow_taint_free)
    return _REFUSE


def _fold_tf_system_read(node: Node, resolve_name, depth, array_resolver,
                         config_resolver, conduit_resolver, ext) -> Any:
    """``System.<read>("lit")`` → TAINT_FREE for authority-approved
    NON-SOURCE reads only. Under the current threat model that set is
    EMPTY (getenv/getProperty are environment taint sources — the b44
    counterexample class; see core.analysis.threat_model_java), so
    this producer refuses everything today; it stays wired for any
    future read the authority approves. Literal (or folded-constant)
    name required; the two-arg default must itself fold or be
    taint-free."""
    if ext is None or not ext.allow_taint_free:
        return _REFUSE
    if ext.ban_tf_system_reads:
        # b42's per-finding circularity ban. With the authority's
        # non-source set empty this branch is structurally
        # never-firing (the name gate below refuses first) — kept as
        # defense-in-depth with its tests as never-firing pins.
        return _REFUSE
    name_node = node.child_by_field_name("name")
    obj = node.child_by_field_name("object")
    if name_node is None or obj is None:
        return _REFUSE
    if name_node.text.decode() not in _TF_SYSTEM_READS:
        return _REFUSE
    chain = _receiver_chain(obj)
    if chain is None or chain.rsplit(".", 1)[-1] != "System":
        return _REFUSE
    args_node = node.child_by_field_name("arguments")
    args = [c for c in (args_node.children if args_node else ())
            if c.is_named]
    if not args or len(args) > 2:
        return _REFUSE
    key = _fold(args[0], resolve_name, depth + 1, array_resolver,
                config_resolver, conduit_resolver, ext)
    if not isinstance(key, str):
        return _REFUSE
    if len(args) == 2:
        dflt = _fold(args[1], resolve_name, depth + 1, array_resolver,
                     config_resolver, conduit_resolver, ext)
        if dflt is _REFUSE or dflt is None:
            return _REFUSE
    if name_node.text.decode() == "getProperty":
        # System properties are runtime-writable (System.setProperty
        # from ANY code — including copying request data into one), so
        # a property read is taint-free only under the cross-file
        # resolver's tree-wide proof that this key is never written
        # and no variable-key write exists. No resolver, no proof —
        # refuse. getenv has no self-write API and needs no scan.
        if ext.xfile is None or not ext.xfile.tf_property_key_ok(key):
            return _REFUSE
    return TAINT_FREE


def _fold(node: Node, resolve_name, depth: int, array_resolver=None,
          config_resolver=None, conduit_resolver=None, ext=None) -> Any:
    if node is None or depth > _MAX_DEPTH:
        return _REFUSE
    t = node.type
    if t == "parenthesized_expression":
        inner = [c for c in node.children if c.is_named]
        return _fold(inner[0], resolve_name, depth + 1, array_resolver,
                 config_resolver, conduit_resolver, ext) \
            if len(inner) == 1 else _REFUSE
    if t == "field_access":
        return _fold_field_access(node, ext)
    if t == "cast_expression":
        # Only the identity cast folds: ``(String) e`` where ``e``
        # folds to a str is the same str (the OWASP-style collection
        # round-trip's ubiquitous shape). Numeric casts can truncate
        # or reinterpret, so every non-String target refuses — the
        # wrong-value direction here selects wrong branches downstream.
        ty = node.child_by_field_name("type")
        val = node.child_by_field_name("value")
        if ty is None or val is None:
            return _REFUSE
        ty_text = ty.text.decode().split("<", 1)[0].strip()
        if ty_text.split(".")[-1] != "String":
            return _REFUSE
        v = _fold(val, resolve_name, depth + 1, array_resolver,
                  config_resolver, conduit_resolver, ext)
        if v is TAINT_FREE:
            return v
        return v if isinstance(v, str) else _REFUSE
    if t == "array_access" and array_resolver is not None:
        return array_resolver(node, resolve_name, depth + 1)
    if t == "decimal_integer_literal":
        try:
            v = int(node.text.decode())
        except ValueError:
            return _REFUSE
        return v if _INT_MIN <= v <= _INT_MAX else _REFUSE
    if t == "string_literal":
        # DECODED value, not raw text: the raw quote-inclusive form
        # made "a" + "b" fold to a value that compared unequal to the
        # folded "ab" — a wrong False in exactly the branch-selection
        # position where it could pick the wrong ternary/switch arm.
        # Escapes refuse rather than risk a mis-decode.
        raw = node.text.decode()
        if len(raw) < 2 or "\\" in raw:
            return _REFUSE
        return raw[1:-1]
    if t in ("true", "false"):
        return t == "true"
    if t == "null_literal":
        return None
    if t == "character_literal":
        # Java char, represented as a 1-char str: switch labels and
        # charAt results then compare under one convention. Escaped
        # chars refuse.
        raw = node.text.decode()
        if len(raw) != 3 or "\\" in raw:
            return _REFUSE
        return raw[1:-1]
    if t == "method_invocation":
        # The taint-free System-read producer runs BEFORE the config
        # resolver: System.getProperty/getenv is never a
        # Properties-file read, and b22's hook claims every
        # getProperty spelling with a refusal that must not shadow
        # the (opt-in) taint-freedom conclusion. With the tier off
        # this is a no-op and the config resolver's ordering is
        # unchanged.
        tf = _fold_tf_system_read(node, resolve_name, depth,
                                  array_resolver, config_resolver,
                                  conduit_resolver, ext)
        if tf is TAINT_FREE:
            return tf
        if config_resolver is not None:
            cfg = config_resolver(node, depth + 1)
            if cfg is not None:
                # a getProperty read: the resolver owns the verdict —
                # a refusal must not fall through to the pure-call
                # allowlist (it would refuse anyway, but the refusal
                # accounting belongs to the config resolver).
                return cfg
        if conduit_resolver is not None:
            def _refold(child, d):
                return _fold(child, resolve_name, d, array_resolver,
                             config_resolver, conduit_resolver, ext)
            cv = conduit_resolver(node, _refold, depth + 1)
            if cv is not None:
                # a resolvable conduit call: the resolver owns the
                # verdict (value or REFUSE); never fall through to the
                # pure-call allowlist. Conduits refuse null constants
                # at derivation, so None stays an unambiguous
                # "not a conduit call" sentinel.
                return cv
        if ext is not None and ext.xfile is not None:
            xf = _fold_xfile_call(node, ext)
            if xf is not _REFUSE:
                return xf
        return _fold_pure_call(node, resolve_name, depth, array_resolver,
                               config_resolver, conduit_resolver, ext)
    if t == "identifier":
        return resolve_name(node.text.decode(), depth + 1)
    if t == "unary_expression":
        operand = node.child_by_field_name("operand")
        op = node.child_by_field_name("operator")
        val = _fold(operand, resolve_name, depth + 1, array_resolver, config_resolver, conduit_resolver, ext)
        if val is _REFUSE or val is TAINT_FREE or op is None:
            return _REFUSE
        text = op.type
        if text == "-" and isinstance(val, int) and not isinstance(val, bool):
            v = -val
            return v if _INT_MIN <= v <= _INT_MAX else _REFUSE
        if text == "!" and isinstance(val, bool):
            return not val
        return _REFUSE
    if t == "binary_expression":
        left = _fold(node.child_by_field_name("left"), resolve_name, depth + 1, array_resolver, config_resolver, conduit_resolver, ext)
        if left is _REFUSE:
            return _REFUSE
        op_node = node.child_by_field_name("operator")
        op = op_node.type if op_node is not None else ""
        # Short-circuit forms fold on the left operand alone when it
        # decides the result — mirrors Java evaluation order.
        if op == "&&" and left is False:
            return False
        if op == "||" and left is True:
            return True
        right = _fold(node.child_by_field_name("right"), resolve_name, depth + 1, array_resolver, config_resolver, conduit_resolver, ext)
        if right is _REFUSE:
            return _REFUSE
        if left is TAINT_FREE or right is TAINT_FREE:
            # Taint-free algebra: string concatenation of
            # constant/taint-free operands is taint-free (an attacker
            # controls neither side); every other operator refuses —
            # comparisons on an unknown value have no truth value.
            if op == "+" and all(
                    v is TAINT_FREE or isinstance(v, str)
                    for v in (left, right)):
                return TAINT_FREE
            return _REFUSE
        return _fold_binop(op, left, right)
    if t == "ternary_expression":
        cond = _fold(node.child_by_field_name("condition"), resolve_name, depth + 1, array_resolver, config_resolver, conduit_resolver, ext)
        if not isinstance(cond, bool):
            if ext is not None and ext.allow_taint_free:
                # Unknown selection over two attacker-free branches is
                # attacker-free — taint-freedom, never a usable value.
                cons = _fold(node.child_by_field_name("consequence"), resolve_name, depth + 1, array_resolver, config_resolver, conduit_resolver, ext)
                alt = _fold(node.child_by_field_name("alternative"), resolve_name, depth + 1, array_resolver, config_resolver, conduit_resolver, ext)
                if cons is not _REFUSE and alt is not _REFUSE:
                    return TAINT_FREE
            return _REFUSE
        branch = "consequence" if cond else "alternative"
        return _fold(node.child_by_field_name(branch), resolve_name, depth + 1, array_resolver, config_resolver, conduit_resolver, ext)
    return _REFUSE


def _fold_xfile_call(node: Node, ext) -> Any:
    """Cross-file returns-literal method calls: ``Cls.m(...)`` (static),
    ``new Cls(...).m(...)`` (exact runtime class by construction), and
    ``recv.m(...)`` where the extension context proves recv's every
    definition creates the SAME class. Creation arguments are
    irrelevant: the resolved body is a single ``return`` of an
    expression that cannot reference parameters or instance state."""
    obj = node.child_by_field_name("object")
    name_node = node.child_by_field_name("name")
    if obj is None or name_node is None:
        return _REFUSE
    args_node = node.child_by_field_name("arguments")
    argc = len([c for c in (args_node.children if args_node else ())
                if c.is_named])
    method = name_node.text.decode("utf-8", "replace")
    cls: str | None = None
    if obj.type == "object_creation_expression":
        ty = obj.child_by_field_name("type")
        if ty is not None:
            cls = ty.text.decode("utf-8", "replace").split("<", 1)[0]
    elif obj.type == "identifier":
        recv = obj.text.decode("utf-8", "replace")
        typed = ext.receiver_type(recv) if ext.receiver_type else None
        cls = typed or recv
    else:
        cls = _receiver_chain(obj)
    if not cls:
        return _REFUSE
    return ext.xfile.resolve_method(cls, method, argc,
                                    ext.allow_taint_free)


# String pure functions computed on folded-constant receivers. Each is
# total on its checked domain, side-effect free, and locale-independent
# as restricted below. Seed set <= 9 names.
_PURE_STRING_METHODS = frozenset({
    "charAt", "length", "substring", "toLowerCase", "toUpperCase",
    "trim", "concat",
})


def _fold_pure_call(node: Node, resolve_name, depth: int,
                    array_resolver=None,
          config_resolver=None, conduit_resolver=None, ext=None) -> Any:
    """Fold the pure-function allowlist on a receiver that itself
    folds: ``charAt``/``length`` (the original pair), plus
    ``substring``/``toLowerCase``/``toUpperCase``/``trim``/``concat``
    (zero-arg case variants only — the Locale-taking overloads refuse)
    and static ``String.valueOf`` on an already-folded value. A
    TAINT_FREE receiver stays TAINT_FREE through the value-erasing
    string ops (the attacker controls no part of the result); every
    argument must still fold to a constant. Every other call refuses
    as before."""
    name_node = node.child_by_field_name("name")
    obj = node.child_by_field_name("object")
    if name_node is None or obj is None:
        return _REFUSE
    method = name_node.text.decode()
    args_node = node.child_by_field_name("arguments")
    args = [c for c in (args_node.children if args_node else ())
            if c.is_named]
    if method == "valueOf" and obj.type == "identifier" \
            and obj.text.decode() == "String" and len(args) == 1:
        v = _fold(args[0], resolve_name, depth + 1, array_resolver,
                  config_resolver, conduit_resolver, ext)
        if v is TAINT_FREE:
            return TAINT_FREE
        if isinstance(v, (str, int, bool)) and v is not None:
            if isinstance(v, bool):
                return "true" if v else "false"
            return v if isinstance(v, str) else str(v)
        return _REFUSE
    if method not in _PURE_STRING_METHODS:
        return _REFUSE
    receiver = _fold(obj, resolve_name, depth + 1, array_resolver,
                     config_resolver, conduit_resolver, ext)
    folded_args: list[Any] = []
    for a in args:
        av = _fold(a, resolve_name, depth + 1, array_resolver,
                   config_resolver, conduit_resolver, ext)
        if av is _REFUSE:
            return _REFUSE
        folded_args.append(av)
    if receiver is TAINT_FREE:
        # Value-erasing ops on an attacker-free receiver: the result
        # carries no caller taint whatever the runtime value. charAt/
        # length yield derived scalars — equally attacker-free.
        if any(a is TAINT_FREE for a in folded_args):
            return TAINT_FREE if method == "concat" else _REFUSE
        return TAINT_FREE
    if not isinstance(receiver, str):
        return _REFUSE
    if any(a is TAINT_FREE for a in folded_args):
        return TAINT_FREE if method == "concat" else _REFUSE
    if method == "length":
        return len(receiver) if not folded_args else _REFUSE
    if method == "trim":
        # Java trim strips <= U+0020 specifically; refuse non-ASCII
        # receivers rather than model the difference from str.strip.
        if folded_args or not receiver.isascii():
            return _REFUSE
        return receiver.strip()
    if method in ("toLowerCase", "toUpperCase"):
        # Zero-arg only, ASCII only: the default-locale overload is
        # locale-dependent (the Turkish-I trap) — non-ASCII refuses.
        if folded_args or not receiver.isascii():
            return _REFUSE
        return (receiver.lower() if method == "toLowerCase"
                else receiver.upper())
    if method == "concat":
        if len(folded_args) != 1 or not isinstance(folded_args[0], str):
            return _REFUSE
        return receiver + folded_args[0]
    if method == "substring":
        if len(folded_args) not in (1, 2):
            return _REFUSE
        if not all(_is_int(a) for a in folded_args):
            return _REFUSE
        lo = folded_args[0]
        hi = folded_args[1] if len(folded_args) == 2 else len(receiver)
        if not (0 <= lo <= hi <= len(receiver)):
            return _REFUSE
        return receiver[lo:hi]
    if method == "charAt":
        if len(folded_args) != 1:
            return _REFUSE
        idx = folded_args[0]
        if isinstance(idx, bool) or not isinstance(idx, int):
            return _REFUSE
        if not (0 <= idx < len(receiver)):
            return _REFUSE
        return receiver[idx]
    return _REFUSE


def _is_int(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _fold_binop(op: str, left: Any, right: Any) -> Any:
    if op == "+" and isinstance(left, str) and isinstance(right, str):
        return left + right
    if _is_int(left) and _is_int(right):
        if op in ("+", "-", "*"):
            v = {"+": left + right, "-": left - right, "*": left * right}[op]
            return v if _INT_MIN <= v <= _INT_MAX else _REFUSE
        if op in ("/", "%"):
            if right == 0:
                return _REFUSE
            # Java integer division truncates toward zero.
            q = abs(left) // abs(right)
            if (left < 0) != (right < 0):
                q = -q
            if op == "/":
                return q if _INT_MIN <= q <= _INT_MAX else _REFUSE
            return left - q * right
        if op in ("<", "<=", ">", ">="):
            return {"<": left < right, "<=": left <= right,
                    ">": left > right, ">=": left >= right}[op]
    if op in ("==", "!="):
        if type(left) is type(right) or (left is None or right is None):
            return (left == right) if op == "==" else (left != right)
        return _REFUSE
    if op in ("&&", "||") and isinstance(left, bool) and isinstance(right, bool):
        return (left and right) if op == "&&" else (left or right)
    return _REFUSE


def _index_ext(index: JavaConstIndex, allow_taint_free: bool):
    """The fold-extension context an index carries: the cross-file
    resolver (when the index was built with a file path and repo root)
    plus the exact-creation receiver-type oracle. None when neither
    extension is active — the folder then runs byte-identically to its
    pre-extension form."""
    if index.xfile is None and not allow_taint_free:
        return None
    return _FoldExt(allow_taint_free=allow_taint_free,
                    xfile=index.xfile,
                    receiver_type=index.receiver_type)


def _make_point_resolver(rd, index: JavaConstIndex, array_resolver=None,
                         config_resolver=None, conduit_resolver=None,
                         ext=None):
    """Name resolver over the reaching-defs oracle: every reaching
    definition of the name at the program point must itself fold, and
    all must fold to the same value (see module docstring; TAINT_FREE
    values agree only with TAINT_FREE — an unknown attacker-free value
    never equals a known constant). Shared by the constant-definers
    gate and the switch-discriminant refinement.
    """

    def resolve_at(node, name: str, depth: int,
                   visiting: set[tuple[int, str]]) -> Any:
        if depth > _MAX_DEPTH:
            return _REFUSE
        try:
            defs = rd.at(node, name)
        except Exception:  # noqa: BLE001
            return _REFUSE
        if not defs:
            return _REFUSE
        values: list[Any] = []
        for d in defs:
            lineno = getattr(d, "lineno", 0)
            key = (lineno, name)
            if key in visiting:
                return _REFUSE
            rhs = index.rhs_at(lineno, name)
            if rhs is None:
                return _REFUSE
            visiting.add(key)
            val = _fold(
                rhs,
                lambda nm, dp, _d=d: resolve_at(_d, nm, dp, visiting),
                depth,
                array_resolver,
                config_resolver,
                conduit_resolver,
                ext,
            )
            visiting.discard(key)
            if val is _REFUSE:
                return _REFUSE
            values.append(val)
        first = values[0]
        for v in values[1:]:
            if v is TAINT_FREE or first is TAINT_FREE:
                if v is not first:
                    return _tf_union(ext, values)
                continue
            if v is not first and v != first:
                return _tf_union(ext, values)
            if type(v) is not type(first):
                return _tf_union(ext, values)
        return first

    return resolve_at


def _tf_union(ext, values) -> Any:
    """Merge verdict for non-agreeing definers that each folded.

    Everything ``_fold`` produces is compile-time-known or proven
    attacker-free by construction, so a disagreement between folded
    values is still a union of attacker-free values — taint-free,
    never a usable value.  Value consumers (tier off) keep the
    historical refusal byte-for-byte; the union exists only for the
    suppression question (b42).

    Concrete STRING members additionally clear the caller's danger
    predicate (``ext.union_member_check``) or the merge refuses — the
    b40 composition: a value-based finding class is violated by the
    constant itself, however attacker-free, and the finite-value-set
    path already refuses such sets per element.  No predicate at this
    entry means no danger authority: refuse, never assume.  Valueless
    TAINT_FREE members ride the b37 tier precedent (no value to
    check); ints and booleans cannot carry a danger charset.
    """
    if ext is None or not ext.allow_taint_free:
        return _REFUSE
    strs = [v for v in values if isinstance(v, str)]
    if strs:
        chk = ext.union_member_check
        if chk is None or not chk(strs):
            return _REFUSE
    ext.union_hits.append(1)
    return TAINT_FREE


def fold_expr_at(rd, at_node, expr_node, index: JavaConstIndex,
                 array_resolver=None,
          config_resolver=None, conduit_resolver=None,
          allow_taint_free: bool = False,
          ban_tf_system_reads: bool = False,
          union_member_check=None) -> Any:
    """Fold an arbitrary expression at a program point: identifiers
    resolve through the reaching-defs oracle at ``at_node`` with the
    same all-defs-must-agree policy as the constant-definers gate.
    Returns the folded value or :data:`REFUSE`; TAINT_FREE only when
    ``allow_taint_free`` (value consumers keep the value-only
    contract)."""
    if not index.ok:
        return _REFUSE
    ext = _index_ext(index, allow_taint_free)
    if ext is not None:
        # A None ext means the taint-free tier is off, so the ban has
        # nothing to withdraw (and the union never fires).
        ext.ban_tf_system_reads = ban_tf_system_reads
        ext.union_member_check = union_member_check
    resolve_at = _make_point_resolver(rd, index, array_resolver,
                                      config_resolver, conduit_resolver,
                                      ext)
    visiting: set[tuple[int, str]] = set()
    val = _fold(
        expr_node,
        lambda nm, dp: resolve_at(at_node, nm, dp, visiting),
        0,
        array_resolver,
        config_resolver,
        conduit_resolver,
        ext,
    )
    return _tf_or_refuse(val, ext if allow_taint_free else None)


def definers_all_fold(
    rd,
    at_node,
    name: str,
    index: JavaConstIndex,
    array_resolver=None,
    config_resolver=None,
    conduit_resolver=None,
    ban_tf_system_reads: bool = False,
    union_member_check=None,
) -> bool:
    """True when EVERY reaching definer of ``name`` at ``at_node``
    folds to a compile-time constant — the values need NOT agree
    (taint-freedom, not value identity; a variable that is provably
    one of several constants carries no caller taint). Nested
    identifier resolution keeps the strict all-defs-must-agree policy
    of :func:`_make_point_resolver`, so relaxation applies only to the
    named variable's own definer set, never inside arithmetic.

    This is the taint-freedom consumer, so the :data:`TAINT_FREE` tier
    is enabled here: a definer that resolves to a provably
    attacker-uncontrolled value (system reads, cross-file static-final
    config, their concats) counts as folding — its exact value is
    irrelevant to the no-caller-taint conclusion this function
    exists to draw. ``ban_tf_system_reads`` withdraws the tier's
    bounded-system-read leg for findings whose own candidate source
    is such a read (the b42 circularity ban — see
    :func:`all_definers_constant`)."""
    if not index.ok:
        return False
    ext = _index_ext(index, allow_taint_free=True)
    ext.ban_tf_system_reads = ban_tf_system_reads
    ext.union_member_check = union_member_check
    resolve_at = _make_point_resolver(rd, index, array_resolver,
                                      config_resolver, conduit_resolver,
                                      ext)
    try:
        defs = rd.at(at_node, name)
    except Exception:  # noqa: BLE001 — oracle failure reads as refuse
        return False
    if not defs:
        return False
    for d in defs:
        rhs = index.rhs_at(getattr(d, "lineno", 0), name)
        if rhs is None:
            return False
        val = _fold(
            rhs,
            lambda nm, dp, _d=d: resolve_at(_d, nm, dp, set()),
            0,
            array_resolver,
            config_resolver,
            conduit_resolver,
            ext,
        )
        if val is _REFUSE:
            return False
    return True


def definer_fold_values(
    rd,
    at_node,
    name: str,
    index: JavaConstIndex,
    array_resolver=None,
    config_resolver=None,
    conduit_resolver=None,
    max_definers: int = 8,
) -> tuple[Any, ...] | None:
    """The folded VALUE of every reaching definer of ``name`` at
    ``at_node``, or None when any definer refuses. Values need not
    agree — this is the finite-value-set consumer (b40): a variable
    provably one of several compile-time constants carries no caller
    taint, and the caller decides whether the SET itself is
    acceptable (danger-model check per element).

    Value-only by construction: the TAINT_FREE tier stays disabled —
    a taint-free-but-unknown value has no member to run through a
    danger model, so it must refuse here (the plain taint-freedom
    conclusion without the set is :func:`definers_all_fold` /
    :func:`all_definers_constant`'s job). Definer sets larger than
    ``max_definers`` refuse (bounded recognizer).
    """
    if not index.ok:
        return None
    ext = _index_ext(index, allow_taint_free=False)
    resolve_at = _make_point_resolver(rd, index, array_resolver,
                                      config_resolver, conduit_resolver,
                                      ext)
    try:
        defs = rd.at(at_node, name)
    except Exception:  # noqa: BLE001 — oracle failure reads as refuse
        return None
    if not defs or len(defs) > max_definers:
        return None
    values = []
    for d in defs:
        rhs = index.rhs_at(getattr(d, "lineno", 0), name)
        if rhs is None:
            return None
        val = _fold(
            rhs,
            lambda nm, dp, _d=d: resolve_at(_d, nm, dp, set()),
            0,
            array_resolver,
            config_resolver,
            conduit_resolver,
            ext,
        )
        if val is _REFUSE or val is TAINT_FREE \
                or not isinstance(val, (str, int)) \
                or isinstance(val, bool):
            return None
        values.append(val)
    return tuple(values)


def all_definers_constant(
    rd,
    sink,
    sink_arg: str,
    index: JavaConstIndex,
    array_resolver=None,
    config_resolver=None,
    conduit_resolver=None,
    ban_tf_system_reads: bool = False,
    union_member_check=None,
) -> str | None:
    """None when the constancy proof fails; a short reason string when
    every reaching definition of ``sink_arg`` at ``sink`` folds to the
    same compile-time constant (the reason names the value's type, not
    the value — audit records shouldn't quote scanned content), or —
    the b37 taint-free tier — when every definer is provably
    attacker-uncontrolled (system reads / cross-file static-final
    config and their concats) though the runtime value is unknown.
    Suppression here is exactly the taint-freedom conclusion, so the
    tier is sound for this consumer; the reason string distinguishes
    the two proofs for the audit record.
    """
    if not index.ok:
        return None

    ext = _index_ext(index, allow_taint_free=True)
    if ext is not None:
        ext.ban_tf_system_reads = ban_tf_system_reads
        ext.union_member_check = union_member_check
    resolve_at = _make_point_resolver(rd, index, array_resolver,
                                      config_resolver, conduit_resolver,
                                      ext)
    value = resolve_at(sink, sink_arg, 0, set())
    if value is _REFUSE:
        return None
    if value is TAINT_FREE:
        if ext.union_hits:
            # b42: the definers disagreed on the value but every one
            # folded — the branch selector is irrelevant to the
            # attacker-control question.
            return (
                "every reaching definer of the sink argument folds to "
                "an attacker-free value (non-agreeing taint-free union)"
            )
        return (
            "every reaching definer of the sink argument is provably "
            "attacker-uncontrolled (taint-free system/config reads)"
        )
    return (
        f"every reaching definer of the sink argument folds to the "
        f"same compile-time {type(value).__name__} constant"
    )

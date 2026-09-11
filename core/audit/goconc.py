"""Go internal-concurrency witness for the anti-self-refutation gate.

Corroborates a reviewer's SELF-REFUTATION of a race hypothesis on a Go
function by proving, mechanically, that the claimed shared state has no
package-internal concurrency: no goroutine spawned anywhere inside the
owning package (``go`` statement) can reach the claimed state by any
named reference chain, and the claimed state never leaves the type's
own methods as a bare value.  When the witness holds, the dismissed
race requires an *external caller* to violate the API's
single-goroutine contract — which is exactly what the reviewer's
dismissal asserted, so re-flagging it would manufacture a false
positive.

Claimed state
    For a method, the receiver type (plus, transitively, the base of
    any type alias in the chain — an alias is the same type under a
    second name).  For a plain function, the base types of its
    pointer-typed parameters (a ``*T`` parameter is the mutable state
    the claim is about).  Value parameters are copies and carry no
    shared state; interface-typed or otherwise unresolvable mutable
    parameters make the claim underivable → no witness (unless the
    zero-spawn arm applies, see below).

Mechanism (all of it must succeed, in order):

1.  Parse every non-test ``.go`` file in the reviewed file's directory
    (tree-sitter Go; leading UTF-8 BOMs stripped).  Package membership
    is decided by each file's PARSED ``package`` clause against the
    anchor file's — never by a regex that a comment or encoding quirk
    could fool.  Any parse error, any file without a package clause,
    any dot-import, cgo, a non-blank ``unsafe`` import, implicit
    spawn machinery (``AfterFunc``, ``SetFinalizer``, ``Go``,
    ``Serve``, ``ListenAndServe``), or blowing the file/byte caps →
    no witness.
2.  No function value may leave the package: a function literal or a
    package-function value passed to a callee that is not
    package-local → no witness (the callee may run it on a goroutine
    the ``go``-statement scan never sees — worker pools, timers,
    servers).  Storage-only builtins (``append``, ``copy``) and
    callees rooted at package-owned state are exempt.  This guard
    runs BEFORE the zero-spawn arm — "zero spawns" is only
    meaningful once no function value escapes.
3.  Enumerate every ``go`` statement.  **Zero spawns** in the whole
    package proves the property for *any* state — nothing internal
    exists to race with — and discharges without needing the claimed
    types (this is the arm that covers plain functions whose parameter
    types pervade the package).
4.  Otherwise, for each spawn require a *decidable* shape and a
    negative reach check:

    - the spawn's enclosing function must not be a method of a claimed
      type (a goroutine born inside the type's own methods holds the
      receiver);
    - no identifier in the spawn statement's subtree may name a
      claimed type, an ``any``/``interface{}``-typed local or
      package-level variable, or a struct field declared with an
      opaque type;
    - the spawned callee must resolve: a package-level function, a
      method on an operand whose type resolves to a package-local or
      imported-package type (a resolved *claimed* type refuses), or a
      function literal.  Function values, unresolvable operands, and
      chained selectors → no witness.
5.  Receiver escape: inside the claimed type's own methods the bare
    receiver may be used only as a field-selector base or in a
    comparison.  A receiver appearing as an assignment RHS, call
    argument, composite-literal entry, channel-send operand, return
    value, ``&``-operand, or any other value position escapes the
    method — a goroutine could then reach the state through an
    interface or container that never names the type → no witness.
6.  Occupancy: every occurrence of a claimed type's name anywhere in
    the package must be inside the type's own declaration or inside a
    method whose receiver is that type.  Together with (5) this is
    what makes the per-spawn check non-transitive-yet-sound: a spawned
    closure can only obtain a claimed-typed value through code that
    *names* the type or through a bare-receiver escape, and both are
    accounted for.

Failure direction is uniformly conservative: every unresolvable
construct degrades to ``isolated=False`` ("no witness") — the floor
stands.  Boost-only: a positive result may only ever ACCEPT a
reviewer's dismissal, never create or suppress a finding.

Known soundness bound (documented, deliberate): a POINTER INTO the
claimed state (``&t.field``) handed to another package function from
inside the type's own methods is not tracked — the same syntactic
shape is how scan-style methods legitimately delegate conversion, so
refusing it would refuse the exact class the witness exists for.  A
package function stashing such a pointer where a goroutine reads it is
therefore out of view.  Consumers gate the discharge on an operator
repo-trust assertion for exactly this reason: on an untrusted target a
crafted package could launder state through that shape.  The
bare-receiver escape rule (5) closes the whole-receiver variants.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator, Mapping

logger = logging.getLogger(__name__)

# Caps for the package scan.  Exceeding either → no witness.
_MAX_PACKAGE_FILES = 64
_MAX_PACKAGE_BYTES = 4 * 1024 * 1024

# Go predeclared types whose values a spawn may freely mention.
_GO_BUILTIN_TYPES = frozenset({
    "bool", "byte", "complex64", "complex128", "error", "float32",
    "float64", "int", "int8", "int16", "int32", "int64", "rune",
    "string", "uint", "uint8", "uint16", "uint32", "uint64",
    "uintptr", "comparable",
})

# ``any`` / ``interface{}``-typed values are opaque carriers — a
# claimed value could hide inside.  Bail on them wherever they can
# reach a spawn.
_OPAQUE_TYPES = frozenset({"any", "interface{}"})

# Standard-library machinery that runs a callback on a goroutine the
# package never visibly spawns: ``time.AfterFunc`` / ``context.
# AfterFunc`` timer goroutines, ``runtime.SetFinalizer`` on the GC
# goroutine, ``sync.WaitGroup.Go`` (and the ``errgroup``/``tomb``
# ``Go`` convention), and HTTP serving (per-connection handler
# goroutines).  Presence anywhere in the package defeats the "every
# spawn is a go statement" premise → no witness.  Seed set, stdlib
# conventions only — misses degrade to a witness that fires where it
# should have been blocked, so keep additions equally universal.
_IMPLICIT_SPAWNER_NAMES = frozenset({
    "AfterFunc", "SetFinalizer", "Go", "TryGo", "Serve",
    "ListenAndServe",
})


@dataclass
class GoroutineIsolationResult:
    """Verdict of the Go internal-concurrency witness.

    ``isolated=True`` means the witness HOLDS: no package-internal
    goroutine reaches the claimed state.  Everything else — including
    every parse/resolution failure — is ``isolated=False`` with the
    refusing construct named in ``reasoning``.
    """

    isolated: bool = False
    spawn_count: int = -1
    claimed_types: tuple[str, ...] = ()
    reasoning: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "isolated": self.isolated,
            "spawn_count": self.spawn_count,
            "claimed_types": list(self.claimed_types),
            "reasoning": self.reasoning,
        }


def _strip_bom(text: str) -> str:
    return text[1:] if text.startswith("﻿") else text


def load_go_package(
    target_path: str | Path,
    rel_file: str,
) -> dict[str, str] | None:
    """Read the ``.go`` siblings of *rel_file* (one directory = the
    package's home).

    Returns ``{filename: content}`` for every non-test ``.go`` file in
    the directory with any leading UTF-8 BOM stripped, or ``None``
    when the directory cannot be loaded within the caps (→ no
    witness).  Package-clause attribution is deliberately NOT done
    here — :func:`check_goroutine_isolation` decides membership from
    the parsed tree, where a comment or encoding quirk cannot fool it.
    """
    try:
        anchor = Path(target_path) / rel_file
        if anchor.suffix != ".go" or not anchor.is_file():
            return None
        siblings = sorted(anchor.parent.glob("*.go"))
    except OSError:
        return None
    files: dict[str, str] = {}
    total = 0
    for path in siblings:
        if path.name.endswith("_test.go"):
            continue
        try:
            text = _strip_bom(
                path.read_text(encoding="utf-8", errors="strict"),
            )
        except (OSError, ValueError, UnicodeDecodeError):
            return None
        files[path.name] = text
        total += len(text)
        if len(files) > _MAX_PACKAGE_FILES or total > _MAX_PACKAGE_BYTES:
            return None
    if anchor.name not in files:
        return None
    return files


# ---------------------------------------------------------------------------
# tree-sitter plumbing
# ---------------------------------------------------------------------------


def _go_parser() -> Any | None:
    """Per-thread cached tree-sitter Go parser (None → no witness)."""
    try:
        from core.inventory.extractors import _ts_parser_for
        return _ts_parser_for("go")
    except Exception:
        return None


def _walk(node: Any) -> Iterator[Any]:
    stack = [node]
    while stack:
        n = stack.pop()
        yield n
        stack.extend(reversed(n.named_children))


def _text(node: Any) -> str:
    return node.text.decode("utf-8", errors="replace")


def _base_type_name(type_node: Any) -> str | None:
    """Base identifier of a (possibly pointer/generic) type node.

    Returns the bare package-local type name, ``"pkg.Name"`` for a
    qualified type, or ``None`` for shapes we do not resolve.
    """
    n = type_node
    while n is not None and n.type in ("pointer_type", "generic_type"):
        n = next(iter(n.named_children), None)
    if n is None:
        return None
    if n.type == "type_identifier":
        return _text(n)
    if n.type == "qualified_type":
        return _text(n)  # "pkg.Name" — never a package-local type
    if n.type == "interface_type" and _text(n).replace(" ", "") == "interface{}":
        return "interface{}"
    return None


def _package_clause_name(tree: Any) -> str | None:
    """Package name from the PARSED package clause (never a regex)."""
    for child in tree.root_node.named_children:
        if child.type == "package_clause":
            for n in child.named_children:
                if n.type == "package_identifier":
                    return _text(n)
    return None


@dataclass
class _FileIndex:
    """Per-file declaration index."""

    name: str
    tree: Any
    imports: set[str] = field(default_factory=set)
    has_dot_import: bool = False
    has_cgo: bool = False
    has_unsafe: bool = False


@dataclass
class _PackageIndex:
    """Package-level declaration index across all files."""

    functions: dict[str, Any] = field(default_factory=dict)
    # type name → alias base name (None for a plain type_spec)
    types: dict[str, str | None] = field(default_factory=dict)
    # package-level var/const name → resolved type name or None (poison)
    package_vars: dict[str, str | None] = field(default_factory=dict)
    # struct field names declared with an opaque (any/interface{}) type
    opaque_fields: set[str] = field(default_factory=set)
    # method names declared on ANY package type — the callback-escape
    # probe reads a selector argument whose field is one of these as a
    # method value (``x.Handle`` passed as a function value)
    methods: set[str] = field(default_factory=set)


def _index_file(fi: _FileIndex, pkg: _PackageIndex) -> None:
    root = fi.tree.root_node
    for child in root.named_children:
        if child.type == "import_declaration":
            for n in _walk(child):
                if n.type != "import_spec":
                    continue
                name_node = n.child_by_field_name("name")
                path_node = n.child_by_field_name("path")
                path = (
                    _text(path_node).strip('"')
                    if path_node is not None else ""
                )
                label = _text(name_node) if name_node is not None else None
                if path == "C":
                    # cgo: C code can run threads no go statement shows.
                    fi.has_cgo = True
                if path == "unsafe" and label != "_":
                    # A real unsafe import can alias memory namelessly.
                    # (A blank import only enables //go:linkname and
                    # grants this package no unsafe.Pointer capability.)
                    fi.has_unsafe = True
                if label is not None:
                    if label == ".":
                        fi.has_dot_import = True
                    elif label != "_":
                        fi.imports.add(label)
                elif path:
                    # Heuristic default import name; only used to
                    # classify selector operands as external.
                    fi.imports.add(path.rsplit("/", 1)[-1])
        elif child.type == "function_declaration":
            name_node = child.child_by_field_name("name")
            if name_node is not None:
                pkg.functions[_text(name_node)] = child
        elif child.type == "method_declaration":
            name_node = child.child_by_field_name("name")
            if name_node is not None:
                pkg.methods.add(_text(name_node))
        elif child.type == "type_declaration":
            for spec in child.named_children:
                name_node = spec.child_by_field_name("name")
                if name_node is None:
                    continue
                alias_base: str | None = None
                if spec.type == "type_alias":
                    type_node = spec.child_by_field_name("type")
                    if type_node is not None:
                        alias_base = _base_type_name(type_node)
                pkg.types[_text(name_node)] = alias_base
                for n in _walk(spec):
                    if n.type != "field_declaration":
                        continue
                    ft = n.child_by_field_name("type")
                    if ft is None:
                        continue
                    base = _base_type_name(ft)
                    if base in _OPAQUE_TYPES:
                        for c in n.named_children:
                            if c.type == "field_identifier":
                                pkg.opaque_fields.add(_text(c))
        elif child.type in ("var_declaration", "const_declaration"):
            for spec in child.named_children:
                if spec.type not in ("var_spec", "const_spec"):
                    continue
                type_node = spec.child_by_field_name("type")
                if (
                    type_node is not None
                    and type_node.type == "function_type"
                ):
                    resolved: str | None = _FUNC_VALUE
                else:
                    resolved = (
                        _base_type_name(type_node)
                        if type_node is not None else None
                    )
                    value = spec.child_by_field_name("value")
                    if value is not None and any(
                        v.type == "func_literal"
                        for v in value.named_children
                    ):
                        resolved = _FUNC_VALUE
                for n in spec.named_children:
                    if n.type == "identifier":
                        pkg.package_vars[_text(n)] = resolved


def _receiver_base_type(method_node: Any) -> str | None:
    recv = method_node.child_by_field_name("receiver")
    if recv is None:
        return None
    for n in recv.named_children:
        if n.type == "parameter_declaration":
            type_node = n.child_by_field_name("type")
            if type_node is not None:
                return _base_type_name(type_node)
    return None


def _receiver_name(method_node: Any) -> str | None:
    recv = method_node.child_by_field_name("receiver")
    if recv is None:
        return None
    for n in recv.named_children:
        if n.type == "parameter_declaration":
            for c in n.named_children:
                if c.type == "identifier":
                    return _text(c)
    return None


def _enclosing_function(node: Any) -> Any | None:
    n = node.parent
    while n is not None:
        if n.type in ("function_declaration", "method_declaration"):
            return n
        n = n.parent
    return None


_POISON = "\x00unresolved"

# Distinguished binding for names that HOLD a function value: closure
# bindings (``f := func() {...}``), func-typed parameters and
# variables.  The callback-escape probe flags these as function
# arguments — one level of local indirection must not hide a closure
# from it.
_FUNC_VALUE = "\x00funcvalue"


def _bindings_in_function(fn_node: Any) -> dict[str, str]:
    """Map identifier → resolved base type name inside a function.

    Sources: receiver, parameters, named results, ``var`` specs,
    ``:=`` / ``=`` bindings whose RHS is a (possibly ``&``-wrapped)
    composite literal, and function-literal parameters.  A name bound
    by anything else — multi-value calls, range clauses, type
    assertions, conflicting literal types — maps to ``_POISON``.
    """
    binds: dict[str, str] = {}

    def bind(name: str, resolved: str | None) -> None:
        value = resolved if resolved is not None else _POISON
        prior = binds.get(name)
        if prior is not None and prior != value:
            binds[name] = _POISON
        else:
            binds[name] = value

    def bind_params(param_list: Any | None) -> None:
        if param_list is None:
            return
        for n in _walk(param_list):
            if n.type not in (
                "parameter_declaration",
                "variadic_parameter_declaration",
            ):
                continue
            type_node = n.child_by_field_name("type")
            if type_node is not None and type_node.type == "function_type":
                resolved: str | None = _FUNC_VALUE
            else:
                resolved = (
                    _base_type_name(type_node)
                    if type_node is not None else None
                )
            for c in n.named_children:
                if c.type == "identifier":
                    bind(_text(c), resolved)

    bind_params(fn_node.child_by_field_name("receiver"))
    bind_params(fn_node.child_by_field_name("parameters"))
    result = fn_node.child_by_field_name("result")
    if result is not None and result.type == "parameter_list":
        bind_params(result)

    def rhs_type(expr: Any) -> str | None:
        n = expr
        if n.type == "func_literal":
            return _FUNC_VALUE
        if n.type == "unary_expression" and _text(n).startswith("&"):
            n = next(iter(n.named_children), None)
            if n is None:
                return None
        if n.type == "composite_literal":
            type_node = n.child_by_field_name("type")
            if type_node is not None:
                return _base_type_name(type_node)
        return None

    for n in _walk(fn_node):
        if n.type == "func_literal":
            bind_params(n.child_by_field_name("parameters"))
        elif n.type in ("short_var_declaration", "assignment_statement"):
            left = n.child_by_field_name("left")
            right = n.child_by_field_name("right")
            if left is None or right is None:
                continue
            lhs = left.named_children
            rhs = right.named_children
            for i, target in enumerate(lhs):
                if target.type != "identifier":
                    continue
                if len(lhs) == len(rhs):
                    bind(_text(target), rhs_type(rhs[i]))
                else:
                    bind(_text(target), None)
        elif n.type == "var_spec":
            type_node = n.child_by_field_name("type")
            resolved: str | None
            if type_node is not None and type_node.type == "function_type":
                resolved = _FUNC_VALUE
            else:
                resolved = (
                    _base_type_name(type_node)
                    if type_node is not None else None
                )
                value = n.child_by_field_name("value")
                if value is not None and any(
                    v.type == "func_literal"
                    for v in value.named_children
                ):
                    resolved = _FUNC_VALUE
            for c in n.named_children:
                if c.type == "identifier":
                    bind(_text(c), resolved)
        elif n.type == "range_clause":
            left = n.child_by_field_name("left")
            if left is not None:
                for c in left.named_children:
                    if c.type == "identifier":
                        bind(_text(c), None)

    return binds


# ---------------------------------------------------------------------------
# Claimed-state derivation
# ---------------------------------------------------------------------------


def _parse_reviewed_function(func_source: str, parser: Any) -> Any | None:
    """Parse the reviewed span and return its Go func/method node.

    Also the content half of the language check: a span that does not
    parse as a Go function declaration gets no witness, whatever the
    file extension said.
    """
    try:
        tree = parser.parse(_strip_bom(func_source).encode("utf-8"))
    except Exception:
        return None
    fn = next(
        (
            n for n in tree.root_node.named_children
            if n.type in ("function_declaration", "method_declaration")
        ),
        None,
    )
    if fn is None or fn.has_error:
        return None
    return fn


def _derive_claimed_types(fn: Any) -> tuple[str, ...] | None:
    """Claimed state of the reviewed function.

    Method → its receiver base type.  Plain function → the base types
    of its pointer-typed parameters.  ``None`` → underivable (only the
    zero-spawn arm may still discharge).
    """
    if fn.type == "method_declaration":
        base = _receiver_base_type(fn)
        if base is None or "." in base or base in _OPAQUE_TYPES:
            return None
        return (base,)
    claimed: list[str] = []
    params = fn.child_by_field_name("parameters")
    if params is None:
        return None
    for n in _walk(params):
        if n.type not in (
            "parameter_declaration", "variadic_parameter_declaration",
        ):
            continue
        type_node = n.child_by_field_name("type")
        if type_node is None:
            continue
        if type_node.type != "pointer_type":
            continue  # value/interface params carry no shared state here
        base = _base_type_name(type_node)
        if base is None or "." in base or base in _OPAQUE_TYPES:
            return None  # unresolvable mutable state → underivable
        claimed.append(base)
    if not claimed:
        return None
    return tuple(dict.fromkeys(claimed))


def _expand_alias_claims(
    claimed: tuple[str, ...],
    pkg: _PackageIndex,
) -> tuple[str, ...]:
    """Add every alias-chain base to the claimed set.

    ``type T = Real`` makes T and Real THE SAME type — state
    circulating under the base name is claimed state.  Qualified bases
    contribute their final component (the name their in-package
    references carry).  Cycle-guarded; widening only (conservative).
    """
    out: list[str] = list(claimed)
    seen: set[str] = set(claimed)
    frontier = list(claimed)
    for _ in range(8):
        nxt: list[str] = []
        for t in frontier:
            base = pkg.types.get(t)
            if base is None:
                continue
            base = base.rsplit(".", 1)[-1]
            if base and base not in seen:
                seen.add(base)
                out.append(base)
                nxt.append(base)
        if not nxt:
            break
        frontier = nxt
    return tuple(out)


# ---------------------------------------------------------------------------
# Witness
# ---------------------------------------------------------------------------


def _identifier_names(node: Any) -> set[str]:
    return {
        _text(n)
        for n in _walk(node)
        if n.type in ("identifier", "type_identifier", "field_identifier")
    }


def _spawn_reaches(
    spawn: Any,
    claimed: tuple[str, ...],
    fi: _FileIndex,
    pkg: _PackageIndex,
) -> str | None:
    """Why this ``go`` statement refuses the witness, or None if clean.

    Any return string is fatal to the witness — both "reaches the
    claimed state" and "cannot be decided" land on the same
    conservative side.
    """
    line = spawn.start_point[0] + 1
    where = f"{fi.name}:{line}"
    claimed_set = set(claimed)

    enclosing = _enclosing_function(spawn)
    if enclosing is None:
        return f"spawn outside any function at {where}"
    if enclosing.type == "method_declaration":
        recv = _receiver_base_type(enclosing)
        if recv is None:
            return f"unresolvable receiver on spawning method at {where}"
        if recv in claimed_set:
            return (
                f"goroutine spawned inside a {recv} method at {where} "
                f"— internal concurrency reaches the claimed type"
            )

    names = _identifier_names(spawn)
    hit = names & claimed_set
    if hit:
        return (
            f"spawn at {where} names claimed type "
            f"{sorted(hit)[0]} — internal concurrency reaches it"
        )

    call = next(iter(spawn.named_children), None)
    if call is None or call.type != "call_expression":
        return f"unrecognized spawn shape at {where}"

    binds = _bindings_in_function(enclosing)

    def resolve_ident(name: str) -> str | None:
        got = binds.get(name)
        if got == _POISON:
            return None
        if got is not None:
            return got
        if name in pkg.package_vars:
            return pkg.package_vars[name]
        if name in fi.imports:
            return f"import:{name}"
        return None

    # Opaque carriers anywhere in the spawn subtree: a local, a
    # package-level variable, or a struct field of type any /
    # interface{} could hide claimed state.
    for name in names:
        got = binds.get(name)
        if got is not None and got != _POISON and got in _OPAQUE_TYPES:
            return f"opaque-typed value {name} in spawn at {where}"
        if got is None and pkg.package_vars.get(name) in _OPAQUE_TYPES:
            return (
                f"opaque-typed package variable {name} in spawn "
                f"at {where}"
            )
        if name in pkg.opaque_fields:
            return (
                f"opaque-typed field {name} referenced in spawn "
                f"at {where}"
            )

    fn = call.child_by_field_name("function")
    if fn is None:
        return f"unrecognized spawn callee at {where}"
    if fn.type == "identifier":
        callee = _text(fn)
        if callee not in pkg.functions:
            return (
                f"spawned callee {callee} is not a package-level "
                f"function at {where}"
            )
        return None
    if fn.type == "func_literal":
        return None  # subtree already screened; inner spawns are
        # enumerated as their own go statements by the caller's scan
    if fn.type == "selector_expression":
        operand = fn.child_by_field_name("operand")
        if operand is None or operand.type != "identifier":
            return f"chained/complex spawn selector at {where}"
        op_name = _text(operand)
        resolved = resolve_ident(op_name)
        if resolved is None:
            return (
                f"unresolvable spawn operand {op_name} at {where}"
            )
        base = resolved.split(":", 1)[-1]
        if base in claimed_set:
            return (
                f"spawned method on claimed type {base} at {where}"
            )
        if base in _OPAQUE_TYPES:
            return f"opaque-typed spawn operand {op_name} at {where}"
        return None
    return f"unrecognized spawn callee shape {fn.type} at {where}"


def _arg_carries_function_value(arg: Any, pkg: _PackageIndex) -> tuple[bool, list[str]]:
    """(function value present, non-callee identifiers) for one call
    argument's whole subtree.

    Function values counted: a func literal (nested composites
    included — ``Config{Handler: func(){…}}`` hid the closure from a
    top-level-only scan), a package function's name used as a value,
    and a METHOD VALUE (``x.Handle`` where ``Handle`` is any package
    type's method — invisible to the identifier/literal checks, it
    escaped with ``isolated=True`` standing).  A name or literal in
    CALLEE position is a call, not a value.  Name collisions over-flag
    toward escape — the witness then stands down (inconclusive),
    never discharges on a hidden carrier.
    """
    idents: list[str] = []
    for n in _walk(arg):
        parent = n.parent
        in_callee_position = (
            parent is not None
            and parent.type == "call_expression"
            and parent.child_by_field_name("function") is n
        )
        if in_callee_position:
            continue
        if n.type == "func_literal":
            return True, idents
        if n.type == "identifier":
            name = _text(n)
            if name in pkg.functions:
                return True, idents
            idents.append(name)
        elif n.type == "selector_expression":
            fld = n.child_by_field_name("field")
            if fld is not None and _text(fld) in pkg.methods:
                return True, idents
    return False, idents


def _callback_escape(
    indexes: list[_FileIndex],
    pkg: _PackageIndex,
) -> str | None:
    """A function value handed to a non-package callee, or None.

    A function literal (or a package function's name used as a value)
    passed to a callee outside the package can be run on a goroutine
    the ``go``-statement scan never sees.  Package-local callees are
    fine — their own bodies are inside the analysis.
    """
    bind_cache: dict[int, dict[str, str]] = {}

    def binds_for(call: Any) -> dict[str, str]:
        enclosing = _enclosing_function(call)
        if enclosing is None:
            return {}
        key = id(enclosing)
        if key not in bind_cache:
            bind_cache[key] = _bindings_in_function(enclosing)
        return bind_cache[key]

    for fi in indexes:
        for call in _walk(fi.tree.root_node):
            if call.type != "call_expression":
                continue
            args = call.child_by_field_name("arguments")
            if args is None:
                continue
            # A function value reaches this call as: a literal
            # (anywhere in an argument subtree — composite-literal
            # fields included), a package function's name, a method
            # value, a local name bound to a closure or declared
            # func-typed (parameters included — one level of
            # indirection must not hide the closure), or a
            # package-level func var.
            has_func_arg = False
            ident_args: list[str] = []
            for a in args.named_children:
                carries, idents = _arg_carries_function_value(a, pkg)
                if carries:
                    has_func_arg = True
                    break
                ident_args.extend(idents)
            if not has_func_arg and ident_args:
                binds = binds_for(call)
                for name in ident_args:
                    got = binds.get(name)
                    if got == _FUNC_VALUE or (
                        got is None
                        and pkg.package_vars.get(name) == _FUNC_VALUE
                    ):
                        has_func_arg = True
                        break
            if not has_func_arg:
                continue
            where = f"{fi.name}:{call.start_point[0] + 1}"
            callee = call.child_by_field_name("function")
            if callee is None:
                return f"function value passed at {where} (no callee)"
            if callee.type == "identifier":
                callee_name = _text(callee)
                if callee_name in pkg.functions:
                    continue
                if callee_name in ("append", "copy"):
                    # Builtins that STORE their arguments, never run
                    # them.  A stored closure can only execute later
                    # through a function-value call, which the spawn
                    # analysis refuses on its own.
                    continue
                return (
                    f"function value passed to non-package callee "
                    f"{callee_name} at {where}"
                )
            if callee.type == "func_literal":
                continue  # in-package body, analysed like any other
            if callee.type == "selector_expression":
                # Walk the selector chain to its root identifier:
                # x.retry(fn) and c.once.Do(fn) both root at a value
                # the PACKAGE owns, while http.HandleFunc(fn) roots at
                # an import.  Package-owned roots are allowed — a
                # package method's body is inside the analysis, and an
                # external method reached through a package-owned
                # field that SPAWNS its callback is the implicit-
                # spawner name fence's job (Go/AfterFunc/Serve/...).
                root = callee
                while root.type == "selector_expression":
                    nxt = root.child_by_field_name("operand")
                    if nxt is None:
                        root = None
                        break
                    root = nxt
                if root is not None and root.type == "identifier":
                    op_name = _text(root)
                    got = binds_for(call).get(op_name)
                    if got is not None and got != _POISON:
                        if got in pkg.types:
                            continue  # rooted at package-owned state
                    elif op_name in pkg.package_vars:
                        pv = pkg.package_vars[op_name]
                        if pv is not None and pv in pkg.types:
                            continue
                return (
                    f"function value passed to non-package callee "
                    f"{_text(callee)} at {where}"
                )
            return (
                f"function value passed to unresolvable callee "
                f"at {where}"
            )
    return None


# Contexts where a bare receiver identifier does not escape: the
# receiver declaration itself, a field-selector base, a comparison.
def _receiver_escape(
    claimed: tuple[str, ...],
    indexes: list[_FileIndex],
) -> str | None:
    """First bare-receiver escape from a claimed type's methods."""
    claimed_set = set(claimed)
    for fi in indexes:
        for m in _walk(fi.tree.root_node):
            if m.type != "method_declaration":
                continue
            if _receiver_base_type(m) not in claimed_set:
                continue
            rname = _receiver_name(m)
            if rname is None or rname == "_":
                continue
            body = m.child_by_field_name("body")
            if body is None:
                continue
            for n in _walk(body):
                if n.type != "identifier" or _text(n) != rname:
                    continue
                node, parent = n, n.parent
                while (
                    parent is not None
                    and parent.type == "parenthesized_expression"
                ):
                    node, parent = parent, parent.parent
                if parent is None:
                    continue
                if (
                    parent.type == "selector_expression"
                    and parent.child_by_field_name("operand") == node
                ):
                    continue  # t.field — the allowed shape
                if parent.type == "binary_expression":
                    continue  # t == nil and friends
                if parent.type == "parameter_declaration":
                    continue  # a shadowing declaration, not a use
                if parent.type == "expression_list":
                    gp = parent.parent
                    if (
                        gp is not None
                        and gp.type in (
                            "assignment_statement",
                            "short_var_declaration",
                        )
                        and gp.child_by_field_name("left") == parent
                    ):
                        continue  # rebinding the name, not an escape
                line = n.start_point[0] + 1
                return (
                    f"receiver {rname} of claimed type escapes its "
                    f"method as a bare value at {fi.name}:{line} "
                    f"(context: {parent.type})"
                )
    return None


def _occupancy_violation(
    claimed: tuple[str, ...],
    indexes: list[_FileIndex],
) -> str | None:
    """First occurrence of a claimed type outside its own decl/methods."""
    for t in claimed:
        for fi in indexes:
            allowed: list[tuple[int, int]] = []
            root = fi.tree.root_node
            for n in _walk(root):
                if (
                    n.type in ("type_spec", "type_alias")
                    and (name := n.child_by_field_name("name")) is not None
                    and _text(name) == t
                ):
                    allowed.append((n.start_byte, n.end_byte))
                elif (
                    n.type == "method_declaration"
                    and _receiver_base_type(n) == t
                ):
                    allowed.append((n.start_byte, n.end_byte))
            for n in _walk(root):
                if n.type not in (
                    "identifier", "type_identifier", "field_identifier",
                ):
                    continue
                if _text(n) != t:
                    continue
                pos = n.start_byte
                if not any(s <= pos < e for s, e in allowed):
                    line = n.start_point[0] + 1
                    return (
                        f"claimed type {t} referenced outside its own "
                        f"declaration/methods at {fi.name}:{line}"
                    )
    return None


def check_goroutine_isolation(
    func_source: str,
    package_files: Mapping[str, str],
    anchor_file: str | None = None,
) -> GoroutineIsolationResult:
    """Mechanical witness: no package-internal goroutine reaches the
    reviewed function's claimed state.

    *anchor_file* names the reviewed file inside *package_files*; its
    parsed package clause decides which siblings belong to the
    package.  Without it, every file must carry the same clause.

    See the module docstring for the full mechanism and the
    conservative-failure contract.  Boost-only: a positive result may
    only ever be used to ACCEPT a reviewer's dismissal.
    """
    from .safety_contract import assert_boost_only
    assert_boost_only("goconc")

    if not func_source or not func_source.strip():
        return GoroutineIsolationResult(reasoning="empty source")
    if not package_files:
        return GoroutineIsolationResult(reasoning="no package files")

    parser = _go_parser()
    if parser is None:
        return GoroutineIsolationResult(
            reasoning="tree-sitter Go grammar unavailable",
        )

    reviewed_fn = _parse_reviewed_function(func_source, parser)
    if reviewed_fn is None:
        return GoroutineIsolationResult(
            reasoning="reviewed span does not parse as a Go function",
        )

    # Parse everything first; package membership comes from the PARSED
    # clause (a regex here was fooled by comments and BOMs).
    parsed: dict[str, tuple[Any, str]] = {}
    for name in sorted(package_files):
        text = _strip_bom(package_files[name])
        try:
            tree = parser.parse(text.encode("utf-8"))
        except Exception:
            return GoroutineIsolationResult(
                reasoning=f"parse failure in {name}",
            )
        if tree.root_node.has_error:
            return GoroutineIsolationResult(
                reasoning=f"syntax errors in {name}",
            )
        clause = _package_clause_name(tree)
        if clause is None:
            return GoroutineIsolationResult(
                reasoning=f"no package clause in {name}",
            )
        parsed[name] = (tree, clause)

    if anchor_file is not None:
        if anchor_file not in parsed:
            return GoroutineIsolationResult(
                reasoning=f"anchor file {anchor_file} not in package set",
            )
        pkg_name = parsed[anchor_file][1]
    else:
        clauses = {c for _, c in parsed.values()}
        if len(clauses) != 1:
            return GoroutineIsolationResult(
                reasoning=(
                    "multiple package clauses without an anchor file: "
                    + ", ".join(sorted(clauses))
                ),
            )
        pkg_name = next(iter(clauses))

    pkg = _PackageIndex()
    indexes: list[_FileIndex] = []
    for name in sorted(parsed):
        tree, clause = parsed[name]
        if clause != pkg_name:
            continue  # a different package sharing the directory
        fi = _FileIndex(name=name, tree=tree)
        _index_file(fi, pkg)
        if fi.has_dot_import:
            return GoroutineIsolationResult(
                reasoning=f"dot-import in {name} defeats name resolution",
            )
        if fi.has_cgo:
            return GoroutineIsolationResult(
                reasoning=f"cgo in {name} — C-side threads are invisible",
            )
        if fi.has_unsafe:
            return GoroutineIsolationResult(
                reasoning=(
                    f"unsafe import in {name} — nameless memory "
                    f"aliasing defeats the reach analysis"
                ),
            )
        indexes.append(fi)

    # Implicit spawn machinery (timer/finalizer/waitgroup/server
    # callbacks) runs code on goroutines no go statement shows.
    for fi in indexes:
        for n in _walk(fi.tree.root_node):
            if (
                n.type in ("identifier", "field_identifier")
                and _text(n) in _IMPLICIT_SPAWNER_NAMES
            ):
                line = n.start_point[0] + 1
                return GoroutineIsolationResult(
                    reasoning=(
                        f"implicit goroutine machinery "
                        f"({_text(n)}) at {fi.name}:{line}"
                    ),
                )

    spawns: list[tuple[_FileIndex, Any]] = [
        (fi, n)
        for fi in indexes
        for n in _walk(fi.tree.root_node)
        if n.type == "go_statement"
    ]

    # Callback escape guards the zero-spawn arm too: a spawn-free
    # package handing a function value to a callee outside the
    # package (an unseeded imported worker pool, say) can run it on a
    # goroutine no go statement shows — "zero spawns" is only
    # meaningful once no function value leaves the package.
    cb = _callback_escape(indexes, pkg)
    if cb is not None:
        return GoroutineIsolationResult(
            spawn_count=len(spawns),
            reasoning=cb,
        )

    if not spawns:
        return GoroutineIsolationResult(
            isolated=True,
            spawn_count=0,
            reasoning=(
                f"no goroutine spawn in the package "
                f"({len(indexes)} file(s)) — no internal concurrency "
                f"exists for any state, and no function value leaves "
                f"the package"
            ),
        )

    claimed = _derive_claimed_types(reviewed_fn)
    if claimed is None:
        return GoroutineIsolationResult(
            spawn_count=len(spawns),
            reasoning=(
                "claimed state underivable from the function signature "
                "and the package spawns goroutines"
            ),
        )
    if any(t not in pkg.types for t in claimed):
        missing = next(t for t in claimed if t not in pkg.types)
        return GoroutineIsolationResult(
            spawn_count=len(spawns),
            claimed_types=claimed,
            reasoning=(
                f"claimed type {missing} is not declared in the package"
            ),
        )
    claimed = _expand_alias_claims(claimed, pkg)

    for fi, spawn in spawns:
        why = _spawn_reaches(spawn, claimed, fi, pkg)
        if why is not None:
            return GoroutineIsolationResult(
                spawn_count=len(spawns),
                claimed_types=claimed,
                reasoning=why,
            )

    for probe in (_receiver_escape(claimed, indexes),
                  _occupancy_violation(claimed, indexes)):
        if probe is not None:
            return GoroutineIsolationResult(
                spawn_count=len(spawns),
                claimed_types=claimed,
                reasoning=probe,
            )

    return GoroutineIsolationResult(
        isolated=True,
        spawn_count=len(spawns),
        claimed_types=claimed,
        reasoning=(
            f"{len(spawns)} package-internal goroutine spawn(s), none "
            f"reaches {', '.join(claimed)}; the claimed type is "
            f"referenced only by its own declaration and methods and "
            f"its receivers never escape as bare values"
        ),
    )

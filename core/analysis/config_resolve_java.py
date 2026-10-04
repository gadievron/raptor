"""Bounded Java config-value resolution.

Resolves ``props.getProperty("literalKey")`` to the compile-time value
a same-source-tree ``.properties`` file records for that key, under a
strict refusal-first contract. Two consumers with different soundness
needs share one resolver:

* the constant folder (``core.analysis.const_fold_java``) — folding an
  identifier to a config value participates in branch selection and
  the constant-definers suppression gate, so only the ZERO-DEFAULT
  form resolves there: ``getProperty(key, default)`` has two possible
  runtime values and folding either one could select the wrong branch
  (the exact hazard class the switch-refinement work pinned);
* the additive finding channel
  (``core.analysis.config_resolved_findings``) — detection may accept
  the two-arg form because the FILE value is the realistic runtime
  value whenever the named resource loads; emission still requires the
  full resolver proof, and a resolution failure emits nothing.

Resolver contract (every refusal is named and counted):

* the receiver must be a method-local ``new java.util.Properties()``
  whose only appearances in the enclosing method are its declaration,
  exactly one ``recv.load(...)`` naming exactly one string-literal
  resource, and ``recv.getProperty(...)`` reads; anything else —
  aliasing, call arguments, returns, field stores — refuses
  (``receiver_escapes``);
* the load must precede the read on a STRICTLY earlier row
  (``load_after_get``) and DOMINATE it — the upward walk from the load
  must pass through execution-transparent statement containers ONLY
  (an allowlist: block, constructor body, expression statement,
  labeled statement, synchronized statement) until it reaches a block
  enclosing the get; any other ancestor refuses
  (``conditional_load``). A load and get inside the SAME try block
  qualify (a throwing load exits the block past the get); a load
  whose failure a handler swallows before the get, a load in a
  different arm of an if/switch, and every deferred or conditionally
  evaluated vehicle (lambda, class initializer, short-circuit
  operand, assert) do not;
* the resource literal's basename must end ``.properties`` and match
  at most ``_CANDIDATE_CAP`` files under the search root; the key must
  appear exactly once across every matching file (``file_ambiguous``,
  ``key_missing``, ``key_duplicated``);
* files parse under a strict grammar: ``key=value`` lines, ``#``/``!``
  comments, no backslash anywhere (continuations and escapes refuse
  the whole file, ``grammar_unsupported``).

Refusal taxonomy: ``parser_unavailable``, ``not_getproperty``,
``dynamic_key``, ``default_present``, ``no_receiver``,
``receiver_not_local``, ``multiple_loads``, ``load_not_found``,
``load_after_get``, ``conditional_load``, ``receiver_escapes``,
``dynamic_resource``,
``not_properties_file``, ``candidate_cap``, ``file_not_found``,
``file_ambiguous``, ``key_missing``, ``key_duplicated``,
``grammar_unsupported``, ``no_enclosing_method``.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from tree_sitter import Node

_CANDIDATE_CAP = 8
_SKIP_DIR_PARTS = frozenset({
    ".git", "node_modules", "target", "build", "out", "dist",
})


def _parser():
    try:
        import tree_sitter_java
        from tree_sitter import Language, Parser
    except Exception:  # noqa: BLE001 — optional dependency
        return None
    try:
        from core.inventory._ts_cache import bounded
        return bounded(Parser(Language(tree_sitter_java.language())),
                       label="java")
    except Exception:  # noqa: BLE001
        return None


@dataclass
class ConfigResolution:
    """Outcome of one resolution attempt. ``value`` is set only when
    ``refusal`` is empty; ``default`` records a two-arg form's default
    literal (informational — the fold path refuses those anyway)."""

    value: str | None = None
    key: str | None = None
    config_file: str | None = None
    default: str | None = None
    refusal: str = ""

    @property
    def resolved(self) -> bool:
        return not self.refusal and self.value is not None


@dataclass
class _FileEntry:
    entries: dict[str, list[str]] = field(default_factory=dict)
    unsupported: bool = False


def parse_properties_strict(text: str) -> _FileEntry:
    """Strict ``.properties`` grammar: ``key=value`` per line, ``#`` or
    ``!`` comments, blank lines. Any backslash anywhere, or a
    non-comment line without ``=``, marks the whole file unsupported —
    java.util.Properties' continuation and escape semantics are not
    modelled, so a file using them must never contribute a value."""
    entry = _FileEntry()
    if "\\" in text:
        entry.unsupported = True
        return entry
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("!"):
            continue
        if "=" not in line:
            entry.unsupported = True
            return entry
        key, _, value = line.partition("=")
        entry.entries.setdefault(key.strip(), []).append(value.strip())
    return entry


class _FileIndex:
    """Bounded basename search + strict parse, cached per resolver."""

    def __init__(self, search_root: Path) -> None:
        self._root = search_root
        self._parsed: dict[Path, _FileEntry] = {}
        self._located: dict[str, tuple[list[Path], bool]] = {}

    def locate(self, basename: str) -> tuple[list[Path], bool]:
        """(matches, capped). Hidden/build directories are skipped so a
        vendored or generated copy cannot shadow the source of truth
        silently — if both survive the skip list, ambiguity refuses."""
        cached = self._located.get(basename)
        if cached is not None:
            return cached
        matches: list[Path] = []
        capped = False
        try:
            for p in self._root.rglob(basename):
                # Relative to the search root: the root's own parent
                # dirs (a checkout under out/, build/, ...) must not
                # hide every candidate file.
                try:
                    rel_parts = p.relative_to(self._root).parts
                except ValueError:
                    rel_parts = p.parts
                if any(part in _SKIP_DIR_PARTS for part in rel_parts):
                    continue
                if not p.is_file():
                    continue
                matches.append(p)
                if len(matches) > _CANDIDATE_CAP:
                    capped = True
                    break
        except OSError:
            matches, capped = [], False
        self._located[basename] = (matches, capped)
        return matches, capped

    def parsed(self, path: Path) -> _FileEntry:
        cached = self._parsed.get(path)
        if cached is not None:
            return cached
        try:
            entry = parse_properties_strict(
                path.read_text(encoding="utf-8", errors="strict"))
        except (OSError, UnicodeDecodeError):
            entry = _FileEntry(unsupported=True)
        self._parsed[path] = entry
        return entry


def _text(node) -> str:
    try:
        return node.text.decode("utf-8", "replace")
    except Exception:  # noqa: BLE001
        return ""


def _string_literal_value(node) -> str | None:
    if node is None or node.type != "string_literal":
        return None
    raw = _text(node)
    if len(raw) >= 2 and raw[0] == '"' and raw[-1] == '"':
        return raw[1:-1]
    return None


def _call_arguments(node: Node) -> list:
    args = node.child_by_field_name("arguments")
    if args is None:
        return []
    return [c for c in args.children if c.is_named]


def _enclosing_method(node):
    cur = node
    while cur is not None:
        if cur.type in ("method_declaration", "constructor_declaration"):
            return cur
        cur = cur.parent
    return None


def _string_literals_within(node) -> list[str]:
    out: list[str] = []
    stack = [node]
    while stack:
        n = stack.pop()
        if n.type == "string_literal":
            val = _string_literal_value(n)
            if val is not None:
                out.append(val)
        stack.extend(n.children)
    return out


# Ancestor node types that are execution-TRANSPARENT: when every
# node between a load and an enclosing block is one of these,
# executing that block's statement sequence executes the load. The
# dominance walk ACCEPTS only these and refuses on anything else —
# fail-closed, per the module's refusal-first contract. A blocklist
# here was the unsound shape: every deferred or conditionally
# evaluated construct it omitted (class bodies — instance
# initializers run at instantiation, not declaration; short-circuit
# ``&&``/``||`` operands; assert statements, disabled by default)
# made the walk resolve a load that never or only conditionally
# executes. Conditionals, loops, try, lambdas, and every
# never-adjudicated construct now all refuse by absence.
# synchronized blocks execute unconditionally once reached and are
# members; labeled statements are plain wrappers.
_EXECUTION_TRANSPARENT_PARENTS = frozenset({
    "block", "constructor_body", "expression_statement",
    "labeled_statement", "synchronized_statement",
})

# Statement-list node types that scope the dominance walk. Only these
# count as a shared region: multi-arm constructs (if/else, switch
# groups) share a non-block ancestor, so an arm-to-arm pair never
# meets a shared BLOCK before the construct node refuses it.
_BLOCK_TYPES = frozenset({"block", "constructor_body"})

_METHOD_TYPES = ("method_declaration", "constructor_declaration")


def _load_dominates_get(load_node, get_node) -> bool:
    """True when every execution path that reaches the get has already
    executed the load.

    The load dominates the get iff the walk UP from the load reaches a
    block that also encloses the get while crossing ONLY
    execution-transparent ancestors (``_EXECUTION_TRANSPARENT_PARENTS``
    — an allowlist; anything else refuses, fail-closed). A load and
    get in the SAME try block qualify: if the load throws, control
    leaves the block past the get — no path reads an unloaded
    receiver. A load whose failure a handler swallows
    (``try { load } catch {}`` with the get after the try) does not:
    the try_statement is not transparent. Mutually exclusive arms
    (if/else, switch groups) share only the construct node, never a
    block. Deferred vehicles (a lambda body or class initializer with
    the get OUTSIDE it) and conditionally evaluated positions
    (short-circuit operands, asserts) are not transparent either — a
    load+get pair inside the SAME lambda body still resolves, because
    the shared block is met before the lambda node. Statement ORDER
    within the shared block is the caller's row check, not this
    walk's job.
    """
    # Node identity via ``Node.id`` (the underlying parse-tree node):
    # the Python bindings hand out a FRESH wrapper object per
    # ``.parent`` access, so ``id(node)`` is unstable across walks.
    get_blocks: set[int] = set()
    cur = get_node.parent
    while cur is not None:
        if cur.type in _BLOCK_TYPES:
            get_blocks.add(cur.id)
        if cur.type in _METHOD_TYPES:
            break
        cur = cur.parent
    cur = load_node.parent
    while cur is not None:
        if cur.id in get_blocks:
            return True
        if cur.type not in _EXECUTION_TRANSPARENT_PARENTS:
            return False
        cur = cur.parent
    return False


def _receiver_discipline(method_node, receiver: str,
                         get_node: Node) -> tuple[str | None, str]:
    """(resource_basename, refusal). Walks the enclosing method once:
    classifies every appearance of ``receiver`` and extracts the single
    load resource literal. Any unclassified appearance refuses."""
    get_row = get_node.start_point[0] + 1
    new_props = 0
    load_rows: list[int] = []
    load_node: Node | None = None
    resource: str | None = None
    dynamic_resource = False
    other_appearance = False

    stack = [method_node]
    claimed: set = set()
    while stack:
        n = stack.pop()
        if n.type == "variable_declarator":
            name = n.child_by_field_name("name")
            value = n.child_by_field_name("value")
            if name is not None and _text(name) == receiver:
                if (value is not None
                        and value.type == "object_creation_expression"
                        and _text(value).replace(" ", "").endswith(
                            "Properties()")):
                    new_props += 1
                    claimed.add((name.start_point[0], name.start_point[1]))
                # a declarator with any other initializer is an
                # unverified receiver; the identifier scan below will
                # flag it as an unclaimed appearance.
        elif n.type == "method_invocation":
            obj = n.child_by_field_name("object")
            meth = n.child_by_field_name("name")
            if (obj is not None and obj.type == "identifier"
                    and _text(obj) == receiver and meth is not None):
                mname = _text(meth)
                if mname == "load":
                    load_rows.append(n.start_point[0] + 1)
                    load_node = n
                    literals = _string_literals_within(n)
                    if len(literals) == 1:
                        resource = literals[0]
                    else:
                        dynamic_resource = True
                    claimed.add((obj.start_point[0], obj.start_point[1]))
                elif mname == "getProperty":
                    claimed.add((obj.start_point[0], obj.start_point[1]))
        stack.extend(n.children)

    # Second pass: every identifier occurrence must have been claimed
    # by the declaration, a load, or a getProperty receiver position.
    stack = [method_node]
    while stack:
        n = stack.pop()
        if n.type == "identifier" and _text(n) == receiver:
            pos = (n.start_point[0], n.start_point[1])
            if pos not in claimed:
                other_appearance = True
        stack.extend(n.children)

    if new_props == 0:
        return None, "receiver_not_local"
    if new_props > 1 or len(load_rows) > 1:
        return None, "multiple_loads"
    if not load_rows:
        return None, "load_not_found"
    if other_appearance:
        return None, "receiver_escapes"
    if dynamic_resource or resource is None:
        return None, "dynamic_resource"
    if load_node is None or not _load_dominates_get(load_node, get_node):
        return None, "conditional_load"
    # >=: a load sharing the get's row could execute AFTER it (the
    # one-liner 'get(...); load(...)' spelling) — row order cannot
    # prove load-before-read there, refuse.
    if load_rows[0] >= get_row:
        return None, "load_after_get"
    basename = resource.rsplit("/", 1)[-1]
    if not basename.endswith(".properties"):
        return None, "not_properties_file"
    return basename, ""


class ConfigResolver:
    """Per-file resolver instance. ``stats`` counts refusals by name
    plus ``resolved`` — postpass telemetry consumes it directly."""

    def __init__(self, source_text: str, file_path: str,
                 repo_root: str | None = None) -> None:
        self.stats: Counter = Counter()
        self._ok = False
        root = Path(repo_root) if repo_root else Path(file_path).parent
        self._index = _FileIndex(root)
        parser = _parser()
        if parser is None:
            self.stats["parser_unavailable"] += 1
            return
        try:
            self._tree = parser.parse(source_text.encode("utf-8"))
        except Exception:  # noqa: BLE001
            self.stats["parser_unavailable"] += 1
            return
        self._ok = True

    def _refuse(self, reason: str) -> ConfigResolution:
        self.stats[reason] += 1
        return ConfigResolution(refusal=reason)

    def resolve_call(self, node: Node, *,
                     allow_default: bool = False) -> ConfigResolution:
        """Resolve one ``getProperty`` method_invocation node."""
        if not self._ok:
            return self._refuse("parser_unavailable")
        if node is None or node.type != "method_invocation":
            return self._refuse("not_getproperty")
        meth = node.child_by_field_name("name")
        if meth is None or _text(meth) != "getProperty":
            return self._refuse("not_getproperty")
        obj = node.child_by_field_name("object")
        if obj is None:
            return self._refuse("no_receiver")
        if obj.type != "identifier":
            # System.getProperty / chained receivers: never a verified
            # local Properties object.
            return self._refuse("receiver_not_local")
        args = _call_arguments(node)
        if len(args) not in (1, 2):
            return self._refuse("not_getproperty")
        key = _string_literal_value(args[0])
        if key is None:
            return self._refuse("dynamic_key")
        default = None
        if len(args) == 2:
            if not allow_default:
                return self._refuse("default_present")
            default = _string_literal_value(args[1])
            if default is None:
                return self._refuse("dynamic_key")
        method_node = _enclosing_method(node)
        if method_node is None:
            return self._refuse("no_enclosing_method")
        basename, refusal = _receiver_discipline(
            method_node, _text(obj), node)
        if refusal:
            return self._refuse(refusal)

        assert basename is not None
        matches, capped = self._index.locate(basename)
        if capped:
            return self._refuse("candidate_cap")
        if not matches:
            return self._refuse("file_not_found")
        holders: list[tuple[Path, list[str]]] = []
        unsupported = False
        for path in matches:
            entry = self._index.parsed(path)
            if entry.unsupported:
                unsupported = True
                continue
            values = entry.entries.get(key)
            if values:
                holders.append((path, values))
        if len(holders) > 1:
            return self._refuse("file_ambiguous")
        if not holders:
            # A grammar-unsupported candidate could hold the key — the
            # honest verdict is unsupported, not missing.
            return self._refuse(
                "grammar_unsupported" if unsupported else "key_missing")
        path, values = holders[0]
        if len(values) > 1:
            return self._refuse("key_duplicated")
        self.stats["resolved"] += 1
        return ConfigResolution(
            value=values[0], key=key, config_file=str(path),
            default=default)

    def fold_hook(self, node: Node, _depth: int):
        """``config_resolver`` callable for the constant folder: None
        when the node is not a getProperty call (not ours), the module
        REFUSE sentinel on any refusal, else the resolved str value.
        Zero-default form only — see the module docstring."""
        from core.analysis.const_fold_java import REFUSE
        meth = (node.child_by_field_name("name")
                if node is not None else None)
        if meth is None or _text(meth) != "getProperty":
            return None
        res = self.resolve_call(node, allow_default=False)
        if not res.resolved:
            return REFUSE
        return res.value


def _getproperty_nodes_on_row(tree, row: int) -> list:
    """All getProperty method_invocation nodes starting on 0-based *row*."""
    out: list = []
    stack = [tree.root_node]
    while stack:
        n = stack.pop()
        if n.start_point[0] > row or n.end_point[0] < row:
            continue
        if n.type == "method_invocation" and n.start_point[0] == row:
            meth = n.child_by_field_name("name")
            if meth is not None and _text(meth) == "getProperty":
                out.append(n)
        stack.extend(n.children)
    return out


def resolve_line(resolver: ConfigResolver, line: int,
                 ) -> ConfigResolution:
    """Resolve the single getProperty invocation on 1-based *line*.

    Locator-facing entry: the postpass source locator asks "is this
    read a proven config constant?" — a read whose every possible
    runtime value is a file constant or a literal default is not
    attacker-controlled, so ``allow_default=True`` here (unlike the
    fold side, which needs THE value and refuses two-arg reads).
    Multiple getProperty invocations on one line refuse (ambiguous).
    """
    if not resolver._ok:  # noqa: SLF001 — module-internal companion
        return ConfigResolution(refusal="parser_unavailable")
    nodes = _getproperty_nodes_on_row(resolver._tree, line - 1)  # noqa: SLF001
    if len(nodes) != 1:
        resolver.stats["line_ambiguous"] += 1
        return ConfigResolution(refusal="line_ambiguous")
    return resolver.resolve_call(nodes[0], allow_default=True)


def make_config_resolver(source_text: str, file_path: str,
                         repo_root: str | None = None
                         ) -> ConfigResolver | None:
    """Build a resolver, or None when the parser is unavailable."""
    resolver = ConfigResolver(source_text, file_path, repo_root)
    if resolver.stats.get("parser_unavailable"):
        return None
    return resolver

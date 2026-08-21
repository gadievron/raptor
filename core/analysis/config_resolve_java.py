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
* the load must precede the read (``load_after_get``);
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
``load_after_get``, ``receiver_escapes``, ``dynamic_resource``,
``not_properties_file``, ``candidate_cap``, ``file_not_found``,
``file_ambiguous``, ``key_missing``, ``key_duplicated``,
``grammar_unsupported``, ``no_enclosing_method``.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

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
        return Parser(Language(tree_sitter_java.language()))
    except Exception:  # noqa: BLE001
        return None


@dataclass
class ConfigResolution:
    """Outcome of one resolution attempt. ``value`` is set only when
    ``refusal`` is empty; ``default`` records a two-arg form's default
    literal (informational — the fold path refuses those anyway)."""

    value: Optional[str] = None
    key: Optional[str] = None
    config_file: Optional[str] = None
    default: Optional[str] = None
    refusal: str = ""

    @property
    def resolved(self) -> bool:
        return not self.refusal and self.value is not None


@dataclass
class _FileEntry:
    entries: Dict[str, List[str]] = field(default_factory=dict)
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
        self._parsed: Dict[Path, _FileEntry] = {}
        self._located: Dict[str, Tuple[List[Path], bool]] = {}

    def locate(self, basename: str) -> Tuple[List[Path], bool]:
        """(matches, capped). Hidden/build directories are skipped so a
        vendored or generated copy cannot shadow the source of truth
        silently — if both survive the skip list, ambiguity refuses."""
        cached = self._located.get(basename)
        if cached is not None:
            return cached
        matches: List[Path] = []
        capped = False
        try:
            for p in self._root.rglob(basename):
                if any(part in _SKIP_DIR_PARTS for part in p.parts):
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


def _string_literal_value(node) -> Optional[str]:
    if node is None or node.type != "string_literal":
        return None
    raw = _text(node)
    if len(raw) >= 2 and raw[0] == '"' and raw[-1] == '"':
        return raw[1:-1]
    return None


def _call_arguments(node) -> List:
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


def _string_literals_within(node) -> List[str]:
    out: List[str] = []
    stack = [node]
    while stack:
        n = stack.pop()
        if n.type == "string_literal":
            val = _string_literal_value(n)
            if val is not None:
                out.append(val)
        stack.extend(n.children)
    return out


def _receiver_discipline(method_node, receiver: str,
                         get_row: int) -> Tuple[Optional[str], str]:
    """(resource_basename, refusal). Walks the enclosing method once:
    classifies every appearance of ``receiver`` and extracts the single
    load resource literal. Any unclassified appearance refuses."""
    new_props = 0
    load_rows: List[int] = []
    resource: Optional[str] = None
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
    if load_rows[0] > get_row:
        return None, "load_after_get"
    basename = resource.rsplit("/", 1)[-1]
    if not basename.endswith(".properties"):
        return None, "not_properties_file"
    return basename, ""


class ConfigResolver:
    """Per-file resolver instance. ``stats`` counts refusals by name
    plus ``resolved`` — postpass telemetry consumes it directly."""

    def __init__(self, source_text: str, file_path: str,
                 repo_root: Optional[str] = None) -> None:
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

    def resolve_call(self, node, *,
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
            method_node, _text(obj), node.start_point[0] + 1)
        if refusal:
            return self._refuse(refusal)

        matches, capped = self._index.locate(basename)
        if capped:
            return self._refuse("candidate_cap")
        if not matches:
            return self._refuse("file_not_found")
        holders: List[Tuple[Path, List[str]]] = []
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

    def fold_hook(self, node, depth: int):
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


def _getproperty_nodes_on_row(tree, row: int) -> List:
    """All getProperty method_invocation nodes starting on 0-based *row*."""
    out: List = []
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


def resolve_line(resolver: "ConfigResolver", line: int,
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
                         repo_root: Optional[str] = None
                         ) -> Optional[ConfigResolver]:
    """Build a resolver, or None when the parser is unavailable."""
    resolver = ConfigResolver(source_text, file_path, repo_root)
    if resolver.stats.get("parser_unavailable"):
        return None
    return resolver

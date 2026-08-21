"""Bounded cross-file constant resolution for the Java const-folder.

Two resolutions, both refusal-first, both under the b21 cross-file
discipline (unambiguous declaring file located under the source root,
hard candidate caps, package-qualified match when the import map gives
one):

* ``Cls.FIELD`` where the declaring field is ``static final`` with an
  initializer that folds using ONLY literals, other static-final
  fields of the same class (depth-capped recursion), and the
  taint-free system-read allowlist. Yields a compile-time constant, or
  the :data:`~core.analysis.const_fold_java.TAINT_FREE` sentinel when
  the initializer is provably attacker-uncontrolled but its runtime
  value is unknown (``System.getProperty("user.dir") + "x"``-style).
* ``Cls.m(...)`` / ``new Cls(...).m(...)`` where the declaring class
  has exactly ONE method named ``m`` whose body is a single
  ``return <expr>;`` folding under the same restricted resolver.
  Parameters never resolve, so any body that touches an argument or
  instance state refuses; creation arguments are therefore irrelevant
  to the returned value and tolerated. Instance dispatch is sound only
  when the runtime class is exact — the caller must prove it (direct
  ``new Cls().m()`` or a creation-typed local); a subclass override
  can never be selected because the exact class's own declaration is
  the resolved body.

Finality makes a resolved String field immutable, so no
mutation-anywhere tree scan is needed (unlike the mutable-collection
resolver this mirrors).
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

logger = logging.getLogger(__name__)

_MAX_DECLARING_CANDIDATES = 8
_MAX_FIELD_DEPTH = 4
_MAX_CLASS_CACHE = 32


def _parser():
    try:
        from core.inventory.extractors import _ts_language
        import tree_sitter
        lang = _ts_language("java")
        if lang is None:
            return None
        return tree_sitter.Parser(lang)
    except Exception:  # noqa: BLE001 — optional dependency
        return None


def _text(n) -> str:
    return n.text.decode("utf-8", "replace") if n is not None else ""


def _package_of(root) -> str:
    for ch in root.children:
        if ch.type == "package_declaration":
            for c in ch.children:
                if c.type in ("scoped_identifier", "identifier"):
                    return _text(c)
    return ""


def _chain_text(node) -> Optional[str]:
    """Dotted text of a pure identifier chain; None for anything with
    a non-identifier link (calls, array access, this/super)."""
    parts = []
    cur = node
    while cur is not None:
        if cur.type in ("field_access", "scoped_identifier"):
            fld = (cur.child_by_field_name("field")
                   or cur.child_by_field_name("name"))
            obj = (cur.child_by_field_name("object")
                   or cur.child_by_field_name("scope"))
            if fld is None or fld.type != "identifier":
                return None
            parts.append(_text(fld))
            cur = obj
            continue
        if cur.type == "identifier":
            parts.append(_text(cur))
            return ".".join(reversed(parts))
        return None
    return None


class _Refused(Exception):
    pass


class XFileConst:
    """Per-finding cross-file resolver; every lookup memoized, every
    failure a refusal (``None``)."""

    def __init__(self, java_file_path: str, repo_root: Optional[str]):
        self._file = Path(java_file_path)
        self._root = Path(repo_root) if repo_root else None
        self._parser = _parser()
        self.ok = self._parser is not None and self._root is not None \
            and self._root.is_dir()
        self._imports: Dict[str, str] = {}
        self._class_cache: Dict[str, Optional[Tuple[Any, Path]]] = {}
        self._field_cache: Dict[Tuple[str, str], Any] = {}
        self._method_cache: Dict[Tuple[str, str, int], Any] = {}
        # None = not scanned; ("poisoned",) = a variable-key
        # System.setProperty exists somewhere (any key may be written);
        # otherwise the frozenset of literally-written property keys.
        self._setproperty_scan = None
        # imports are needed even without a source root: the JDK tier
        # resolves imported simple names (ResultSet -> java.sql.*)
        # from them, and JDK resolution reads no tree files.
        if self._parser is not None:
            try:
                text = self._file.read_text(encoding="utf-8",
                                            errors="replace")
                tree = self._parser.parse(
                    text.encode("utf-8", errors="replace"))
                from core.analysis.cfg_builder_java import build_import_map
                types, _statics = build_import_map(tree.root_node)
                self._imports = dict(types)
            except Exception:  # noqa: BLE001 — no imports, same-package only
                self._imports = {}

    # ---- class location -------------------------------------------------

    def _locate_class(self, chain: str):
        """Locate the single declaring file for ``chain`` (simple name
        or dotted FQN). Returns (root_node, path) or None."""
        if chain in self._class_cache:
            return self._class_cache[chain]
        if len(self._class_cache) >= _MAX_CLASS_CACHE:
            return None
        result = None
        try:
            fqn = self._imports.get(chain, chain)
            simple = fqn.rsplit(".", 1)[-1]
            package = fqn.rsplit(".", 1)[0] if "." in fqn else ""
            candidates = []
            for f in self._root.rglob(f"{simple}.java"):
                candidates.append(f)
                if len(candidates) > _MAX_DECLARING_CANDIDATES:
                    raise _Refused("too many declaring-file candidates")
            declaring = None
            declaring_root = None
            for f in candidates:
                try:
                    text = f.read_text(encoding="utf-8", errors="replace")
                    tree = self._parser.parse(
                        text.encode("utf-8", errors="replace"))
                except (OSError, ValueError):
                    continue
                pkg = _package_of(tree.root_node)
                if package and pkg != package:
                    continue
                if not package and pkg:
                    # Unqualified name: accept only the current file's
                    # own package (same-package visibility rule).
                    try:
                        cur = self._file.read_text(
                            encoding="utf-8", errors="replace")
                        cur_pkg = _package_of(self._parser.parse(
                            cur.encode("utf-8", errors="replace")).root_node)
                    except Exception:  # noqa: BLE001
                        cur_pkg = ""
                    if pkg != cur_pkg:
                        continue
                if declaring is not None:
                    raise _Refused("ambiguous declaring file")
                declaring, declaring_root = f, tree.root_node
            if declaring_root is not None:
                result = (declaring_root, declaring)
        except _Refused:
            result = None
        except Exception:  # noqa: BLE001 — refusal direction
            result = None
        self._class_cache[chain] = result
        return result

    # ---- restricted folding over a declaring class ----------------------

    def _class_static_final_rhs(self, root, field: str):
        """The initializer node of ``static final <T> field = ...;`` in
        the class body, or None. Both modifiers must be present."""
        stack = [root]
        while stack:
            n = stack.pop()
            if n.type == "field_declaration":
                mods = {_text(c) for c in n.children
                        if c.type == "modifiers"}
                modtext = " ".join(mods)
                for ch in n.children:
                    if ch.type != "variable_declarator":
                        continue
                    name = ch.child_by_field_name("name")
                    value = ch.child_by_field_name("value")
                    if (name is not None and _text(name) == field
                            and value is not None
                            and "static" in modtext
                            and "final" in modtext):
                        return value
            stack.extend(n.children)
        return None

    def _fold_restricted(self, node, root, depth: int,
                         allow_taint_free: bool) -> Any:
        """Fold with identifiers resolving ONLY to static-final fields
        of the same class — parameters and locals refuse."""
        from core.analysis.const_fold_java import REFUSE, fold_expr

        def resolve_name(name: str, d: int) -> Any:
            if d > _MAX_FIELD_DEPTH:
                return REFUSE
            rhs = self._class_static_final_rhs(root, name)
            if rhs is None:
                return REFUSE
            return self._fold_restricted(rhs, root, d + 1,
                                         allow_taint_free)

        # The declaring class's initializers fold with THIS resolver as
        # the cross-file context: a getProperty in a static-final
        # initializer gets the same tree-wide setProperty proof as an
        # inline read (without it, USERDIR-style fields would refuse).
        return fold_expr(node, resolve_name,
                         allow_taint_free=allow_taint_free,
                         xfile_resolver=self)

    # ---- public resolutions ---------------------------------------------

    def tf_property_key_ok(self, key: str) -> bool:
        """True when ``System.getProperty(key)`` is provably not
        runtime-overwritten anywhere under the root: no variable-key
        System.setProperty exists, and no literal setProperty writes
        this key. System properties are runtime-writable (any code can
        copy request data into one), so without this proof a property
        read is NOT taint-free — the b22 corpus fixture pins that."""
        if not self.ok:
            return False
        if self._setproperty_scan is None:
            try:
                self._setproperty_scan = _scan_setproperty(
                    self._root, self._parser)
            except Exception:  # noqa: BLE001 — refusal direction
                self._setproperty_scan = ("poisoned",)
        scan = self._setproperty_scan
        if scan == ("poisoned",):
            return False
        return key not in scan

    def is_jdk_chain(self, chain: str) -> bool:
        """True when ``chain`` names a JDK class — a fully-qualified
        ``java.*``/``javax.*`` chain or a simple name the analysed
        file imports from those packages. JDK class fields cannot
        carry the current request's taint under the gate's
        intra-procedural model (b36 tier, merged here: XFileConst
        cannot resolve JDK classes from source, so without this the
        ResultSet.TYPE_FORWARD_ONLY sibling class refuses forever)."""
        fqn = self._imports.get(chain, chain) if "." not in chain             else chain
        return fqn.startswith(("java.", "javax."))

    def resolve_field(self, chain: str, field: str,
                      allow_taint_free: bool) -> Any:
        """``chain.field`` → constant | TAINT_FREE | REFUSE."""
        from core.analysis.const_fold_java import REFUSE, TAINT_FREE
        if self.is_jdk_chain(chain):
            return TAINT_FREE if allow_taint_free else REFUSE
        key = (chain, field)
        if key in self._field_cache:
            val = self._field_cache[key]
        else:
            # Pre-mark as refused: a cyclic cross-class chain
            # (A.F = B.G; B.G = A.F) re-enters here mid-computation
            # and must read refuse, not recurse.
            self._field_cache[key] = REFUSE
            val = REFUSE
            located = self._locate_class(chain) if self.ok else None
            if located is not None:
                root, _path = located
                rhs = self._class_static_final_rhs(root, field)
                if rhs is not None:
                    val = self._fold_restricted(rhs, root, 0,
                                                allow_taint_free=True)
            self._field_cache[key] = val
        if val is TAINT_FREE and not allow_taint_free:
            return REFUSE
        return val

    def covered_identifiers(self, source_text: str,
                            lineno: int):
        """Identifier texts on ``lineno``'s enclosing STATEMENT that
        occur only inside chains this resolver accepts under the
        taint-free tier (b36 port). A sink call routinely spans lines
        (three-argument prepareCall), so the scope is the smallest
        statement intersecting the line — uncovered occurrences win."""
        covered, uncovered = set(), set()
        if self._parser is None:
            return covered
        try:
            tree = self._parser.parse(
                source_text.encode("utf-8", errors="replace"))
        except Exception:  # noqa: BLE001
            return covered
        stmt_types = ("expression_statement",
                      "local_variable_declaration",
                      "return_statement", "throw_statement")

        def find_stmt(node):
            if node.start_point[0] + 1 > lineno \
                    or node.end_point[0] + 1 < lineno:
                return None
            for c in node.children:
                found = find_stmt(c)
                if found is not None:
                    return found
            return node if node.type in stmt_types else None

        scope = find_stmt(tree.root_node)
        if scope is None:
            return covered

        from core.analysis.const_fold_java import REFUSE

        def accepts(node) -> bool:
            fld = node.child_by_field_name("field") \
                or node.child_by_field_name("name")
            obj = node.child_by_field_name("object") \
                or node.child_by_field_name("scope")
            if fld is None or fld.type != "identifier" or obj is None:
                return False
            chain = _chain_text(obj)
            if chain is None:
                return False
            val = self.resolve_field(chain, _text(fld), True)
            return val is not REFUSE

        def visit(node, inside: bool) -> None:
            here = inside
            if not here and node.type in ("field_access",
                                          "scoped_identifier"):
                here = accepts(node)
            if node.type == "identifier":
                (covered if here else uncovered).add(_text(node))
                return
            for c in node.children:
                visit(c, here)

        visit(scope, False)
        return covered - uncovered

    def resolve_method(self, chain: str, method: str, argc: int,
                       allow_taint_free: bool) -> Any:
        """``chain.method(...)`` (argc args) → constant | TAINT_FREE |
        REFUSE. The class must declare exactly one method with that
        name (any arity — overloads refuse wholesale) whose body is a
        single ``return <restricted-foldable>;``."""
        from core.analysis.const_fold_java import REFUSE, TAINT_FREE
        key = (chain, method, argc)
        if key in self._method_cache:
            val = self._method_cache[key]
        else:
            self._method_cache[key] = REFUSE  # cycle guard, as fields
            val = REFUSE
            located = self._locate_class(chain) if self.ok else None
            if located is not None:
                root, _path = located
                decls = []
                stack = [root]
                while stack:
                    n = stack.pop()
                    if n.type == "method_declaration":
                        nm = n.child_by_field_name("name")
                        if nm is not None and _text(nm) == method:
                            decls.append(n)
                    stack.extend(n.children)
                if len(decls) == 1:
                    body = decls[0].child_by_field_name("body")
                    stmts = [c for c in (body.children if body else ())
                             if c.is_named and c.type != "line_comment"
                             and c.type != "block_comment"]
                    if len(stmts) == 1 and stmts[0].type == "return_statement":
                        exprs = [c for c in stmts[0].children if c.is_named]
                        if len(exprs) == 1:
                            val = self._fold_restricted(
                                exprs[0], root, 0, allow_taint_free=True)
            self._method_cache[key] = val
        if val is TAINT_FREE and not allow_taint_free:
            return REFUSE
        return val


_MAX_SCAN_FILES = 5000


def _scan_setproperty(root: Path, parser):
    """All System.setProperty writes under the root: the frozenset of
    literally-written keys, or ``("poisoned",)`` when any write has a
    non-literal key (it could write anything) or the tree defeats the
    scan (size cap, unreadable, unparseable — refusal direction)."""
    keys = set()
    n = 0
    for f in root.rglob("*.java"):
        n += 1
        if n > _MAX_SCAN_FILES:
            return ("poisoned",)
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ("poisoned",)
        if "setProperty" not in text:
            continue
        try:
            tree = parser.parse(text.encode("utf-8", errors="replace"))
        except ValueError:
            return ("poisoned",)
        stack = [tree.root_node]
        while stack:
            node = stack.pop()
            if node.type == "method_invocation":
                nm = node.child_by_field_name("name")
                obj = node.child_by_field_name("object")
                if nm is not None and _text(nm) == "setProperty" \
                        and obj is not None:
                    chain = _text(obj)
                    if chain.rsplit(".", 1)[-1] == "System":
                        args_node = node.child_by_field_name("arguments")
                        args = [c for c in
                                (args_node.children if args_node else ())
                                if c.is_named]
                        if not args or args[0].type != "string_literal":
                            return ("poisoned",)
                        raw = _text(args[0])
                        if len(raw) < 2 or "\\" in raw:
                            return ("poisoned",)
                        keys.add(raw[1:-1])
            stack.extend(node.children)
    return frozenset(keys)


def make_xfile_resolver(java_file_path: Optional[str],
                        repo_root: Optional[str]) -> Optional[XFileConst]:
    if not java_file_path:
        return None
    try:
        r = XFileConst(java_file_path, repo_root)
        # ok=False (no root / no parser) still serves the JDK tier,
        # which resolves from the import map alone; every tree lookup
        # keeps refusing through the ok gate.
        return r if (r.ok or r._imports or r._parser is not None) \
            else None
    except Exception:  # noqa: BLE001 — refusal direction
        return None

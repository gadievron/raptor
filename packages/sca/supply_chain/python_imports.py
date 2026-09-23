"""Detector for ``python_import_time_execution``.

Real attacks shipped through PyPI repeatedly use the same pattern: a
malicious package places an executable payload (HTTP exfiltration,
shell execution, persistence install) at module top level so it
fires the moment ``import malicious_pkg`` runs — before any code
written by the operator gets a chance to vet it. ``setup.py`` is the
classic vector but ``__init__.py`` works just as well.

We AST-walk every ``.py`` under the target's vendored / third-party
trees (``vendor/``, ``third_party/``, … — see ``_VENDOR_DIR_NAMES``
below; first-party code is deliberately out of scope) and flag
top-level statements whose semantics imply *execution at import time*:

- any call on the ``subprocess`` / ``os`` / ``socket`` / ``urllib`` /
  ``urllib2`` / ``urllib3`` / ``requests`` / ``httpx`` / ``http``
  module surfaces (the whole module, not just the shell-out
  functions — this walk only sees vendored code)
- bare ``eval`` / ``exec`` / ``compile`` / ``__import__`` calls
- ``importlib`` dynamic-import calls
- File IO at module scope (``open(...)``)

Tolerates the common legitimate shapes:

- everything inside ``def`` / ``async def`` bodies and ``lambda``
  bodies (deferred until called) — but NOT decorator expressions or
  argument defaults, which evaluate at definition time
- everything inside ``if __name__ == "__main__":``
- everything inside ``if TYPE_CHECKING:`` where ``TYPE_CHECKING``
  is genuinely imported from ``typing`` (a module that merely
  ASSIGNS ``TYPE_CHECKING = True`` gets no guard credit — its
  "guarded" body runs at import)
- imports themselves
- assignments to module constants (`A = 1`, `_VERSION = "0.1"`)
- string expressions (docstrings)

``class`` BODIES are scanned: a class body executes at import time,
making it the textbook hiding spot for an import-time payload.
Module-level ``import X as Y`` aliases are resolved before the
vocabulary match so ``import subprocess as sp; sp.run(...)`` is
still seen.

Skips test directories (``tests/``, ``test/``, etc.) — test code
legitimately spins up subprocesses and HTTP at module level for
fixture setup. Same vendored-tree exclusion list as the artefact
walk.
"""

from __future__ import annotations

import ast
import logging
import os
import warnings
from dataclasses import dataclass
from pathlib import Path

from .._test_paths import is_test_path as _shared_is_test_path
from ..discovery import EXCLUDED_DIR_NAMES
from ..models import Confidence, Dependency, Manifest
from ..parsers import _safe_read
from ._closest_manifest import project_host_dep
from ._closest_manifest import rel_to_target as _rel
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable

logger = logging.getLogger(__name__)

# Extraction version for the per-file record cache: the class-body /
# decorator / default-arg / guard-provenance semantics change what a
# file's record set contains, so pre-change cache entries must miss
# rather than replay the old (blind) results. Bump on any _compute
# semantics change. (v2 was previously spelled inline in the cache
# label; the axis now lives in the shared helper's key.)
_EXTRACTION_VERSION = 2


# Canonical skip set + this walker's extras. Drift-free: a new entry
# in discovery.EXCLUDED_DIR_NAMES propagates to every walker.
# Vendor / third-party tree names we DO want to scan.
# ``python_import_time_execution`` is a supply-chain heuristic — it
# only carries signal against code that COMES FROM a third-party
# source. Operator-written code that runs ``os.cpu_count()`` /
# ``os.environ.get()`` at import time is benign hygiene, not a
# supply-chain risk; flagging it produces noise that drowns the
# real signals from vendored deps.
#
# The detector therefore restricts its walk to paths whose ancestors
# include one of these directory names. If a project doesn't vendor
# any deps, the detector emits no findings (correct behaviour — there
# is no third-party code to suspect). Projects that DO vendor (the
# ``vendor/``, ``third_party/``, ``_vendor/`` patterns common in
# Go-style monorepos and security-conscious Python projects) get
# the heuristic against vendored content only.
_VENDOR_DIR_NAMES: set[str] = {
    "vendor",
    "_vendor",
    "third_party",
    "thirdparty",
    "external",
}

# Walker exclusion set — same as discovery's, MINUS vendor-tree names
# (we want to walk INTO those). ``site-packages`` is added because any
# virtualenv that snuck in is the operator's local dev environment,
# not a checked-in vendored dep.
_EXCLUDED_DIRS: set[str] = (
    EXCLUDED_DIR_NAMES - _VENDOR_DIR_NAMES
) | {"site-packages"}

# Test-path detection shared with reachability + other supply_chain
# detectors via packages.sca._test_paths — one source of truth.
# (Imported above at module top to satisfy E402.)

# Top-level module names whose function calls at import time we
# consider suspicious. Paired with the call vocabulary below.
_SUSPICIOUS_MODULE_PREFIXES: set[str] = {
    "subprocess",
    "os",
    "socket",
    "urllib", "urllib2", "urllib3",
    "requests", "httpx",
    "http",
}

# Bare names — calls like ``eval(...)``, ``exec(...)``, ``__import__(...)``
# at module scope without a module qualifier.
_SUSPICIOUS_BARE_CALLS: set[str] = {
    "eval", "exec", "compile", "__import__", "open",
}

# Specific (module, attr) pairs we always want to flag. Only list
# pairs whose root module is NOT in _SUSPICIOUS_MODULE_PREFIXES —
# ``_is_suspicious_call`` matches the prefix set first and flags
# every call on those modules, so a pair entry for a prefix-listed
# module would be unreachable dead config.
_SUSPICIOUS_ATTR_PAIRS: set[tuple[str, str]] = {
    ("importlib", "import_module"), ("importlib", "__import__"),
}

_DEFAULT_MAX_DEPTH = 12


@dataclass(frozen=True)
class ImportTimeFinding:
    """One flagged top-level statement."""

    dependency: Dependency
    detail: str
    path: Path
    line: int
    severity: str
    confidence: Confidence


def scan_target(
    target: Path,
    manifests: Iterable[Manifest],
    *,
    max_depth: int = _DEFAULT_MAX_DEPTH,
    cache=None,
) -> list[ImportTimeFinding]:
    """Walk ``target``'s vendored Python sources (see
    ``_VENDOR_DIR_NAMES``); return per-file flagged statements.

    ``cache`` (a :class:`core.json.JsonCache`) caches the per-file
    flagged-call list (line + label) keyed by file content hash —
    repeat scans of unchanged files skip the AST parse entirely.
    The host-dep attribution is recomputed on retrieval (it depends
    on ``manifests`` + ``target`` + ``path`` rather than on file
    content), so a manifest set change doesn't invalidate the
    per-file content cache.
    """
    target = target.resolve()
    manifests_list = list(manifests)
    out: list[ImportTimeFinding] = []
    from .._file_scan_cache import cached_per_file
    for path in _walk_python_sources(target, max_depth=max_depth):
        if _looks_like_test_path(path, target):
            continue
        text = _safe_read.read_bounded(path, follow_symlinks=False)
        if text is None:
            # ``read_bounded`` already logged the underlying reason.
            continue

        def _compute(text=text, path=path):
            """Parse + extract per-file flagged-statement records.
            Returned as plain dicts so the cache can JSON-serialise
            them. Retrieval reconstructs ``ImportTimeFinding`` with
            the current target/manifests/path."""
            try:
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", SyntaxWarning)
                    tree = ast.parse(text, filename=str(path))
            except SyntaxError as e:
                logger.debug(
                    "sca.supply_chain.python_imports: parse failed for %s: %s",
                    path, e,
                )
                return []
            recs = [{
                    "detail": f.detail,
                    "line": f.line,
                    "severity": f.severity,
                    "confidence_level": f.confidence.level,
                    "confidence_reason": f.confidence.reason,
                } for f in _scan_module(tree, path, target, manifests_list)]
            return recs

        recs = cached_per_file(
            cache, "supply_chain:py-imports", text, _compute,
            version=_EXTRACTION_VERSION,
        )
        host_dep = _project_host_dep(manifests_list, path, target)
        out.extend(ImportTimeFinding(
                dependency=host_dep,
                detail=r["detail"],
                path=path,
                line=r["line"],
                severity=r["severity"],
                confidence=Confidence(
                    r["confidence_level"], reason=r["confidence_reason"],
                ),
            ) for r in recs)
    return out


# ---------------------------------------------------------------------------
# Per-module AST walk
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class _ModuleContext:
    """Per-module import facts the statement walk needs."""

    # ``import subprocess as sp`` → {"sp": "subprocess"} — local name
    # to root-module resolution for the vocabulary match.
    alias_map: dict[str, str]
    # Local names bound by ``from typing import TYPE_CHECKING [as X]``.
    type_checking_names: frozenset[str]
    # Local names bound by ``import typing [as X]`` — the
    # ``<X>.TYPE_CHECKING`` attribute guard form.
    typing_module_names: frozenset[str]


def _module_context(tree: ast.Module) -> _ModuleContext:
    """Collect module-level import bindings.  Only top-level imports
    are considered — a guard/alias established inside conditional
    code is not reliable enough to grant suppression credit.

    Guard credit is REVOKED for any name that is also assigned (or
    deleted) anywhere in the module: ``from typing import
    TYPE_CHECKING`` followed by ``TYPE_CHECKING = True`` — or
    ``import typing as t`` followed by ``t = fake`` — runs the
    "guarded" body at import, so the import alone must not buy
    suppression.  The rebind scan is deliberately whole-tree and
    position-blind (a Store/Del anywhere, even inside a function,
    revokes): over-revoking only removes suppression — the fail-closed
    direction — while position tracking would leave an
    order-dependent hole.  ``alias_map`` is NOT pruned by rebinds:
    aliases feed the suspicious-call match, where keeping the
    binding is likewise the fail-closed direction.
    """
    alias_map: dict[str, str] = {}
    tc_names: set[str] = set()
    typing_names: set[str] = set()
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".")[0]
                local = alias.asname or root
                alias_map[local] = root
                if root == "typing":
                    typing_names.add(local)
        elif isinstance(node, ast.ImportFrom):
            if node.module == "typing" and not node.level:
                for alias in node.names:
                    if alias.name == "TYPE_CHECKING":
                        tc_names.add(alias.asname or alias.name)
    if tc_names or typing_names:
        rebound = {
            n.id for n in ast.walk(tree)
            if isinstance(n, ast.Name)
            and isinstance(n.ctx, (ast.Store, ast.Del))
        }
        tc_names -= rebound
        typing_names -= rebound
    return _ModuleContext(
        alias_map=alias_map,
        type_checking_names=frozenset(tc_names),
        typing_module_names=frozenset(typing_names),
    )


def _scan_module(
    tree: ast.Module,
    path: Path,
    target: Path,
    manifests: list[Manifest],
) -> Iterable[ImportTimeFinding]:
    ctx = _module_context(tree)
    for node in tree.body:
        # Whole-statement allowlists.
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            continue
        if _is_main_guard(node) or _is_type_checking_guard(node, ctx):
            for else_stmt in getattr(node, "orelse", []):
                for call in _find_suspicious_calls(else_stmt, ctx):
                    yield ImportTimeFinding(
                        dependency=_project_host_dep(manifests, path, target),
                        detail=(
                            f"`{_rel(path, target)}:{call.lineno}` runs "
                            f"`{_render_call(call)}` at import time "
                            f"(else-branch of guard)"
                        ),
                        path=path,
                        line=call.lineno,
                        severity="medium",
                        confidence=Confidence(
                            "medium",
                            reason="suspicious call in else-branch of "
                            "main/TYPE_CHECKING guard",
                        ),
                    )
            continue
        if _is_constant_assignment(node):
            continue
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant):
            # Module / section docstring.
            continue

        # Anything left can run code at import time — including
        # ``class`` bodies (they execute at import) and function /
        # class decorator lists + argument defaults (evaluated at
        # definition time).  Recursively look for the actual
        # *suspicious* call so the finding's detail cites it
        # specifically.
        for call in _find_suspicious_calls(node, ctx):
            yield ImportTimeFinding(
                dependency=_project_host_dep(manifests, path, target),
                detail=(
                    f"`{_rel(path, target)}:{call.lineno}` runs "
                    f"`{_render_call(call)}` at import time"
                ),
                path=path,
                line=call.lineno,
                severity="medium",
                confidence=Confidence(
                    "medium",
                    reason="top-level call to a suspicious module / builtin",
                ),
            )


def _find_suspicious_calls(
    node: ast.AST, ctx: _ModuleContext | None = None,
) -> Iterable[ast.Call]:
    """Yield every ``ast.Call`` inside ``node`` whose target is in our
    suspicious set, confined to code that actually EXECUTES at import
    time:

      * function / lambda BODIES are skipped (deferred), but their
        decorator lists and argument defaults are scanned — those
        evaluate at definition time;
      * ``class`` bodies, decorators, bases and keywords are scanned —
        a class body executes at import.
    """
    queue: list[ast.AST] = [node]
    while queue:
        sub = queue.pop()
        if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)):
            queue.extend(sub.decorator_list)
            queue.extend(_argument_defaults(sub.args))
            continue
        if isinstance(sub, ast.Lambda):
            queue.extend(_argument_defaults(sub.args))
            continue
        if isinstance(sub, ast.ClassDef):
            queue.extend(sub.decorator_list)
            queue.extend(sub.bases)
            queue.extend(kw.value for kw in sub.keywords)
            queue.extend(sub.body)
            continue
        if isinstance(sub, ast.Call) and _is_suspicious_call(sub, ctx):
            yield sub
        queue.extend(ast.iter_child_nodes(sub))


def _argument_defaults(args: ast.arguments) -> list[ast.expr]:
    """Default-value expressions of a function/lambda signature —
    evaluated once, at definition time."""
    out = list(args.defaults)
    out.extend(d for d in args.kw_defaults if d is not None)
    return out


def _is_suspicious_call(
    call: ast.Call, ctx: _ModuleContext | None = None,
) -> bool:
    func = call.func
    # Bare-name call: ``eval(...)``, ``__import__(...)``.
    if isinstance(func, ast.Name):
        return func.id in _SUSPICIOUS_BARE_CALLS
    # Attribute call: ``os.system(...)``, ``requests.get(...)``.
    if isinstance(func, ast.Attribute):
        root = _attribute_root(func)
        # Resolve module-level import aliases (``import subprocess
        # as sp``) so the alias spelling can't defeat the match.
        if ctx is not None:
            root = ctx.alias_map.get(root, root)
        if root in _SUSPICIOUS_MODULE_PREFIXES:
            return True
        if (root, func.attr) in _SUSPICIOUS_ATTR_PAIRS:
            return True
    return False


def _attribute_root(attr: ast.Attribute) -> str:
    """Walk an attribute chain back to its leftmost name."""
    node: ast.AST = attr
    while isinstance(node, ast.Attribute):
        node = node.value
    if isinstance(node, ast.Name):
        return node.id
    return ""


def _render_call(call: ast.Call) -> str:
    """Cheap human-readable label for the call site."""
    func = call.func
    if isinstance(func, ast.Name):
        return f"{func.id}()"
    if isinstance(func, ast.Attribute):
        # Walk back to leftmost name and rebuild the dotted form.
        names: list[str] = [func.attr]
        node: ast.AST = func.value
        while isinstance(node, ast.Attribute):
            names.append(node.attr)
            node = node.value
        if isinstance(node, ast.Name):
            names.append(node.id)
        return ".".join(reversed(names)) + "()"
    return "<call>"


def _is_main_guard(node: ast.AST) -> bool:
    """``if __name__ == "__main__":`` — body runs only as a script,
    not at import."""
    if not isinstance(node, ast.If):
        return False
    test = node.test
    if not isinstance(test, ast.Compare) or len(test.ops) != 1:
        return False
    if not isinstance(test.ops[0], ast.Eq):
        return False
    left, right = test.left, test.comparators[0]
    name_node = left if isinstance(left, ast.Name) else right
    const_node = right if isinstance(left, ast.Name) else left
    return (
        isinstance(name_node, ast.Name) and name_node.id == "__name__"
        and isinstance(const_node, ast.Constant) and const_node.value == "__main__"
    )


def _is_type_checking_guard(node: ast.AST, ctx: _ModuleContext) -> bool:
    """``if TYPE_CHECKING:`` — body imports types only for static
    analysis, never executed at runtime.

    Guard credit requires ``TYPE_CHECKING`` to be genuinely bound
    from ``typing`` (``from typing import TYPE_CHECKING [as X]`` for
    the name form; ``import typing [as X]`` for the ``X.TYPE_CHECKING``
    attribute form).  A hostile module that merely ASSIGNS
    ``TYPE_CHECKING = True`` runs its "guarded" payload at import —
    it gets no suppression here."""
    if not isinstance(node, ast.If):
        return False
    test = node.test
    if isinstance(test, ast.Name):
        return test.id in ctx.type_checking_names
    return bool(
        isinstance(test, ast.Attribute)
        and test.attr == "TYPE_CHECKING"
        and isinstance(test.value, ast.Name)
        and test.value.id in ctx.typing_module_names
    )


def _is_constant_assignment(node: ast.AST) -> bool:
    """``X = <constant or simple literal collection>`` — module
    constants and simple metadata."""
    if not isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
        return False
    value = getattr(node, "value", None)
    if value is None:
        return True   # bare type annotation, no value
    return _is_simple_literal(value)


def _is_simple_literal(node: ast.AST) -> bool:
    """Constants, tuples/lists/dicts of constants — anything that
    can't trigger side effects at import time."""
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
        return all(_is_simple_literal(el) for el in node.elts)
    if isinstance(node, ast.Dict):
        return all(
            (k is None or _is_simple_literal(k)) and _is_simple_literal(v)
            for k, v in zip(node.keys, node.values, strict=True)
        )
    if isinstance(node, ast.UnaryOp):
        return _is_simple_literal(node.operand)
    if isinstance(node, ast.BinOp):
        return (_is_simple_literal(node.left)
                and _is_simple_literal(node.right))
    if isinstance(node, ast.Name):
        # Reference to another module-level constant. Ambiguous, but
        # not a call — treat as fine.
        return True
    return False


# ---------------------------------------------------------------------------
# Tree walking + helpers
# ---------------------------------------------------------------------------

def _walk_python_sources(target: Path, *, max_depth: int) -> Iterable[Path]:
    """Yield ``.py`` paths under ``target`` that live inside a
    recognised vendor-tree directory. Paths whose ancestors don't
    include one of :data:`_VENDOR_DIR_NAMES` are skipped — operator-
    written code is trusted; the supply-chain heuristic only fires
    against third-party code we can actually attribute to an
    external author."""
    base = len(target.parts)
    for dirpath, dirnames, filenames in os.walk(str(target), followlinks=False):
        cur = Path(dirpath)
        depth = len(cur.parts) - base
        if depth >= max_depth:
            dirnames[:] = []
        else:
        # Sorted so evidence/walk order is filesystem-independent
        # (parity with reachability._walker's determinism rule).
            dirnames[:] = sorted(
                d for d in dirnames if d not in _EXCLUDED_DIRS
            )
        # Only emit when the current directory or one of its
        # ancestors is a recognised vendor tree. Cheap O(depth)
        # check per dir; doesn't slow the walk noticeably.
        if not any(part in _VENDOR_DIR_NAMES for part in cur.parts):
            continue
        for fn in sorted(filenames):
            if fn.endswith(".py"):
                yield cur / fn


def _looks_like_test_path(path: Path, target: Path) -> bool:
    """Backwards-compatible wrapper over the shared helper. Existing
    callers in this module pass through unchanged; new shared
    detection logic lives in ``packages.sca._test_paths``.
    """
    return _shared_is_test_path(path, target)


def _project_host_dep(
    manifests: list[Manifest], path: Path, target: Path,
) -> Dependency:
    return project_host_dep(
        manifests, path, target,
        reason="placeholder for python-import-time finding host",
    )


__all__ = ["ImportTimeFinding", "scan_target"]

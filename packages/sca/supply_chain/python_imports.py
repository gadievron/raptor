"""Detector for ``python_import_time_execution``.

Real attacks shipped through PyPI repeatedly use the same pattern: a
malicious package places an executable payload (HTTP exfiltration,
shell execution, persistence install) at module top level so it
fires the moment ``import malicious_pkg`` runs — before any code
written by the operator gets a chance to vet it. ``setup.py`` is the
classic vector but ``__init__.py`` works just as well.

We AST-walk every ``.py`` under the target's source tree and flag
top-level statements whose semantics imply *execution at import time*:

- ``subprocess`` / ``os.system`` / ``os.popen`` calls
- ``socket`` connect / ``urllib`` / ``urllib2`` / ``urllib3`` /
  ``requests`` / ``httpx`` / ``http.client`` calls
- ``eval`` / ``exec`` / ``compile`` / ``__import__`` / ``importlib``
  dynamic-import calls
- File IO at module scope (``open(...)`` followed by ``.write/.read``)

Tolerates the common legitimate shapes:

- everything inside ``def`` / ``async def`` / ``class`` bodies
- everything inside ``if __name__ == "__main__":``
- everything inside ``if TYPE_CHECKING:``
- imports themselves
- assignments to module constants (`A = 1`, `_VERSION = "0.1"`)
- string expressions (docstrings)

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
from typing import Iterable, List, Set

from .._test_paths import is_test_path as _shared_is_test_path
from ..discovery import EXCLUDED_DIR_NAMES
from ..models import Confidence, Dependency, Manifest, PinStyle

logger = logging.getLogger(__name__)


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
_VENDOR_DIR_NAMES: Set[str] = {
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
_EXCLUDED_DIRS: Set[str] = (
    EXCLUDED_DIR_NAMES - _VENDOR_DIR_NAMES
) | {"site-packages"}

# Test-path detection shared with reachability + other supply_chain
# detectors via packages.sca._test_paths — one source of truth.
# (Imported above at module top to satisfy E402.)

# Top-level module names whose function calls at import time we
# consider suspicious. Paired with the call vocabulary below.
_SUSPICIOUS_MODULE_PREFIXES: Set[str] = {
    "subprocess",
    "os",
    "socket",
    "urllib", "urllib2", "urllib3",
    "requests", "httpx",
    "http",
}

# Bare names — calls like ``eval(...)``, ``exec(...)``, ``__import__(...)``
# at module scope without a module qualifier.
_SUSPICIOUS_BARE_CALLS: Set[str] = {
    "eval", "exec", "compile", "__import__",
}

# Specific (module, attr) pairs we always want to flag.
_SUSPICIOUS_ATTR_PAIRS: Set["tuple[str, str]"] = {
    ("os", "system"), ("os", "popen"),
    ("subprocess", "run"), ("subprocess", "call"),
    ("subprocess", "Popen"), ("subprocess", "check_call"),
    ("subprocess", "check_output"),
    ("socket", "create_connection"), ("socket", "connect"),
    ("urllib", "urlopen"), ("urllib2", "urlopen"),
    ("requests", "get"), ("requests", "post"), ("requests", "put"),
    ("httpx", "get"), ("httpx", "post"),
    ("http", "client"),
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
) -> List[ImportTimeFinding]:
    """Walk ``target`` Python sources; return per-file flagged statements.

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
    out: List[ImportTimeFinding] = []
    from .._file_scan_cache import cached_per_file
    for path in _walk_python_sources(target, max_depth=max_depth):
        if _looks_like_test_path(path, target):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            logger.debug(
                "sca.supply_chain.python_imports: read failed for %s: %s",
                path, e,
            )
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
            recs = []
            for f in _scan_module(tree, path, target, manifests_list):
                recs.append({
                    "detail": f.detail,
                    "line": f.line,
                    "severity": f.severity,
                    "confidence_level": f.confidence.level,
                    "confidence_reason": f.confidence.reason,
                })
            return recs

        recs = cached_per_file(
            cache, "supply_chain:py-imports", text, _compute,
        )
        host_dep = _project_host_dep(manifests_list, path, target)
        for r in recs:
            out.append(ImportTimeFinding(
                dependency=host_dep,
                detail=r["detail"],
                path=path,
                line=r["line"],
                severity=r["severity"],
                confidence=Confidence(
                    r["confidence_level"], reason=r["confidence_reason"],
                ),
            ))
    return out


# ---------------------------------------------------------------------------
# Per-module AST walk
# ---------------------------------------------------------------------------

def _scan_module(
    tree: ast.Module,
    path: Path,
    target: Path,
    manifests: List[Manifest],
) -> Iterable[ImportTimeFinding]:
    for node in tree.body:
        # Whole-statement allowlists.
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            continue
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef,
                             ast.ClassDef)):
            continue
        if _is_main_guard(node) or _is_type_checking_guard(node):
            continue
        if _is_constant_assignment(node):
            continue
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant):
            # Module / section docstring.
            continue

        # Anything left can run code at import time. Recursively look
        # for the actual *suspicious* call so the finding's detail
        # cites it specifically.
        for call in _find_suspicious_calls(node):
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


def _find_suspicious_calls(node: ast.AST) -> Iterable[ast.Call]:
    """Yield every ``ast.Call`` inside ``node`` whose target is in our
    suspicious set."""
    for sub in ast.walk(node):
        if not isinstance(sub, ast.Call):
            continue
        if _is_suspicious_call(sub):
            yield sub


def _is_suspicious_call(call: ast.Call) -> bool:
    func = call.func
    # Bare-name call: ``eval(...)``, ``__import__(...)``.
    if isinstance(func, ast.Name):
        return func.id in _SUSPICIOUS_BARE_CALLS
    # Attribute call: ``os.system(...)``, ``requests.get(...)``.
    if isinstance(func, ast.Attribute):
        root = _attribute_root(func)
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
        names: List[str] = [func.attr]
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


def _is_type_checking_guard(node: ast.AST) -> bool:
    """``if TYPE_CHECKING:`` — body imports types only for static
    analysis, never executed at runtime."""
    if not isinstance(node, ast.If):
        return False
    if isinstance(node.test, ast.Name) and node.test.id == "TYPE_CHECKING":
        return True
    if isinstance(node.test, ast.Attribute) and node.test.attr == "TYPE_CHECKING":
        return True
    return False


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
            for k, v in zip(node.keys, node.values)
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
            dirnames[:] = [d for d in dirnames if d not in _EXCLUDED_DIRS]
        # Only emit when the current directory or one of its
        # ancestors is a recognised vendor tree. Cheap O(depth)
        # check per dir; doesn't slow the walk noticeably.
        if not any(part in _VENDOR_DIR_NAMES for part in cur.parts):
            continue
        for fn in filenames:
            if fn.endswith(".py"):
                yield cur / fn


def _looks_like_test_path(path: Path, target: Path) -> bool:
    """Backwards-compatible wrapper over the shared helper. Existing
    callers in this module pass through unchanged; new shared
    detection logic lives in ``packages.sca._test_paths``.
    """
    return _shared_is_test_path(path, target)


def _project_host_dep(
    manifests: List[Manifest], path: Path, target: Path,
) -> Dependency:
    closest: "Manifest | None" = None
    for m in manifests:
        if m.is_lockfile:
            continue
        try:
            common = os.path.commonpath([m.path.parent, path])
        except ValueError:
            continue
        if not closest or len(common) > len(
            os.path.commonpath([closest.path.parent, path])
        ):
            closest = m
    declared_in = closest.path if closest else target
    ecosystem = closest.ecosystem if closest else "Project"
    return Dependency(
        ecosystem=ecosystem,
        name="<project>",
        version=None,
        declared_in=declared_in,
        scope="main",
        is_lockfile=False,
        pin_style=PinStyle.UNKNOWN,
        direct=True,
        purl="",
        parser_confidence=Confidence(
            "low",
            reason="placeholder for python-import-time finding host",
        ),
    )


def _rel(path: Path, target: Path) -> Path:
    try:
        return path.relative_to(target)
    except ValueError:
        return path


__all__ = ["ImportTimeFinding", "scan_target"]

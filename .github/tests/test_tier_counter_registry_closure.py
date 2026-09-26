"""Closure gate: tier names fed to tier-counter increments are
registered in ``_make_tier_counters()`` — in both directions.

The increment helpers (``increment_tier_dict`` / ``increment_tier``
in ``core/audit/diagnostics.py``, ``_tick_tier`` in
``core/audit/propagation.py``) guard on registry membership: an
unregistered tier's tallies vanish, so the tier-effectiveness table
can never show the channel, however often it errors or refuses. The
runtime helpers warn once per unknown tier; this gate makes the same
mistake fail CI the day a new tier lands.

The tier-name universe is DERIVED from the call sites, never
hand-listed:

* literal tier arguments at calls to the increment helpers
  (underscore-import spellings included);
* dynamic ``tool_type`` sites resolve to the chain-entry universe —
  every ``{"type": <literal>, "config": ...}`` dict in
  ``core/audit`` (the ``_run_tool_chain`` entry idiom; every entry
  type also reaches the chain's per-entry wall-clock increment);
* any other bare-name tier argument must be a parameter of the
  enclosing function, and resolves through that parameter's literal
  default plus every literal keyword for it at the function's call
  sites.

Anything the derivation cannot resolve to literals FAILS the gate:
extend the derivation deliberately; a new dispatch idiom must never
fall outside the census.

Two directions:

* unregistered increment — the tallies drop silently at runtime;
* orphan registration — a tier no derivable call site can reach is
  dead weight or a renamed channel whose tallies now drop under the
  old name. No orphans are tolerated: a deliberately reserved tier
  must come with the call sites that feed it.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from runtime_universe import EXCLUDED_PARTS, repo_root  # noqa: E402

#: Increment-helper spellings (definition names and the orchestrator's
#: underscore import aliases).
_HELPER_NAMES = frozenset({
    "increment_tier_dict",
    "_increment_tier_dict",
    "increment_tier",
    "_increment_tier",
    "_tick_tier",
    "tally_substrate_skip_language",
    "_tally_substrate_language",
})

#: The registry owner.
_REGISTRY_FILE = ("core", "audit", "orchestrator.py")
_REGISTRY_FUNC = "_make_tier_counters"

#: The chain-entry dynamic variable (``tool_type = entry["type"]``).
_CHAIN_VAR = "tool_type"


def _audit_runtime_files() -> list[Path]:
    root = repo_root() / "core" / "audit"
    return sorted(
        p
        for p in root.rglob("*.py")
        if not (set(p.parts) & EXCLUDED_PARTS)
        and "scripts" not in p.parts
    )


def _call_name(call: ast.Call) -> str | None:
    func = call.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


def _tier_arg(call: ast.Call) -> ast.expr | None:
    """The tier argument: positional index 1 in every helper."""
    if len(call.args) >= 2:
        return call.args[1]
    for kw in call.keywords:
        if kw.arg == "tier":
            return kw.value
    return None


def _registered_tiers(tree: ast.Module, path: Path) -> set[str]:
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.FunctionDef)
            and node.name == _REGISTRY_FUNC
        ):
            keys: set[str] = set()
            for sub in ast.walk(node):
                if isinstance(sub, ast.Dict):
                    for k in sub.keys:
                        if isinstance(k, ast.Constant) and isinstance(
                            k.value, str,
                        ):
                            keys.add(k.value)
            assert keys, f"{path}: {_REGISTRY_FUNC} has no dict keys"
            return keys
    raise AssertionError(f"{path}: {_REGISTRY_FUNC} not found")


class _Collector(ast.NodeVisitor):
    """Per-module collection with enclosing-function tracking."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.func_stack: list[ast.FunctionDef | ast.AsyncFunctionDef] = []
        self.literal_tiers: set[str] = set()
        # (lineno, name_id, enclosing funcdef or None)
        self.dynamic_sites: list[
            tuple[int, str, ast.FunctionDef | ast.AsyncFunctionDef | None]
        ] = []
        self.unresolvable: list[str] = []
        self.chain_types: set[str] = set()
        # every call in the module, keyed by callee name — for
        # tier-parameter resolution across the same module set.
        self.calls_by_name: dict[str, list[ast.Call]] = {}

    def _visit_func(self, node) -> None:
        self.func_stack.append(node)
        self.generic_visit(node)
        self.func_stack.pop()

    visit_FunctionDef = _visit_func
    visit_AsyncFunctionDef = _visit_func

    def visit_Dict(self, node: ast.Dict) -> None:
        keys = {
            k.value
            for k in node.keys
            if isinstance(k, ast.Constant) and isinstance(k.value, str)
        }
        if "type" in keys and "config" in keys:
            for k, v in zip(node.keys, node.values):
                if isinstance(k, ast.Constant) and k.value == "type":
                    if isinstance(v, ast.Constant) and isinstance(
                        v.value, str,
                    ):
                        self.chain_types.add(v.value)
                    else:
                        self.unresolvable.append(
                            f"{self.path}:{node.lineno}: chain entry "
                            f"with non-literal 'type'"
                        )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        name = _call_name(node)
        if name is not None:
            self.calls_by_name.setdefault(name, []).append(node)
        if name in _HELPER_NAMES:
            arg = _tier_arg(node)
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                self.literal_tiers.add(arg.value)
            elif isinstance(arg, ast.Name):
                enclosing = self.func_stack[-1] if self.func_stack else None
                self.dynamic_sites.append((node.lineno, arg.id, enclosing))
            elif arg is None and name in {"_tick_tier"}:
                self.unresolvable.append(
                    f"{self.path}:{node.lineno}: {name} call without a "
                    f"resolvable tier argument"
                )
            else:
                self.unresolvable.append(
                    f"{self.path}:{node.lineno}: {name} tier argument is "
                    f"not a literal or bare name — extend the derivation"
                )
        self.generic_visit(node)


def _param_spec(
    func: ast.FunctionDef | ast.AsyncFunctionDef, name: str,
) -> tuple[int | None, ast.expr | None] | None:
    """(positional index or None, default expr) for *name*, or None
    if *name* is not a parameter of *func*."""
    a = func.args
    positional = a.posonlyargs + a.args
    for i, arg in enumerate(positional):
        if arg.arg == name:
            n_defaults = len(a.defaults)
            j = i - (len(positional) - n_defaults)
            return i, (a.defaults[j] if j >= 0 else None)
    for i, arg in enumerate(a.kwonlyargs):
        if arg.arg == name:
            return None, a.kw_defaults[i]
    return None


def _resolve_param_sites(
    func: ast.FunctionDef | ast.AsyncFunctionDef,
    param: str,
    calls_by_name: dict[str, list[tuple[Path, ast.Call]]],
    problems: list[str],
) -> set[str]:
    """Literal values *param* can carry: default + call-site keywords."""
    values: set[str] = set()
    spec = _param_spec(func, param)
    if spec is None:
        problems.append(
            f"{func.name}: dynamic tier name {param!r} is not a "
            f"parameter — extend the derivation"
        )
        return values
    pos_index, default = spec
    if default is not None:
        if isinstance(default, ast.Constant) and isinstance(
            default.value, str,
        ):
            values.add(default.value)
        else:
            problems.append(
                f"{func.name}: non-literal default for tier "
                f"parameter {param!r}"
            )
    for path, call in calls_by_name.get(func.name, []):
        args: list[ast.expr] = []
        if pos_index is not None and pos_index < len(call.args):
            args.append(call.args[pos_index])
        args.extend(
            kw.value for kw in call.keywords if kw.arg == param
        )
        for arg in args:
            if isinstance(arg, ast.Constant) and isinstance(
                arg.value, str,
            ):
                values.add(arg.value)
            elif isinstance(arg, ast.Name) and arg.id == _CHAIN_VAR:
                pass  # covered by the chain-entry universe
            else:
                problems.append(
                    f"{path}:{call.lineno}: unresolvable {param!r} "
                    f"at {func.name}() call site"
                )
    return values


def test_tier_counter_registry_closure() -> None:
    files = _audit_runtime_files()
    assert files, "core/audit runtime universe came back empty"

    registered: set[str] | None = None
    collectors: list[_Collector] = []
    all_calls: dict[str, list[tuple[Path, ast.Call]]] = {}
    chain_types: set[str] = set()
    problems: list[str] = []

    for path in files:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        if path.parts[-3:] == _REGISTRY_FILE:
            registered = _registered_tiers(tree, path)
        col = _Collector(path)
        col.visit(tree)
        collectors.append(col)
        chain_types |= col.chain_types
        problems.extend(col.unresolvable)
        for name, calls in col.calls_by_name.items():
            all_calls.setdefault(name, []).extend(
                (path, c) for c in calls
            )

    assert registered is not None, "registry module never scanned"
    assert chain_types, (
        "no chain-entry dicts derived — the {'type', 'config'} idiom "
        "moved; re-anchor the derivation"
    )

    incremented: set[str] = set(chain_types)
    for col in collectors:
        incremented |= col.literal_tiers
        for lineno, name_id, enclosing in col.dynamic_sites:
            if name_id == _CHAIN_VAR:
                continue  # covered by the chain-entry universe
            if enclosing is None:
                problems.append(
                    f"{col.path}:{lineno}: module-level dynamic tier "
                    f"name {name_id!r} — extend the derivation"
                )
                continue
            incremented |= _resolve_param_sites(
                enclosing, name_id, all_calls, problems,
            )

    assert not problems, (
        "tier-name derivation hit unresolvable sites:\n  "
        + "\n  ".join(problems)
    )

    unregistered = sorted(incremented - registered)
    assert not unregistered, (
        f"tiers incremented but not registered in "
        f"{_REGISTRY_FUNC}() — their telemetry drops: {unregistered}"
    )

    orphans = sorted(registered - incremented)
    assert not orphans, (
        f"tiers registered in {_REGISTRY_FUNC}() but never reachable "
        f"from any derived increment site: {orphans}"
    )

"""Narrow primitive input evidence, separate from whole-source safety proofs."""
from __future__ import annotations

import ast
from dataclasses import dataclass
from hashlib import sha256


@dataclass(frozen=True)
class ExactStringArgumentEvidence:
    source_digest: str
    library_call: str
    call_span: tuple[int, int, int | None, int | None]
    origin: str
    variable: str | None
    guard_span: tuple[int, int, int | None, int | None] | None
    scope: str = "primitive-input-type-and-default-call-form"
    assumptions: tuple[str, ...] = (
        "ordinary Python runtime without external frame mutation",
        "canonical builtins when a source type guard is used",
        "library identity, origin and sink semantics remain separate runtime assumptions",
    )


def _span(node: ast.expr | ast.stmt) -> tuple[int, int, int | None, int | None]:
    return node.lineno, node.col_offset, node.end_lineno, node.end_col_offset


@dataclass(frozen=True)
class DefaultCallFormEvidence:
    source_digest: str
    library_call: str
    call_span: tuple[int, int, int | None, int | None]
    scope: str = "source-call-form-only"
    assumptions: tuple[str, ...] = (
        "library identity, runtime defaults and sink semantics remain separate assumptions",
    )


def _default_positional_call(tree: ast.AST, call_line: int, library_call: str) -> ast.Call | None:
    from core.dataflow.source_identity import _parts

    calls = [node for node in ast.walk(tree)
             if isinstance(node, ast.Call) and node.lineno == call_line
             and _parts(node.func) == tuple(library_call.split("."))]
    if (len(calls) != 1 or len(calls[0].args) != 1 or calls[0].keywords
            or isinstance(calls[0].args[0], ast.Starred)):
        return None
    return calls[0]


def default_positional_call_evidence(
    source_text: str, call_line: int, library_call: str,
) -> DefaultCallFormEvidence | None:
    """Observe one non-starred positional argument and no configured options.

    This records call syntax, not argument types or library/whole-source safety.
    """
    from core.dataflow.source_identity import known_python_identity_conflict

    try:
        tree = ast.parse(source_text)
        if known_python_identity_conflict(source_text, call_line, (library_call,)):
            return None
        call = _default_positional_call(tree, call_line, library_call)
        if call is None:
            return None
        digest = sha256(source_text.encode("utf-8", errors="surrogatepass")).hexdigest()
        return DefaultCallFormEvidence(digest, library_call, _span(call))
    except (SyntaxError, RecursionError, ValueError):
        return None


def exact_str_default_call_evidence(
    source_text: str, call_line: int, variable: str, library_call: str,
) -> ExactStringArgumentEvidence | None:
    """Support one positional input using defaults, never annotation/isinstance.

    Admit literal strings, adjacent literal bindings, or a direct exact-type
    guard before the containing function-body statement. Reuse scope and
    rebinding facts; refuse loop/comprehension epochs and explicit frame
    introspection. This scoped primitive fact is not a vulnerability proof.
    """
    from core.analysis.python_module_callgraph import (
        function_scope_bindings, local_binding_names, module_distrusted_roots,
        module_dynamic_namespace, module_import_map,
    )
    from core.dataflow.source_identity import known_python_identity_conflict
    from core.dataflow.smt_barrier import (
        _function_containing, _nested_scope_escaping_rebinds,
        _walk_same_scope,
    )

    try:
        tree = ast.parse(source_text)
        if known_python_identity_conflict(source_text, call_line, (library_call,)):
            return None
        call = _default_positional_call(tree, call_line, library_call)
        if call is None:
            return None
        digest = sha256(source_text.encode("utf-8", errors="surrogatepass")).hexdigest()
        argument = call.args[0]
        if isinstance(argument, ast.Constant) and type(argument.value) is str:
            return ExactStringArgumentEvidence(digest, library_call, _span(call), "literal", None, None)
        if not isinstance(argument, ast.Name) or argument.id != variable:
            return None
        function = _function_containing(tree, call_line)
        if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return None
        scopes = function_scope_bindings(tree)
        if variable not in local_binding_names(function) or variable not in scopes.get(function, ()):
            return None
        if any(isinstance(node, (ast.Global, ast.Nonlocal)) and variable in node.names
               for node in _walk_same_scope(function)):
            return None
        if variable in _nested_scope_escaping_rebinds(function):
            return None
        parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
        cursor: ast.AST = call
        while cursor in parents and parents[cursor] is not function:
            cursor = parents[cursor]
            if isinstance(cursor, (ast.For, ast.AsyncFor, ast.While, ast.Lambda, ast.ClassDef,
                                   ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
                return None
        statements = [node for node in function.body
                      if node.lineno <= call_line <= (node.end_lineno or node.lineno)]
        if len(statements) != 1 or function.body.index(statements[0]) == 0:
            return None
        guard = function.body[function.body.index(statements[0]) - 1]
        # Defaults/decorators execute outside the nested definition body.
        # Reuse the shared header-aware binder instead of a body-only walk.
        region = ast.Module(body=[statements[0]], type_ignores=[])
        if variable in local_binding_names(region):
            return None
        for node in ast.walk(region):
            if isinstance(node, ast.ClassDef):
                return None  # class namespace execution is a separate contract
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                arguments = (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs)
                arguments += tuple(arg for arg in (node.args.vararg, node.args.kwarg) if arg is not None)
                if (node.returns is not None or any(arg.annotation is not None for arg in arguments)
                        or bool(getattr(node, "type_params", []))):
                    return None  # annotation execution depends on the runtime profile
        if any(
            (isinstance(node, ast.Attribute) and (node.attr.startswith("__") or node.attr in {
                "f_locals", "f_globals", "_getframe", "currentframe", "settrace", "setprofile",
                "import_module", "load_module", "exec_module",
            })) or (isinstance(node, ast.Name) and node.id == "__import__")
            or (isinstance(node, ast.ImportFrom)
                and node.module in {"importlib", "inspect", "ctypes"})
            or (isinstance(node, ast.Import)
                and any(alias.name in {"importlib", "inspect", "ctypes"} for alias in node.names))
            for node in ast.walk(tree)
        ):
            return None
        if (isinstance(guard, ast.Assign) and len(guard.targets) == 1
                and isinstance(guard.targets[0], ast.Name) and guard.targets[0].id == variable
                and isinstance(guard.value, ast.Constant) and type(guard.value.value) is str):
            return ExactStringArgumentEvidence(
                digest, library_call, _span(call), "adjacent-literal-binding", variable, _span(guard),
            )
        if (not isinstance(guard, ast.If) or guard.orelse or len(guard.body) != 1
                or not isinstance(guard.body[0], (ast.Return, ast.Raise))):
            return None
        test = guard.test
        if (not isinstance(test, ast.Compare) or len(test.ops) != 1
                or not isinstance(test.ops[0], ast.IsNot) or len(test.comparators) != 1
                or not isinstance(test.comparators[0], ast.Name) or test.comparators[0].id != "str"
                or not isinstance(test.left, ast.Call) or test.left.keywords
                or not isinstance(test.left.func, ast.Name) or test.left.func.id != "type"
                or len(test.left.args) != 1 or not isinstance(test.left.args[0], ast.Name)
                or test.left.args[0].id != variable):
            return None
        dynamic, poisoned = module_dynamic_namespace(tree)
        forbidden = module_distrusted_roots(tree) | poisoned | set(module_import_map(tree))
        if dynamic or any(name in forbidden or name in scopes.get(function, ()) for name in ("type", "str")):
            return None
        return ExactStringArgumentEvidence(
            digest, library_call, _span(call), "adjacent-exact-type-guard", variable, _span(guard),
        )
    except (SyntaxError, RecursionError, ValueError):
        return None

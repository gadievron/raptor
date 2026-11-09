"""Refusal facts for Python library identities used by certificates.

No conflict is not proof of canonical identity. Positive source/type
receipts also require import execution, origin and value evidence.
"""
from __future__ import annotations

import ast


def _parts(node: ast.AST) -> tuple[str, ...] | None:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return None
    return (node.id, *reversed(parts))


def _member_root(node: ast.AST) -> str | None:
    while isinstance(node, (ast.Attribute, ast.Subscript)):
        node = node.value
    return node.id if isinstance(node, ast.Name) else None


def known_python_identity_conflict(
    source_text: str, call_line: int, canonical_calls: tuple[str, ...],
) -> str | None:
    """Refuse known namespace conflicts without inventing another binder.

    Written canonical names without an import retain the legacy model
    assumption; this routine must not authorise new transfer contracts.
    """
    from core.analysis.python_module_callgraph import (
        function_scope_bindings,
        module_distrusted_roots,
        module_dynamic_namespace,
        module_import_map,
    )

    try:
        tree = ast.parse(source_text)
        imports = module_import_map(tree)
        distrusted = module_distrusted_roots(tree)
        dynamic, poisoned = module_dynamic_namespace(tree)
        scopes = function_scope_bindings(tree)
    except (SyntaxError, RecursionError):
        return "source namespace cannot be established"
    if dynamic:
        return "dynamic source namespace invalidates the library identity"
    parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
    candidates: list[tuple[ast.Call, tuple[str, ...], str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or node.lineno != call_line:
            continue
        written = _parts(node.func)
        if written is None:
            continue
        resolved = ".".join((imports.get(written[0], written[0]), *written[1:]))
        for canonical in canonical_calls:
            parts = tuple(canonical.split("."))
            if written == parts[-len(written):] or resolved == canonical:
                candidates.append((node, written, canonical))
                break
    if len(candidates) != 1:
        return "source library call is missing or ambiguous"
    call, written, canonical = candidates[0]
    root = written[0]
    if root in distrusted or root in poisoned:
        return "source library root is rebound"
    if root in imports:
        resolved = ".".join((imports[root], *written[1:]))
        if resolved != canonical:
            return "source import resolves to a different library identity"
    elif ".".join(written) != canonical:
        return "source library alias is unbound"
    child: ast.AST = call
    while child in parents:
        frame = parents[child]
        if isinstance(frame, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if any(child is statement for statement in frame.body):
                if isinstance(frame, ast.ClassDef):
                    return "class-body library identity is unsupported"
                visible = scopes.get(frame)
                if visible is None:
                    return "source function scope cannot be established"
                if root in visible:
                    return "source library root is locally shadowed"
                break
        elif isinstance(frame, ast.Lambda) and child is frame.body:
            visible = scopes.get(frame)
            if visible is None:
                return "source function scope cannot be established"
            if root in visible:
                return "source library root is locally shadowed"
            break
        child = frame
    canonical_root = canonical.split(".", 1)[0]
    roots = {root, canonical_root} | {
        alias for alias, target in imports.items()
        if target in {canonical_root, canonical}
    }
    def scope_of(node: ast.AST) -> ast.AST | None:
        child = node
        while child in parents:
            parent = parents[child]
            if isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                if any(child is statement for statement in parent.body):
                    return parent
            elif isinstance(parent, ast.Lambda) and child is parent.body:
                return parent
            child = parent
        return None
    # Canonical imports inside helpers still refer to the same module
    # singleton. A local binding alone must not hide their mutations.
    local_imports: dict[ast.AST, set[str]] = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            owner = scope_of(node)
            if owner is None:
                continue
            bindings = module_import_map(ast.Module(body=[node], type_ignores=[]))
            aliases = {alias for alias, target in bindings.items()
                       if target in {canonical_root, canonical}}
            roots.update(aliases)
            local_imports.setdefault(owner, set()).update(aliases)

    def relevant_root(node: ast.AST, name: str | None) -> bool:
        if name not in roots:
            return False
        owner = scope_of(node)
        if owner is None or name not in scopes.get(owner, frozenset()):
            return True
        # Binding facts include closures. Keep canonical imports in any
        # enclosing frame conservative rather than treating them as shadows.
        frame: ast.AST | None = owner
        while frame is not None:
            if name in local_imports.get(frame, set()):
                return True
            frame = parents.get(frame)
        return False

    for node in ast.walk(tree):
        if (isinstance(node, (ast.Attribute, ast.Subscript))
                and isinstance(node.ctx, (ast.Store, ast.Del))
                and relevant_root(node, _member_root(node))):
            return "source library member is mutated"
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                and node.func.id in {"setattr", "delattr"} and node.args
                and relevant_root(node, _member_root(node.args[0]))):
            return "source library member may be mutated dynamically"
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) and relevant_root(node, node.id):
            parent = parents.get(node)
            if not (
                (isinstance(parent, ast.Attribute) and parent.value is node)
                or (isinstance(parent, ast.Call) and parent.func is node)
            ):
                return "source library object escapes its call position"
        if isinstance(node, ast.Attribute) and relevant_root(node, _member_root(node)):
            if node.attr.startswith("__"):
                return "source library namespace is exposed"
            parent = parents.get(node)
            if isinstance(parent, ast.Attribute) and parent.value is node:
                continue
            if isinstance(parent, ast.Call) and parent.func is node:
                continue
            # Exception-type lookup does not hand the module/member to
            # arbitrary source code before the validating call.
            current: ast.AST = node
            while isinstance(parents.get(current), ast.Tuple):
                current = parents[current]
            if isinstance(parents.get(current), ast.ExceptHandler):
                continue
            if isinstance(node.ctx, ast.Load):
                return "source library member escapes its call position"
    return None

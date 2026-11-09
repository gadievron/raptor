"""Inventory parser declarations and bounded source evidence of report flags.

Never imports command modules or executes parsers. Roots, fragments and
containers are distinguished from subcommands. Tracing follows imported
helpers, parser aliases and literal collections; dynamic dispatch stays unknown.
"""
from __future__ import annotations

import ast
import json
from pathlib import Path

REPORT_FLAGS = frozenset({"--report-format", "--report-output", "--no-report"})


def _nodes(scope):
    for child in ast.iter_child_nodes(scope):
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        yield child
        yield from _nodes(child)
        if isinstance(child, (ast.For, ast.AsyncFor)):
            yield ("loop end", child)


def _references(node, bindings):
    if isinstance(node, ast.Name):
        return bindings.get(node.id, {node.id})
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return set().union(*(_references(item, bindings) for item in node.elts)) if node.elts else set()
    return set()


def _imports(nodes, package):
    result = {}
    for node in nodes:
        if isinstance(node, ast.ImportFrom):
            parts = package.split(".") if package else []
            base = parts[:len(parts) - node.level + 1] if node.level else []
            prefix = ".".join([*base, *([node.module] if node.module else [])])
            for name in node.names:
                if name.name != "*":
                    result[name.asname or name.name] = prefix + "." + name.name
        elif isinstance(node, ast.Import):
            for name in node.names:
                result[name.asname or name.name.split(".")[0]] = name.name if name.asname else name.name.split(".")[0]
    return result


def _callee(node, imports, module):
    if isinstance(node, ast.Name):
        return imports.get(node.id, module + "." + node.id)
    if isinstance(node, ast.Attribute):
        base = _callee(node.value, imports, module)
        return base + "." + node.attr if base else ""
    return ""


def _flow(nodes, parameters, imports, module, registrars):
    bindings = {name: {"argument:" + name} for name in parameters}
    enabled, literal_flags, declarations, containers = set(), {}, [], set()
    loops = []
    for node in nodes:
        if isinstance(node, tuple):
            loop, before, influences, targets = loops.pop()
            changed = {name for name, references in bindings.items()
                       if references & influences and before.get(name) != references}
            # A loop's union is valid inside its body, not afterwards. Keep
            # post-loop values unknown instead of granting sibling coverage.
            for name in changed | targets:
                bindings[name] = {f"loop-exit:{loop.lineno}:{loop.col_offset}:{name}"}
            continue
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            value = node.value
            identity = f"local:{node.lineno}:{node.col_offset}"
            references = _references(value, bindings) or {identity}
            for target in targets:
                if isinstance(target, ast.Name):
                    bindings[target.id] = references
            if isinstance(value, ast.Call):
                kind = None
                name = None
                if isinstance(value.func, ast.Attribute) and value.func.attr == "add_parser":
                    kind = "subcommand"
                    if value.args and isinstance(value.args[0], ast.Constant):
                        name = value.args[0].value
                elif ((isinstance(value.func, ast.Attribute) and value.func.attr == "ArgumentParser")
                      or _callee(value.func, imports, module) == "argparse.ArgumentParser"):
                    kind = "root"
                    for keyword in value.keywords:
                        if keyword.arg == "prog" and isinstance(keyword.value, ast.Constant):
                            name = keyword.value.value
                        if keyword.arg == "add_help" and isinstance(keyword.value, ast.Constant) and keyword.value.value is False:
                            kind = "fragment"
                if kind:
                    parents = set()
                    for keyword in value.keywords:
                        if keyword.arg == "parents":
                            parents.update(_references(keyword.value, bindings))
                    declarations.append((node.lineno, identity, name, kind, parents))
        elif isinstance(node, (ast.For, ast.AsyncFor)):
            influences = _references(node.iter, bindings)
            targets = {target.id for target in ast.walk(node.target) if isinstance(target, ast.Name) and isinstance(target.ctx, ast.Store)}
            loops.append((node, bindings.copy(), influences, targets))
            for name in targets:
                bindings[name] = (influences if isinstance(node.target, ast.Name) and influences
                                  else {f"loop:{node.lineno}:{node.col_offset}:{name}"})
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                receiver = _references(node.func.value, bindings)
                if node.func.attr == "add_subparsers":
                    containers.update(receiver)
                if node.func.attr == "add_argument" and node.args:
                    flags = {arg.value for arg in node.args if isinstance(arg, ast.Constant) and isinstance(arg.value, str)}
                    for reference in receiver:
                        literal_flags.setdefault(reference, set()).update(flags)
            callee_root = node.func
            while isinstance(callee_root, ast.Attribute):
                callee_root = callee_root.value
            # An argument may shadow an imported callable/module. Its runtime
            # value is not evidence that the known registrar is being called.
            shadowed = isinstance(callee_root, ast.Name) and callee_root.id in parameters
            registrar = None if shadowed else registrars.get(_callee(node.func, imports, module))
            if registrar:
                names, registered, positional_count = registrar
                for index, name in enumerate(names):
                    if name not in registered:
                        continue
                    argument = next((k.value for k in node.keywords if k.arg == name), None)
                    if argument is None and index < positional_count and index < len(node.args):
                        if not any(isinstance(arg, ast.Starred) for arg in node.args[:index + 1]):
                            argument = node.args[index]
                    enabled.update(_references(argument, bindings))
    enabled.update(reference for reference, flags in literal_flags.items() if REPORT_FLAGS <= flags)
    for _ in declarations:
        inherited = {identity for _, identity, _, _, parents in declarations if parents & enabled}
        if inherited <= enabled:
            break
        enabled.update(inherited)
    return enabled, declarations, containers


def census(root: Path) -> list[dict]:
    sources = set(root.glob("raptor*.py")) | set((root / "libexec").glob("raptor-*"))
    for folder in ("core", "packages"):
        sources.update(p for p in (root / folder).rglob("*.py")
                       if "tests" not in p.parts and not p.name.startswith("test_"))
    scopes = []
    for path in sorted(sources):
        try:
            source = path.read_text()
            if not (path.suffix == ".py" or "python" in source.splitlines()[0]):
                continue
            tree = ast.parse(source)
        except (OSError, ValueError, SyntaxError, UnicodeError, IndexError):
            continue
        relative = path.relative_to(root)
        parts = list(relative.with_suffix("").parts)
        if parts[-1] == "__init__":
            parts.pop()
            package = ".".join(parts)
        else:
            package = ".".join(parts[:-1])
        module = ".".join(parts)
        global_imports = _imports(tree.body, package)
        declarations = [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))]
        for scope in [tree, *declarations]:
            nodes = list(_nodes(scope))
            names = ([arg.arg for arg in [*scope.args.posonlyargs, *scope.args.args, *scope.args.kwonlyargs]]
                     if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)) else [])
            positional_count = len(scope.args.posonlyargs) + len(scope.args.args) if names else 0
            imports = {**global_imports, **_imports(nodes, package)}
            # Only module-level functions are resolved as importable helpers.
            # Nested/class methods with the same name must not replace them.
            key = module + "." + scope.name if scope in tree.body and names else None
            scopes.append((str(relative), module, getattr(scope, "name", "module"), nodes, names, imports, key, positional_count))
    registrars = {}
    # Bounded source tracing is not execution or proof that a conditional call
    # is reached. Cycles without flag evidence stop without granting coverage.
    for _ in range(16):
        changed = False
        for _, module, scope, nodes, names, imports, key, positional_count in scopes:
            if key is None:
                continue
            enabled, _, _ = _flow(nodes, names, imports, module, registrars)
            registered = {name for name in names if "argument:" + name in enabled}
            if registered and registrars.get(key) != (names, registered, positional_count):
                registrars[key] = names, registered, positional_count
                changed = True
        if not changed:
            break
    records = []
    for source, module, scope, nodes, names, imports, _, _ in scopes:
        enabled, declarations, containers = _flow(nodes, names, imports, module, registrars)
        for line, identity, name, kind, _ in declarations:
            supported = identity in enabled
            records.append({"source": source, "line": line, "scope": scope, "leaf_declaration": name,
                            "declaration_kind": "container" if identity in containers else kind,
                            "status": "common flags registered" if supported else "domain interface retained",
                            "reason": "Shared report flags found in source, directly or through traced helpers/parents" if supported else
                                      "Registration not proven by bounded source tracing; review defaults and delegation before migration."})
    return records


if __name__ == "__main__":
    print(json.dumps(census(Path(__file__).resolve().parents[2]), indent=2, sort_keys=True))

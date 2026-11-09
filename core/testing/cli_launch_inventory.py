"""Reviewable inventory of process launch contracts in repository test code.

This is a conservative review fence, not a Python or shell security analyser.
Unknown command builders stay visible rather than being assumed standalone.
"""

from __future__ import annotations

import ast
import hashlib
import re
from collections import defaultdict
from pathlib import Path

_SPAWNS = {"run", "Popen", "call", "check_call", "check_output"}
_OWNERS = {"run_standalone_cli", "standalone_cli_env", "run_in_process_group"}


def process_sites(path: str, source: str, *, launch_helpers=frozenset()) -> list[dict]:
    """Find direct, imported, assigned and getattr subprocess entry points."""
    tree = ast.parse(source, filename=path)
    aliases = {}
    bindings = defaultdict(list)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for item in node.names:
                aliases[item.asname or item.name] = item.name
        elif isinstance(node, ast.ImportFrom):
            for item in node.names:
                aliases[item.asname or item.name] = f"{node.module}.{item.name}"
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if node.value is not None:
                for target in targets:
                    if isinstance(target, ast.Name):
                        bindings[target.id].append(node.value)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            bindings[node.name].extend(
                item.value for item in ast.walk(node)
                if isinstance(item, ast.Return) and item.value is not None
            )

    def names(node, seen=frozenset()):
        if isinstance(node, ast.Name):
            result = {aliases.get(node.id, node.id)}
            if node.id not in seen:
                for value in bindings.get(node.id, ()):
                    result.update(names(value, seen | {node.id}))
            return result
        if isinstance(node, ast.Attribute):
            return {f"{value}.{node.attr}" for value in names(node.value, seen)}
        if isinstance(node, ast.Call):
            if (isinstance(node.func, ast.Name) and node.func.id == "__import__"
                    and node.args and isinstance(node.args[0], ast.Constant)):
                return {str(node.args[0].value)}
            if (isinstance(node.func, ast.Name) and node.func.id == "getattr"
                    and len(node.args) >= 2):
                attribute = (node.args[1].value if isinstance(node.args[1], ast.Constant)
                             else "<dynamic>")
                return {f"{value}.{attribute}" for value in names(node.args[0], seen)}
            if (isinstance(node.func, ast.Attribute) and node.func.attr == "import_module"
                    and node.args and isinstance(node.args[0], ast.Constant)):
                return {str(node.args[0].value)}
        return set()

    def references(node):
        result, expanded = set(), set()
        pending = [node]
        while pending:
            for item in ast.walk(pending.pop()):
                if isinstance(item, ast.Constant) and isinstance(item.value, str):
                    result.add(item.value)
                elif isinstance(item, ast.Name) and item.id not in expanded:
                    expanded.add(item.id)
                    pending.extend(bindings.get(item.id, ()))
        return result

    rows = []
    calls = []
    stack = []

    class Visitor(ast.NodeVisitor):
        def visit_ClassDef(self, node):
            stack.append(node.name)
            self.generic_visit(node)
            stack.pop()

        def visit_FunctionDef(self, node):
            stack.append(node.name)
            self.generic_visit(node)
            stack.pop()

        visit_AsyncFunctionDef = visit_FunctionDef

        def visit_Call(self, node):
            calls.append((node, ".".join(stack)))
            resolved = names(node.func)
            matched = sorted(value for value in resolved if (
                value.startswith("subprocess.") and value.split(".")[-1] in (_SPAWNS | {"<dynamic>"})
                or value in {"os.system", "os.popen", "os.posix_spawn", "os.posix_spawnp",
                             "asyncio.create_subprocess_exec", "asyncio.create_subprocess_shell",
                             "runpy.run_path", "runpy.run_module"}
                or value.startswith(("os.exec", "os.spawn"))
                or value.endswith((".SourceFileLoader", ".exec_module", ".load_module"))
                or value.startswith("core.testing.") and value.split(".")[-1] in _OWNERS
            ))
            if matched:
                command = node.args[0] if node.args else next(
                    (kw.value for kw in node.keywords if kw.arg in {"args", "command"}),
                    ast.Constant(None),
                )
                signature = hashlib.sha256(ast.dump(node, include_attributes=False).encode()).hexdigest()
                rows.append({"path": path, "scope": ".".join(stack), "line": node.lineno, "column": node.col_offset,
                             "callees": matched, "signature": signature,
                             "command_references": sorted(references(command))})
            self.generic_visit(node)

    Visitor().visit(tree)
    local = {row["scope"].split(".")[-1] for row in rows if row["scope"]}
    seen = {(row["scope"], row["signature"], row["line"], row["column"]) for row in rows}
    changed = True
    while changed:
        changed = False
        for node, scope in calls:
            resolved = names(node.func)
            helper = sorted(value for value in resolved if (
                value in launch_helpers
                or value.split(".")[-1] in local
                and ("." not in value or value.startswith(("self.", "cls.")))
            ))
            if not helper:
                continue
            signature = hashlib.sha256(ast.dump(node, include_attributes=False).encode()).hexdigest()
            if (scope, signature, node.lineno, node.col_offset) in seen:
                continue
            seen.add((scope, signature, node.lineno, node.col_offset))
            rows.append({"path": path, "scope": scope, "line": node.lineno, "column": node.col_offset,
                         "callees": helper, "signature": signature,
                         "command_references": sorted(references(node))})
            if scope and scope.split(".")[-1] not in local:
                local.add(scope.split(".")[-1])
                changed = True
    return rows


def shell_routes(path: str, source: str) -> dict:
    """Expose RAPTOR delegates even when the initial shell router has no Python."""
    return {"path": path, "delegates": sorted(set(re.findall(
        r"(?:libexec/|bin/)(raptor[\w-]*)|\b(raptor[\w-]*\.py)\b", source,
    ))), "modules": sorted(set(re.findall(
        r"python[0-9.]*\s+(?:-[A-Za-z]+\s+)*-m\s+([\w.]+)", source,
    )))}


def inventory(root: Path, paths: list[str]) -> list[dict]:
    sources = {}
    for path in sorted(paths):
        if path.endswith(".py") and (
            "test" in path or path.startswith(("core/testing/", ".github/"))
        ):
            sources[path] = (root / path).read_text(encoding="utf-8")
    helpers = set()
    while True:
        rows = [row for path, source in sources.items()
                for row in process_sites(path, source, launch_helpers=helpers)]
        discovered = {
            row["path"][:-3].replace("/", ".") + "." + row["scope"]
            for row in rows if row["scope"]
        }
        if discovered <= helpers:
            return rows
        helpers.update(discovered)


def source_witnesses(root: Path, paths: list[str], rows: list[dict]) -> dict[str, str]:
    """Pin command/env factories as well as their eventual process sinks."""
    available = set(paths)
    pending = {row["path"] for row in rows}
    pending.update(path for path in paths if path.endswith("conftest.py"))
    pending.update(path for path in (
        "core/testing/state_isolation.py", "core/testing/standalone_cli.py",
        "core/security/launch_scratch.py", "core/security/env_sanitisation.py",
        "core/startup/process_init.py",
    ) if path in available)
    witnessed = {}
    while pending:
        path = pending.pop()
        if path in witnessed:
            continue
        source = (root / path).read_text()
        witnessed[path] = hashlib.sha256((root / path).read_bytes()).hexdigest()
        package = path[:-3].replace("/", ".").split(".")[:-1]
        for node in ast.walk(ast.parse(source, filename=path)):
            modules = []
            if isinstance(node, ast.Import):
                modules.extend(item.name for item in node.names)
            elif isinstance(node, ast.ImportFrom):
                if node.level:
                    prefix = package[:len(package) - node.level + 1]
                    module = ".".join(prefix + ([node.module] if node.module else []))
                else:
                    module = node.module or ""
                modules.append(module)
                modules.extend(module + "." + item.name for item in node.names)
            for module in modules:
                for candidate in (module.replace(".", "/") + ".py",
                                  module.replace(".", "/") + "/__init__.py"):
                    if (candidate in available and candidate not in witnessed
                            and ("test" in candidate or candidate.startswith(("core/testing/", ".github/")))):
                        pending.add(candidate)
    return dict(sorted(witnessed.items()))

"""Inventory literal argparse leaves without importing or invoking commands.

Run with Python from the checkout root. This is source evidence, not runtime
capability discovery: delegated/dynamic parsers remain explicitly unresolved.
"""
from __future__ import annotations

import ast
import json
from pathlib import Path


def census(root: Path) -> list[dict]:
    sources = set(root.glob("raptor*.py")) | set((root / "libexec").glob("raptor-*"))
    for folder in ("core", "packages"):
        sources.update(p for p in (root / folder).rglob("*.py")
                       if "tests" not in p.parts and not p.name.startswith("test_"))
    records = []
    for path in sorted(sources):
        try:
            source = path.read_text()
            if not (path.suffix == ".py" or "python" in source.splitlines()[0]):
                continue
            tree = ast.parse(source)
        except (ValueError, SyntaxError, UnicodeError, IndexError):
            continue
        scopes = [tree, *(n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)))]
        for scope in scopes:
            nodes = []
            def walk(node):
                for child in ast.iter_child_nodes(node):
                    if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                        continue
                    nodes.append(child)
                    walk(child)
            walk(scope)
            enabled = set()
            for node in nodes:
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in {"add_report_arguments", "add_scan_args"}:
                    if node.args and isinstance(node.args[0], ast.Name):
                        enabled.add(node.args[0].id)
            for node in nodes:
                if not isinstance(node, ast.Assign) or not isinstance(node.value, ast.Call):
                    continue
                call = node.value
                if not isinstance(call.func, ast.Attribute) or call.func.attr != "add_parser":
                    continue
                literal = call.args[0].value if call.args and isinstance(call.args[0], ast.Constant) else None
                parser = node.targets[0].id if isinstance(node.targets[0], ast.Name) else ""
                supported = parser in enabled
                records.append({"source": str(path.relative_to(root)), "line": node.lineno,
                                "scope": getattr(scope, "name", "module"), "leaf_declaration": literal,
                                "status": "common flags registered" if supported else "domain interface retained",
                                "reason": "Shared argument helper is applied to this parser" if supported else
                                          "No shared registration at this declaration; use the domain interface or offline native export. Delegation may add capabilities."})
    return records


if __name__ == "__main__":
    print(json.dumps(census(Path(__file__).resolve().parents[2]), indent=2, sort_keys=True))

"""Evaluation fixtures may exercise engine policy, never select its behavior."""

import ast
from importlib.util import resolve_name
import json
from pathlib import Path


CORE = Path(__file__).resolve().parents[2]
ENGINE_MODULES = (
    "audit/orchestrator.py", "audit/refutation.py", "audit/receipt_resolution.py",
    "audit/context.py", "audit/caller_context.py",
    "analysis/reachability.py", "analysis/_included_c.py",
)


def test_engine_has_no_static_dependency_on_evaluation_modules_or_case_names():
    fixtures = json.loads((CORE / "audit/corpus/replay_cases/receipt_floors.json").read_text())
    case_names = {case["outcome"]["function"] for case in fixtures["cases"]}
    violations = []
    for relative in ENGINE_MODULES:
        path = CORE / relative
        package = ".".join(path.relative_to(CORE.parent).with_suffix("").parts[:-1])
        tree = ast.parse(path.read_text(), filename=str(path))
        for node in ast.walk(tree):
            modules = []
            if isinstance(node, ast.Import):
                modules = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                module = (resolve_name("." * node.level + (node.module or ""), package)
                          if node.level else node.module or "")
                modules = [module] + [f"{module}.{alias.name}" for alias in node.names]
            if any(module == "core.audit.corpus" or module.startswith("core.audit.corpus.")
                   for module in modules):
                violations.append(f"{relative}:{node.lineno}: engine imports evaluation code")
            if isinstance(node, ast.Constant) and isinstance(node.value, str) and node.value in case_names:
                violations.append(f"{relative}:{node.lineno}: engine contains an evaluation case name")
    assert not violations, "\n".join(violations)

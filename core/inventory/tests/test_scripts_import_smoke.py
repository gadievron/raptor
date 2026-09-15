"""Import-smoke for the ``core/inventory/scripts/`` harnesses.

The scripts are launcher-run (dash-named, ``RAPTOR_DIR`` sys.path
setup) so nothing imports them at test time — a repo-internal module
move can silently strand their imports and every later invocation dies
with ModuleNotFoundError before a single check runs. This smoke
statically extracts each script's repo-internal imports and resolves
them for real, so a stale import fails a test instead of the
operator's run.
"""

from __future__ import annotations

import ast
import importlib
from collections.abc import Iterator
from pathlib import Path

_SCRIPTS_DIR = Path(__file__).resolve().parents[1] / "scripts"
_REPO_TOP_LEVEL = {"core", "packages"}


def _repo_imports(script: Path) -> Iterator[tuple[str, list[str]]]:
    """Yield ``(module, imported_names)`` for repo-internal imports."""
    tree = ast.parse(script.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            if (node.level == 0 and node.module
                    and node.module.split(".")[0] in _REPO_TOP_LEVEL):
                yield node.module, [alias.name for alias in node.names]
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] in _REPO_TOP_LEVEL:
                    yield alias.name, []


def test_scripts_dir_exists_and_is_populated():
    scripts = [p for p in _SCRIPTS_DIR.iterdir() if p.is_file()]
    assert scripts, f"no scripts found under {_SCRIPTS_DIR}"


def test_script_repo_imports_resolve():
    for script in sorted(_SCRIPTS_DIR.iterdir()):
        if not script.is_file():
            continue
        found_any = False
        for module, names in _repo_imports(script):
            found_any = True
            mod = importlib.import_module(module)
            for name in names:
                assert hasattr(mod, name), (
                    f"{script.name}: `from {module} import {name}` does "
                    f"not resolve — the symbol moved or was renamed"
                )
        assert found_any, (
            f"{script.name}: no repo-internal imports found — the smoke "
            f"is vacuous for this script; update the extractor"
        )

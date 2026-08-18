#!/usr/bin/env python3
"""Optional-dependency import lint for test files (daily CI scan).

Bare CI installs ``requirements-dev.txt`` only; every dependency that
ships commented out in ``requirements.txt`` (the anthropic SDK,
botocore, the tree-sitter grammar wheels, ...) is ABSENT there. A test
file that imports one of them unguarded therefore passes on developer
hosts and fails collection or execution on CI — the environment-parity
defect class behind the 2026-08 91-failure sweep.

Self-contained, stdlib-only. The optional-module list is DERIVED, not
hardcoded: commented ``# name==version`` pins in requirements.txt,
minus dists actively installed by requirements(-dev).txt, minus dists
guaranteed transitively (see ``TRANSITIVE_PRESENT``), mapped to import
names via ``DIST_TO_MODULES``.

A test file importing an optional module is a finding UNLESS the file
shows guard evidence for that module:

  * the import sits inside ``try/except ImportError`` (availability
    probe / needs_x-mark pattern);
  * ``pytest.importorskip("mod")`` anywhere in the file;
  * a ``sys.modules`` stub for the module (hermetic stub-module
    pattern, cf. core/llm/tests/test_cc_adapter.py);
  * a ``skipif`` whose source mentions the module token.

Evidence is per (file, module): once a file demonstrates it handles
the module's absence, its other imports of the same module are
accepted (they are reachable only past the guard).

CI semantics (baseline pattern, cf. ``check_miswiring.py``): findings
are keyed ``<path>::<module>`` and compared against
``optional_dep_imports_baseline.json`` next to this script. A finding
not in the baseline fails the run — guard the import, or
(deliberately, with a note) baseline it. The baseline target is EMPTY.

Usage:
    python3 .github/scripts/check_optional_dep_imports.py            # CI mode
    python3 .github/scripts/check_optional_dep_imports.py --root <tree>
    python3 .github/scripts/check_optional_dep_imports.py --write-baseline
    python3 .github/scripts/check_optional_dep_imports.py --list-modules

Exit codes: 0 clean (stale-only is clean), 1 new findings, 2 usage error.
"""

from __future__ import annotations

import argparse
import ast
import json
import re
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
BASELINE_PATH = SCRIPT_DIR / "optional_dep_imports_baseline.json"

PY_ROOTS = ["core", "packages", "plugins"]
SKIP_DIR_NAMES = {
    ".git", "__pycache__", "node_modules", "out", ".out", ".tox",
    ".venv", "venv", "build", "dist", "fixtures", "data",
}

# Distribution name -> import name(s). Anything not listed maps by the
# usual dash-to-underscore rule.
DIST_TO_MODULES = {
    "google-genai": ("google.genai",),
    "z3-solver": ("z3",),
    "beautifulsoup4": ("bs4",),
    "sage-agent-sdk": ("sage_sdk", "sage_agent_sdk"),
}

# Commented out in requirements.txt but guaranteed present on bare CI
# anyway, so an unguarded test import cannot fail there:
#   openai — hard requirement of the pinned ``instructor``;
#   httpx  — hard requirement of the openai SDK;
#   tomli  — stdlib ``tomllib`` from Python 3.11 (CI runs newer).
TRANSITIVE_PRESENT = {"openai", "httpx", "tomli"}

_COMMENTED_PIN_RE = re.compile(r"^#\s*([A-Za-z0-9][A-Za-z0-9._-]*)==\S+")
_ACTIVE_PIN_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==\S+")


def optional_modules(root: Path) -> set[str]:
    """Import names absent from a bare requirements-dev.txt install."""
    commented: set[str] = set()
    active: set[str] = set()
    for req_name in ("requirements.txt", "requirements-dev.txt"):
        req = root / req_name
        if not req.is_file():
            continue
        for line in req.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            m = _COMMENTED_PIN_RE.match(line)
            if m:
                commented.add(m.group(1).lower())
                continue
            m = _ACTIVE_PIN_RE.match(line.split(";")[0].strip())
            if m:
                active.add(m.group(1).lower())
    mods: set[str] = set()
    for dist in sorted(commented - active):
        if dist in TRANSITIVE_PRESENT:
            continue
        for mod in DIST_TO_MODULES.get(dist, (dist.replace("-", "_"),)):
            if mod in TRANSITIVE_PRESENT:
                continue
            mods.add(mod)
    return mods


def is_test_file(path: Path) -> bool:
    if path.suffix != ".py":
        return False
    if "tests" in path.parts:
        return True
    return path.name.startswith("test_") or path.name == "conftest.py"


def iter_test_files(root: Path):
    for sub in PY_ROOTS:
        base = root / sub
        if not base.is_dir():
            continue
        for p in sorted(base.rglob("*.py")):
            if any(part in SKIP_DIR_NAMES for part in p.parts):
                continue
            if is_test_file(p):
                yield p


def _module_matches(imported: str, optional: str) -> bool:
    """``imported`` is ``optional`` itself or a submodule of it."""
    return imported == optional or imported.startswith(optional + ".")


def _handler_catches_import_error(handler: ast.ExceptHandler) -> bool:
    if handler.type is None:
        return True  # bare except
    names = []
    t = handler.type
    for node in ast.walk(t):
        if isinstance(node, ast.Name):
            names.append(node.id)
        elif isinstance(node, ast.Attribute):
            names.append(node.attr)
    return any(
        n in ("ImportError", "ModuleNotFoundError", "Exception",
              "BaseException")
        for n in names
    )


class _ImportScan(ast.NodeVisitor):
    """Imports of optional modules, split guarded / unguarded."""

    def __init__(self, mods: set[str]):
        self.mods = mods
        self._try_guard_depth = 0
        self.guarded: set[str] = set()
        self.unguarded: dict[str, int] = {}  # module -> first lineno

    def _record(self, imported: str, lineno: int) -> None:
        for opt in self.mods:
            if _module_matches(imported, opt):
                if self._try_guard_depth:
                    self.guarded.add(opt)
                else:
                    self.unguarded.setdefault(opt, lineno)

    def visit_Try(self, node: ast.Try) -> None:
        catches = any(
            _handler_catches_import_error(h) for h in node.handlers
        )
        if catches:
            self._try_guard_depth += 1
        for child in node.body:
            self.visit(child)
        if catches:
            self._try_guard_depth -= 1
        for part in (node.handlers, node.orelse, node.finalbody):
            for child in part:
                self.visit(child)

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self._record(alias.name, node.lineno)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.level == 0 and node.module:
            self._record(node.module, node.lineno)


def _text_evidence(text: str, module: str) -> bool:
    """Non-AST guard evidence for *module* in the file's source."""
    tok = re.escape(module)
    patterns = (
        # pytest.importorskip("module") / importorskip("module.sub")
        rf"importorskip\(\s*['\"]{tok}[.'\"]",
        # sys.modules stubs: monkeypatch.setitem(sys.modules, "module",
        # ...) and sys.modules["module"] = ...
        rf"sys\.modules\s*,\s*['\"]{tok}[.'\"]",
        rf"sys\.modules\[\s*['\"]{tok}[.'\"]",
        # a skipif whose condition/reason names the module (bounded
        # window: the condition may wrap across a few lines)
        rf"skipif[\s\S]{{0,200}}?{tok}",
    )
    return any(re.search(p, text) for p in patterns)


def scan(root: Path) -> tuple[dict[str, int], set[str]]:
    """Return ({finding_key: lineno}, optional_module_set)."""
    mods = optional_modules(root)
    findings: dict[str, int] = {}
    for path in iter_test_files(root):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(text)
        except (OSError, SyntaxError):
            continue
        visitor = _ImportScan(mods)
        visitor.visit(tree)
        for module, lineno in sorted(visitor.unguarded.items()):
            if module in visitor.guarded:
                continue  # file demonstrated absence handling
            if _text_evidence(text, module):
                continue
            rel = path.relative_to(root).as_posix()
            findings[f"{rel}::{module}"] = lineno
    return findings, mods


def load_baseline() -> set[str]:
    if not BASELINE_PATH.is_file():
        return set()
    data = json.loads(BASELINE_PATH.read_text(encoding="utf-8"))
    return set(data.get("findings", []))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--root", type=Path, default=SCRIPT_DIR.parents[1])
    ap.add_argument("--write-baseline", action="store_true")
    ap.add_argument("--list-modules", action="store_true",
                    help="print the derived optional-module list")
    args = ap.parse_args()
    root = args.root.resolve()
    if not root.is_dir():
        print(f"error: root {root} is not a directory", file=sys.stderr)
        return 2

    findings, mods = scan(root)

    if args.list_modules:
        for m in sorted(mods):
            print(m)
        return 0

    if args.write_baseline:
        BASELINE_PATH.write_text(json.dumps({
            "_comment": (
                "Deliberate unguarded optional-dependency imports in "
                "test files. Target: keep this EMPTY — guard with "
                "importorskip / try-except ImportError / a sys.modules "
                "stub instead of baselining."
            ),
            "findings": sorted(findings),
        }, indent=2) + "\n", encoding="utf-8")
        print(f"baseline written: {len(findings)} finding(s)")
        return 0

    baseline = load_baseline()
    new = {k: v for k, v in findings.items() if k not in baseline}
    stale = baseline - set(findings)

    print(
        f"optional-dep import lint: {len(mods)} optional module(s) "
        f"derived from requirements pins; {len(findings)} finding(s), "
        f"{len(new)} new, {len(stale)} stale-baselined",
    )
    for key in sorted(stale):
        print(f"  stale baseline entry (no longer fires): {key}")
    if new:
        print(
            "\nNEW unguarded optional-dependency imports in test "
            "files (these FAIL on bare CI where the dependency is "
            "not installed):",
            file=sys.stderr,
        )
        for key, lineno in sorted(new.items()):
            path, module = key.rsplit("::", 1)
            print(
                f"  {path}:{lineno}: imports optional module "
                f"'{module}' without importorskip / try-except "
                f"ImportError / sys.modules stub / skipif",
                file=sys.stderr,
            )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

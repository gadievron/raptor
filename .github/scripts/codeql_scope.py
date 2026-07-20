"""Compute the minimal Python file set for a CodeQL PR scan.

Parses every .py file under core/ and packages/ with the stdlib ast
module, builds a reverse import graph, then walks outward from the
changed-file set to collect everything that transitively depends on
a change.  Emits a dynamic CodeQL config with ``paths:`` restricted
to that closure.

Falls back to full scan when:
  - the closure exceeds FULL_SCAN_THRESHOLD of the total file count
  - import parsing fails on enough files to make the graph unreliable
  - no changed-file list is available (schedule / workflow_dispatch)

Usage (from GitHub Actions):
    python3 .github/scripts/codeql_scope.py \
        --changed-files /tmp/changed_files.txt \
        --base-config  .github/codeql/codeql-config.yml \
        --out          /tmp/codeql-scoped-config.yml

Exit code 0 always.  Writes the config and prints a summary.
Sets GITHUB_OUTPUT ``codeql_scoped_config`` to the output path
and ``codeql_scope_mode`` to ``scoped`` or ``full``.
"""

from __future__ import annotations

import argparse
import ast
import os
import sys
from collections import defaultdict
from pathlib import Path


SCAN_ROOTS = ("core", "packages")

FULL_SCAN_THRESHOLD = 0.60

PARSE_FAILURE_THRESHOLD = 0.05

EXTRA_ROOTS = (
    "raptor.py",
    "raptor_agentic.py",
)


def discover_py_files(
    repo: Path, extra_roots: tuple[str, ...] = ()
) -> list[Path]:
    """Walk SCAN_ROOTS (+ extra_roots) and collect every .py file."""
    files: list[Path] = []
    for root in (*SCAN_ROOTS, *extra_roots):
        root_path = repo / root
        if not root_path.is_dir():
            continue
        for p in root_path.rglob("*.py"):
            files.append(p.relative_to(repo))
    for name in EXTRA_ROOTS:
        p = repo / name
        if p.is_file():
            files.append(Path(name))
    return files


def file_to_module(path: Path) -> str | None:
    """Convert a file path to a dotted module name.

    core/llm/client.py        -> core.llm.client
    core/llm/__init__.py      -> core.llm
    packages/sca/findings.py  -> packages.sca.findings
    raptor.py                 -> raptor
    """
    if not path.name:
        return None
    parts = list(path.with_suffix("").parts)
    if not parts:
        return None
    if parts[-1] == "__init__":
        parts = parts[:-1]
    if not parts:
        return None
    return ".".join(parts)


def module_to_files(module: str, all_modules: dict[str, Path]) -> list[Path]:
    """Resolve a module name to the file(s) it could refer to.

    ``import core.llm`` might mean core/llm/__init__.py or
    core/llm.py.  ``from core.llm import client`` means
    core/llm/client.py.  We return all matches.
    """
    hits: list[Path] = []
    if module in all_modules:
        hits.append(all_modules[module])
    # A dotted import ``from X.Y import Z`` might mean X/Y/Z.py
    # (submodule) or an attribute of X/Y/__init__.py (already covered
    # by the parent module being in all_modules).  We don't need to
    # distinguish — both are valid edges.
    return hits


def _get_str_literal(node: ast.expr) -> str | None:
    """Extract a plain string from an AST node, or None."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _extract_dynamic_imports(tree: ast.Module) -> list[str]:
    """Find importlib.import_module("x") and __import__("x") calls.

    Handles both ``importlib.import_module("x")`` (attribute form)
    and ``import_module("x")`` after ``from importlib import
    import_module`` (bare-name form).
    """
    bare_names: set[str] = set()
    for node in ast.walk(tree):
        if (isinstance(node, ast.ImportFrom)
                and node.module == "importlib"
                and node.level == 0):
            for alias in node.names:
                if alias.name == "import_module":
                    bare_names.add(alias.asname or alias.name)

    modules: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not node.args:
            continue
        func = node.func
        if isinstance(func, ast.Attribute):
            # importlib.import_module("mod.name")
            if (func.attr == "import_module"
                    and isinstance(func.value, ast.Name)
                    and func.value.id == "importlib"):
                val = _get_str_literal(node.args[0])
                if val:
                    modules.append(val)
        elif isinstance(func, ast.Name):
            if func.id in bare_names:
                val = _get_str_literal(node.args[0])
                if val:
                    modules.append(val)
            elif func.id == "__import__":
                val = _get_str_literal(node.args[0])
                if val:
                    modules.append(val)
    return modules


def _extract_lazy_export_dicts(tree: ast.Module) -> list[str]:
    """Find PEP 562 lazy-export dicts assigned to conventional names.

    Only matches module-level ``Assign`` where the target name
    contains ``EXPORT`` or ``LAZY`` (e.g. ``_LAZY_EXPORTS``).
    """
    modules: list[str] = []
    for node in ast.iter_child_nodes(tree):
        if not isinstance(node, ast.Assign):
            continue
        if not any(
            isinstance(t, ast.Name)
            and ("EXPORT" in t.id or "LAZY" in t.id)
            for t in node.targets
        ):
            continue
        if not isinstance(node.value, ast.Dict):
            continue
        for val in node.value.values:
            if not isinstance(val, ast.Tuple) or len(val.elts) < 1:
                continue
            mod = _get_str_literal(val.elts[0])
            if mod:
                modules.append(mod)
    return modules


_MODULE_PATH_RE = __import__("re").compile(
    r"^(?:core|packages)\.[a-z_][a-z0-9_.]*[a-z0-9_]$"
)


def _extract_parametrize_modules(tree: ast.Module) -> list[str]:
    """Find project-internal module paths in string constants.

    Catches the pattern where a test parametrizes over module path
    strings and calls ``importlib.import_module(param)`` in the body,
    or uses ``mock.patch("core.some.module.func")`` — the variable-arg
    call is invisible to ``_extract_dynamic_imports``, but the string
    literals are extractable.

    Only matches strings that look like valid dotted module paths
    (no spaces, colons, format specifiers, etc.).
    """
    modules: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Constant):
            continue
        if not isinstance(node.value, str):
            continue
        val = node.value
        if _MODULE_PATH_RE.match(val):
            modules.append(val)
    return modules


def extract_imports(path: Path, repo: Path) -> list[str] | None:
    """Parse a .py file and return the dotted module names it imports.

    Covers static imports, importlib.import_module() /
    __import__() with string literals, PEP 562 lazy-export
    dicts, and project-internal module paths in string constants
    (e.g. ``@pytest.mark.parametrize`` arguments).
    """
    try:
        source = (repo / path).read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(source, filename=str(path))
    except (SyntaxError, ValueError):
        return None

    modules: list[str] = []
    own_package = ".".join(path.parts[:-1]) if len(path.parts) > 1 else ""

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                modules.append(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module is None:
                base = own_package
            elif node.level > 0:
                # Relative import — resolve against the file's package.
                pkg_parts = own_package.split(".") if own_package else []
                # level=1 means current package, level=2 means parent, etc.
                up = node.level - 1
                if up > 0 and len(pkg_parts) >= up:
                    pkg_parts = pkg_parts[:-up]
                base = ".".join(pkg_parts + [node.module]) if node.module else ".".join(pkg_parts)
            else:
                base = node.module

            if base:
                modules.append(base)
                # ``from X import Y`` — Y might be a submodule.
                if node.names:
                    for alias in node.names:
                        if alias.name != "*":
                            modules.append(f"{base}.{alias.name}")

    # Dynamic imports: importlib.import_module("x") / __import__("x").
    modules.extend(_extract_dynamic_imports(tree))

    # PEP 562 lazy-export dicts in __init__.py files.
    if path.name == "__init__.py":
        modules.extend(_extract_lazy_export_dicts(tree))

    # Project-internal module paths in string constants (parametrize etc.).
    modules.extend(_extract_parametrize_modules(tree))

    # Only keep imports that point into our scan roots.
    return [
        m for m in modules
        if any(m == r or m.startswith(r + ".") for r in SCAN_ROOTS)
    ]


def build_graph(
    py_files: list[Path], repo: Path
) -> tuple[dict[Path, set[Path]], int]:
    """Build a reverse dependency graph: file → files that depend on it.

    Returns (reverse_graph, parse_failure_count).
    """
    # Module name → file path mapping.
    mod_to_file: dict[str, Path] = {}
    for f in py_files:
        mod = file_to_module(f)
        if mod:
            mod_to_file[mod] = f

    forward: dict[Path, set[Path]] = defaultdict(set)
    parse_failures = 0

    for f in py_files:
        imports = extract_imports(f, repo)
        if imports is None:
            parse_failures += 1
            continue
        for imp in imports:
            targets = module_to_files(imp, mod_to_file)
            for t in targets:
                if t != f:
                    forward[f].add(t)

    # Invert: for each target, who imports it?
    reverse: dict[Path, set[Path]] = defaultdict(set)
    for src, deps in forward.items():
        for dep in deps:
            reverse[dep].add(src)

    return dict(reverse), parse_failures


def transitive_dependents(
    changed: set[Path], reverse: dict[Path, set[Path]]
) -> set[Path]:
    """BFS outward from changed files through the reverse graph."""
    closure = set(changed)
    frontier = list(changed)
    while frontier:
        current = frontier.pop()
        for dep in reverse.get(current, []):
            if dep not in closure:
                closure.add(dep)
                frontier.append(dep)
    return closure


def init_imports(
    changed: set[Path], all_files: list[Path]
) -> set[Path]:
    """If any __init__.py changed, pull in the whole package.

    A change to __init__.py can affect every sibling via implicit
    re-exports, namespace changes, or __all__ modifications.
    """
    extra: set[Path] = set()
    for f in changed:
        if f.name == "__init__.py":
            pkg_dir = f.parent
            for af in all_files:
                if af != f and str(af).startswith(str(pkg_dir) + "/"):
                    extra.add(af)
    return extra


def load_base_config(path: Path) -> dict:
    """Load the base CodeQL config YAML (simple enough to avoid PyYAML)."""
    # The config is simple key-value + list YAML.  Parse just what we
    # need: name and paths-ignore.
    config: dict = {"name": "RAPTOR CodeQL config", "paths-ignore": []}
    if not path.is_file():
        return config
    text = path.read_text(encoding="utf-8")
    current_list_key: str | None = None
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("#") or not stripped:
            continue
        if stripped.startswith("- ") and current_list_key:
            val = stripped[2:].strip().strip("'\"")
            config.setdefault(current_list_key, []).append(val)
        elif ":" in stripped:
            key, _, val = stripped.partition(":")
            key = key.strip()
            val = val.strip()
            if val:
                config[key] = val
                current_list_key = None
            else:
                current_list_key = key
    return config


def write_scoped_config(
    out_path: Path,
    base_config: dict,
    scoped_paths: list[str] | None,
) -> None:
    """Write a CodeQL config YAML.

    If scoped_paths is None, writes the base config unchanged (full scan).
    Otherwise, adds a ``paths:`` directive restricting extraction.
    """
    lines = [f"name: {base_config.get('name', 'RAPTOR CodeQL config')}", ""]

    if scoped_paths is not None:
        lines.append("paths:")
        for p in sorted(scoped_paths):
            lines.append(f"  - {p}")
        lines.append("")

    pi = base_config.get("paths-ignore", [])
    if pi:
        lines.append("paths-ignore:")
        for p in pi:
            lines.append(f"  - {p}")
        lines.append("")

    out_path.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--changed-files",
        help="File listing changed paths, one per line",
    )
    parser.add_argument(
        "--base-config",
        default=".github/codeql/codeql-config.yml",
        help="Base CodeQL config to extend",
    )
    parser.add_argument(
        "--out",
        default="/tmp/codeql-scoped-config.yml",
        help="Output path for the scoped config",
    )
    parser.add_argument(
        "--repo",
        default=".",
        help="Repository root",
    )
    args = parser.parse_args()

    repo = Path(args.repo).resolve()
    out_path = Path(args.out)
    base_config = load_base_config(repo / args.base_config)
    gh_output = os.environ.get("GITHUB_OUTPUT")

    def set_output(key: str, val: str) -> None:
        if gh_output:
            with open(gh_output, "a", encoding="utf-8") as fh:
                fh.write(f"{key}={val}\n")

    # Load changed files.
    changed_py: set[Path] = set()
    full_reason: str | None = None

    if not args.changed_files:
        full_reason = "no changed-file list provided"
    else:
        cf_path = Path(args.changed_files)
        if not cf_path.is_file():
            full_reason = f"changed-file list not found: {cf_path}"
        else:
            all_changed = [
                line.strip()
                for line in cf_path.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
            if not all_changed:
                full_reason = "changed-file list is empty"
            else:
                changed_py = {
                    Path(f) for f in all_changed if f.endswith(".py")
                }
                # If workflow or config files changed, full scan.
                ci_triggers = {
                    ".github/workflows/codeql.yml",
                    ".github/codeql/codeql-config.yml",
                    "pyproject.toml",
                }
                if any(f in ci_triggers for f in all_changed):
                    full_reason = "CI/config file changed"
                elif any(
                    f.startswith("requirements") and f.endswith(".txt")
                    for f in all_changed
                ):
                    full_reason = "requirements file changed"
                elif not changed_py:
                    full_reason = "no Python files in changeset"

    # Discover all .py files and build the graph.
    all_py = discover_py_files(repo)
    total = len(all_py)

    if full_reason:
        print(f"::notice::CodeQL Python scope: full scan ({full_reason})")
        write_scoped_config(out_path, base_config, None)
        set_output("codeql_scoped_config", str(out_path))
        set_output("codeql_scope_mode", "full")
        return 0

    print(f"Building import graph for {total} Python files...")
    reverse_graph, parse_failures = build_graph(all_py, repo)

    if total > 0 and parse_failures / total > PARSE_FAILURE_THRESHOLD:
        full_reason = (
            f"too many parse failures ({parse_failures}/{total} = "
            f"{parse_failures / total:.0%} > {PARSE_FAILURE_THRESHOLD:.0%})"
        )
        print(f"Full scan: {full_reason}")
        write_scoped_config(out_path, base_config, None)
        set_output("codeql_scoped_config", str(out_path))
        set_output("codeql_scope_mode", "full")
        return 0

    # Expand __init__.py changes to their package.
    changed_py |= init_imports(changed_py, all_py)

    # Compute transitive closure.
    closure = transitive_dependents(changed_py, reverse_graph)

    ratio = len(closure) / total if total > 0 else 1.0

    if ratio >= FULL_SCAN_THRESHOLD:
        msg = (f"closure {len(closure)}/{total} files "
               f"({ratio:.0%} >= {FULL_SCAN_THRESHOLD:.0%} threshold)")
        print(f"::notice::CodeQL Python scope: full scan ({msg})")
        write_scoped_config(out_path, base_config, None)
        set_output("codeql_scoped_config", str(out_path))
        set_output("codeql_scope_mode", "full")
        return 0

    # Scoped scan.
    scoped_paths = [str(f) for f in sorted(closure)]
    write_scoped_config(out_path, base_config, scoped_paths)
    set_output("codeql_scoped_config", str(out_path))
    set_output("codeql_scope_mode", "scoped")

    msg = (f"scoped to {len(closure)}/{total} files ({ratio:.0%}) — "
           f"{len(changed_py)} changed, {len(closure) - len(changed_py)} dependents")
    print(f"::notice::CodeQL Python scope: {msg}")
    if parse_failures:
        print(f"  Parse failures: {parse_failures} (below threshold)")

    return 0


if __name__ == "__main__":
    sys.exit(main())

"""Inventory and execution contracts for policy-owning sandbox wrappers."""
from __future__ import annotations

import ast
import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
REGISTRY = ROOT / '.github/sandbox-wrapper-tests.json'
_EXECUTORS = {'run', 'sandbox', 'run_untrusted', 'run_untrusted_networked'}
_SKIP_PARTS = {'tests', 'scripts', 'calibration', '__pycache__', 'fixtures'}


def policy_entrypoints(path: Path) -> list[str]:
    """Find public sandbox dispatch and named injected runners, including aliases.

    Core backend implementations have their own enforcement suites. This
    inventory also tracks ``state.sandbox_run(...)`` in shared policy stages.
    It owns callers outside core/sandbox; explicit self-confining and
    delegated adapters can additionally be registered without a direct call.
    """
    try:
        text = path.read_text(encoding='utf-8')
        if "sandbox" not in text:
            return []
        tree = ast.parse(text)
    except (SyntaxError, UnicodeError):
        return []  # non-Python libexec launchers
    names, modules, calls = set(), set(), []
    class Visitor(ast.NodeVisitor):
        def __init__(self):
            self.scope = []
        def visit_ClassDef(self, node):
            self.scope.append(node.name)
            self.generic_visit(node)
            self.scope.pop()
        def visit_FunctionDef(self, node):
            self.scope.append(node.name)
            self.generic_visit(node)
            self.scope.pop()
        visit_AsyncFunctionDef = visit_FunctionDef
        def visit_ImportFrom(self, node):
            if node.module in ('core.sandbox', 'core.sandbox.context'):
                names.update(alias.asname or alias.name for alias in node.names if alias.name in _EXECUTORS)
            if node.module == 'core':
                modules.update(alias.asname or alias.name for alias in node.names if alias.name == 'sandbox')
        def visit_Import(self, node):
            modules.update(alias.asname or alias.name for alias in node.names
                           if alias.name in ('core.sandbox', 'core.sandbox.context'))
        def visit_Call(self, node):
            target = node.func
            if (isinstance(target, ast.Name)
                    or isinstance(target, ast.Attribute) and (target.attr in _EXECUTORS or target.attr == 'sandbox_run')):
                calls.append((target, tuple(self.scope)))
            self.generic_visit(node)
        def visit_Name(self, node):
            pass  # Names and constants cannot contain calls, imports or scopes.
        visit_Constant = visit_Name
    Visitor().visit(tree)
    # Imports have always been collected file-wide, including those appearing
    # after a call. Keep that behavior while visiting each node only once.
    qualified_names = {module + '.' + executor for module in modules for executor in _EXECUTORS}
    found = set()
    for target, scope in calls:
        direct = isinstance(target, ast.Name) and target.id in names
        qualified = False
        if qualified_names and isinstance(target, ast.Attribute) and target.attr in _EXECUTORS:
            # Imported modules/aliases are dotted names. Arbitrary receiver
            # expressions cannot match them, so never unparse incidental
            # method calls (or their potentially large receiver subtrees).
            parts = []
            receiver = target
            while isinstance(receiver, ast.Attribute):
                parts.append(receiver.attr)
                receiver = receiver.value
            if isinstance(receiver, ast.Name):
                qualified = '.'.join([receiver.id, *reversed(parts)]) in qualified_names
        injected = isinstance(target, ast.Attribute) and target.attr == 'sandbox_run'
        if direct or qualified or injected:
            found.add('.'.join(scope) or '<module>')
    return sorted(found)


def discover_wrappers(root: Path) -> dict[str, list[str]]:
    found = {}
    for directory in ('core', 'packages', 'libexec'):
        base = root / directory
        for parent, directories, filenames in os.walk(base):
            directories[:] = sorted(name for name in directories if name not in _SKIP_PARTS)
            for filename in sorted(filenames):
                path = Path(parent) / filename
                rel = path.relative_to(root)
                if (str(rel).startswith('core/sandbox/')
                        or (directory != 'libexec' and path.suffix != '.py')
                        or filename.startswith('test_')):
                    continue
                entries = policy_entrypoints(path)
                if entries:
                    found[rel.as_posix()] = entries
    return found


def load_registry(path: Path = REGISTRY) -> dict:
    return json.loads(path.read_text(encoding='utf-8'))


def node_exists(root: Path, selector: str, *, trees: dict | None = None) -> bool:
    filename, *parts = selector.split('::')
    path = root / filename
    if not path.is_file() or not parts:
        return False
    try:
        if trees is None:
            node = ast.parse(path.read_text(encoding='utf-8'))
        else:
            if path not in trees:
                trees[path] = ast.parse(path.read_text(encoding='utf-8'))
            node = trees[path]
        for part in parts:
            name = part.split('[', 1)[0]
            node = next(child for child in node.body
                        if isinstance(child, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)) and child.name == name)
        return isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith('test_')
    except (SyntaxError, StopIteration):
        return False


def registry_errors(root: Path, registry: dict) -> list[str]:
    errors = []
    # Local to this census: repeated selectors share an AST, while a later
    # census still sees source/test mutations rather than stale cached trees.
    trees = {}
    rows = registry['wrappers']
    indexed = {row['source']: row for row in rows}
    if len(indexed) != len(rows):
        errors.append('duplicate wrapper source')
    discovered = discover_wrappers(root)
    for source, entries in discovered.items():
        row = indexed.get(source)
        if row is None:
            errors.append(source + ': unregistered sandbox wrapper; add an owned test case')
        elif row.get('entrypoints') != entries:
            errors.append(source + ': sandbox entrypoints changed; review test bindings')
    for row in rows:
        if not (root / row['source']).is_file():
            errors.append(row['source'] + ': source missing')
        if not row.get('contracts'):
            errors.append(row['source'] + ': no contract test case')
        for selectors in row.get('contract_platforms', {}).values():
            for selector in selectors:
                if not node_exists(root, selector, trees=trees):
                    errors.append(row['source'] + ': missing platform test ' + selector)
        if row['source'] not in discovered and not row.get('discovery'):
            errors.append(row['source'] + ': explicit wrapper needs discovery rationale')
        for selector in row.get('contracts', []):
            if not node_exists(root, selector, trees=trees):
                errors.append(row['source'] + ': missing test ' + selector)
    families = registry['native']
    if len({family['id'] for family in families}) != len(families):
        errors.append('duplicate native family')
    for family in families:
        if set(family['platforms']) != {'linux', 'darwin'}:
            errors.append(family['id'] + ': both platform cells must be explicit')
        for platform, cell in family['platforms'].items():
            if platform not in ('linux', 'darwin'):
                errors.append(family['id'] + ': unknown platform')
            if cell.get('tests'):
                if type(cell.get('expected')) is not int or cell['expected'] < 1:
                    errors.append(family['id'] + ': missing execution count')
                for selector in cell['tests']:
                    if not node_exists(root, selector, trees=trees):
                        errors.append(family['id'] + ': missing native test ' + selector)
            elif not cell.get('reason'):
                errors.append(family['id'] + ': untested platform needs an explicit reason')
    return errors

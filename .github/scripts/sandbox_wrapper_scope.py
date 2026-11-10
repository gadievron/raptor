"""Select registered wrapper contracts and native families conservatively.

The full registration census always runs first. Python dependencies include
parent initializers, literal dynamic imports and repo-local paths. Collected
test files inherit their parent conftests; imported modules do not.
Computed imports without static targets broaden selection for runtime edits;
resources broaden to their owning component. Unknown history and parse errors
run everything. Selection never relies on a nightly run to repair a missing edge.
"""
from __future__ import annotations

import ast
from collections import deque
from html import escape
import json
import os
import re
import subprocess
from pathlib import Path

from ci_change_scope import changed_paths
from codeql_scope import discover_root_modules, extract_imports
from sandbox_wrapper_tests import load_registry, registry_errors

GLOBAL_INPUTS = {'tuning.json', 'conftest.py', 'pytest.ini', 'pyproject.toml', 'uv.lock',
                 '.github/sandbox-wrapper-tests.json', '.github/workflows/sandbox-wrappers.yml',
                 '.github/scripts/run_sandbox_wrapper_tests.py', '.github/scripts/sandbox_wrapper_tests.py',
                 '.github/scripts/sandbox_wrapper_scope.py', '.github/scripts/ci_change_scope.py',
                 '.github/scripts/codeql_scope.py', '.github/scripts/ci_push_base.py',
                 '.github/scripts/requirements-sandbox-wrappers.txt'}
GLOBAL_DIRS = ('core/sandbox/', 'bin/', 'libexec/', 'test/', '.github/actions/setup-venv/', '.github/actions/enable-userns/')
PLATFORMS = {'linux': 'ubuntu-24.04', 'darwin': 'macos-latest'}
REGISTRY_INPUT = '.github/sandbox-wrapper-tests.json'


def base_registry(repo: Path, base: str) -> dict | None:
    """Read the same immutable base used by changed_paths, without fetching."""
    if not re.fullmatch(r'(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})', base or '') or set(base) == {'0'}:
        return None
    try:
        result = subprocess.run(['git', 'show', base + ':' + REGISTRY_INPUT], cwd=repo,
                                check=True, capture_output=True, timeout=10)
        if len(result.stdout) > 2 * 1024 * 1024:
            return None
        registry = json.loads(result.stdout)
        return registry if isinstance(registry, dict) else None
    except (OSError, subprocess.SubprocessError, ValueError, UnicodeError, RecursionError):
        return None


def native_cell_changes(previous: dict | None, current: dict) -> set[tuple[str, str]] | None:
    """Admit only native selector/count edits; unknown policy needs full coverage.

    The current registry census runs before this comparison. Historical nodes
    need not exist in the current tree, so do not run that census on old data.
    """
    def indexed(registry):
        if (not isinstance(registry, dict) or not {'wrappers', 'native'} <= registry.keys()
                or registry.keys() - {'version', 'wrappers', 'native'}
                or ('version' in registry and (type(registry['version']) is not int or registry['version'] != 1))
                or not isinstance(registry['wrappers'], list) or not isinstance(registry['native'], list)):
            return None
        if any(not isinstance(row, dict) or row.keys() - {'source', 'entrypoints', 'contracts', 'contract_platforms', 'discovery'}
               or ('discovery' in row and not isinstance(row['discovery'], str))
               for row in registry['wrappers']):
            return None
        families = {}
        for family in registry['native']:
            if (not isinstance(family, dict) or family.keys() - {'id', 'platforms', 'env'}
                    or not isinstance(family.get('id'), str) or not family['id'] or family['id'] in families
                    or not isinstance(family.get('platforms'), dict) or set(family['platforms']) != set(PLATFORMS)
                    or not isinstance(family.get('env', {}), dict)
                    or any(not isinstance(k, str) or not isinstance(v, str) for k, v in family.get('env', {}).items())):
                return None
            for cell in family['platforms'].values():
                if (not isinstance(cell, dict) or cell.keys() - {'tests', 'expected', 'manual', 'reason'}
                        or ('manual' in cell and type(cell['manual']) is not bool)
                        or ('reason' in cell and not isinstance(cell['reason'], str))
                        or ('expected' in cell and (type(cell['expected']) is not int or cell['expected'] < 1))):
                    return None
                tests = cell.get('tests')
                if tests:
                    if (not isinstance(tests, list) or any(not isinstance(s, str) or not s for s in tests)
                            or len(set(tests)) != len(tests)
                            or type(cell.get('expected')) is not int or cell['expected'] < 1):
                        return None
                elif tests not in (None, []) or not cell.get('reason'):
                    return None
            families[family['id']] = family
        return families

    old, new = indexed(previous), indexed(current)
    if old is None or new is None or old.keys() != new.keys():
        return None
    if {k: v for k, v in previous.items() if k != 'native'} != {k: v for k, v in current.items() if k != 'native'}:
        return None
    changes = set()
    for name, family in new.items():
        before = old[name]
        if {k: v for k, v in before.items() if k != 'platforms'} != {k: v for k, v in family.items() if k != 'platforms'}:
            return None
        for platform, cell in family['platforms'].items():
            prior = before['platforms'][platform]
            if cell == prior:
                continue
            if (not cell.get('tests') or not prior.get('tests') or cell.get('manual') or prior.get('manual')
                    or {k: v for k, v in cell.items() if k not in {'tests', 'expected'}}
                    != {k: v for k, v in prior.items() if k not in {'tests', 'expected'}}):
                return None
            changes.add((platform, name))
    return changes


def component(path: str) -> str:
    parts = Path(path).parts
    return '/'.join(parts[:2]) if len(parts) > 1 and parts[0] in {'core', 'packages', 'engine'} else str(Path(path).parent)


def lazy_exports(path: str, tree: ast.Module) -> tuple[dict[str, str], set[int]]:
    """Recognize finite PEP 562 export tables; custom loaders stay opaque.

    Only a literal map, a guarded lookup, and the standard import/getattr/cache
    handler are accepted. Never execute a module to discover dependencies.
    """
    if not path.endswith('/__init__.py'):
        return {}, set()
    getters = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == '__getattr__']
    if len(getters) != 1:
        return {}, set()
    getter = getters[0]
    for assignment in tree.body:
        if not isinstance(assignment, ast.Assign) or len(assignment.targets) != 1:
            continue
        target = assignment.targets[0]
        if not isinstance(target, ast.Name) or not any(k in target.id for k in ('EXPORT', 'LAZY')):
            continue
        try:
            table = ast.literal_eval(assignment.value)
        except (ValueError, TypeError):
            continue
        if not isinstance(table, dict) or not table or not all(isinstance(k, str) for k in table):
            continue
        calls = [n for n in ast.walk(getter) if isinstance(n, ast.Call)]
        lookups = [n for n in ast.walk(getter) if isinstance(n, ast.Assign)
                   and isinstance(n.value, ast.Call) and isinstance(n.value.func, ast.Attribute)
                   and isinstance(n.value.func.value, ast.Name) and n.value.func.value.id == target.id
                   and n.value.func.attr == 'get' and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name)]
        imports = [n for n in calls if (getattr(n.func, 'attr', '') == 'import_module'
                                       or isinstance(n.func, ast.Name) and n.func.id == 'import_module')]
        if len(lookups) != 1 or len(imports) != 1 or len(imports[0].args) != 1:
            continue
        lookup_name = lookups[0].targets[0].id
        imported = imports[0].args[0]
        module_name = None
        if all(isinstance(v, tuple) and len(v) == 2 and isinstance(v[0], str) and (v[1] is None or isinstance(v[1], str)) for v in table.values()):
            for node in ast.walk(getter):
                if (isinstance(node, ast.Assign) and isinstance(node.value, ast.Name)
                        and node.value.id == lookup_name and len(node.targets) == 1
                        and isinstance(node.targets[0], ast.Tuple) and len(node.targets[0].elts) == 2
                        and isinstance(node.targets[0].elts[0], ast.Name)):
                    module_name = node.targets[0].elts[0].id
            valid_import = isinstance(imported, ast.Name) and imported.id == module_name
            exports = {k: v[0] for k, v in table.items()}
        elif all(isinstance(v, str) for v in table.values()):
            valid_import = (isinstance(imported, ast.JoinedStr) and len(imported.values) == 3
                            and isinstance(imported.values[0], ast.FormattedValue)
                            and isinstance(imported.values[0].value, ast.Name)
                            and imported.values[0].value.id == '__name__'
                            and isinstance(imported.values[1], ast.Constant) and imported.values[1].value == '.'
                            and isinstance(imported.values[2], ast.FormattedValue)
                            and isinstance(imported.values[2].value, ast.Name)
                            and imported.values[2].value.id == lookup_name)
            exports = {k: path[:-12].replace('/', '.') + '.' + v for k, v in table.items()}
        else:
            continue
        if not valid_import:
            continue
        assigned = {lookup_name} | ({module_name} if module_name else set())
        if any(sum(isinstance(n, ast.Name) and n.id == name and isinstance(n.ctx, ast.Store)
                   for n in ast.walk(getter)) != 1 for name in assigned):
            continue
        if len(lookups[0].value.args) != 1 or lookups[0].value.keywords:
            continue
        if any(isinstance(n, ast.Subscript) and isinstance(n.ctx, ast.Store)
               and isinstance(n.value, ast.Name) and n.value.id == target.id for n in ast.walk(tree)):
            continue
        allowed = {'getattr', 'globals', 'AttributeError', 'import_module'}
        if any(not ((isinstance(n.func, ast.Name) and n.func.id in allowed)
                    or (isinstance(n.func, ast.Attribute) and n.func.attr == 'get'
                        and isinstance(n.func.value, ast.Name) and n.func.value.id == target.id)
                    or (isinstance(n.func, ast.Attribute) and n.func.attr == 'import_module'
                        and isinstance(n.func.value, ast.Name) and n.func.value.id == 'importlib')) for n in calls):
            continue
        if any(isinstance(n, (ast.Import, ast.ImportFrom))
               and ((isinstance(n, ast.Import) and any(a.name != 'importlib' for a in n.names))
                    or isinstance(n, ast.ImportFrom) and n.module != 'importlib') for n in ast.walk(getter)):
            continue
        # Reassignment or mutation invalidates a literal table's bound.
        writes = [n for n in ast.walk(tree) if isinstance(n, ast.Name)
                  and n.id == target.id and isinstance(n.ctx, ast.Store)]
        if len(writes) != 1 or any(isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                                  and isinstance(n.func.value, ast.Name) and n.func.value.id == target.id
                                  and n.func.attr != 'get' for n in ast.walk(tree)):
            continue
        return exports, {id(assignment), id(getter)}
    return {}, set()


class StripDocumentation(ast.NodeTransformer):
    def visit_Expr(self, node):
        return None if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str) else node


class Dependencies:
    def __init__(self, repo: Path):
        self.repo = repo
        self.roots = frozenset(p.stem for p in discover_root_modules(repo))
        self.edges = {}
        self.packages = {}
        self.opaque_sources = set()
        # One immutable checkout per selection, like the existing edge cache.
        # Keep misses too: imported attributes repeatedly probe the same paths.
        self._module_files = {}
        self._resolved = {}
        self._package_trees = {}
        self._file_checks = {}

    def _is_file(self, path: str) -> bool:
        if path not in self._file_checks:
            self._file_checks[path] = (self.repo / path).is_file()
        return self._file_checks[path]

    def module_files(self, prefix: str) -> frozenset[str]:
        if prefix not in self._module_files:
            self._module_files[prefix] = frozenset(
                candidate for candidate in (prefix + '.py', prefix + '/__init__.py')
                if self._is_file(candidate)
            )
        return self._module_files[prefix]

    def collection_inputs(self, path: str) -> set[str]:
        """Pytest loads conftests for collected paths, not Python imports."""
        inputs = {path}
        for parent in Path(path).parents:
            candidate = (parent / 'conftest.py').as_posix()
            if self._is_file(candidate):
                inputs.add(candidate)
        return inputs

    def package_exports(self, prefix: str) -> dict[str, str]:
        if prefix not in self.packages:
            path = prefix + '/__init__.py'
            if path in self.module_files(prefix):
                tree = ast.parse((self.repo / path).read_text())
                exports, ignored = lazy_exports(path, tree)
                self.packages[prefix] = exports
                self._package_trees[path] = tree, ignored
            else:
                self.packages[prefix] = {}
        return self.packages[prefix]

    def resolve(self, module: str) -> set[str]:
        if module in self._resolved:
            return set(self._resolved[module])
        deps = set()
        pieces = module.split('.')
        for i in range(1, len(pieces) + 1):
            prefix = '/'.join(pieces[:i])
            deps.update(self.module_files(prefix))
            if i < len(pieces):
                exported = self.package_exports(prefix).get(pieces[i])
                if exported and exported != module:
                    # Export targets are plain literal module names, not another
                    # attribute expression. Their own imports are walked later.
                    target = exported.replace('.', '/')
                    deps.update(self.module_files(target))
        self._resolved[module] = frozenset(deps)
        return deps

    def direct(self, path: str) -> tuple[set[str], bool]:
        if path in self.edges:
            return self.edges[path]
        cached = self._package_trees.pop(path, None)
        if cached is None:
            text = (self.repo / path).read_text()
            try:
                tree = ast.parse(text)
            except SyntaxError:
                if path.startswith('libexec/') and not path.endswith('.py'):
                    self.edges[path] = set(), True
                    return self.edges[path]
                raise
            exports, ignored = lazy_exports(path, tree)
        else:
            tree, ignored = cached
            exports = self.packages[path[:-12]]
        if path.endswith('/__init__.py'):
            self.packages[path[:-12]] = exports
        tree.body = [node for node in tree.body if id(node) not in ignored]
        tree = StripDocumentation().visit(tree)
        modules = extract_imports(Path(path), self.repo, self.roots, source_tree=tree)
        if modules is None:
            raise ValueError('unreadable dependency: ' + path)
        deps = set()
        imports, calls, attributes, literals = [], [], [], []
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                imports.append(node)
            elif isinstance(node, ast.Call):
                calls.append(node)
            elif isinstance(node, ast.Attribute):
                attributes.append(node)
            elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                literals.append(node.value)
        for value in literals:
            modules.extend(re.findall(r'\b(?:core|packages|engine)(?:\.[A-Za-z_]\w*)+', value))
        aliases = {}
        for node in imports:
            if isinstance(node, ast.Import):
                for alias in node.names:
                    aliases[alias.asname or alias.name.split('.')[0]] = alias.name if alias.asname else alias.name.split('.')[0]
                    modules.extend(self.package_exports(alias.name.replace('.', '/')).values())
            elif isinstance(node, ast.ImportFrom):
                base = node.module or ''
                if node.level:
                    parent = Path(path).parts[:-node.level]
                    base = '.'.join((*parent, base)) if base else '.'.join(parent)
                for alias in node.names:
                    if alias.name == '*':
                        modules.extend(self.package_exports(base.replace('.', '/')).values())
                    else:
                        aliases[alias.asname or alias.name] = base + '.' + alias.name
        for node in calls:
            if isinstance(node.func, ast.Name) and node.func.id == 'getattr' and node.args:
                if isinstance(node.args[0], ast.Name) and node.args[0].id in aliases:
                    base = aliases[node.args[0].id]
                    if len(node.args) > 1 and isinstance(node.args[1], ast.Constant) and isinstance(node.args[1].value, str):
                        modules.append(base + '.' + node.args[1].value)
                    else:
                        modules.extend(self.package_exports(base.replace('.', '/')).values())
        for node in attributes:
            parts = []
            base = node
            while isinstance(base, ast.Attribute):
                parts.append(base.attr)
                base = base.value
            if isinstance(base, ast.Name):
                parts = [base.id, *reversed(parts)]
            else:
                # Keep the old treatment of calls, subscripts and arbitrary
                # expressions; only plain dotted names avoid the unparser.
                parts = ast.unparse(node).split('.')
            if parts[0] in aliases:
                modules.append('.'.join([aliases[parts[0]], *parts[1:]]))
        for module in modules:
            deps.update(self.resolve(module))
        for value in literals:
            if value.startswith(('core/', 'packages/', 'engine/', 'libexec/')):
                if (self.repo / value).exists():
                    deps.add(value)
        opaque = False
        aliases = {}
        for node in imports:
            if isinstance(node, ast.ImportFrom) and node.module in {'importlib', 'importlib.util', 'runpy'}:
                aliases.update({alias.asname or alias.name: alias.name for alias in node.names})
        for node in calls:
            name = node.func.id if isinstance(node.func, ast.Name) else getattr(node.func, 'attr', '')
            name = aliases.get(name, name)
            if name in {'import_module', '__import__', 'spec_from_file_location', 'run_path'}:
                index = 1 if name == 'spec_from_file_location' else 0
                if len(node.args) <= index or not isinstance(node.args[index], ast.Constant):
                    opaque = True
                elif name in {'import_module', '__import__'} and isinstance(node.args[index].value, str):
                    deps.update(self.resolve(node.args[index].value))
        for parent in Path(path).parents:
            candidate = (parent / '__init__.py').as_posix()
            if candidate != path and self._is_file(candidate):
                deps.add(candidate)
        self.edges[path] = deps, opaque
        return deps, opaque

    def closure(self, seeds: set[str], *, stop_on_opaque=False) -> tuple[set[str], bool]:
        seen, todo, opaque = set(), deque(sorted(seeds)), False
        while todo:
            path = todo.popleft()
            if path in seen:
                continue
            seen.add(path)
            if not path.endswith('.py') and not path.startswith('libexec/'):
                continue
            deps, dynamic = self.direct(path)
            if dynamic:
                self.opaque_sources.add(path)
            opaque |= dynamic
            if opaque and stop_on_opaque:
                return seen, True
            todo.extend(sorted(deps - seen))
        return seen, opaque


def select(repo: Path, registry: dict, changed: list[str] | None, *, explanations: list[str] | None = None,
           previous_registry: dict | None = None) -> dict:
    def explain(message):
        if explanations is not None and message not in explanations:
            explanations.append(message)

    registry_changes = set()
    if changed is not None and REGISTRY_INPUT in changed:
        delta = native_cell_changes(previous_registry, registry)
        if delta is not None:
            registry_changes = delta
            changed = [path for path in changed if path != REGISTRY_INPUT]

    collected = {selector.split('::', 1)[0] for row in registry['wrappers']
                 for platform in PLATFORMS
                 for selector in row.get('contract_platforms', {}).get(platform, row['contracts'])}
    collected.update(selector.split('::', 1)[0] for family in registry['native']
                     for platform, cell in family['platforms'].items() if platform in PLATFORMS and not cell.get('manual')
                     for selector in (cell.get('tests') or ()))
    bound = {row['source'] for row in registry['wrappers']} | collected
    for path in collected:
        # Include absent candidates too: adding or deleting a conftest changes
        # collection even when its path is outside the usual source roots.
        bound.update((parent / 'conftest.py').as_posix() for parent in Path(path).parents)
    relevant = lambda p: (p.startswith(('core/', 'packages/', 'engine/', '.github/scripts/')) or p in bound
                          or ('/' not in p and not p.endswith(('.md', '.txt'))))
    full = changed is None or any(p in GLOBAL_INPUTS or p.startswith(GLOBAL_DIRS) for p in changed)
    if changed is None:
        if not explanations:
            explain('Full coverage: scheduled/manual run or unavailable change history.')
    else:
        triggers = sorted(p for p in changed if p in GLOBAL_INPUTS or p.startswith(GLOBAL_DIRS))
        if triggers:
            explain('Full coverage: shared sandbox or test-harness inputs changed: ' + ', '.join(triggers))
    # Deleted modules can no longer supply the old dependency graph. A registry
    # retirement can also remove the last binding to an external test module.
    deleted = sorted(p for p in changed or [] if p.endswith('.py') and (relevant(p) or registry_changes)
                     and not (repo / p).is_file())
    full |= bool(deleted)
    if deleted:
        explain('Full coverage: deleted Python modules require the old dependency graph: ' + ', '.join(deleted))
    if not full and registry_changes:
        explain('Scoped registry coverage: native test cells changed: ' + ', '.join(
            platform + '/' + family for platform, family in sorted(registry_changes)))
    if not full and not registry_changes and not any(relevant(p) for p in changed):
        explain('No platform runners: no wrapper source, dependency or harness inputs changed.')
        return {'include': []}
    graph = Dependencies(repo)
    runtime = bool(changed and any(relevant(p) for p in changed))
    if not full and runtime and (repo / 'conftest.py').is_file():
        try:
            _, shared_opaque = graph.closure({'conftest.py'}, stop_on_opaque=True)
        except (OSError, ValueError, SyntaxError, RecursionError) as error:
            explain('Full coverage: shared pytest dependencies could not be analysed (' + type(error).__name__ + ').')
            shared_opaque = True
        if shared_opaque:
            if graph.opaque_sources:
                explain('Full coverage: computed imports in shared pytest dependencies: ' + ', '.join(sorted(graph.opaque_sources)))
            return select(repo, registry, None, explanations=explanations)
    def affected(sources, collected):
        if full:
            return True
        seeds = set(sources)
        for path in collected:
            seeds.update(graph.collection_inputs(path))
        closure, opaque = graph.closure(seeds, stop_on_opaque=runtime)
        if runtime and opaque:
            explain('Broadened selection: computed imports in wrapper dependencies: ' + ', '.join(sorted(graph.opaque_sources & closure)))
            return True
        owners = {component(p) for p in closure}
        return any(p in closure or ((not p.endswith('.py') or {'fixtures', 'testdata'} & set(Path(p).parts)) and component(p) in owners) for p in changed)
    matrix = []
    try:
        for platform, runner in PLATFORMS.items():
            contracts = set()
            for row in registry['wrappers']:
                selectors = row.get('contract_platforms', {}).get(platform, row['contracts'])
                for selector in selectors:
                    if affected([row['source']], [selector.split('::', 1)[0]]):
                        contracts.add(selector)
            families = []
            for family in registry['native']:
                cell = family['platforms'][platform]
                if cell.get('tests') and not cell.get('manual') and (
                        (platform, family['id']) in registry_changes
                        or affected((), (s.split('::', 1)[0] for s in cell['tests']))):
                    families.append(family['id'])
            if contracts or families:
                matrix.append(dict(os=runner, platform=platform, contracts=sorted(contracts), families=families, full=full))
    except (OSError, ValueError, SyntaxError, RecursionError) as error:
        if full:
            raise
        explain('Full coverage: wrapper dependencies could not be analysed (' + type(error).__name__ + ').')
        return select(repo, registry, None, explanations=explanations)
    if not matrix:
        explain('No platform runners: changed files do not affect registered wrappers or native families.')
    elif not full and not explanations:
        explain('Scoped coverage: changed files are reachable from selected wrapper contracts or native families.')
    return {'include': matrix}


def main() -> None:
    repo = Path.cwd()
    registry = load_registry(repo / '.github/sandbox-wrapper-tests.json')
    errors = registry_errors(repo, registry)
    if errors:
        raise SystemExit('\n'.join(errors))
    event = os.environ.get('EVENT', '')
    base = os.environ.get('BASE_SHA', '')
    changes = None if event in {'schedule', 'workflow_dispatch'} else changed_paths(repo, base)
    previous = base_registry(repo, base) if changes is not None and REGISTRY_INPUT in changes else None
    explanations = []
    matrix = select(repo, registry, changes, explanations=explanations, previous_registry=previous)
    with open(os.environ['GITHUB_OUTPUT'], 'a') as output:
        output.write('run=' + str(bool(matrix['include'])).lower() + '\n')
        output.write('matrix=' + json.dumps(matrix) + '\n')
    details = dict(changed_files=changes, reasons=explanations, selection=matrix['include'])
    print(json.dumps(details, indent=2))
    if summary := os.environ.get('GITHUB_STEP_SUMMARY'):
        with open(summary, 'a') as output:
            output.write('## Sandbox wrapper selection\n\n<pre>' + escape(json.dumps(details, indent=2)) + '</pre>\n')


if __name__ == '__main__':
    main()

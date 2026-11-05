"""Retain selected sandbox files unless their module mark proves macOS skips.

Do not import tests or evaluate host capabilities on the Linux scope runner.
Unknown expressions and mutations keep the file selected on the real Mac.
"""

from __future__ import annotations

import ast
import json
import os
from pathlib import Path

AUDIT_FILE = Path('core/sandbox/tests/test_macos_spawn.py')
_UNKNOWN = object()


def _value(node, sys_names, platform_names):
    if isinstance(node, ast.Constant) and isinstance(node.value, (str, bool)):
        return node.value
    if isinstance(node, ast.Name) and node.id in platform_names:
        return 'darwin'
    if (isinstance(node, ast.Attribute) and node.attr == 'platform'
            and isinstance(node.value, ast.Name) and node.value.id in sys_names):
        return 'darwin'
    return _UNKNOWN


def _condition(node, sys_names, platform_names):
    value = _value(node, sys_names, platform_names)
    if isinstance(value, bool):
        return value
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        operand = _condition(node.operand, sys_names, platform_names)
        return None if operand is None else not operand
    if isinstance(node, ast.BoolOp):
        # Respect short-circuit order: an earlier unknown call can raise or
        # change state before a later platform comparison is evaluated.
        for child in node.values:
            value = _condition(child, sys_names, platform_names)
            if value is None:
                return None
            if isinstance(node.op, ast.Or) and value:
                return True
            if isinstance(node.op, ast.And) and not value:
                return False
        return isinstance(node.op, ast.And)
    if isinstance(node, ast.Compare) and len(node.ops) == 1:
        left = _value(node.left, sys_names, platform_names)
        right = _value(node.comparators[0], sys_names, platform_names)
        if left is not _UNKNOWN and right is not _UNKNOWN:
            if isinstance(node.ops[0], ast.Eq):
                return left == right
            if isinstance(node.ops[0], ast.NotEq):
                return left != right
    if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and node.func.attr == 'startswith' and len(node.args) == 1
            and not node.keywords
            and _value(node.func.value, sys_names, platform_names) == 'darwin'):
        try:
            prefix = ast.literal_eval(node.args[0])
        except (ValueError, TypeError, SyntaxError):
            return None
        if isinstance(prefix, str) or (isinstance(prefix, tuple) and all(isinstance(p, str) for p in prefix)):
            return 'darwin'.startswith(prefix)
    return None


def skipped_on_macos(path: Path) -> bool:
    try:
        tree = ast.parse(path.read_text(encoding='utf-8'))
    except (OSError, UnicodeError, SyntaxError, ValueError, RecursionError):
        return False
    bindings = {}
    imports = set()
    for node in tree.body:
        if isinstance(node, ast.Import):
            imports.add(id(node))
            for alias in node.names:
                name = alias.asname or alias.name.split('.')[0]
                bindings[name] = alias.name if alias.asname else alias.name.split('.')[0]
        elif isinstance(node, ast.ImportFrom):
            imports.add(id(node))
            if any(alias.name == '*' for alias in node.names):
                return False
            for alias in node.names:
                bindings[alias.asname or alias.name] = f'{node.module}.{alias.name}' if node.level == 0 else None
    sys_names = {name for name, target in bindings.items() if target == 'sys'}
    pytest_names = {name for name, target in bindings.items() if target == 'pytest'}
    platform_names = {name for name, target in bindings.items() if target == 'sys.platform'}
    aliases = sys_names | pytest_names | platform_names
    writes = {id(node) for node in ast.walk(tree) if isinstance(node, ast.Name)
              and node.id == 'pytestmark' and isinstance(node.ctx, (ast.Store, ast.Del))}
    recognized = set()
    marks = {}
    skip_names = set()
    top_stores = set()
    marker_reads = set()

    def record_reads(node):
        if isinstance(node, ast.Name):
            marker_reads.add(id(node))
        elif isinstance(node, (ast.List, ast.Tuple)):
            for child in node.elts:
                record_reads(child)

    def marker(node):
        if isinstance(node, ast.Name):
            return marks.get(node.id, False)
        if isinstance(node, (ast.List, ast.Tuple)):
            return any(marker(child) for child in node.elts)
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Attribute) and node.func.value.attr == 'mark'
                and isinstance(node.func.value.value, ast.Name) and node.func.value.value.id in pytest_names):
            if node.func.attr == 'skip':
                return True
            if node.func.attr == 'skipif' and node.args:
                return _condition(node.args[0], sys_names, platform_names) is True
        return False

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node.name in aliases:
            return False
        if isinstance(node, (ast.Import, ast.ImportFrom)) and id(node) not in imports:
            if any((alias.asname or alias.name.split('.')[0]) in aliases or alias.name == '*' for alias in node.names):
                return False
        if isinstance(node, ast.Name) and node.id in aliases and isinstance(node.ctx, (ast.Store, ast.Del)):
            return False
        if isinstance(node, (ast.Attribute, ast.Subscript)) and isinstance(node.ctx, (ast.Store, ast.Del)):
            target = node.value
            while isinstance(target, (ast.Attribute, ast.Subscript)):
                target = target.value
            if isinstance(target, ast.Name) and target.id in aliases | {'pytestmark'}:
                return False
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id in {'globals', 'locals', 'exec', 'eval'}:
                return False
            if (isinstance(node.func, ast.Name) and node.func.id in {'setattr', 'delattr'}
                    and node.args and isinstance(node.args[0], ast.Name) and node.args[0].id in aliases | {'pytestmark'}):
                return False
            if (isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name)
                    and node.func.value.id == 'pytestmark'):
                return False
    for node in tree.body:
        targets = node.targets if isinstance(node, ast.Assign) else [node.target] if isinstance(node, ast.AnnAssign) else []
        if len(targets) != 1 or not isinstance(targets[0], ast.Name):
            continue
        name = targets[0].id
        top_stores.add(id(targets[0]))
        record_reads(node.value)
        if name != 'pytestmark' and node.value is not None and any(
                isinstance(child, ast.Name) and child.id == 'pytestmark' for child in ast.walk(node.value)):
            return False
        if name == 'pytestmark':
            recognized.add(id(targets[0]))
        marks[name] = marker(node.value)
        if marks[name]:
            skip_names.add(name)
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and node.id in skip_names:
            if isinstance(node.ctx, ast.Load) and id(node) not in marker_reads:
                return False
            if isinstance(node.ctx, (ast.Store, ast.Del)) and id(node) not in top_stores:
                return False
    return bool(recognized) and writes == recognized and marks.get('pytestmark', False)


def selection(repo: Path, candidates: list[str], *, force_full=False) -> dict:
    files = sorted(set(path for path in candidates if force_full or not skipped_on_macos(repo / path.partition('::')[0])))
    audit = bool(files) and (force_full or any(Path(path.partition('::')[0]) == AUDIT_FILE or (
        (repo / path).is_dir() and AUDIT_FILE.is_relative_to(Path(path))) for path in files))
    return {'run': bool(files), 'files': files, 'native_audit': audit}


def main():
    result = selection(Path.cwd(), os.environ.get('SANDBOX_FILES', '').split(),
                       force_full=os.environ.get('SCOPE_MODE') != 'scoped')
    with open(os.environ['GITHUB_OUTPUT'], 'a', encoding='utf-8') as output:
        output.write(f"run={str(result['run']).lower()}\n")
        output.write('files=' + ' '.join(result['files']) + '\n')
        output.write(f"native_audit={str(result['native_audit']).lower()}\n")
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()

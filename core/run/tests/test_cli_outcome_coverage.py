"""New libexec dispatchers must not silently omit native outcome receipts."""
import ast
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
# These helpers do not dispatch analysis workflows. Their exit statuses are
# consent decisions, operator actions, transport lifecycle or source reads.
# Keep exceptions explicit: ordinary new helpers must opt into cli_outcome.
NON_DISPATCHERS = {
    'raptor-annotate': 'operator annotation actions',
    'raptor-coverage-summary': 'operator coverage review and grants',
    'raptor-may-ask': 'consent/interactivity verdict, not workflow failure',
    'raptor-read': 'source reads have their own authenticated receipts',
    'raptor-review': 'operator finding verdicts',
    'raptor-sage-mcp-guard': 'long-lived MCP transport filter',
    'raptor-seatbelt-shim': 'isolated sandbox transport with no RAPTOR imports',
    'raptor-session-init': 'startup and exec modes have dedicated lifecycle tests',
    'raptor-wsl-consent': 'host consent ceremony',
}


def _wrapped(body):
    if len(body) != 2:
        return False
    imported, wrapped = body
    return (
        isinstance(imported, ast.ImportFrom)
        and imported.module == 'core.run.cli_outcome'
        and [(name.name, name.asname) for name in imported.names] == [('cli_outcome', None)]
        and isinstance(wrapped, ast.With)
        and len(wrapped.items) == 1
        and ast.dump(wrapped.items[0].context_expr) == ast.dump(
            ast.parse('cli_outcome()', mode='eval').body)
    )


def _covered(tree):
    # raptor-run-sandboxed and raptor-r2-sandboxed dispatch at module scope.
    if _wrapped(tree.body[-2:]):
        return True
    for node in tree.body:
        if not isinstance(node, ast.If):
            continue
        if ast.dump(node.test) == ast.dump(ast.parse("__name__ == '__main__'", mode='eval').body):
            return _wrapped(node.body) and not node.orelse
    return False


def _missing(root):
    missing = []
    for path in sorted((root / 'libexec').glob('raptor-*')):
        if not path.is_file() or path.name in NON_DISPATCHERS:
            continue
        source = path.read_text(encoding='utf-8')
        if 'python' not in source.splitlines()[0]:
            continue
        if not _covered(ast.parse(source, filename=str(path))):
            missing.append(path.name)
    return missing


def test_all_python_libexec_dispatchers_record_native_outcomes():
    assert list((ROOT / 'libexec').glob('raptor-*')), 'empty libexec inventory'
    missing = _missing(ROOT)
    assert not missing, ('Wrap the new dispatcher entry point with '
                         f'core.run.cli_outcome.cli_outcome: {missing}')
    assert all((ROOT / 'libexec' / name).is_file() for name in NON_DISPATCHERS)


@pytest.mark.parametrize('entry', [
    'main()',
    'from core.run.cli_outcome import cli_outcome\nmain()',
    'from core.run.cli_outcome import cli_outcome\nmain()\nwith cli_outcome():\n    pass',
])
def test_new_or_partially_wrapped_dispatcher_fails_inventory(tmp_path, entry):
    directory = tmp_path / 'libexec'
    directory.mkdir()
    path = directory / 'raptor-new-helper'
    path.write_text('#!/usr/bin/env python3\nif __name__ == "__main__":\n'
                    + '\n'.join('    ' + line for line in entry.splitlines()) + '\n')
    assert _missing(tmp_path) == ['raptor-new-helper']
    path.write_text('#!/usr/bin/env python3\nif __name__ == "__main__":\n'
                    '    from core.run.cli_outcome import cli_outcome\n'
                    '    with cli_outcome():\n        main()\n')
    assert _missing(tmp_path) == []

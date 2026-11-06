"""Membership checks must establish a contract before suppressing request taint."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess

import pytest

_RULES = Path(__file__).resolve().parents[1] / 'rules/php'
_FAMILIES = (
    ('include-injection', 'request-path', "include 'pages/' . $v . '.php';"),
    ('open-redirect', 'header-location', "header('Location: ' . $v);"),
    ('unsafe-reflection', 'tainted-callable', '$v();'),
)
pytestmark = [pytest.mark.slow, pytest.mark.skipif(
    shutil.which('semgrep') is None, reason='semgrep not installed')]


@pytest.mark.parametrize('bracketed', [False, True])
def test_membership_requires_a_literal_allowlist_and_rejection(tmp_path, bracketed):
    safe = [
        "if (!in_array($v, ['home', 'about'], true)) { return; }",
        "if (!in_array($v, ['home', 'about'], true)) { return null; }",
        'if (!in_array($v, ["home", "about"], true)) { die("bad"); }',
        r"if (!\in_array($v, ['home', 'about'], true)) { exit(1); }",
        "if (!in_array($v, ['home', 'about'], true)) { $v = 'home'; }",
        "if (!IN_ARRAY($v, ['home', 'about'], true)) { $v = 'home'; }",
    ]
    unsafe = [
        "in_array($v, ['home', 'about'], true);",
        "if (in_array($v, ['home', 'about'], true)) { return; }",
        "if (!in_array($v, $_GET['allowed'], true)) { return; }",
        "if (!in_array($v, ['home', $_GET['extra']], true)) { return; }",
        'if (!in_array($v, ["home", "$extra"], true)) { return; }',
        "if (!in_array($v, ['home'], false)) { return; }",
        "if (!in_array($v, ['home'])) { return; }",
        "if (!in_array($v, ['home'], true)) { }",
        "if (!in_array($v, ['home'], true)) { $v = $_GET['fallback']; }",
        "if (!in_array($v, ['home'], true)) { $v = 'home'; } $v = $_GET['again'];",
        "if (!in_array($v, ['home'], true)) { $v = 'home'; $v = $_GET['again']; }",
    ]
    targets = []
    expected = set()
    for family, _, sink in _FAMILIES:
        lines = ['<?php', 'namespace Main {' if bracketed else 'namespace Main;']
        for index, guard in enumerate(safe + unsafe):
            lines += [f'function case_{index}($extra) {{', "  $v = $_GET['value'];",
                      f'  {guard}', f'  {sink}', '}']
            if index >= len(safe):
                expected.add((family, len(lines) - 1))
        # A rejection branch is not allowed to consume the unsafe value first.
        for index, terminal in enumerate(('return;', '$v = "home";')):
            lines += [f'function before_reject_{index}() {{', "  $v = $_GET['value'];",
                      "  if (!in_array($v, ['home'], true)) {", f'    {sink}']
            expected.add((family, len(lines)))
            lines += [f'    {terminal}', '  }', '}']
        # Never sanitize sinks evaluated as part of a rejecting expression.
        expression = sink.rstrip(';')
        for index, terminal in enumerate((f'return {expression};', f'die({expression});')):
            lines += [f'function nested_reject_{index}() {{', "  $v = $_GET['value'];",
                      "  if (!in_array($v, ['home'], true)) {", f'    {terminal}']
            expected.add((family, len(lines)))
            lines += ['  }', '}']
        if bracketed:
            lines.append('}')
        lines += ['namespace Shadow {' if bracketed else 'namespace Shadow;',
                  'function IN_ARRAY($v, $allowed, $strict) { return true; }']
        for index, reader in enumerate(('in_array', r'\in_array')):
            lines += [f'function shadow_{index}() {{', "  $v = $_GET['value'];",
                      f"  if (!{reader}($v, ['home'], true)) {{ return; }}", f'  {sink}', '}']
            if index == 0:
                expected.add((family, len(lines) - 1))
        if bracketed:
            lines.append('}')
        for index, declaration in enumerate((
            r'use function Vendor\accept as in_array;',
            r'use function Vendor\in_array;',
            r'use function Vendor\{accept as in_array};',
            r'use Vendor\{function accept as in_array};',
            r'use function Vendor\unrelated;',
        )):
            lines += [f'namespace Imported{index} {{' if bracketed
                      else f'namespace Imported{index};', declaration]
            for qualified, reader in enumerate(('in_array', r'\in_array')):
                lines += [f'function import_{qualified}() {{', "  $v = $_GET['value'];",
                          f"  if (!{reader}($v, ['home'], true)) {{ return; }}",
                          f'  {sink}', '}']
                if not qualified:
                    expected.add((family, len(lines) - 1))
            if bracketed:
                lines.append('}')
        target = tmp_path / f'{family}.php'
        target.write_text('\n'.join(lines) + '\n')
        targets.append(target)
        # Imports also apply at file scope without a namespace declaration.
        global_lines = ['<?php', r'use function Vendor\accept as in_array;']
        for index, reader in enumerate(('in_array', r'\in_array')):
            global_lines += [f'function global_{index}() {{', "  $v = $_GET['value'];",
                             f"  if (!{reader}($v, ['home'], true)) {{ return; }}",
                             f'  {sink}', '}']
            if index == 0:
                expected.add((family + '--global', len(global_lines) - 1))
        target = tmp_path / f'{family}--global.php'
        target.write_text('\n'.join(global_lines) + '\n')
        targets.append(target)
    for args in (['git', 'init', '-q'], ['git', 'add', '--', *[p.name for p in targets]]):
        subprocess.run(args, cwd=tmp_path, check=True, capture_output=True, timeout=20)
    configs = [arg for family, _, _ in _FAMILIES
               for arg in ('--config', str(_RULES / f'{family}.yaml'))]
    result = subprocess.run(
        ['semgrep', 'scan', *configs, '--metrics', 'off', '--disable-version-check',
         '--jobs', '1', '--json', *map(str, targets)],
        cwd=tmp_path, capture_output=True, text=True, timeout=180, check=False,
        env={**os.environ, 'SEMGREP_SETTINGS_FILE': str(tmp_path / 'settings.yml'),
             'SEMGREP_LOG_FILE': str(tmp_path / 'semgrep.log')},
    )
    assert result.returncode == 0, result.stderr
    data = json.loads(result.stdout)
    assert not data.get('errors'), data.get('errors')
    assert {Path(p).name for p in data['paths']['scanned']} == {p.name for p in targets}
    actual = set()
    for row in data['results']:
        target_name = Path(row['path']).stem
        family = target_name.split('--')[0]
        suffix = next(suffix for name, suffix, _ in _FAMILIES if name == family)
        if row['check_id'].endswith(f'raptor.php.{family}.{suffix}'):
            actual.add((target_name, row['start']['line']))
    assert actual == expected, {'missing': sorted(expected - actual),
                                'unexpected': sorted(actual - expected)}

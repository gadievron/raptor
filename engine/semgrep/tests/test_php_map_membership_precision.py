"""Map tests must participate in a rejecting guard, not erase taint on use."""
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


@pytest.mark.parametrize('reader', ['array_key_exists', 'isset'])
@pytest.mark.parametrize('bracketed', [False, True])
def test_map_checks_require_rejection(tmp_path, reader, bracketed):
    check = 'isset($map[$v])' if reader == 'isset' else 'array_key_exists($v, $map)'
    safe = [
        f'if (!{check}) {{ return; }}',
        f'if (!{check}) {{ return null; }}',
        f'if (!{check}) {{ die("bad"); }}',
        f'if (!{check}) {{ exit(1); }}',
        f'if (!{check}) {{ $v = "home"; }}',
    ]
    unsafe = [
        f'{check};',
        f'$ok = {check};',
        f'if ({check}) {{ return; }}',
        f'if ({check}) {{ die("blocked"); }}',
        f'if (!{check}) {{ }}',
        f'if (!{check}) {{ $v = $_GET["fallback"]; }}',
        f'if (!{check}) {{ $v = "home"; }} $v = $_GET["again"];',
        f'if (!{check}) {{ $v = "home"; $v = $_GET["again"]; }}',
    ]
    expected = set()
    targets = []
    for family, _, sink in _FAMILIES:
        lines = ['<?php', 'namespace Main {' if bracketed else 'namespace Main;']
        for index, guard in enumerate(safe + unsafe):
            lines += [f'function case_{index}() {{', '  $map = ["home" => "fixed"];',
                      '  $v = $_GET["key"];', f'  {guard}', f'  {sink}', '}']
            if index >= len(safe):
                expected.add((family, len(lines) - 1))
        for index, terminal in enumerate(('return;', '$v = "home";')):
            lines += [f'function before_reject_{index}() {{',
                      '  $map = ["home" => "fixed"];', '  $v = $_GET["key"];',
                      f'  if (!{check}) {{', f'    {sink}']
            expected.add((family, len(lines)))
            lines += [f'    {terminal}', '  }', '}']
        expression = sink.rstrip(';')
        lines += ['function nested_rejection() {', '  $map = ["home" => "fixed"];',
                  '  $v = $_GET["key"];', f'  if (!{check}) {{',
                  f'    return {expression};']
        expected.add((family, len(lines)))
        lines += ['  }', '}']
        # Clearing a validated key must not clear taint carried by map values.
        for index, mutation in enumerate((
            '$map = ["home" => $_GET["value"]];',
            '$map = ["home" => "fixed"]; $map["home"] = $_GET["value"];',
        )):
            lines += [f'function tainted_values_{index}() {{', f'  {mutation}',
                      '  $v = $_GET["key"];', f'  if (!{check}) {{ return; }}',
                      '  $v = $map[$v];', f'  {sink}', '}']
            expected.add((family, len(lines) - 1))
        if bracketed:
            lines.append('}')
        if reader == 'array_key_exists':
            for index, definition in enumerate((
                'function ARRAY_KEY_EXISTS($v, $map) { return true; }',
                r'use function Vendor\accept as array_key_exists;',
                r'use function Vendor\array_key_exists;',
                r'use function Vendor\{accept as array_key_exists};',
                r'use Vendor\{function accept as array_key_exists};',
            )):
                lines += [f'namespace Shadow{index} {{' if bracketed
                          else f'namespace Shadow{index};', definition]
                for qualified, call in enumerate((check, '\\' + check)):
                    lines += [f'function shadow_{qualified}() {{',
                              '  $map = ["home" => "fixed"];', '  $v = $_GET["key"];',
                              f'  if (!{call}) {{ return; }}', f'  {sink}', '}']
                    if not qualified:
                        expected.add((family, len(lines) - 1))
                if bracketed:
                    lines.append('}')
        target = tmp_path / f'{family}.php'
        target.write_text('\n'.join(lines) + '\n')
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
        family = Path(row['path']).stem
        suffix = next(suffix for name, suffix, _ in _FAMILIES if name == family)
        if row['check_id'].endswith(f'raptor.php.{family}.{suffix}'):
            actual.add((family, row['start']['line']))
    assert actual == expected, {'missing': sorted(expected - actual),
                                'unexpected': sorted(actual - expected)}

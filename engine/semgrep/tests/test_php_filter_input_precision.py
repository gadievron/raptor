"""Raw PHP input readers are sources; other filter contracts are not inferred."""
from __future__ import annotations

import itertools
import json
import os
from pathlib import Path
import shutil
import subprocess

import pytest

_RULES = Path(__file__).resolve().parents[1] / 'rules' / 'php'
_FAMILIES = (
    ('argument-injection', 'exec-family', 'system("echo " . $v);'),
    ('attr-xss', 'attr-context', 'echo "<a href=\'" . $v . "\'>x</a>";'),
    ('crlf-injection', 'socket-write', 'socket_write($socket, $v);'),
    ('include-injection', 'request-path', "include 'pages/' . $v . '.php';"),
    ('open-redirect', 'header-location', "header('Location: ' . $v);"),
    ('unsafe-reflection', 'tainted-callable', '$v();'),
    ('unserialize-taint', 'request-data', 'unserialize($v);'),
)
pytestmark = [pytest.mark.slow, pytest.mark.skipif(
    shutil.which('semgrep') is None, reason='semgrep not installed')]


@pytest.mark.parametrize('bracketed', [False, True])
def test_raw_input_sources_across_php_families(tmp_path, bracketed):
    targets = []
    expected = set()
    for family, suffix, sink in _FAMILIES:
        positive = []
        for (reader, prefix), kind, filter_name in itertools.product(
            (('filter_input', ''), (r'\filter_input', '\\')),
            ('INPUT_GET', 'INPUT_POST', 'INPUT_COOKIE'),
            (None, 'FILTER_DEFAULT', 'FILTER_UNSAFE_RAW'),
        ):
            args = f"{prefix}{kind}, 'value'"
            if filter_name:
                args += f', {prefix}{filter_name}'
            positive.append(f'{reader}({args})')
        positive += ["FILTER_INPUT(INPUT_GET, 'value')",
                     r"filter_input(\INPUT_GET, 'value')",
                     r"\filter_input(INPUT_GET, 'value', FILTER_UNSAFE_RAW)"]
        positive += [r"\FILTER_INPUT(\INPUT_GET, 'value')",
                     r"\FiLtEr_InPuT(\INPUT_POST, 'value', \FILTER_UNSAFE_RAW)"]
        controls = [
            "filter_input(INPUT_GET, 'value', FILTER_VALIDATE_INT)",
            "filter_input(INPUT_POST, 'value', FILTER_SANITIZE_SPECIAL_CHARS)",
            "filter_input(INPUT_COOKIE, 'value', FILTER_CALLBACK, ['options' => 'intval'])",
            "filter_input(INPUT_GET, 'value', FILTER_UNSAFE_RAW, FILTER_FLAG_STRIP_LOW)",
            "filter_input(INPUT_ENV, 'value')",
            "$obj->filter_input(INPUT_GET, 'value')",
            "Other::filter_input(INPUT_GET, 'value')",
            r"Other\filter_input(INPUT_GET, 'value')",
        ]
        # Each function isolates taint; line markers are generated with the source.
        lines = ['<?php', 'namespace Main {' if bracketed else 'namespace Main;']
        for index, expression in enumerate(positive + controls):
            lines += [f'function case_{index}($socket, $obj) {{',
                      f'  $v = {expression};', f'  {sink}', '}']
            if index < len(positive):
                expected.add((family, len(lines) - 1))
        # A source is the return value, never its argument expressions.
        lines += ["function source_arguments($socket) {",
                  "  $name = 'fixed';",
                  "  filter_input(INPUT_GET, $name);",
                  "  $v = $name;", f'  {sink}', '}']
        lines += ["function overwritten_raw($socket) {",
                  "  $v = filter_input(INPUT_GET, 'value');",
                  "  $v = 'fixed';", f'  {sink}', '}']
        if bracketed:
            lines.append('}')
        for namespace, definition, local, qualified in (
            ('Reader', "function filter_input($kind, $name) { return 'fixed'; }",
             "filter_input(INPUT_GET, 'value')", r"\filter_input(\INPUT_GET, 'value')"),
            ('Kind', r'const INPUT_GET = \INPUT_ENV;',
             "filter_input(INPUT_GET, 'value')", r"filter_input(\INPUT_GET, 'value')"),
            ('Filter', r'const FILTER_DEFAULT = \FILTER_VALIDATE_INT;',
             "filter_input(INPUT_GET, 'value', FILTER_DEFAULT)",
             r"filter_input(INPUT_GET, 'value', \FILTER_DEFAULT)"),
        ):
            lines += [f'namespace {namespace} {{' if bracketed else f'namespace {namespace};',
                      definition]
            for index, expression in enumerate((local, qualified)):
                lines += [f'function shadow_{index}($socket) {{',
                          f'  $v = {expression};', f'  {sink}', '}']
                if index:
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

"""Unserialize findings depend on the serialized input and effective class policy."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess

import pytest

_RULE = Path(__file__).resolve().parents[1] / 'rules/php/unserialize-taint.yaml'
pytestmark = [pytest.mark.slow, pytest.mark.skipif(
    shutil.which('semgrep') is None, reason='semgrep not installed')]


@pytest.mark.parametrize('bracketed', [False, True])
def test_unserialize_class_policy_and_input_focus(tmp_path, bracketed):
    unsafe_options = [
        None, '[]', 'array()', "['max_depth' => 64]", "array('max_depth' => 64)",
        "['max_depth' => $depth]", "['allowed_classes' => true]",
        "array('allowed_classes' => true)",
        "['allowed_classes' => true, 'max_depth' => 64]",
        "['max_depth' => 64, 'allowed_classes' => true]",
        "['allowed_classes' => false, 'allowed_classes' => true]",
        "['allowed_classes' => true, 'allowed_classes' => false, 'allowed_classes' => true]",
        "array('allowed_classes' => false, 'allowed_classes' => true)",
        "['max_depth' => 64, 'max_depth' => 128]",
        "['max_depth' => $_GET['depth']]",
        "['allowed_classes' => true, 'max_depth' => $_GET['depth']]",
        '[' + ' ' * 8000 + "'max_depth' => 64]",
    ]
    restricted_or_unresolved = [
        "['allowed_classes' => false]", "array('allowed_classes' => false)",
        "['allowed_classes' => []]", "['allowed_classes' => ['KnownClass']]",
        "['max_depth' => 64, 'allowed_classes' => false]",
        "['max_depth' => 64, 'allowed_classes' => $policy]",
        "['allowed_classes' => true, 'allowed_classes' => false]",
        "['allowed_classes' => true, ...$options]",
        "['allowed_classes' => true, 'allowed_classes' => false, 'max_depth' => 64]",
        "[...$options, 'max_depth' => 64]", '$options', 'make_options()',
        '[' + ' ' * 8000 + "'allowed_classes' => false]",
    ]
    unsafe_options += [
        "[/* policy */ 'allowed_classes' /* key */ => true]",
        "[ // depth\n 'max_depth' => 64, # policy\n 'allowed_classes' => true,\n]",
        "array(/* policy */ 'allowed_classes' => true /* end */)",
        "['allowed_classes' => false, // old\r\n 'allowed_classes' => true]",
    ]
    restricted_or_unresolved += [
        "[/* old */ 'allowed_classes' => true, /* new */ 'allowed_classes' => false]",
        '[/*' + 'x' * 10000 + "*/ 'allowed_classes' => false]",
        "['allowed_classes' => true, $key => false]",
    ]
    unsafe_options.append('[' + ', '.join(
        ["'allowed_classes' => false", "'allowed_classes' => true"] * 128) + ']')
    restricted_or_unresolved.append('[' + ', '.join(
        ["'allowed_classes' => true", "'allowed_classes' => false"] * 128) + ']')
    lines = ['<?php', 'namespace Main {' if bracketed else 'namespace Main;']
    expected = set()
    for reader in ('unserialize', r'\unserialize', 'UNSERIALIZE', r'\UNSERIALIZE'):
        for options in unsafe_options + restricted_or_unresolved:
            suffix = '' if options is None else ', ' + options
            lines += [f'function case_{len(lines)}($depth, $policy, $options, $key) {{',
                      "  $raw = $_GET['payload'];"]
            if options in unsafe_options:
                expected.add(len(lines) + 1)
            lines += f'  return {reader}($raw{suffix});'.splitlines() + ['}']
        # Request data in options must not taint a fixed serialized argument.
        for options in ("['max_depth' => $_GET['depth']]",
                        "['allowed_classes' => true, 'max_depth' => $_GET['depth']]"):
            lines += [f'function fixed_{len(lines)}() {{',
                      f"  return {reader}('a:0:{{}}', {options});", '}']
    lines += ['function method_lookalike($obj) {',
              "  return $obj->unserialize($_GET['payload']);", '}']
    if bracketed:
        lines.append('}')
    target = tmp_path / 'policies.php'
    target.write_text('\n'.join(lines) + '\n')
    for args in (['git', 'init', '-q'], ['git', 'add', '--', target.name]):
        subprocess.run(args, cwd=tmp_path, check=True, capture_output=True, timeout=20)
    result = subprocess.run(
        ['semgrep', 'scan', '--config', str(_RULE), '--metrics', 'off',
         '--disable-version-check', '--jobs', '1', '--json', str(target)],
        cwd=tmp_path, capture_output=True, text=True, timeout=180, check=False,
        env={**os.environ, 'SEMGREP_SETTINGS_FILE': str(tmp_path / 'settings.yml'),
             'SEMGREP_LOG_FILE': str(tmp_path / 'semgrep.log')},
    )
    assert result.returncode == 0, result.stderr
    data = json.loads(result.stdout)
    assert not data.get('errors'), data.get('errors')
    assert {Path(p).name for p in data['paths']['scanned']} == {target.name}
    assert all(row['check_id'].endswith('raptor.php.unserialize-taint.request-data')
               for row in data['results'])
    actual = {row['start']['line'] for row in data['results']}
    assert actual == expected, {'missing': sorted(expected - actual),
                                'unexpected': sorted(actual - expected)}

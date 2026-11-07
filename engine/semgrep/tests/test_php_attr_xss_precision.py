"""Attribute values must not borrow request taint from later body operands."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess

import pytest


_RULE = Path(__file__).resolve().parents[1] / 'rules/php/attr-xss.yaml'
_ID = 'raptor.php.attr-xss.attr-context'
pytestmark = [pytest.mark.slow, pytest.mark.skipif(
    shutil.which('semgrep') is None, reason='semgrep not installed')]


def test_attribute_operand_context_and_sanitizer_results(tmp_path):
    cases = [
        ('$v=$_GET[\'x\']; echo "<a title=\'" . $v . "\'>";', True),
        ('echo "<a title=\'" . transform($_GET[\'x\'], \'fixed\') . "\'>";', True),
        ('echo "<a title=\'" . $_GET [ \'x\' ] . "\'>";', True),
        ('echo "<a title=\'" . outer(inner($_GET[\'x\'])) . "\'>";', True),
        ('echo "<a title=" . $_GET[\'x\'] . ">";', True),
        ('echo "<a title=\'" . \'prefix-\' . $_GET[\'x\'] . "\'>";', True),
        ('echo "<a title=" . \'prefix-\' . $_GET[\'x\'] . ">";', True),
        ('$v=$_GET[\'x\']; echo "<a title=\'" . \'fixed\' . "\'>" . $v;', False),
        ('echo "<a title=\'" . htmlspecialchars($_GET[\'x\'], ENT_QUOTES) . "\'>" . $_GET[\'body\'];', False),
        ('echo "<a title=" . \'fixed\' . ">" . $_GET[\'body\'];', False),
        ('echo "<a title=" . intval($_GET[\'x\']) . ">" . $_GET[\'body\'];', False),
        ('echo "<a title=\'" . transform(\'fixed\') . "\'>" . $_GET[\'body\'];', False),
        ('echo "<a title=\'" . $_GET[\'part.with.dot\'] . "\'>";', True),
        ('echo "<a title=\'" . transform($_GET[\'x\'], "quoted\'argument") . "\'>";', True),
        ('echo "<a href=\\"fixed\\" title=\'" . $_GET[\'x\'] . "\'>";', True),
        ('echo "prefix\\n<a title=\'" . $_GET[\'x\'] . "\'>";', True),
        ('echo "<a title=\'" . (float)$_GET[\'x\'] . "\'>";', False),
        ('echo "<a title=" . (bool)$_GET[\'x\'] . ">";', False),
        ('$v=\\FLOATVAL($_GET[\'x\']); echo "<a title=" . $v . ">";', False),
        ('$v=\\HTMLSPECIALCHARS($_GET[\'x\'], ENT_QUOTES); echo "<a title=\'" . $v . "\'>";', False),
        ('echo "<a title=" . strlen($_GET[\'x\']) . ">";', False),
        ('echo "<a title=" . count($_GET[\'items\']) . ">";', False),
        ('echo "<a title=" . sizeof($_POST[\'items\']) . ">";', False),
        ('$v=$_GET[\'x\']; intval($v); echo "<a title=" . $v . ">";', True),
        ('$v=$_GET[\'x\']; $safe=(float)$v; echo "<a title=\'" . $v . "\'>";', True),
        ('$v=$_GET[\'x\']; echo "<a title=\'" . $obj->htmlspecialchars($v) . "\'>";', True),
        ('$v=$_GET[\'x\']; rawurlencode(print("<a title=" . $v . ">"));', True),
        ('$v=$_GET[\'x\']; $safe=intval(print("<a title=" . $v . ">"));', True),
        ('$v=$_GET[\'x\']; echo "<a title=\'$v\'>";', True),
        ('$v=$_GET[\'x\']; echo "<a title=\'{$v}\'>";', True),
        ('echo "<a title=\'{$_GET[\'x\']}\'>";', True),
        ('$v=$_GET[\'x\']; echo "<a a=\'$v\' b=\'fixed\'>";', True),
        ('$v=$_GET[\'x\']; echo "<a a=\'fixed\' b=\'$v\' c=\'fixed\'>";', True),
        ('$v=$_GET[\'x\']; echo "<a a=\'fixed\' b=\'$v\'>";', True),
        ('$v=$_GET[\'x\']; echo "<a title=\'" . \'x\' . $v . \'y\' . $v . "\'>";', True),
        ('echo "<a title=" . \'fixed \' . \'>\' . $_GET[\'body\'];', False),
        ('echo "<a title=\'".\'fixed\'."\'>".$_GET[\'body\'];', False),
        ('echo "<a title=".\'fixed\'.">".$_GET[\'body\'];', False),
        ('echo "<a title=\'".htmlspecialchars($_GET[\'x\'],ENT_QUOTES)."\'>".$_GET[\'body\'];', False),
        ('echo "<a title=\'".\'prefix-\'.$_GET[\'x\']."\'>";', True),
        ('echo "<a title=\'" . \'prefix\\n\' . $_GET[\'x\'] . "\'>";', True),
        ('echo "<a title=" . \'prefix\\n\' . $_GET[\'x\'] . ">";', True),
        ('echo "<a title=\'" . "prefix\\q" . $_GET[\'x\'] . "\'>";', True),
    ]
    targets = []
    expected = set()
    for index, (body, finding) in enumerate(cases):
        target = tmp_path / f'case_{index}.php'
        target.write_text('<?php\nfunction f() {\n  ' + body + '\n}\n')
        targets.append(target)
        if finding:
            expected.add(target.name)
    segment = '"<a title=" . $_GET["x"] . ">"'
    target = tmp_path / 'chain.php'
    target.write_text('<?php\nfunction chain() {\n echo ' + ' . '.join([segment] * 120) + ';\n}\n')
    targets.append(target)
    expected.add(target.name)
    segment = '\"<a title=\'\" . $_GET[\"x\"] . \"\'>\"'
    target = tmp_path / 'quoted_chain.php'
    target.write_text('<?php\nfunction chain() {\n echo ' + ' . '.join([segment] * 120) + ';\n}\n')
    targets.append(target)
    expected.add(target.name)
    target = tmp_path / 'rejected.php'
    target.write_text('<?php\nfunction rejected() {\n echo "<a ' + 'x' * 20000 + '" . $_GET["x"];\n}\n')
    targets.append(target)
    for args in (['git', 'init', '-q'], ['git', 'add', '--', *[p.name for p in targets]]):
        subprocess.run(args, cwd=tmp_path, capture_output=True, check=True, timeout=20)
    proc = subprocess.run(
        ['semgrep', 'scan', '--config', str(_RULE), '--metrics', 'off',
         '--disable-version-check', '--jobs', '1', '--json', *map(str, targets)],
        cwd=tmp_path, capture_output=True, text=True, timeout=180, check=False,
        env={**os.environ, 'SEMGREP_SETTINGS_FILE': str(tmp_path / 'settings.yml'),
             'SEMGREP_LOG_FILE': str(tmp_path / 'semgrep.log')},
    )
    data = json.loads(proc.stdout)
    assert proc.returncode == 0, proc.stderr
    assert not data.get('errors'), data.get('errors')
    assert {Path(path).name for path in data['paths']['scanned']} == {p.name for p in targets}
    relevant = [row for row in data['results'] if row['check_id'].endswith(_ID)]
    actual = {Path(row['path']).name for row in relevant}
    for name in ('chain.php', 'quoted_chain.php'):
        assert sum(Path(row['path']).name == name for row in relevant) == 120
    assert actual == expected, {'missing': sorted(expected - actual),
                                'unexpected': sorted(actual - expected)}

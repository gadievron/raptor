"""HTML encoding of request data does not replace attribute quoting."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess

import pytest

from core.analysis.rule_versions import version_tuple

_RULE = Path(__file__).resolve().parents[1] / 'rules/php/attr-encoding.yaml'
_ID = 'raptor.php.attr-encoding.unquoted-encoded-request'
pytestmark = [pytest.mark.slow, pytest.mark.skipif(
    shutil.which('semgrep') is None, reason='semgrep not installed')]


def test_encoded_request_requires_attribute_quoting(tmp_path):
    cases = [
        ("echo \"<a title=\" . htmlspecialchars($_GET['x'], ENT_QUOTES) . \">\";", True),
        ("echo '<a title=' . htmlentities($_POST['x']) . '>';", True),
        ("echo \"<a title=\" . \\HTMLENTITIES($_COOKIE['x'], ENT_QUOTES, 'UTF-8', false) . \">\";", True),
        ("$v=htmlspecialchars($_REQUEST['x']); $copy=$v; echo \"<a title=\" . $copy . \">\";", True),
        ("$v=htmlentities(filter_input(INPUT_GET, 'x')); echo \"<a title=\" . $v . \">\";", True),
        ("$v=htmlentities($_GET['x']); rawurlencode($v); echo \"<a title=\" . $v . \">\";", True),
        ("echo \"<a title='\" . htmlspecialchars($_GET['x'], ENT_QUOTES) . \"'>\";", False),
        ("echo \"<p>\" . htmlspecialchars($_GET['x']) . \"</p>\";", False),
        ("echo \"setting=\" . htmlspecialchars($_GET['x']);", False),
        ("echo \"<a title=\" . htmlspecialchars('fixed', $_GET['flags']) . \">\";", False),
        ("$v=htmlspecialchars('fixed', $_GET['flags']); echo \"<a title=\" . $v . \">\";", False),
        ("$v=$_GET['x']; htmlspecialchars($v); echo \"<a title=\" . $v . \">\";", False),
        ("$v=htmlspecialchars($_GET['x']); $v='fixed'; echo \"<a title=\" . $v . \">\";", False),
        ("$v=htmlspecialchars((int)$_GET['x']); echo \"<a title=\" . $v . \">\";", False),
        ("$v=(int)htmlspecialchars($_GET['x']); echo \"<a title=\" . $v . \">\";", False),
        ("$v=htmlspecialchars(urlencode($_GET['x'])); echo \"<a title=\" . $v . \">\";", False),
        ("$v=rawurlencode(htmlspecialchars($_GET['x'])); echo \"<a title=\" . $v . \">\";", False),
        ("echo \"<a title=\" . htmlspecialchars('fixed') . \">\" . htmlspecialchars($_GET['x']);", False),
        (r'''echo "<a title='prefix data-x=" . htmlspecialchars($_GET['x'], ENT_QUOTES);''', False),
        (r'''echo "<a title=\"prefix data-x=" . htmlspecialchars($_GET['x'], ENT_QUOTES);''', False),
        (r'''echo '<a title="prefix data-x=' . htmlspecialchars($_GET['x'], ENT_QUOTES);''', False),
        (r'''echo '<a title=\'prefix data-x=' . htmlspecialchars($_GET['x'], ENT_QUOTES);''', False),
        (r'''$v=htmlspecialchars($_GET['x']); echo "<a title=" . $v->fixed();''', False),
        (r'''$v=htmlspecialchars($_GET['x']); echo "<a title=" . $v[0];''', False),
        (r'''$v=htmlspecialchars($_GET['x']); echo "<a title=" . $v();''', False),
    ]
    cases += [
        (r'''$v=htmlspecialchars($_GET['x']); urlencode(print("<a title=" . $v . ">"));''', True),
        (r'''$v=htmlspecialchars($_GET['x']); $safe=urlencode(print("<a title=" . $v . ">"));''', True),
        (r'''$v=htmlspecialchars($_GET['x']); $safe=(int)$v; echo "<a title=" . $v . ">";''', True),
        (r'''$raw=$_GET['x']; $safe=htmlspecialchars((int)$raw); $v=htmlspecialchars($raw); echo "<a title=" . $v . ">";''', True),
        (r'''$v=\RAWURLENCODE(htmlspecialchars($_GET['x'])); echo "<a title=" . $v . ">";''', False),
        (r'''$v=htmlspecialchars(\INTVAL($_GET['x'])); echo "<a title=" . $v . ">";''', False),
    ]
    cases += [
        (r'''$v=htmlspecialchars(count($_GET['items'])); echo "<a title=" . $v . ">";''', False),
        (r'''$v=strlen(htmlspecialchars($_GET['x'])); echo "<a title=" . $v . ">";''', False),
        (r'''$v=htmlspecialchars(sizeof($_POST['items'])); echo "<a title=" . $v . ">";''', False),
    ]
    cases += [
        ('echo "<a title=" . (bool)htmlspecialchars($_GET["x"]) . ">";', False),
        ('$v=(bool)htmlspecialchars($_GET["x"]); echo "<a title=" . $v . ">";', False),
        ('$raw=$_GET["x"]; $safe=(bool)$raw; $v=htmlspecialchars($raw); echo "<a title=" . $v . ">";', True),
    ]
    targets = []
    expected = set()
    for index, (body, finding) in enumerate(cases):
        target = tmp_path / f'case_{index}.php'
        target.write_text('<?php\nfunction f() {\n  ' + body + '\n}\n')
        targets.append(target)
        if finding:
            expected.add(target.name)
    segment = '"<a title=" . htmlspecialchars($_GET["x"], ENT_QUOTES) . ">"'
    target = tmp_path / 'chain.php'
    target.write_text('<?php\nfunction chain() {\n echo ' + ' . '.join([segment] * 120) + ';\n}\n')
    targets.append(target)
    expected.add(target.name)
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
    installed = version_tuple(data.get('version'))
    if installed is not None and installed < (1, 47, 0):
        pytest.skip('unquoted conditional-taint rule requires Semgrep >= 1.47.0')
    assert proc.returncode == 0, proc.stderr
    assert not data.get('errors'), data.get('errors')
    assert {Path(path).name for path in data['paths']['scanned']} == {p.name for p in targets}
    relevant = [row for row in data['results'] if row['check_id'].endswith(_ID)]
    actual = {Path(row['path']).name for row in relevant}
    assert sum(Path(row['path']).name == 'chain.php' for row in relevant) == 120
    assert actual == expected, {'missing': sorted(expected - actual),
                                'unexpected': sorted(actual - expected)}
